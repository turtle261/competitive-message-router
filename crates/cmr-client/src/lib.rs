//! High-level client API for CMR applications.
//!
//! This crate is intentionally client-only. It builds CMR messages, sends them
//! to a router over supported transports, and can host a simple HTTP inbox for
//! replies routed back to the client identity.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cmr_core::protocol::{
    CmrMessage, CmrTimestamp, MessageId, ParseContext, Signature, parse_message,
};
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use lettre::message::header;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use rand::RngCore;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use url::Url;

const UDP_MAX_PAYLOAD_BYTES: usize = 65_507;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_HEADER_IDS: usize = 1_024;

/// SMTP transport settings for `mailto:` destinations.
#[derive(Clone, Debug)]
pub struct SmtpClientConfig {
    /// SMTP relay hostname.
    pub relay: String,
    /// SMTP relay port.
    pub port: u16,
    /// Allow plaintext SMTP.
    pub allow_insecure: bool,
    /// Optional auth username.
    pub username: Option<String>,
    /// Optional auth password.
    pub password: Option<String>,
    /// Envelope sender address.
    pub from: String,
}

/// SSH transport settings for `ssh://` destinations.
#[derive(Clone, Debug)]
pub struct SshClientConfig {
    /// SSH binary path.
    pub binary: String,
    /// Remote command used when destination path is empty.
    pub default_remote_command: String,
}

impl Default for SshClientConfig {
    fn default() -> Self {
        Self {
            binary: "ssh".to_owned(),
            default_remote_command: "cmr-peer receive-stdin --transport ssh".to_owned(),
        }
    }
}

/// Client transport configuration.
#[derive(Clone, Debug, Default)]
pub struct ClientTransportConfig {
    /// Optional SMTP transport.
    pub smtp: Option<SmtpClientConfig>,
    /// SSH transport settings.
    pub ssh: SshClientConfig,
}

/// Errors returned by `cmr-client`.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// HTTP/HTTPS transport failure.
    #[error("http transport error: {0}")]
    Http(String),
    /// UDP transport failure.
    #[error("udp transport error: {0}")]
    Udp(String),
    /// SMTP transport failure.
    #[error("smtp transport error: {0}")]
    Smtp(String),
    /// SSH transport failure.
    #[error("ssh transport error: {0}")]
    Ssh(String),
    /// I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// CMR parse failure.
    #[error("cmr parse error: {0}")]
    Parse(#[from] cmr_core::protocol::ParseError),
}

/// Inbound message received by a client inbox.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// Parsed CMR message.
    pub message: CmrMessage,
    /// Raw transport payload bytes.
    pub raw_payload: Vec<u8>,
}

/// Running HTTP inbox for receiving routed CMR messages.
pub struct HttpInbox {
    identity: String,
    receiver: mpsc::UnboundedReceiver<ReceivedMessage>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpInbox {
    /// Binds a local HTTP inbox and returns a running handle.
    pub async fn bind(bind: &str, path: &str) -> Result<Self, ClientError> {
        let normalized_path = normalize_path(path);
        let listener = TcpListener::bind(bind).await?;
        let bound = listener.local_addr()?;
        let host = match bound.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        let identity = match host {
            IpAddr::V4(ip) => format!("http://{ip}:{}{}", bound.port(), normalized_path),
            IpAddr::V6(ip) => format!("http://[{ip}]:{}{}", bound.port(), normalized_path),
        };

        let (tx, rx) = mpsc::unbounded_channel::<ReceivedMessage>();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let service_path = normalized_path.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let tx = tx.clone();
                        let service_path = service_path.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                handle_inbox_http(req, service_path.clone(), tx.clone())
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            identity,
            receiver: rx,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    /// Binds a local HTTPS inbox and returns a running handle.
    pub async fn bind_https(
        bind: &str,
        path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, ClientError> {
        let normalized_path = normalize_path(path);
        let listener = TcpListener::bind(bind).await?;
        let bound = listener.local_addr()?;
        let host = match bound.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        let identity = match host {
            IpAddr::V4(ip) => format!("https://{ip}:{}{}", bound.port(), normalized_path),
            IpAddr::V6(ip) => format!("https://[{ip}]:{}{}", bound.port(), normalized_path),
        };

        let tls_cfg = load_tls_config(cert_path, key_path)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

        let (tx, rx) = mpsc::unbounded_channel::<ReceivedMessage>();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let service_path = normalized_path.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let tx = tx.clone();
                        let service_path = service_path.clone();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let Ok(tls_stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req| {
                                handle_inbox_http(req, service_path.clone(), tx.clone())
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            identity,
            receiver: rx,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    /// Returns the HTTP identity URL for this inbox.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Receives the next routed CMR message.
    pub async fn recv(&mut self) -> Option<ReceivedMessage> {
        self.receiver.recv().await
    }

    /// Stops the inbox and waits for task shutdown.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// High-level CMR client.
pub struct CmrClient {
    identity: String,
    shared_keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    http_client: Client<HttpConnector, Full<Bytes>>,
    https_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    udp_socket: UdpSocket,
    smtp: Option<AsyncSmtpTransport<Tokio1Executor>>,
    smtp_from: Option<String>,
    ssh_cfg: SshClientConfig,
    max_message_bytes: usize,
    max_header_ids: usize,
}

impl CmrClient {
    /// Creates a client for a fixed identity address.
    pub async fn new(
        identity: impl Into<String>,
        transport_cfg: ClientTransportConfig,
    ) -> Result<Self, ClientError> {
        let identity = validate_identity(&identity.into())?;

        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(true);
        let http_client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(http_connector);

        let https_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| ClientError::Http(format!("failed to load native TLS roots: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let https_client: Client<_, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(https_connector);

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

        let (smtp, smtp_from) = build_smtp_transport(transport_cfg.smtp)?;

        Ok(Self {
            identity,
            shared_keys: Arc::new(Mutex::new(HashMap::new())),
            http_client,
            https_client,
            udp_socket,
            smtp,
            smtp_from,
            ssh_cfg: transport_cfg.ssh,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_header_ids: DEFAULT_MAX_HEADER_IDS,
        })
    }

    /// Sets parser bounds used for incoming validation in helper methods.
    pub fn set_validation_limits(&mut self, max_message_bytes: usize, max_header_ids: usize) {
        self.max_message_bytes = max_message_bytes.max(1);
        self.max_header_ids = max_header_ids.max(1);
    }

    /// Returns the configured client identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Sets a shared key used to sign messages sent to `destination`.
    pub fn set_shared_key_for_destination(
        &self,
        destination: impl Into<String>,
        key: Vec<u8>,
    ) -> Result<(), ClientError> {
        if key.is_empty() {
            return Err(ClientError::InvalidInput(
                "shared key cannot be empty".to_owned(),
            ));
        }
        let mut guard = self
            .shared_keys
            .lock()
            .map_err(|_| ClientError::InvalidInput("shared key store is poisoned".to_owned()))?;
        guard.insert(destination.into(), key);
        Ok(())
    }

    /// Builds one CMR message body from this client's identity.
    pub fn build_message(&self, body: impl AsRef<[u8]>) -> Result<CmrMessage, ClientError> {
        let body = body.as_ref().to_vec();
        if body.is_empty() {
            return Err(ClientError::InvalidInput(
                "message body cannot be empty".to_owned(),
            ));
        }
        Ok(CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId {
                timestamp: CmrTimestamp::now_utc(),
                address: self.identity.clone(),
            }],
            body,
        })
    }

    /// Serializes one message, optionally applying HMAC for destination.
    pub fn render_for_destination(
        &self,
        destination: &str,
        mut message: CmrMessage,
        sign: bool,
    ) -> Result<Vec<u8>, ClientError> {
        if !sign {
            message.make_unsigned();
            return Ok(message.to_bytes());
        }
        let key = self
            .shared_keys
            .lock()
            .map_err(|_| ClientError::InvalidInput("shared key store is poisoned".to_owned()))?
            .get(destination)
            .cloned()
            .ok_or_else(|| {
                ClientError::InvalidInput(format!(
                    "no shared key configured for destination `{destination}`"
                ))
            })?;
        message.sign_with_key(&key);
        Ok(message.to_bytes())
    }

    /// Sends one body payload to a router/destination URL.
    pub async fn send_body(
        &self,
        destination: &str,
        body: impl AsRef<[u8]>,
        sign: bool,
    ) -> Result<(), ClientError> {
        let message = self.build_message(body)?;
        let wire = self.render_for_destination(destination, message, sign)?;
        self.send_wire(destination, &wire).await
    }

    /// Sends a fully-encoded wire message to a destination URL.
    pub async fn send_wire(
        &self,
        destination: &str,
        wire_message: &[u8],
    ) -> Result<(), ClientError> {
        if destination.starts_with("mailto:") {
            return self.send_smtp(destination, wire_message).await;
        }
        let url = Url::parse(destination)
            .map_err(|_| ClientError::InvalidInput(destination.to_owned()))?;
        match url.scheme() {
            "http" | "https" => self.send_http_like(&url, wire_message).await,
            "udp" => self.send_udp(&url, wire_message).await,
            "ssh" => self.send_ssh(&url, wire_message).await,
            other => Err(ClientError::InvalidInput(format!(
                "unsupported scheme `{other}`"
            ))),
        }
    }

    /// Parses incoming wire bytes against this client's identity and bounds.
    pub fn parse_incoming_wire(&self, wire: &[u8]) -> Result<CmrMessage, ClientError> {
        let now = CmrTimestamp::now_utc();
        let ctx = ParseContext {
            now,
            recipient_address: Some(&self.identity),
            max_message_bytes: self.max_message_bytes,
            max_header_ids: self.max_header_ids,
        };
        parse_message(wire, &ctx).map_err(ClientError::Parse)
    }

    async fn send_http_like(&self, url: &Url, wire_message: &[u8]) -> Result<(), ClientError> {
        let boundary = random_hex(16);
        let multipart = encode_single_file_multipart(&boundary, wire_message);
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|e| ClientError::Http(format!("invalid URI: {e}")))?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Full::new(Bytes::from(multipart)))
            .map_err(|e| ClientError::Http(e.to_string()))?;

        let resp = if url.scheme() == "https" {
            self.https_client
                .request(req)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        } else {
            self.http_client
                .request(req)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        };

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ClientError::Http(format!(
                "router returned status {}",
                resp.status()
            )))
        }
    }

    async fn send_udp(&self, url: &Url, wire_message: &[u8]) -> Result<(), ClientError> {
        let service = parse_udp_service_tag(url)?;
        let packet = encode_udp_packet(&service, wire_message)
            .map_err(|e| ClientError::Udp(format!("invalid UDP service tag: {e}")))?;
        if packet.len() > UDP_MAX_PAYLOAD_BYTES {
            return Err(ClientError::Udp(
                "message too large for UDP datagram".to_owned(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| ClientError::InvalidInput(url.as_str().to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ClientError::InvalidInput(url.as_str().to_owned()))?;
        self.udp_socket
            .send_to(&packet, format!("{host}:{port}"))
            .await
            .map_err(|e| ClientError::Udp(e.to_string()))?;
        Ok(())
    }

    async fn send_smtp(&self, destination: &str, wire_message: &[u8]) -> Result<(), ClientError> {
        let Some(transport) = &self.smtp else {
            return Err(ClientError::Smtp(
                "SMTP transport not configured for this client".to_owned(),
            ));
        };
        let Some(from) = &self.smtp_from else {
            return Err(ClientError::Smtp(
                "SMTP sender address is missing".to_owned(),
            ));
        };
        let to = destination
            .strip_prefix("mailto:")
            .ok_or_else(|| ClientError::InvalidInput(destination.to_owned()))?;
        let from_mailbox = from
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| ClientError::Smtp(e.to_string()))?;
        let to_mailbox = to
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| ClientError::Smtp(e.to_string()))?;
        let message = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject("cmr")
            .header(
                header::ContentType::parse("application/octet-stream")
                    .map_err(|e| ClientError::Smtp(e.to_string()))?,
            )
            .header(header::ContentTransferEncoding::Base64)
            .body(wire_message.to_vec())
            .map_err(|e| ClientError::Smtp(e.to_string()))?;
        transport
            .send(message)
            .await
            .map_err(|e| ClientError::Smtp(e.to_string()))?;
        Ok(())
    }

    async fn send_ssh(&self, url: &Url, wire_message: &[u8]) -> Result<(), ClientError> {
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::InvalidInput(url.as_str().to_owned()))?;
        let port = url.port().unwrap_or(22);
        let user = if url.username().is_empty() {
            None
        } else {
            Some(url.username())
        };
        let remote = if let Some(user) = user {
            format!("{user}@{host}")
        } else {
            host.to_owned()
        };
        let command = ssh_remote_command_from_url(url, &self.ssh_cfg.default_remote_command)?;

        let mut child = Command::new(&self.ssh_cfg.binary)
            .arg("-p")
            .arg(port.to_string())
            .arg(remote)
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ClientError::Ssh(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut stdin, wire_message)
                .await
                .map_err(|e| ClientError::Ssh(e.to_string()))?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| ClientError::Ssh(e.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ClientError::Ssh(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        }
    }
}

async fn handle_inbox_http(
    req: Request<Incoming>,
    path: String,
    tx: mpsc::UnboundedSender<ReceivedMessage>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let uri_path = req.uri().path().to_owned();
    if method != Method::POST || uri_path != path {
        return Ok(response(StatusCode::NOT_FOUND));
    }

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(response(StatusCode::BAD_REQUEST)),
    };

    let payload = match extract_cmr_payload(content_type.as_deref(), &body) {
        Ok(payload) => payload,
        Err(_) => return Ok(response(StatusCode::BAD_REQUEST)),
    };

    let now = CmrTimestamp::now_utc();
    let ctx = ParseContext {
        now,
        recipient_address: None,
        max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        max_header_ids: DEFAULT_MAX_HEADER_IDS,
    };
    let message = match parse_message(&payload, &ctx) {
        Ok(message) => message,
        Err(_) => return Ok(response(StatusCode::BAD_REQUEST)),
    };

    let _ = tx.send(ReceivedMessage {
        message,
        raw_payload: payload,
    });

    Ok(response(StatusCode::OK))
}

fn response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn build_smtp_transport(
    cfg: Option<SmtpClientConfig>,
) -> Result<(Option<AsyncSmtpTransport<Tokio1Executor>>, Option<String>), ClientError> {
    let Some(cfg) = cfg else {
        return Ok((None, None));
    };

    let mut builder = if cfg.allow_insecure {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.relay).port(cfg.port)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.relay)
            .map_err(|e| ClientError::Smtp(e.to_string()))?
            .port(cfg.port)
    };

    if let Some(username) = cfg.username.clone() {
        let password = cfg.password.unwrap_or_default();
        builder = builder.credentials(Credentials::new(username, password));
    }

    Ok((Some(builder.build()), Some(cfg.from)))
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, ClientError> {
    let cert_chain = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| ClientError::Http(format!("failed to open cert file: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ClientError::Http(format!("failed to parse cert chain: {e}")))?;
    if cert_chain.is_empty() {
        return Err(ClientError::Http(
            "certificate file does not contain any PEM certificates".to_owned(),
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| ClientError::Http(format!("failed to parse private key: {e}")))?;

    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| ClientError::Http(format!("invalid TLS certificate/key pair: {e}")))?;
    Ok(tls)
}

fn validate_identity(identity: &str) -> Result<String, ClientError> {
    let trimmed = identity.trim();
    if trimmed.is_empty() {
        return Err(ClientError::InvalidInput(
            "identity cannot be empty".to_owned(),
        ));
    }
    if trimmed.contains('\r') || trimmed.contains('\n') {
        return Err(ClientError::InvalidInput(
            "identity must not contain CR/LF".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

fn parse_udp_service_tag(url: &Url) -> Result<String, ClientError> {
    let service = url.path().trim_start_matches('/');
    if service.is_empty() || service.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err(ClientError::InvalidInput(url.as_str().to_owned()));
    }
    Ok(service.to_owned())
}

fn encode_udp_packet(service: &str, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if service.is_empty() || service.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err("invalid service string");
    }
    let mut out = Vec::with_capacity(service.len() + 1 + payload.len());
    out.extend_from_slice(service.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    Ok(out)
}

fn ssh_remote_command_from_url(url: &Url, default_command: &str) -> Result<String, ClientError> {
    let cmd = url.path().trim_start_matches('/');
    let command = if cmd.is_empty() { default_command } else { cmd };
    if command.is_empty()
        || command
            .bytes()
            .any(|b| matches!(b, b'\r' | b'\n' | b'\0' | b';' | b'&' | b'|' | b'`'))
    {
        return Err(ClientError::InvalidInput(
            "invalid ssh remote command in destination".to_owned(),
        ));
    }
    Ok(command.to_owned())
}

fn extract_cmr_payload(content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>, ClientError> {
    let Some(content_type) = content_type else {
        return Ok(body.to_vec());
    };
    let lower = content_type.to_ascii_lowercase();
    if !lower.starts_with("multipart/form-data") {
        return Ok(body.to_vec());
    }
    let Some(boundary) = parse_boundary(content_type) else {
        return Err(ClientError::InvalidInput(
            "missing multipart boundary".to_owned(),
        ));
    };
    parse_first_multipart_part(body, &boundary)
        .ok_or_else(|| ClientError::InvalidInput("malformed multipart payload".to_owned()))
}

fn parse_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("boundary=") {
            return Some(value.trim_matches('"').to_owned());
        }
    }
    None
}

fn parse_first_multipart_part(body: &[u8], boundary: &str) -> Option<Vec<u8>> {
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    let start = body.windows(marker.len()).position(|w| w == marker)?;
    let after_marker = &body[start + marker.len()..];
    let header_end = after_marker.windows(4).position(|w| w == b"\r\n\r\n")?;
    let data_start = start + marker.len() + header_end + 4;
    let tail = &body[data_start..];
    let end_marker = format!("\r\n--{boundary}");
    let end = tail
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_bytes())?;
    Some(tail[..end].to_vec())
}

fn encode_single_file_multipart(boundary: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 256);
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"message.cmr\"\r\n",
    );
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    out.extend_from_slice(payload);
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{ClientTransportConfig, CmrClient, normalize_path};

    #[test]
    fn normalize_path_normalizes_slashes() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/inbox/"), "/inbox");
        assert_eq!(normalize_path("inbox"), "/inbox");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn client_builds_unsigned_message() {
        let client = CmrClient::new(
            "http://127.0.0.1:9999/inbox",
            ClientTransportConfig::default(),
        )
        .await
        .expect("client init");
        let msg = client.build_message("hello world").expect("build");
        assert_eq!(msg.header.len(), 1);
        assert_eq!(msg.header[0].address, "http://127.0.0.1:9999/inbox");
        assert_eq!(msg.body, b"hello world");
    }
}
