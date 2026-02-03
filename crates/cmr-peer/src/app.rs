//! Peer runtime orchestration.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cmr_core::policy::RoutingPolicy;
use cmr_core::protocol::{CmrTimestamp, TransportKind};
use cmr_core::router::{ForwardAction, ProcessOutcome, Router};
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

use crate::compressor_client::{
    CompressorClient, CompressorClientConfig, CompressorClientInitError,
};
use crate::config::{HttpsListenConfig, PeerConfig};
use crate::transport::{HandshakeStore, TransportError, TransportManager, extract_cmr_payload};

/// Runtime state shared by transport listeners.
#[derive(Clone)]
struct AppState {
    router: Arc<Mutex<Router<CompressorClient>>>,
    transport: Arc<TransportManager>,
    handshake_store: Arc<HandshakeStore>,
}

impl AppState {
    async fn ingest_and_forward(
        &self,
        payload: Vec<u8>,
        transport_kind: TransportKind,
    ) -> Result<ProcessOutcome, AppError> {
        let router = Arc::clone(&self.router);
        let outcome = tokio::task::spawn_blocking(move || {
            let mut guard = router
                .lock()
                .map_err(|_| AppError::Runtime("router mutex poisoned".to_owned()))?;
            Ok::<_, AppError>(guard.process_incoming(
                &payload,
                transport_kind,
                CmrTimestamp::now_utc(),
            ))
        })
        .await
        .map_err(|e| AppError::Runtime(format!("router task join error: {e}")))??;

        for forward in &outcome.forwards {
            if let Err(err) = self.send_forward(forward).await {
                eprintln!(
                    "forward to {} failed (reason={:?}): {err}",
                    forward.destination, forward.reason
                );
            }
        }
        Ok(outcome)
    }

    async fn send_forward(&self, forward: &ForwardAction) -> Result<(), AppError> {
        self.transport
            .send_message(&forward.destination, &forward.message_bytes)
            .await
            .map_err(AppError::Transport)
    }
}

/// App startup/runtime errors.
#[derive(Debug, Error)]
pub enum AppError {
    /// Config validation failure.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Runtime transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS setup failure.
    #[error("tls configuration error: {0}")]
    Tls(String),
    /// Runtime coordination failure.
    #[error("runtime error: {0}")]
    Runtime(String),
    /// Compressor setup failure.
    #[error("compressor setup error: {0}")]
    CompressorInit(#[from] CompressorClientInitError),
}

/// Runs peer listeners until interrupted.
pub async fn run_peer(config: PeerConfig) -> Result<(), AppError> {
    let policy = config.effective_policy();
    let compressor_cfg = CompressorClientConfig {
        command: config.compressor.command.clone(),
        args: config.compressor.args.clone(),
        max_frame_bytes: config.compressor.max_frame_bytes,
    };
    let compressor = CompressorClient::new(compressor_cfg)?;
    let mut router = Router::new(config.local_address.clone(), policy, compressor);
    apply_static_keys(&mut router, &config)?;

    let handshake_store = Arc::new(HandshakeStore::default());
    let transport = Arc::new(
        TransportManager::new(
            config.local_address.clone(),
            config.smtp.clone(),
            config.ssh.clone(),
            config.prefer_http_handshake,
            Arc::clone(&handshake_store),
        )
        .await?,
    );
    let state = AppState {
        router: Arc::new(Mutex::new(router)),
        transport,
        handshake_store,
    };

    let mut handles = Vec::new();
    if let Some(http_cfg) = config.listen.http.clone() {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_http_listener(http_cfg.bind, http_cfg.path, state, false).await {
                eprintln!("http listener stopped with error: {err}");
            }
        }));
    }
    if let Some(https_cfg) = config.listen.https.clone() {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_https_listener(https_cfg, state).await {
                eprintln!("https listener stopped with error: {err}");
            }
        }));
    }
    if let Some(udp_cfg) = config.listen.udp.clone() {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_udp_listener(udp_cfg.bind, udp_cfg.service, state).await {
                eprintln!("udp listener stopped with error: {err}");
            }
        }));
    }
    if handles.is_empty() {
        return Err(AppError::InvalidConfig(
            "at least one listener (http/https/udp) must be configured".to_owned(),
        ));
    }

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AppError::Runtime(format!("ctrl-c handler: {e}")))?;
    for handle in handles {
        handle.abort();
    }
    Ok(())
}

/// Ingests one message from stdin (useful for ssh forced-command mode).
pub async fn ingest_stdin_once(
    config: PeerConfig,
    transport: TransportKind,
) -> Result<(), AppError> {
    let policy: RoutingPolicy = config.effective_policy();
    let compressor_cfg = CompressorClientConfig {
        command: config.compressor.command.clone(),
        args: config.compressor.args.clone(),
        max_frame_bytes: config.compressor.max_frame_bytes,
    };
    let compressor = CompressorClient::new(compressor_cfg)?;
    let mut router = Router::new(config.local_address.clone(), policy, compressor);
    apply_static_keys(&mut router, &config)?;

    let payload = tokio::fs::read("/dev/stdin").await?;
    let outcome = router.process_incoming(&payload, transport, CmrTimestamp::now_utc());
    if !outcome.accepted {
        return Err(AppError::Runtime(format!(
            "stdin message rejected: {}",
            outcome
                .drop_reason
                .map_or_else(|| "unknown".to_owned(), |e| e.to_string())
        )));
    }
    Ok(())
}

fn apply_static_keys(
    router: &mut Router<CompressorClient>,
    config: &PeerConfig,
) -> Result<(), AppError> {
    for entry in &config.static_keys {
        let key = hex::decode(&entry.hex_key)
            .map_err(|e| AppError::InvalidConfig(format!("invalid static hex key: {e}")))?;
        router.set_shared_key(entry.peer.clone(), key);
    }
    Ok(())
}

async fn run_http_listener(
    bind: String,
    path: String,
    state: AppState,
    is_https: bool,
) -> Result<(), AppError> {
    let listener = TcpListener::bind(&bind).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                handle_http_request(req, path.clone(), state.clone(), is_https)
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("http conn error: {err}");
            }
        });
    }
}

async fn run_https_listener(cfg: HttpsListenConfig, state: AppState) -> Result<(), AppError> {
    let tls_cfg = load_tls_config(&cfg.cert_path, &cfg.key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(&cfg.bind).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();
        let path = cfg.path.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("tls accept error: {err}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let service =
                service_fn(move |req| handle_http_request(req, path.clone(), state.clone(), true));
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("https conn error: {err}");
            }
        });
    }
}

async fn run_udp_listener(bind: String, service: String, state: AppState) -> Result<(), AppError> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("udp listener active for service tag `{service}`");
    let mut buf = vec![0_u8; 65_536];
    loop {
        let (size, _) = socket.recv_from(&mut buf).await?;
        let payload = buf[..size].to_vec();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = state.ingest_and_forward(payload, TransportKind::Udp).await {
                eprintln!("udp ingest failed: {err}");
            }
        });
    }
}

async fn handle_http_request(
    req: Request<Incoming>,
    ingest_path: String,
    state: AppState,
    is_https: bool,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let transport_kind = if is_https {
        TransportKind::Https
    } else {
        TransportKind::Http
    };
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_owned();

    if method == Method::GET {
        let params = parse_query(uri.query().unwrap_or_default());
        if let (Some(requester), Some(key)) = (params.get("request"), params.get("key")) {
            let requester = requester.clone();
            let key = key.clone();
            let state2 = state.clone();
            tokio::spawn(async move {
                match state2
                    .transport
                    .fetch_http_handshake_reply(&requester, &key)
                    .await
                {
                    Ok(reply_payload) => {
                        if let Err(err) = state2
                            .ingest_and_forward(reply_payload, transport_kind)
                            .await
                        {
                            eprintln!("handshake callback ingest failed: {err}");
                        }
                    }
                    Err(err) => eprintln!("handshake callback fetch failed: {err}"),
                }
            });
            return Ok(response(StatusCode::OK, Bytes::new()));
        }
        if let Some(reply_key) = params.get("reply") {
            if let Some(payload) = state.handshake_store.take(reply_key) {
                return Ok(response(StatusCode::OK, Bytes::from(payload)));
            }
            return Ok(response(StatusCode::NOT_FOUND, Bytes::new()));
        }
    }

    if method == Method::POST && path == ingest_path {
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                eprintln!("http body read failed: {err}");
                return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
            }
        };
        let payload = match extract_cmr_payload(content_type.as_deref(), &body) {
            Ok(payload) => payload,
            Err(err) => {
                eprintln!("http payload parse failed: {err}");
                return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
            }
        };
        if let Err(err) = state.ingest_and_forward(payload, transport_kind).await {
            eprintln!("ingest failed: {err}");
            return Ok(response(StatusCode::BAD_REQUEST, Bytes::new()));
        }
        return Ok(response(StatusCode::OK, Bytes::new()));
    }

    Ok(response(StatusCode::NOT_FOUND, Bytes::new()))
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, AppError> {
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_data.as_slice());
    let mut key_reader = std::io::BufReader::new(key_data.as_slice());

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| AppError::Tls(format!("failed to parse certs: {e}")))?;
    if certs.is_empty() {
        return Err(AppError::Tls("no certificates found".to_owned()));
    }
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| AppError::Tls(format!("failed to parse private key: {e}")))?
        .ok_or_else(|| AppError::Tls("no private key found".to_owned()))?;

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Tls(format!("invalid certificate/key pair: {e}")))?;
    Ok(cfg)
}
