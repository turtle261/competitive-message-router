//! Public web client UI and client-only APIs.

use std::collections::HashMap;
use std::convert::Infallible;

use base64::Engine as _;
use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

use crate::app::{AppState, PeerBody, full_body};
use crate::config::WebClientConfig;

const CLIENT_HTML: &str = include_str!("../assets/client.html");
const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_COUNT: usize = 32;
const MAX_ATTACHMENTS: usize = 8;
const MAX_ATTACHMENT_BYTES: usize = 512 * 1024;

#[derive(Debug, Serialize)]
struct ApiEnvelope<T: Serialize> {
    ok: bool,
    data: Option<T>,
    error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: String,
    message: String,
    details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ClientComposePayload {
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    extra_destinations: Option<Vec<String>>,
    body_text: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    attachments: Vec<ClientAttachmentPayload>,
    #[serde(default)]
    sign: bool,
    #[serde(default)]
    identity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientAttachmentPayload {
    #[serde(default)]
    name: String,
    #[serde(default)]
    mime: String,
    data_base64: String,
}

#[derive(Debug, Serialize)]
struct ClientBootstrapPayload {
    local_address: Option<String>,
    transport_enabled: bool,
    ingest_enabled: bool,
}

#[derive(Debug, Serialize)]
struct ClientCachePayload {
    offset: usize,
    limit: usize,
    total: usize,
    entries: Vec<cmr_core::CacheEntryView>,
}

#[derive(Debug, Serialize)]
struct ClientInboxPayload {
    offset: usize,
    limit: usize,
    total: usize,
    entries: Vec<crate::app::DashboardInboxMessage>,
}

pub(crate) async fn handle_client_request(
    req: Request<Incoming>,
    state: AppState,
    cfg: WebClientConfig,
    is_https: bool,
    remote_ip: Option<std::net::IpAddr>,
) -> Result<Response<PeerBody>, Infallible> {
    if !web_client_transport_allowed(&cfg, is_https, remote_ip) {
        return Ok(response_api_error(
            StatusCode::FORBIDDEN,
            "https_required",
            "client web UI requires HTTPS for non-localhost access",
            None,
        ));
    }

    let path = req.uri().path().to_owned();
    let base = normalize_base_path(&cfg.path);
    let relative = if path == base {
        "/".to_owned()
    } else {
        path.strip_prefix(&base)
            .map_or(path.clone(), |suffix| suffix.to_owned())
    };

    let response = match (req.method().clone(), relative.as_str()) {
        (Method::GET, "/") | (Method::GET, "/index.html") => response_html(CLIENT_HTML),
        (Method::GET, "/api/bootstrap") => {
            let local_address = state.config_snapshot().map(|cfg| cfg.local_address);
            response_api_ok(
                StatusCode::OK,
                ClientBootstrapPayload {
                    local_address,
                    transport_enabled: state.transport_enabled(),
                    ingest_enabled: state.ingest_enabled(),
                },
            )
        }
        (Method::GET, "/api/health") => response_api_ok(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "client_ui": true,
            }),
        ),
        (Method::GET, "/api/cache") => {
            let query = parse_query(req.uri().query().unwrap_or_default());
            let offset = parse_usize_query(&query, "offset", 0);
            let limit = parse_usize_query(&query, "limit", 200).clamp(1, 1000);
            let sender_filter = query
                .get("sender")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty());
            let q_filter = query
                .get("q")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty());
            match state.router_snapshot(|router| router.cache_entries()) {
                Ok(mut entries) => {
                    entries.retain(|entry| {
                        if let Some(sender) = &sender_filter
                            && !entry.sender.to_ascii_lowercase().contains(sender)
                        {
                            return false;
                        }
                        if let Some(q) = &q_filter {
                            let body = entry.body_preview.to_ascii_lowercase();
                            let sender = entry.sender.to_ascii_lowercase();
                            if !body.contains(q) && !sender.contains(q) {
                                return false;
                            }
                        }
                        true
                    });
                    entries.reverse();
                    let total = entries.len();
                    let entries = entries.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
                    response_api_ok(
                        StatusCode::OK,
                        ClientCachePayload {
                            offset,
                            limit,
                            total,
                            entries,
                        },
                    )
                }
                Err(err) => response_api_error(
                    StatusCode::BAD_REQUEST,
                    "runtime_error",
                    &err.to_string(),
                    None,
                ),
            }
        }
        (Method::GET, "/api/inbox") => {
            let query = parse_query(req.uri().query().unwrap_or_default());
            let offset = parse_usize_query(&query, "offset", 0);
            let limit = parse_usize_query(&query, "limit", 200).clamp(1, 1000);
            let sender_filter = query
                .get("sender")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty());
            let q_filter = query
                .get("q")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty());

            let mut entries = state.inbox_messages();
            entries.retain(|entry| {
                if let Some(sender) = &sender_filter
                    && !entry.sender.to_ascii_lowercase().contains(sender)
                {
                    return false;
                }
                if let Some(q) = &q_filter {
                    let body = entry.body_text.to_ascii_lowercase();
                    let sender = entry.sender.to_ascii_lowercase();
                    if !body.contains(q) && !sender.contains(q) {
                        return false;
                    }
                }
                true
            });
            entries.reverse();
            let total = entries.len();
            let entries = entries.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
            response_api_ok(
                StatusCode::OK,
                ClientInboxPayload {
                    offset,
                    limit,
                    total,
                    entries,
                },
            )
        }
        (Method::POST, "/api/compose") => match parse_json_body::<ClientComposePayload>(req).await {
            Ok(payload) => {
                let body_text = match build_message_body(payload.body_text, payload.sources, payload.attachments) {
                    Ok(body) => body,
                    Err(err) => {
                        return Ok(response_api_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_input",
                            &err,
                            None,
                        ));
                    }
                };
                let destination = match payload.destination.as_deref().map(str::trim) {
                    Some("") | None => None,
                    Some(value) => match canonicalize_client_url(value) {
                        Ok(normalized) => Some(normalized),
                        Err(err) => {
                            return Ok(response_api_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_input",
                                &err,
                                None,
                            ));
                        }
                    },
                };
                let extra_destinations = match payload.extra_destinations {
                    Some(items) => {
                        let mut normalized = Vec::new();
                        for item in items {
                            let trimmed = item.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            match canonicalize_client_url(trimmed) {
                                Ok(value) => normalized.push(value),
                                Err(err) => {
                                    return Ok(response_api_error(
                                        StatusCode::BAD_REQUEST,
                                        "invalid_input",
                                        &format!("invalid extra destination `{trimmed}`: {err}"),
                                        None,
                                    ));
                                }
                            }
                        }
                        normalized
                    }
                    None => Vec::new(),
                };
                let identity = payload
                    .identity
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                match state
                    .compose_and_send(
                        destination,
                        extra_destinations,
                        body_text,
                        payload.sign,
                        identity,
                    )
                    .await
                {
                    Ok(result) => response_api_ok(StatusCode::OK, result),
                    Err(err) => response_api_error(
                        StatusCode::BAD_REQUEST,
                        "runtime_error",
                        &err.to_string(),
                        None,
                    ),
                }
            }
            Err(resp) => resp,
        },
        _ => response_api_error(StatusCode::NOT_FOUND, "not_found", "not found", None),
    };

    Ok(response)
}

fn web_client_transport_allowed(
    cfg: &WebClientConfig,
    is_https: bool,
    remote_ip: Option<std::net::IpAddr>,
) -> bool {
    if !cfg.require_https {
        return true;
    }
    is_https || remote_ip.is_some_and(|ip| ip.is_loopback())
}

fn normalize_base_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

fn canonicalize_client_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("url is required".to_owned());
    }

    let mut parsed =
        url::Url::parse(trimmed).map_err(|err| format!("invalid url `{trimmed}`: {err}"))?;
    if let Some(host) = parsed.host_str() {
        let normalized_host = if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1".to_owned()
        } else {
            host.to_ascii_lowercase()
        };
        parsed
            .set_host(Some(&normalized_host))
            .map_err(|_| format!("invalid host in url `{trimmed}`"))?;
    }

    parsed.set_query(None);
    parsed.set_fragment(None);
    if matches!(parsed.scheme(), "http" | "https") && parsed.path().is_empty() {
        parsed.set_path("/");
    }
    Ok(parsed.to_string())
}

fn build_message_body(
    body_text: String,
    sources: Vec<String>,
    attachments: Vec<ClientAttachmentPayload>,
) -> Result<String, String> {
    let text = body_text.trim().to_owned();
    if text.is_empty() {
        return Err("message body is required".to_owned());
    }

    let normalized_sources = normalize_sources(sources)?;
    let normalized_attachments = normalize_attachments(attachments)?;
    if normalized_sources.is_empty() && normalized_attachments.is_empty() {
        return Ok(text);
    }

    serde_json::to_string(&serde_json::json!({
        "text": text,
        "sources": normalized_sources,
        "attachments": normalized_attachments,
    }))
    .map_err(|err| format!("failed to encode message envelope: {err}"))
}

fn normalize_sources(sources: Vec<String>) -> Result<Vec<String>, String> {
    if sources.len() > MAX_SOURCE_COUNT {
        return Err(format!("too many sources (max {MAX_SOURCE_COUNT})"));
    }
    let mut out = Vec::new();
    for source in sources {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = url::Url::parse(trimmed)
            .map_err(|err| format!("invalid source url `{trimmed}`: {err}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("source URLs must be http:// or https://".to_owned());
        }
        out.push(parsed.to_string());
    }
    Ok(out)
}

fn normalize_attachments(
    attachments: Vec<ClientAttachmentPayload>,
) -> Result<Vec<serde_json::Value>, String> {
    if attachments.len() > MAX_ATTACHMENTS {
        return Err(format!("too many attachments (max {MAX_ATTACHMENTS})"));
    }
    let mut out = Vec::new();
    for attachment in attachments {
        let name = attachment.name.trim().to_owned();
        let mime = attachment.mime.trim().to_owned();
        if attachment.data_base64.trim().is_empty() {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(attachment.data_base64.trim())
            .map_err(|err| format!("invalid attachment base64: {err}"))?;
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(format!(
                "attachment `{name}` exceeds max size of {MAX_ATTACHMENT_BYTES} bytes"
            ));
        }
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        out.push(serde_json::json!({
            "name": name,
            "mime": mime,
            "data_base64": data_base64,
        }));
    }
    Ok(out)
}

fn parse_usize_query(query: &HashMap<String, String>, key: &str, default: usize) -> usize {
    query
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

async fn parse_json_body<T: DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Response<PeerBody>> {
    let mut body = req.into_body();
    let mut out = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|err| {
            response_api_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "failed to read request body",
                Some(serde_json::json!({"io_error": err.to_string()})),
            )
        })?;
        if let Ok(chunk) = frame.into_data() {
            if out.len().saturating_add(chunk.len()) > MAX_JSON_BODY_BYTES {
                return Err(response_api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "request body exceeds max JSON size",
                    Some(serde_json::json!({"max_bytes": MAX_JSON_BODY_BYTES})),
                ));
            }
            out.extend_from_slice(&chunk);
        }
    }

    serde_json::from_slice::<T>(&out).map_err(|err| {
        response_api_error(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body is not valid JSON",
            Some(serde_json::json!({"parse_error": err.to_string()})),
        )
    })
}

#[allow(dead_code)]
fn parse_query(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn response_html(html: &str) -> Response<PeerBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(html.as_bytes())))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

fn response_api_ok<T: Serialize>(status: StatusCode, data: T) -> Response<PeerBody> {
    response_api(
        status,
        ApiEnvelope {
            ok: true,
            data: Some(data),
            error: None,
        },
    )
}

fn response_api_error(
    status: StatusCode,
    code: &str,
    message: &str,
    details: Option<serde_json::Value>,
) -> Response<PeerBody> {
    response_api(
        status,
        ApiEnvelope::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(ApiError {
                code: code.to_owned(),
                message: message.to_owned(),
                details,
            }),
        },
    )
}

fn response_api<T: Serialize>(status: StatusCode, value: ApiEnvelope<T>) -> Response<PeerBody> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| {
        b"{\"ok\":false,\"data\":null,\"error\":{\"code\":\"serialize_error\",\"message\":\"failed to serialize response\",\"details\":null}}".to_vec()
    });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{
        build_message_body, canonicalize_client_url, normalize_base_path,
        web_client_transport_allowed,
    };

    #[test]
    fn normalize_base_path_treats_trailing_slash_consistently() {
        assert_eq!(normalize_base_path("/_cmr_client"), "/_cmr_client");
        assert_eq!(normalize_base_path("/_cmr_client/"), "/_cmr_client");
        assert_eq!(normalize_base_path("_cmr_client/"), "/_cmr_client");
        assert_eq!(normalize_base_path("/"), "/");
    }

    #[test]
    fn canonicalize_client_url_normalizes_host_and_strips_query() {
        let left = canonicalize_client_url("http://localhost:8081").expect("left");
        let right =
            canonicalize_client_url("HTTP://127.0.0.1:8081/?x=1#frag").expect("right");
        assert_eq!(left, "http://127.0.0.1:8081/");
        assert_eq!(right, "http://127.0.0.1:8081/");
    }

    #[test]
    fn transport_gate_requires_https_when_configured() {
        let cfg = crate::config::WebClientConfig {
            enabled: true,
            path: "/_client".to_owned(),
            require_https: true,
        };
        assert!(web_client_transport_allowed(&cfg, true, None));
        assert!(web_client_transport_allowed(
            &cfg,
            false,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        ));
        assert!(!web_client_transport_allowed(
            &cfg,
            false,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)))
        ));
    }

    #[test]
    fn build_message_body_wraps_sources_and_attachments_when_present() {
        let payload = build_message_body(
            "hello".to_owned(),
            vec!["https://example.com/doc".to_owned()],
            vec![super::ClientAttachmentPayload {
                name: "a.txt".to_owned(),
                mime: "text/plain".to_owned(),
                data_base64: base64::engine::general_purpose::STANDARD.encode("abc"),
            }],
        )
        .expect("payload");
        assert!(payload.contains("hello"));
        assert!(payload.contains("example.com"));
        assert!(payload.contains("a.txt"));
    }
}
