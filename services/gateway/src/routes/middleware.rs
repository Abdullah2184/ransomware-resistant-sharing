use std::{net::SocketAddr, time::Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};

#[cfg(not(test))]
use super::unix_seconds;
use super::{AppState, error, failure, parse_bearer_token};
use crate::store::{encode_hex, hash_session_token, source_identifier};

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

pub(crate) fn rate_limit_action(method: &str, path: &str) -> Option<&'static str> {
    match (method, path) {
        ("GET", path) if path.starts_with("/v1/identities/") => Some("identity.lookup"),
        ("POST", "/v1/auth/challenge") => Some("auth.challenge"),
        ("POST", "/v1/auth/session")
        | ("GET", "/v1/auth/session")
        | ("DELETE", "/v1/auth/session") => Some("auth.session"),
        ("GET", "/v1/files") => Some("file.list"),
        ("POST", "/v1/files") => Some("file.create"),
        ("GET", path) if path.starts_with("/v1/files/") && path.ends_with("/versions") => {
            Some("file.history")
        }
        ("POST", path) if path.starts_with("/v1/files/") && path.ends_with("/versions") => {
            Some("file.version_append")
        }
        ("POST", path) if path.starts_with("/v1/files/") && path.ends_with("/access") => {
            Some("file.access")
        }
        ("GET", path) if path.starts_with("/v1/files/") && path.ends_with("/content") => {
            Some("file.content")
        }
        ("GET", path) if path.starts_with("/v1/files/") && path.ends_with("/envelope") => {
            Some("file.envelope")
        }
        ("POST", path) if path.starts_with("/v1/files/") && path.ends_with("/envelopes") => {
            Some("file.envelope_update")
        }
        ("POST", "/v1/blobs/content") => Some("blob.content_upload"),
        ("POST", "/v1/blobs/envelopes") => Some("blob.envelope_upload"),
        ("GET", "/v1/audit") => Some("audit.query"),
        _ => None,
    }
}

fn sanitize_or_generate_request_id(headers: &HeaderMap) -> String {
    if let Some(candidate) = headers
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return candidate.to_owned();
    }
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    encode_hex(&bytes)
}

pub(crate) async fn request_id_and_logging(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let request_id = sanitize_or_generate_request_id(request.headers());
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let source_id = source_identifier(&peer.ip().to_string());

    let mut response = next.run(request).await;
    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER, header_value);
    }

    #[cfg(not(test))]
    {
        let latency_ms = start.elapsed().as_millis();
        let status = response.status().as_u16();
        let ts = unix_seconds().unwrap_or(0);
        let log_line = serde_json::json!({
            "ts": ts,
            "requestId": request_id,
            "method": method,
            "path": path,
            "sourceId": source_id,
            "status": status,
            "latencyMs": latency_ms,
        });
        eprintln!("{log_line}");
    }
    #[cfg(test)]
    let _ = (start, method, path, source_id);

    response
}

pub(crate) async fn enforce_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let Some(action) = rate_limit_action(request.method().as_str(), request.uri().path()) else {
        return next.run(request).await;
    };
    let source_id = source_identifier(&peer.ip().to_string());
    let source_key = format!("src:{action}:{source_id}");
    match state
        .store
        .take_rate_limit_token(
            &source_key,
            f64::from(state.config.rate_limit_capacity),
            state.config.rate_limit_refill_per_second,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return failure(
                &state,
                action,
                &source_id,
                "rate_limited",
                None,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    // Independent per-member budget for authenticated traffic (§8.2).
    if let Some(token) = parse_bearer_token(request.headers()) {
        match state
            .store
            .active_session_member(&hash_session_token(&token))
            .await
        {
            Ok(Some(member_id)) => {
                let member_key = format!("member:{action}:{member_id}");
                match state
                    .store
                    .take_rate_limit_token(
                        &member_key,
                        f64::from(state.config.member_rate_limit_capacity),
                        state.config.member_rate_limit_refill_per_second,
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return failure(
                            &state,
                            action,
                            &source_id,
                            "member_rate_limited",
                            None,
                            StatusCode::TOO_MANY_REQUESTS,
                            "rate_limited",
                        )
                        .await;
                    }
                    Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
                }
            }
            Ok(None) => {}
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        }
    }

    next.run(request).await
}

/// Tracks invalid signature failures in a dedicated per-source bucket so spoofed
/// claims against a victim's member ID throttle the caller without locking out
/// the victim (§8.2).
pub(crate) async fn invalid_signature_failure(
    state: &AppState,
    action: &'static str,
    source_id: &str,
    operation_id: Option<&str>,
) -> Response {
    let key = format!("invalid_sig_src:{source_id}");
    match state
        .store
        .take_rate_limit_token(
            &key,
            f64::from(state.config.invalid_sig_limit_capacity),
            state.config.invalid_sig_limit_refill_per_second,
        )
        .await
    {
        Ok(true) => {
            failure(
                state,
                action,
                source_id,
                "invalid_signature",
                operation_id,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await
        }
        Ok(false) => {
            failure(
                state,
                action,
                source_id,
                "invalid_signature_rate_limited",
                operation_id,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            )
            .await
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}
