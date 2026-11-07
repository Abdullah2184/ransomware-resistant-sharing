use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Path, Request, State, rejection::JsonRejection,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chain_adapter::BesuClient;
use crypto::{AccessLookup, ChainId, Eip712Domain, UnixDeadline};
use domain::{FileId, KeyVersion, OperationNonce, VersionNumber};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{
        LoginChallenge, challenge_digest, parse_fixed_hex, parse_member_id, parse_nonce,
        recover_signer,
    },
    config::GatewayConfig,
    store::{GatewayStore, encode_hex, hash_session_token, source_identifier},
};

#[derive(Clone)]
pub struct AppState {
    store: GatewayStore,
    chain: Arc<BesuClient>,
    config: Arc<GatewayConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    member_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    challenge: LoginChallenge,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AccessLookupRequest {
    encryption_key_version: u32,
    operation_nonce: String,
    deadline: u64,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    token: String,
    token_type: &'static str,
    expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionIdentity {
    member_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessLookupResponse {
    file_id: String,
    version_number: u64,
    content_cid: String,
    envelope_set_cid: String,
    epoch_id: String,
    envelope_revision: u32,
    finalized_block: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl AppState {
    pub fn new(store: GatewayStore, chain: BesuClient, config: GatewayConfig) -> Self {
        Self {
            store,
            chain: Arc::new(chain),
            config: Arc::new(config),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/v1/auth/challenge", post(create_challenge))
        .route(
            "/v1/auth/session",
            get(session_identity).post(create_session),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/access",
            post(access_lookup),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ));
    Router::new()
        .route("/healthz", get(health))
        .merge(auth_routes)
        .layer(DefaultBodyLimit::max(8 * 1024))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn create_challenge(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                "auth.challenge",
                &source_id,
                "invalid_json",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let member = match parse_member_id(&request.member_id) {
        Ok(member) => member,
        Err(_) => {
            return failure(
                &state,
                "auth.challenge",
                &source_id,
                "invalid_request",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let issued_at = match unix_seconds() {
        Some(now) => now,
        None => {
            return failure(
                &state,
                "auth.challenge",
                &source_id,
                "clock_unavailable",
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await;
        }
    };
    let Some(expires_at) = issued_at.checked_add(state.config.challenge_ttl_seconds) else {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "clock_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let mut nonce = [0; 32];
    if getrandom::fill(&mut nonce).is_err() || nonce == [0; 32] {
        return failure(
            &state,
            "auth.challenge",
            &source_id,
            "randomness_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    }
    let challenge = LoginChallenge {
        member_id: member.to_string(),
        nonce: encode_hex(&nonce),
        issued_at,
        expires_at,
        audience: state.config.audience.clone(),
        protocol_version: 1,
    };
    match state
        .store
        .create_challenge(&challenge, &source_id, state.config.chain_id)
        .await
    {
        Ok(()) => Json(challenge).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn create_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<SessionRequest>, JsonRejection>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                "auth.session",
                &source_id,
                "invalid_json",
                None,
                StatusCode::BAD_REQUEST,
                "unauthorized",
            )
            .await;
        }
    };
    let operation_id = None;
    let member = match parse_member_id(&request.challenge.member_id) {
        Ok(member) => member,
        Err(_) => {
            return failure(
                &state,
                "auth.session",
                &source_id,
                "invalid_challenge",
                operation_id,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    if validate_challenge(&state, &request.challenge).is_err() {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_challenge",
            operation_id,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }
    let digest = match challenge_digest(
        &request.challenge,
        state.config.chain_id,
        state.config.access_governance,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            return failure(
                &state,
                "auth.session",
                &source_id,
                "invalid_challenge",
                operation_id,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let claimed_signer = match recover_signer(&digest, &request.signature) {
        Ok(address) => address,
        Err(_) => {
            return failure(
                &state,
                "auth.session",
                &source_id,
                "invalid_signature",
                operation_id,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let active_signer = match state
        .chain
        .active_member_signer(&state.config.access_governance, member.as_bytes())
        .await
    {
        Ok(signer) => signer,
        Err(_) => {
            return failure(
                &state,
                "auth.session",
                &source_id,
                "chain_unavailable",
                operation_id,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await;
        }
    };
    if active_signer != Some(claimed_signer) {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "invalid_signature",
            operation_id,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }

    let Some(now) = unix_seconds() else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "clock_unavailable",
            operation_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let Some(session_expires_at) = now.checked_add(state.config.session_ttl_seconds) else {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "clock_unavailable",
            operation_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };
    let mut token = [0; 32];
    if getrandom::fill(&mut token).is_err() || token == [0; 32] {
        return failure(
            &state,
            "auth.session",
            &source_id,
            "randomness_unavailable",
            operation_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    }
    match state
        .store
        .complete_login(
            &request.challenge,
            &hash_session_token(&token),
            session_expires_at,
            &source_id,
            state.config.chain_id,
        )
        .await
    {
        Ok(true) => Json(SessionResponse {
            token: encode_hex(&token),
            token_type: "Bearer",
            expires_at: session_expires_at,
        })
        .into_response(),
        Ok(false) => {
            failure(
                &state,
                "auth.session",
                &source_id,
                "challenge_consumed_or_expired",
                operation_id,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn session_identity(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(parse_fixed_hex::<32>);
    let Some(token) = token else {
        return failure(
            &state,
            "auth.session.validate",
            &source_id,
            "invalid_session",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    match state
        .store
        .active_session_member(&hash_session_token(&token))
        .await
    {
        Ok(Some(member_id)) => {
            match state
                .store
                .record_session_validation(
                    Some(&member_id),
                    &source_id,
                    "authenticated",
                    None,
                    state.config.chain_id,
                )
                .await
            {
                Ok(()) => Json(SessionIdentity { member_id }).into_response(),
                Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
            }
        }
        Ok(None) => {
            match state
                .store
                .record_session_validation(
                    None,
                    &source_id,
                    "denied",
                    Some("invalid_session"),
                    state.config.chain_id,
                )
                .await
            {
                Ok(()) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
                Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
            }
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn access_lookup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
    body: Result<Json<AccessLookupRequest>, JsonRejection>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let file_id = match parse_fixed_hex::<32>(&raw_file_id) {
        Some(file_id) if file_id != [0; 32] && raw_file_id == raw_file_id.to_ascii_lowercase() => {
            FileId::from_bytes(file_id)
        }
        _ => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_request",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let version = match VersionNumber::new(version_number) {
        Ok(version) => version,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_request",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_request",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(parse_fixed_hex::<32>);
    let Some(token) = token else {
        return failure(
            &state,
            "file.access_lookup",
            &source_id,
            "unauthenticated",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let member_id = match state
        .store
        .active_session_member(&hash_session_token(&token))
        .await
    {
        Ok(Some(member_id)) => match parse_member_id(&member_id) {
            Ok(member_id) => member_id,
            Err(_) => {
                return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
            }
        },
        Ok(None) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let nonce = match parse_nonce(&request.operation_nonce) {
        Ok(nonce) => nonce,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_operation",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let now = match unix_seconds() {
        Some(now) => now,
        None => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let deadline = match UnixDeadline::from_unix_seconds(request.deadline) {
        Ok(deadline)
            if request.deadline > now
                && request.deadline.saturating_sub(now)
                    <= state.config.challenge_ttl_seconds =>
        {
            deadline
        }
        _ => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "expired_operation",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let key_version = match KeyVersion::new(request.encryption_key_version) {
        Ok(version) => version,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_operation",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let operation_nonce = OperationNonce::from_bytes(nonce);
    let operation = match AccessLookup::new(
        member_id,
        file_id,
        version,
        key_version,
        operation_nonce,
        deadline,
    ) {
        Ok(operation) => operation,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_operation",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let domain = Eip712Domain::access_governance(
        ChainId::from_u64(state.config.chain_id),
        state.config.access_governance,
    );
    let digest = match operation.digest(&domain) {
        Ok(digest) => digest,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_operation",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let signer = match recover_signer(&digest, &request.signature) {
        Ok(signer) => signer,
        Err(_) => {
            return failure(
                &state,
                "file.access_lookup",
                &source_id,
                "invalid_signature",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                None,
                "chain_unavailable",
            )
            .await;
        }
    };
    let member = match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(member) => member,
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "chain_unavailable",
            )
            .await;
        }
    };
    let Some(member) = member.filter(|member| member.active) else {
        return signed_access_failure(
            &state,
            member_id,
            &source_id,
            &file_id,
            version_number,
            &nonce,
            request.deadline,
            Some(finalized.number),
            "unauthorized",
        )
        .await;
    };
    if signer != member.signing_address || key_version != KeyVersion::new(member.encryption_key_version).unwrap_or(key_version) {
        return signed_access_failure(
            &state,
            member_id,
            &source_id,
            &file_id,
            version_number,
            &nonce,
            request.deadline,
            Some(finalized.number),
            "invalid_signature",
        )
        .await;
    }

    let authorized = match state
        .chain
        .has_read_access(
            &state.config.access_governance,
            member_id.as_bytes(),
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(allowed) => allowed,
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "chain_unavailable",
            )
            .await;
        }
    };
    let head = match state
        .chain
        .file_head_at(
            &state.config.file_registry,
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(head) => head,
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "chain_unavailable",
            )
            .await;
        }
    };
    let version_exists = head
        .as_ref()
        .is_some_and(|head| head.status == 1 && version_number <= head.version_number);
    if !authorized || !version_exists {
        return signed_access_failure(
            &state,
            member_id,
            &source_id,
            &file_id,
            version_number,
            &nonce,
            request.deadline,
            Some(finalized.number),
            "unauthorized",
        )
        .await;
    }
    let content = match state
        .chain
        .file_version(
            &state.config.file_registry,
            file_id.as_bytes(),
            version_number,
            finalized.number,
        )
        .await
    {
        Ok(Some(content)) => content,
        Ok(None) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "version_unavailable",
            )
            .await;
        }
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "chain_unavailable",
            )
            .await;
        }
    };
    let envelope = match state
        .chain
        .current_envelope_set(
            &state.config.access_governance,
            file_id.as_bytes(),
            version_number,
            finalized.number,
        )
        .await
    {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "envelope_unavailable",
            )
            .await;
        }
        Err(_) => {
            return signed_access_failure(
                &state,
                member_id,
                &source_id,
                &file_id,
                version_number,
                &nonce,
                request.deadline,
                Some(finalized.number),
                "chain_unavailable",
            )
            .await;
        }
    };
    match state
        .store
        .record_access_attempt(
            &member_id.to_string(),
            &source_id,
            &file_id.to_string(),
            version_number,
            &nonce,
            request.deadline,
            state.config.chain_id,
            finalized.number,
            true,
            None,
        )
        .await
    {
        Ok(true) => Json(AccessLookupResponse {
            file_id: file_id.to_string(),
            version_number,
            content_cid: content.content_cid,
            envelope_set_cid: envelope.cid,
            epoch_id: encode_hex(&envelope.epoch_id),
            envelope_revision: envelope.revision,
            finalized_block: finalized.number,
        })
        .into_response(),
        Ok(false) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn signed_access_failure(
    state: &AppState,
    member_id: domain::MemberId,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    nonce: &[u8; 32],
    deadline: u64,
    block_number: Option<u64>,
    reason: &'static str,
) -> Response {
    let result = state
        .store
        .record_access_attempt(
            &member_id.to_string(),
            source_id,
            &file_id.to_string(),
            version,
            nonce,
            deadline,
            state.config.chain_id,
            block_number.unwrap_or_default(),
            false,
            Some(reason),
        )
        .await;
    match result {
        Ok(_) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn enforce_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let action = match (request.method().as_str(), request.uri().path()) {
        ("POST", "/v1/auth/challenge") => "auth.challenge",
        ("POST", "/v1/auth/session") | ("GET", "/v1/auth/session") => "auth.session",
        _ => return next.run(request).await,
    };
    let source_id = source_identifier(&peer.ip().to_string());
    let key = format!("{action}:{source_id}");
    match state
        .store
        .take_rate_limit_token(
            &key,
            f64::from(state.config.rate_limit_capacity),
            state.config.rate_limit_refill_per_second,
        )
        .await
    {
        Ok(true) => next.run(request).await,
        Ok(false) => {
            failure(
                &state,
                action,
                &source_id,
                "rate_limited",
                None,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            )
            .await
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn failure(
    state: &AppState,
    action: &'static str,
    source_id: &str,
    reason: &'static str,
    operation_id: Option<&str>,
    status: StatusCode,
    public_error: &'static str,
) -> Response {
    match state
        .store
        .record_auth_failure(
            action,
            source_id,
            reason,
            operation_id,
            state.config.chain_id,
        )
        .await
    {
        Ok(()) => error(status, public_error),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

fn validate_challenge(state: &AppState, challenge: &LoginChallenge) -> Result<(), ()> {
    let now = unix_seconds().ok_or(())?;
    parse_nonce(&challenge.nonce).map_err(|_| ())?;
    if challenge.protocol_version != 1
        || challenge.audience != state.config.audience
        || challenge.issued_at == 0
        || challenge.issued_at > now
        || challenge.expires_at <= now
        || challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > state.config.challenge_ttl_seconds
    {
        return Err(());
    }
    Ok(())
}

fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(ErrorResponse { error: code })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_route_accepts_the_documented_json_names() {
        let request: ChallengeRequest =
            serde_json::from_str(&format!(r#"{{"memberId":"0x{}"}}"#, "11".repeat(32))).unwrap();
        assert_eq!(request.member_id, format!("0x{}", "11".repeat(32)));
    }

    #[test]
    fn challenge_response_uses_the_typed_data_field_names() {
        let challenge = LoginChallenge {
            member_id: format!("0x{}", "11".repeat(32)),
            nonce: format!("0x{}", "22".repeat(32)),
            issued_at: 10,
            expires_at: 130,
            audience: "rrds-local".to_owned(),
            protocol_version: 1,
        };
        let value = serde_json::to_value(challenge).unwrap();
        assert_eq!(value["memberId"], format!("0x{}", "11".repeat(32)));
        assert_eq!(value["issuedAt"], 10);
        assert_eq!(value["protocolVersion"], 1);
        assert!(value.get("member_id").is_none());
    }
}
