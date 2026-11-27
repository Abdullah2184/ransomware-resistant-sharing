mod auth;
mod blobs;
mod middleware;
mod reads;
mod writes;

#[cfg(test)]
mod tests;

use std::{sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{HeaderMap, StatusCode},
    middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chain_adapter::{FileHeadState, FinalizedBlock, MemberIdentityState};
use crypto::UnixDeadline;
use domain::{EnvelopeSetCid, EvmAddress, FileId, KeyVersion, MemberId};
use ports::BlobStore;
use serde::Serialize;
use tokio::io::AsyncReadExt;

use crate::{
    auth::{parse_fixed_hex, parse_member_id},
    config::GatewayConfig,
    ports::{GatewayChainPort, GatewayRelayerPort, GatewayStorePort},
    store::hash_session_token,
};

#[cfg(test)]
pub(crate) use self::auth::{ChallengeRequest, PublicIdentityResponse};
#[cfg(test)]
pub(crate) use self::middleware::rate_limit_action;

pub(crate) const MAX_ENVELOPE_SET_BYTES: usize = 512 * 1024;
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = 256;
pub(crate) const MAX_WRITE_DEADLINE_HORIZON_SECONDS: u64 = 3600;
pub(crate) const DEFAULT_AUDIT_LIMIT: u32 = 50;
pub(crate) const MAX_AUDIT_LIMIT: u32 = 100;

#[derive(Clone)]
pub struct AppState {
    pub(crate) store: Arc<dyn GatewayStorePort>,
    pub(crate) chain: Arc<dyn GatewayChainPort>,
    pub(crate) blob_store: Arc<dyn BlobStore>,
    pub(crate) relayer: Option<Arc<dyn GatewayRelayerPort>>,
    pub(crate) config: Arc<GatewayConfig>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl AppState {
    pub fn new(
        store: impl GatewayStorePort + 'static,
        chain: impl GatewayChainPort + 'static,
        blob_store: impl BlobStore + 'static,
        config: GatewayConfig,
    ) -> Self {
        Self {
            store: Arc::new(store),
            chain: Arc::new(chain),
            blob_store: Arc::new(blob_store),
            relayer: None,
            config: Arc::new(config),
        }
    }

    pub fn with_relayer(mut self, relayer: impl GatewayRelayerPort + 'static) -> Self {
        self.relayer = Some(Arc::new(relayer));
        self
    }
}

pub fn router(state: AppState) -> Router {
    let max_blob_bytes = state.config.max_blob_upload_bytes;
    let auth_routes = Router::new()
        .route("/v1/identities/{member_id}", get(auth::public_identity))
        .route("/v1/auth/challenge", post(auth::create_challenge))
        .route(
            "/v1/auth/session",
            get(auth::session_identity)
                .post(auth::create_session)
                .delete(auth::revoke_session),
        )
        .route(
            "/v1/files",
            get(reads::list_files).post(writes::create_file),
        )
        .route(
            "/v1/files/{file_id}/versions",
            get(reads::file_version_history).post(writes::append_version),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/access",
            post(reads::access_lookup),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/content",
            get(reads::retrieve_version_content),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/envelope",
            get(reads::retrieve_version_envelope),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/envelopes",
            post(writes::update_envelope_set),
        )
        .route("/v1/audit", get(reads::query_audit))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::enforce_rate_limit,
        ));
    let content_blob_route = Router::new()
        .route("/v1/blobs/content", post(blobs::upload_content_blob))
        .layer(DefaultBodyLimit::max(max_blob_bytes))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::enforce_rate_limit,
        ));
    let envelope_blob_route = Router::new()
        .route("/v1/blobs/envelopes", post(blobs::upload_envelope_blob))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_SET_BYTES))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::enforce_rate_limit,
        ));
    Router::new()
        .route("/healthz", get(auth::health))
        .merge(auth_routes)
        .merge(content_blob_route)
        .merge(envelope_blob_route)
        .layer(axum_middleware::from_fn(middleware::request_id_and_logging))
        .with_state(state)
}

pub(crate) fn parse_nonzero_file_id(raw: &str) -> Option<FileId> {
    domain::hex::parse_lowercase_fixed_hex::<32>(raw)
        .filter(|bytes| *bytes != [0; 32])
        .map(FileId::from_bytes)
}

pub(crate) fn parse_bearer_token(headers: &HeaderMap) -> Option<[u8; 32]> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(parse_fixed_hex::<32>)
}

pub(crate) enum BearerError {
    Unauthenticated,
    Unavailable,
}

pub(crate) async fn authenticate_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<MemberId, BearerError> {
    let token = parse_bearer_token(headers).ok_or(BearerError::Unauthenticated)?;
    match state
        .store
        .active_session_member(&hash_session_token(&token))
        .await
    {
        Ok(Some(member_id)) => parse_member_id(&member_id).map_err(|_| BearerError::Unavailable),
        Ok(None) => Err(BearerError::Unauthenticated),
        Err(_) => Err(BearerError::Unavailable),
    }
}

pub(crate) struct ActiveMemberContext {
    pub(crate) member_id: MemberId,
    pub(crate) member_id_string: String,
    pub(crate) finalized: FinalizedBlock,
    pub(crate) member: MemberIdentityState,
}

pub(crate) enum ActiveMemberError {
    Unauthenticated,
    Unauthorized,
    Unavailable,
}

pub(crate) async fn authenticate_active_member(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ActiveMemberContext, ActiveMemberError> {
    let member_id = match authenticate_bearer(state, headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => return Err(ActiveMemberError::Unauthenticated),
        Err(BearerError::Unavailable) => return Err(ActiveMemberError::Unavailable),
    };
    let finalized = state
        .chain
        .finalized_block()
        .await
        .map_err(|_| ActiveMemberError::Unavailable)?;
    let member = match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(member)) if member.active() => member,
        Ok(_) => return Err(ActiveMemberError::Unauthorized),
        Err(_) => return Err(ActiveMemberError::Unavailable),
    };
    Ok(ActiveMemberContext {
        member_id_string: member_id.to_string(),
        member_id,
        finalized,
        member,
    })
}

pub(crate) struct AuthorizedVersionRead {
    pub(crate) finalized: FinalizedBlock,
    pub(crate) member: MemberIdentityState,
    #[allow(dead_code)]
    pub(crate) head: FileHeadState,
}

pub(crate) enum VersionReadAuthError {
    ChainUnavailable(Option<u64>),
    Unauthorized(u64),
    InvalidSignature(u64),
}

/// Authorizes a member to read a specific file version at one QBFT-committed block:
/// active member, optional signer/encryption-key-version match, file Read ACL,
/// active file head containing `version_number`, and historical grant if non-head.
pub(crate) async fn authorize_version_read(
    state: &AppState,
    member_id: MemberId,
    file_id: &FileId,
    version_number: u64,
    expected_key_binding: Option<(EvmAddress, KeyVersion)>,
) -> Result<AuthorizedVersionRead, VersionReadAuthError> {
    let finalized = state
        .chain
        .finalized_block()
        .await
        .map_err(|_| VersionReadAuthError::ChainUnavailable(None))?;
    let block = finalized.number;

    let member = state
        .chain
        .member_identity(&state.config.access_governance, member_id.as_bytes(), block)
        .await
        .map_err(|_| VersionReadAuthError::ChainUnavailable(Some(block)))?
        .filter(|member| member.active())
        .ok_or(VersionReadAuthError::Unauthorized(block))?;

    if let Some((signer, key_version)) = expected_key_binding
        && (signer != member.signing_address || key_version.get() != member.encryption_key_version)
    {
        return Err(VersionReadAuthError::InvalidSignature(block));
    }

    let read_access = state
        .chain
        .has_read_access(
            &state.config.access_governance,
            member_id.as_bytes(),
            file_id.as_bytes(),
            block,
        )
        .await
        .map_err(|_| VersionReadAuthError::ChainUnavailable(Some(block)))?;

    let head = state
        .chain
        .file_head_at(&state.config.file_registry, file_id.as_bytes(), block)
        .await
        .map_err(|_| VersionReadAuthError::ChainUnavailable(Some(block)))?
        .filter(|head| head.status == 1 && version_number <= head.version_number)
        .ok_or(VersionReadAuthError::Unauthorized(block))?;

    if !read_access {
        return Err(VersionReadAuthError::Unauthorized(block));
    }

    if version_number < head.version_number {
        let historical = state
            .chain
            .has_historical_read_access(
                &state.config.access_governance,
                member_id.as_bytes(),
                file_id.as_bytes(),
                version_number,
                block,
            )
            .await
            .map_err(|_| VersionReadAuthError::ChainUnavailable(Some(block)))?;
        if !historical {
            return Err(VersionReadAuthError::Unauthorized(block));
        }
    }

    Ok(AuthorizedVersionRead {
        finalized,
        member,
        head,
    })
}

pub(crate) enum EnvelopeReadError {
    StorageUnavailable,
    InvalidEnvelopeSet,
}

/// Fetches an envelope-set JSON object from IPFS with a strict byte bound and
/// verifies that its raw SHA-256 CID matches the expected `EnvelopeSetCid`.
pub(crate) async fn read_bounded_envelope_set(
    state: &AppState,
    envelope_cid: &EnvelopeSetCid,
) -> Result<Vec<u8>, EnvelopeReadError> {
    let mut reader = state
        .blob_store
        .get_envelope_set(envelope_cid)
        .await
        .map_err(|_| EnvelopeReadError::StorageUnavailable)?;
    let mut envelope_bytes = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if envelope_bytes.len().saturating_add(read) > MAX_ENVELOPE_SET_BYTES {
                    return Err(EnvelopeReadError::InvalidEnvelopeSet);
                }
                envelope_bytes.extend_from_slice(&buffer[..read]);
            }
            Err(_) => return Err(EnvelopeReadError::StorageUnavailable),
        }
    }
    let actual_cid = crypto::raw_sha256_cid(&envelope_bytes)
        .map(|cid| cid.to_string())
        .map_err(|_| EnvelopeReadError::InvalidEnvelopeSet)?;
    if actual_cid != envelope_cid.to_string() {
        return Err(EnvelopeReadError::InvalidEnvelopeSet);
    }
    Ok(envelope_bytes)
}

pub(crate) enum WriteDeadlineError {
    ClockUnavailable,
    Expired,
}

pub(crate) fn verify_write_deadline(
    deadline_seconds: u64,
) -> Result<UnixDeadline, WriteDeadlineError> {
    let now = unix_seconds().ok_or(WriteDeadlineError::ClockUnavailable)?;
    let deadline = UnixDeadline::from_unix_seconds(deadline_seconds)
        .map_err(|_| WriteDeadlineError::Expired)?;
    if deadline_seconds <= now
        || deadline_seconds.saturating_sub(now) > MAX_WRITE_DEADLINE_HORIZON_SECONDS
    {
        return Err(WriteDeadlineError::Expired);
    }
    Ok(deadline)
}

pub(crate) async fn failure(
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

pub(crate) fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub(crate) fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(ErrorResponse { error: code })).into_response()
}
