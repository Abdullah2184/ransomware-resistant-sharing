use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Instant, SystemTime},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, Path, Query, Request, State, rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chain_adapter::{EnvelopeSetUpdateCall, RelayError, RelayOutcome, VersionAppendCall};
use crypto::{
    AccessLookup, ChainId, Eip712Domain, EnvelopeSetUpdate, KeyEnvelopeSet, UnixDeadline,
    VersionAppend,
};
use domain::{
    ContentCid, EnvelopeSetCid, EpochId, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, ProposalId, VersionNumber,
};
use ports::{BlobStore, StorageCid, StorageReader, decode_content_package_frame};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::{
    auth::{
        LoginChallenge, challenge_digest, parse_fixed_hex, parse_member_id, parse_nonce,
        recover_signer,
    },
    config::GatewayConfig,
    ports::{GatewayChainPort, GatewayRelayerPort, GatewayStorePort},
    store::{
        AuditEventRecord, ProjectedFile, ProjectedFolder, ProjectedVersion, encode_hex,
        hash_session_token, source_identifier,
    },
};

const MAX_ENVELOPE_SET_BYTES: usize = 512 * 1024;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_WRITE_DEADLINE_HORIZON_SECONDS: u64 = 3600;
const DEFAULT_AUDIT_LIMIT: u32 = 50;
const MAX_AUDIT_LIMIT: u32 = 100;

#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn GatewayStorePort>,
    chain: Arc<dyn GatewayChainPort>,
    blob_store: Arc<dyn BlobStore>,
    relayer: Option<Arc<dyn GatewayRelayerPort>>,
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
struct PublicIdentityResponse {
    member_id: String,
    organization_id: String,
    signing_address: String,
    signing_key_version: u32,
    encryption_key_version: u32,
    encryption_public_key: String,
    status: &'static str,
    finalized_block: u64,
    finalized_block_hash: String,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileListQuery {
    folder_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditQuery {
    action: Option<String>,
    limit: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileListResponse {
    folder_id: String,
    folders: Vec<ProjectedFolder>,
    files: Vec<ProjectedFile>,
    finalized_block: u64,
    finalized_block_hash: String,
    indexed_block: Option<u64>,
    indexed_block_hash: Option<String>,
    authoritative: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionHistoryResponse {
    file_id: String,
    current_version: u64,
    current_head_manifest_hash: String,
    finalized_block: u64,
    finalized_block_hash: String,
    indexed_block: Option<u64>,
    indexed_block_hash: Option<String>,
    versions: Vec<ProjectedVersion>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditQueryResponse {
    member_id: String,
    finalized_block: u64,
    events: Vec<AuditEventRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct CreateFileRequest {
    file_id: String,
    display_name: String,
    parent_folder_id: String,
    version_number: u64,
    parent_manifest_hash: String,
    manifest_hash: String,
    content_cid: String,
    envelope_set_cid: String,
    epoch_id: String,
    operation_nonce: String,
    deadline: u64,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AppendVersionRequest {
    version_number: u64,
    parent_manifest_hash: String,
    manifest_hash: String,
    content_cid: String,
    envelope_set_cid: String,
    epoch_id: String,
    operation_nonce: String,
    deadline: u64,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct UpdateEnvelopeSetRequest {
    epoch_id: String,
    old_envelope_set_cid: String,
    new_envelope_set_cid: String,
    proposal_id: String,
    operation_nonce: String,
    deadline: u64,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteCommitResponse {
    file_id: String,
    version_number: u64,
    transaction_hash: String,
    block_number: u64,
    block_hash: String,
    gas_used: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayErrorResponse {
    error: &'static str,
    transaction_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BlobUploadResponse {
    cid: String,
    bytes_written: u64,
    required_replicas: usize,
    pinned_peers: Vec<String>,
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
        .route("/v1/identities/{member_id}", get(public_identity))
        .route("/v1/auth/challenge", post(create_challenge))
        .route(
            "/v1/auth/session",
            get(session_identity)
                .post(create_session)
                .delete(revoke_session),
        )
        .route("/v1/files", get(list_files).post(create_file))
        .route(
            "/v1/files/{file_id}/versions",
            get(file_version_history).post(append_version),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/access",
            post(access_lookup),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/content",
            get(retrieve_version_content),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/envelope",
            get(retrieve_version_envelope),
        )
        .route(
            "/v1/files/{file_id}/versions/{version}/envelopes",
            post(update_envelope_set),
        )
        .route("/v1/audit", get(query_audit))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ));
    let content_blob_route = Router::new()
        .route("/v1/blobs/content", post(upload_content_blob))
        .layer(DefaultBodyLimit::max(max_blob_bytes))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ));
    let envelope_blob_route = Router::new()
        .route("/v1/blobs/envelopes", post(upload_envelope_blob))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_SET_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ));
    Router::new()
        .route("/healthz", get(health))
        .merge(auth_routes)
        .merge(content_blob_route)
        .merge(envelope_blob_route)
        .layer(middleware::from_fn(request_id_and_logging))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn public_identity(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw_member_id): Path<String>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let member_id = match parse_member_id(&raw_member_id) {
        Ok(member_id) => member_id,
        Err(_) => {
            return failure(
                &state,
                "identity.lookup",
                &source_id,
                "invalid_request",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let identity = match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let status = match identity.status {
        1 => "active",
        2 => "suspended",
        3 => "revoked",
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    Json(PublicIdentityResponse {
        member_id: member_id.to_string(),
        organization_id: encode_hex(&identity.organization_id),
        signing_address: identity.signing_address.to_string(),
        signing_key_version: identity.signing_key_version,
        encryption_key_version: identity.encryption_key_version,
        encryption_public_key: encode_hex(&identity.encryption_public_key),
        status,
        finalized_block: finalized.number,
        finalized_block_hash: finalized.hash,
    })
    .into_response()
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
            return invalid_signature_failure(&state, "auth.session", &source_id, operation_id)
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
        return invalid_signature_failure(&state, "auth.session", &source_id, operation_id).await;
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

async fn revoke_session(
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
            "auth.session.revoke",
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
        .revoke_session(
            &hash_session_token(&token),
            &source_id,
            state.config.chain_id,
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            failure(
                &state,
                "auth.session.revoke",
                &source_id,
                "invalid_session",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await
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
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
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
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
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
                && request.deadline.saturating_sub(now) <= state.config.challenge_ttl_seconds =>
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
    let signer = match recover_signer(digest.as_bytes(), &request.signature) {
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
    let Some(member) = member.filter(|member| member.active()) else {
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
    if signer != member.signing_address || key_version.get() != member.encryption_key_version {
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
    let Some(head) = head.filter(|head| head.status == 1 && version_number <= head.version_number)
    else {
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
    if !authorized {
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
    if version_number < head.version_number {
        let historical_access = match state
            .chain
            .has_historical_read_access(
                &state.config.access_governance,
                member_id.as_bytes(),
                file_id.as_bytes(),
                version_number,
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
        if !historical_access {
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

async fn retrieve_version_content(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let file_id = match parse_fixed_hex::<32>(&raw_file_id) {
        Some(bytes) if bytes != [0; 32] && raw_file_id == raw_file_id.to_ascii_lowercase() => {
            FileId::from_bytes(bytes)
        }
        _ => {
            return failure(
                &state,
                "file.content_retrieval",
                &source_id,
                "invalid_request",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    if VersionNumber::new(version_number).is_err() {
        return content_attempt_failure(
            &state,
            None,
            &source_id,
            &file_id,
            version_number,
            None,
            "denied",
            "invalid_request",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }

    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return content_attempt_failure(
                &state,
                None,
                &source_id,
                &file_id,
                version_number,
                None,
                "denied",
                "unauthenticated",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => {
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                None,
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let read_access = match state
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
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
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
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let Some(head) = head.filter(|head| head.status == 1 && version_number <= head.version_number)
    else {
        return content_attempt_failure(
            &state,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    };
    if !read_access {
        return content_attempt_failure(
            &state,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    if version_number < head.version_number {
        match state
            .chain
            .has_historical_read_access(
                &state.config.access_governance,
                member_id.as_bytes(),
                file_id.as_bytes(),
                version_number,
                finalized.number,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return content_attempt_failure(
                    &state,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(finalized.number),
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                )
                .await;
            }
            Err(_) => {
                return content_attempt_failure(
                    &state,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(finalized.number),
                    "denied",
                    "chain_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            }
        }
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
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "unauthorized",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(_) => {
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let content_cid = match ContentCid::parse(&content.content_cid) {
        Ok(cid) => cid,
        Err(_) => {
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "invalid_chain_reference",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let reader = match state.blob_store.get_content(&content_cid).await {
        Ok(reader) => reader,
        Err(_) => {
            return content_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    if state
        .store
        .record_content_attempt(
            Some(&member_id_string),
            &source_id,
            &file_id.to_string(),
            version_number,
            state.config.chain_id,
            Some(finalized.number),
            "authorized",
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }

    let mut response = Response::new(Body::from_stream(ReaderStream::new(reader)));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/vnd.ipld.car"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn retrieve_version_envelope(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let file_id = match parse_fixed_hex::<32>(&raw_file_id) {
        Some(bytes) if bytes != [0; 32] && raw_file_id == raw_file_id.to_ascii_lowercase() => {
            FileId::from_bytes(bytes)
        }
        _ => {
            return failure(
                &state,
                "file.envelope_retrieval",
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
            return envelope_attempt_failure(
                &state,
                None,
                &source_id,
                &file_id,
                version_number,
                None,
                "denied",
                "invalid_request",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    };

    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return envelope_attempt_failure(
                &state,
                None,
                &source_id,
                &file_id,
                version_number,
                None,
                "denied",
                "unauthenticated",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                None,
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
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
        Ok(Some(member)) if member.active() => member,
        Ok(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "unauthorized",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let read_access = match state
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
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
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
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let Some(head) = head.filter(|head| head.status == 1 && version_number <= head.version_number)
    else {
        return envelope_attempt_failure(
            &state,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    };
    if !read_access {
        return envelope_attempt_failure(
            &state,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    if version_number < head.version_number {
        match state
            .chain
            .has_historical_read_access(
                &state.config.access_governance,
                member_id.as_bytes(),
                file_id.as_bytes(),
                version_number,
                finalized.number,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return envelope_attempt_failure(
                    &state,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(finalized.number),
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                )
                .await;
            }
            Err(_) => {
                return envelope_attempt_failure(
                    &state,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(finalized.number),
                    "denied",
                    "chain_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            }
        }
    }

    let pointer = match state
        .chain
        .current_envelope_set(
            &state.config.access_governance,
            file_id.as_bytes(),
            version_number,
            finalized.number,
        )
        .await
    {
        Ok(Some(pointer)) => pointer,
        Ok(None) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "envelope_unavailable",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
        Err(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "chain_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let envelope_cid = match EnvelopeSetCid::parse(&pointer.cid) {
        Ok(cid) => cid,
        Err(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "invalid_chain_reference",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let mut reader = match state.blob_store.get_envelope_set(&envelope_cid).await {
        Ok(reader) => reader,
        Err(_) => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let mut envelope_bytes = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if envelope_bytes.len().saturating_add(read) > MAX_ENVELOPE_SET_BYTES {
                    return envelope_attempt_failure(
                        &state,
                        Some(&member_id_string),
                        &source_id,
                        &file_id,
                        version_number,
                        Some(finalized.number),
                        "denied",
                        "invalid_envelope_set",
                        StatusCode::SERVICE_UNAVAILABLE,
                    )
                    .await;
                }
                envelope_bytes.extend_from_slice(&buffer[..read]);
            }
            Err(_) => {
                return envelope_attempt_failure(
                    &state,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(finalized.number),
                    "storage_failed",
                    "storage_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
            }
        }
    }

    let parsed = match KeyEnvelopeSet::parse_canonical(&envelope_bytes) {
        Ok(set)
            if set.file_id() == file_id
                && set.version_number() == version
                && set.epoch_id() == EpochId::from_bytes(pointer.epoch_id)
                && set.revision() == pointer.revision =>
        {
            set
        }
        _ => {
            return envelope_attempt_failure(
                &state,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(finalized.number),
                "denied",
                "invalid_envelope_set",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
    };
    let has_recipient_envelope = parsed.envelopes().iter().any(|entry| {
        entry.member_id() == member_id
            && entry.encryption_key_version().get() == member.encryption_key_version
    });
    if !has_recipient_envelope {
        return envelope_attempt_failure(
            &state,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(finalized.number),
            "denied",
            "missing_recipient_envelope",
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }

    if state
        .store
        .record_envelope_attempt(
            Some(&member_id_string),
            &source_id,
            &file_id.to_string(),
            version_number,
            state.config.chain_id,
            Some(finalized.number),
            "authorized",
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }

    let mut response = Response::new(Body::from(envelope_bytes));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn list_files(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<FileListQuery>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let folder_id = match query.folder_id {
        Some(raw) => match parse_fixed_hex::<32>(&raw) {
            Some(_) if raw == raw.to_ascii_lowercase() => raw,
            _ => {
                return failure(
                    &state,
                    "file.list",
                    &source_id,
                    "invalid_request",
                    None,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await;
            }
        },
        None => encode_hex(&[0; 32]),
    };

    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                "file.list",
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
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
        Ok(Some(member)) if member.active() => member,
        Ok(_) => {
            return failure(
                &state,
                "file.list",
                &source_id,
                "unauthorized",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };

    let organization_id = encode_hex(&member.organization_id);
    match state
        .store
        .list_files_and_folders(
            state.config.chain_id,
            &member_id.to_string(),
            &organization_id,
            &folder_id,
        )
        .await
    {
        Ok(listing) => Json(FileListResponse {
            folder_id,
            folders: listing.folders,
            files: listing.files,
            finalized_block: finalized.number,
            finalized_block_hash: finalized.hash,
            indexed_block: listing.indexed_block,
            indexed_block_hash: listing.indexed_block_hash,
            authoritative: false,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn file_version_history(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_file_id): Path<String>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let file_id = match parse_fixed_hex::<32>(&raw_file_id) {
        Some(bytes) if bytes != [0; 32] && raw_file_id == raw_file_id.to_ascii_lowercase() => {
            FileId::from_bytes(bytes)
        }
        _ => {
            return failure(
                &state,
                "file.history",
                &source_id,
                "invalid_request",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };

    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                "file.history",
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let read_access = match state
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
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
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
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let Some(head) = head.filter(|head| head.status == 1) else {
        return failure(
            &state,
            "file.history",
            &source_id,
            "unauthorized",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    if !read_access {
        return failure(
            &state,
            "file.history",
            &source_id,
            "unauthorized",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }

    match state
        .store
        .list_file_versions(
            state.config.chain_id,
            &file_id.to_string(),
            &member_id.to_string(),
        )
        .await
    {
        Ok(history) => Json(VersionHistoryResponse {
            file_id: file_id.to_string(),
            current_version: head.version_number,
            current_head_manifest_hash: head.manifest_hash,
            finalized_block: finalized.number,
            finalized_block_hash: finalized.hash,
            indexed_block: history.indexed_block,
            indexed_block_hash: history.indexed_block_hash,
            versions: history.versions,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn query_audit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let limit = query.limit.unwrap_or(DEFAULT_AUDIT_LIMIT);
    if limit == 0 || limit > MAX_AUDIT_LIMIT {
        return failure(
            &state,
            "audit.query",
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    if let Some(action) = query.action.as_deref()
        && (action.is_empty()
            || action.len() > 64
            || !action
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return failure(
            &state,
            "audit.query",
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }

    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                "audit.query",
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(member)) if member.active() => {}
        Ok(_) => {
            return failure(
                &state,
                "audit.query",
                &source_id,
                "unauthorized",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    let member_id_string = member_id.to_string();
    match state
        .store
        .query_member_audit_events(
            &member_id_string,
            &source_id,
            state.config.chain_id,
            finalized.number,
            query.action.as_deref(),
            limit,
        )
        .await
    {
        Ok(events) => Json(AuditQueryResponse {
            member_id: member_id_string,
            finalized_block: finalized.number,
            events,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn create_file(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<CreateFileRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.create";
    let source_id = source_identifier(&peer.ip().to_string());
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "invalid_json",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let Some(relayer) = state.relayer.as_ref() else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "relayer_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };

    let Some(file_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.file_id).filter(|bytes| *bytes != [0; 32])
    else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let file_id = FileId::from_bytes(file_bytes);
    if request.display_name.is_empty()
        || request.display_name.len() > MAX_DISPLAY_NAME_BYTES
        || request.display_name.chars().any(char::is_control)
        || request.version_number != 1
    {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    let Some(parent_folder_id) = parse_lowercase_fixed_hex::<32>(&request.parent_folder_id) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(parent_manifest_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.parent_manifest_hash)
            .filter(|bytes| *bytes == [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(manifest_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.manifest_hash).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(epoch_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.epoch_id).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(nonce_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.operation_nonce).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let op_id = request.operation_nonce.as_str();
    let Ok(content_cid) = ContentCid::parse(&request.content_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Ok(envelope_set_cid) = EnvelopeSetCid::parse(&request.envelope_set_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(signature_bytes) = parse_fixed_hex::<65>(&request.signature) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            None,
            "denied",
            "invalid_signature",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Some(now) = unix_seconds() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let Ok(deadline) = UnixDeadline::from_unix_seconds(request.deadline) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    if request.deadline <= now
        || request.deadline.saturating_sub(now) > MAX_WRITE_DEADLINE_HORIZON_SECONDS
    {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
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
        Ok(Some(member)) if member.active() => member,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                1,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "unauthorized",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };

    let Ok(typed_append) = VersionAppend::new(
        file_id,
        VersionNumber::ONE,
        ManifestHash::from_bytes(parent_manifest_bytes),
        ManifestHash::from_bytes(manifest_bytes),
        content_cid.clone(),
        envelope_set_cid.clone(),
        EpochId::from_bytes(epoch_bytes),
        member_id,
        member.signing_address,
        OperationNonce::from_bytes(nonce_bytes),
        deadline,
    ) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            1,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "invalid_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let domain = Eip712Domain::file_registry(
        ChainId::from_u64(state.config.chain_id),
        state.config.file_registry,
    );
    let Ok(digest) = typed_append.digest(&domain) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    match recover_signer(digest.as_bytes(), &request.signature) {
        Ok(recovered) if recovered == member.signing_address => {}
        _ => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                1,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "invalid_signature",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    }

    match state
        .chain
        .file_head_at(
            &state.config.file_registry,
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(None) => {}
        Ok(Some(_)) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                1,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "file_already_exists",
                StatusCode::CONFLICT,
                "conflict",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    if let Err(response) = verify_pin_quorum(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        1,
        op_id,
        finalized.number,
        StorageCid::Content(content_cid.clone()),
    )
    .await
    {
        return *response;
    }
    if let Err(response) = verify_pin_quorum(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        1,
        op_id,
        finalized.number,
        StorageCid::EnvelopeSet(envelope_set_cid.clone()),
    )
    .await
    {
        return *response;
    }

    let call = VersionAppendCall {
        file_id: file_bytes,
        version_number: 1,
        parent_manifest_hash: parent_manifest_bytes,
        content_cid: content_cid.to_string(),
        envelope_set_cid: envelope_set_cid.to_string(),
        epoch_id: epoch_bytes,
        manifest_hash: manifest_bytes,
        member_id: *member_id.as_bytes(),
        signer_address: member.signing_address,
        operation_nonce: nonce_bytes,
        deadline: request.deadline,
    };
    let relay_result = relayer
        .relay_create_file(
            call,
            request.display_name,
            parent_folder_id,
            signature_bytes.to_vec(),
        )
        .await;
    finalize_relay_response(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        1,
        op_id,
        StatusCode::CREATED,
        relay_result,
    )
    .await
}

async fn append_version(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_file_id): Path<String>,
    body: Result<Json<AppendVersionRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.version_append";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_bytes) =
        parse_lowercase_fixed_hex::<32>(&raw_file_id).filter(|bytes| *bytes != [0; 32])
    else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let file_id = FileId::from_bytes(file_bytes);
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "invalid_json",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let Some(relayer) = state.relayer.as_ref() else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "relayer_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };

    let Ok(version) = VersionNumber::new(request.version_number) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(parent_manifest_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.parent_manifest_hash)
            .filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(manifest_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.manifest_hash).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(epoch_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.epoch_id).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(nonce_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.operation_nonce).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let op_id = request.operation_nonce.as_str();
    let Ok(content_cid) = ContentCid::parse(&request.content_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Ok(envelope_set_cid) = EnvelopeSetCid::parse(&request.envelope_set_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(signature_bytes) = parse_fixed_hex::<65>(&request.signature) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_signature",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Some(now) = unix_seconds() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let Ok(deadline) = UnixDeadline::from_unix_seconds(request.deadline) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    if request.deadline <= now
        || request.deadline.saturating_sub(now) > MAX_WRITE_DEADLINE_HORIZON_SECONDS
    {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
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
        Ok(Some(member)) if member.active() => member,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                request.version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "unauthorized",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };

    let write_access = match state
        .chain
        .has_write_access(
            &state.config.access_governance,
            member_id.as_bytes(),
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(allowed) => allowed,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    if !write_access {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }

    let head = match state
        .chain
        .file_head_at(
            &state.config.file_registry,
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(head)) if head.status == 1 => head,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                request.version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "file_not_writable",
                StatusCode::CONFLICT,
                "conflict",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let expected_version = head.version_number.saturating_add(1);
    if request.version_number != expected_version
        || request.parent_manifest_hash != head.manifest_hash
    {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "stale_head",
            StatusCode::CONFLICT,
            "stale_head",
        )
        .await;
    }

    let Ok(typed_append) = VersionAppend::new(
        file_id,
        version,
        ManifestHash::from_bytes(parent_manifest_bytes),
        ManifestHash::from_bytes(manifest_bytes),
        content_cid.clone(),
        envelope_set_cid.clone(),
        EpochId::from_bytes(epoch_bytes),
        member_id,
        member.signing_address,
        OperationNonce::from_bytes(nonce_bytes),
        deadline,
    ) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            request.version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "invalid_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let domain = Eip712Domain::file_registry(
        ChainId::from_u64(state.config.chain_id),
        state.config.file_registry,
    );
    let Ok(digest) = typed_append.digest(&domain) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    match recover_signer(digest.as_bytes(), &request.signature) {
        Ok(recovered) if recovered == member.signing_address => {}
        _ => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                request.version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "invalid_signature",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    }

    if let Err(response) = verify_pin_quorum(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        request.version_number,
        op_id,
        finalized.number,
        StorageCid::Content(content_cid.clone()),
    )
    .await
    {
        return *response;
    }
    if let Err(response) = verify_pin_quorum(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        request.version_number,
        op_id,
        finalized.number,
        StorageCid::EnvelopeSet(envelope_set_cid.clone()),
    )
    .await
    {
        return *response;
    }

    let call = VersionAppendCall {
        file_id: file_bytes,
        version_number: request.version_number,
        parent_manifest_hash: parent_manifest_bytes,
        content_cid: content_cid.to_string(),
        envelope_set_cid: envelope_set_cid.to_string(),
        epoch_id: epoch_bytes,
        manifest_hash: manifest_bytes,
        member_id: *member_id.as_bytes(),
        signer_address: member.signing_address,
        operation_nonce: nonce_bytes,
        deadline: request.deadline,
    };
    let relay_result = relayer
        .relay_append_version(call, signature_bytes.to_vec())
        .await;
    finalize_relay_response(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        request.version_number,
        op_id,
        StatusCode::CREATED,
        relay_result,
    )
    .await
}

async fn update_envelope_set(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
    body: Result<Json<UpdateEnvelopeSetRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.envelope_update";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_bytes) =
        parse_lowercase_fixed_hex::<32>(&raw_file_id).filter(|bytes| *bytes != [0; 32])
    else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let file_id = FileId::from_bytes(file_bytes);
    let Ok(version) = VersionNumber::new(version_number) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Json(request) = match body {
        Ok(body) => body,
        Err(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "invalid_json",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let Some(relayer) = state.relayer.as_ref() else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "relayer_unavailable",
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )
        .await;
    };

    let Some(epoch_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.epoch_id).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(proposal_bytes) = parse_lowercase_fixed_hex::<32>(&request.proposal_id) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Some(nonce_bytes) =
        parse_lowercase_fixed_hex::<32>(&request.operation_nonce).filter(|bytes| *bytes != [0; 32])
    else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            None,
            None,
            "denied",
            "invalid_request",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let op_id = request.operation_nonce.as_str();
    let Ok(old_cid) = EnvelopeSetCid::parse(&request.old_envelope_set_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let Ok(new_cid) = EnvelopeSetCid::parse(&request.new_envelope_set_cid) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_cid",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    if old_cid == new_cid {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "unchanged_envelope_set",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    let Some(signature_bytes) = parse_fixed_hex::<65>(&request.signature) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "invalid_signature",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Some(now) = unix_seconds() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let Ok(deadline) = UnixDeadline::from_unix_seconds(request.deadline) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    if request.deadline <= now
        || request.deadline.saturating_sub(now) > MAX_WRITE_DEADLINE_HORIZON_SECONDS
    {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            None,
            "denied",
            "expired_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }

    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
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
        Ok(Some(member)) if member.active() => member,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "unauthorized",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let read_access = match state
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
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    if !read_access {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "unauthorized",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    }

    let current = match state
        .chain
        .current_envelope_set(
            &state.config.access_governance,
            file_id.as_bytes(),
            version_number,
            finalized.number,
        )
        .await
    {
        Ok(Some(current)) => current,
        Ok(None) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "envelope_unavailable",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    if current.cid != old_cid.to_string() || current.epoch_id != epoch_bytes {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "stale_head",
            StatusCode::CONFLICT,
            "stale_head",
        )
        .await;
    }
    let Some(expected_revision) = current.revision.checked_add(1) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "revision_overflow",
            StatusCode::CONFLICT,
            "conflict",
        )
        .await;
    };

    let Ok(typed_update) = EnvelopeSetUpdate::new(
        file_id,
        version,
        EpochId::from_bytes(epoch_bytes),
        old_cid.clone(),
        new_cid.clone(),
        member_id,
        ProposalId::from_bytes(proposal_bytes),
        OperationNonce::from_bytes(nonce_bytes),
        deadline,
    ) else {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "invalid_operation",
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    };
    let domain = Eip712Domain::access_governance(
        ChainId::from_u64(state.config.chain_id),
        state.config.access_governance,
    );
    let Ok(digest) = typed_update.digest(&domain) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    match recover_signer(digest.as_bytes(), &request.signature) {
        Ok(recovered) if recovered == member.signing_address => {}
        _ => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(op_id),
                Some(finalized.number),
                "denied",
                "invalid_signature",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    }

    if let Err(response) = verify_pin_quorum(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        version_number,
        op_id,
        finalized.number,
        StorageCid::EnvelopeSet(new_cid.clone()),
    )
    .await
    {
        return *response;
    }

    let mut reader = match state.blob_store.get_envelope_set(&new_cid).await {
        Ok(reader) => reader,
        Err(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version_number,
                Some(op_id),
                Some(finalized.number),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await;
        }
    };
    let mut envelope_bytes = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if envelope_bytes.len().saturating_add(read) > MAX_ENVELOPE_SET_BYTES {
                    return write_attempt_failure(
                        &state,
                        ACTION,
                        Some(&member_id_string),
                        &source_id,
                        &file_id,
                        version_number,
                        Some(op_id),
                        Some(finalized.number),
                        "denied",
                        "invalid_envelope_set",
                        StatusCode::BAD_REQUEST,
                        "invalid_envelope_set",
                    )
                    .await;
                }
                envelope_bytes.extend_from_slice(&buffer[..read]);
            }
            Err(_) => {
                return write_attempt_failure(
                    &state,
                    ACTION,
                    Some(&member_id_string),
                    &source_id,
                    &file_id,
                    version_number,
                    Some(op_id),
                    Some(finalized.number),
                    "storage_failed",
                    "storage_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                )
                .await;
            }
        }
    }
    let valid_envelope = KeyEnvelopeSet::parse_canonical(&envelope_bytes).is_ok_and(|set| {
        set.file_id() == file_id
            && set.version_number() == version
            && set.epoch_id() == EpochId::from_bytes(epoch_bytes)
            && set.revision() == expected_revision
    });
    if !valid_envelope {
        return write_attempt_failure(
            &state,
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id,
            version_number,
            Some(op_id),
            Some(finalized.number),
            "denied",
            "invalid_envelope_set",
            StatusCode::BAD_REQUEST,
            "invalid_envelope_set",
        )
        .await;
    }

    let call = EnvelopeSetUpdateCall {
        file_id: file_bytes,
        version_number,
        epoch_id: epoch_bytes,
        old_envelope_set_cid: old_cid.to_string(),
        new_envelope_set_cid: new_cid.to_string(),
        actor_member_id: *member_id.as_bytes(),
        proposal_id: proposal_bytes,
        operation_nonce: nonce_bytes,
        deadline: request.deadline,
    };
    let relay_result = relayer
        .relay_update_envelope_set(call, signature_bytes.to_vec())
        .await;
    finalize_relay_response(
        &state,
        ACTION,
        &member_id_string,
        &source_id,
        &file_id,
        version_number,
        op_id,
        StatusCode::OK,
        relay_result,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn verify_pin_quorum(
    state: &AppState,
    action: &'static str,
    member_id: &str,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    operation_id: &str,
    block_number: u64,
    cid: StorageCid,
) -> Result<(), Box<Response>> {
    match state
        .blob_store
        .ensure_replication(cid, state.config.min_pin_replicas)
        .await
    {
        Ok(receipt) if receipt.is_satisfied() => Ok(()),
        Ok(_) => Err(Box::new(
            write_attempt_failure(
                state,
                action,
                Some(member_id),
                source_id,
                file_id,
                version,
                Some(operation_id),
                Some(block_number),
                "denied",
                "replication_insufficient",
                StatusCode::SERVICE_UNAVAILABLE,
                "replication_insufficient",
            )
            .await,
        )),
        Err(_) => Err(Box::new(
            write_attempt_failure(
                state,
                action,
                Some(member_id),
                source_id,
                file_id,
                version,
                Some(operation_id),
                Some(block_number),
                "storage_failed",
                "replication_insufficient",
                StatusCode::SERVICE_UNAVAILABLE,
                "replication_insufficient",
            )
            .await,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_relay_response(
    state: &AppState,
    action: &'static str,
    member_id: &str,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    operation_id: &str,
    success_status: StatusCode,
    relay_result: Result<RelayOutcome, RelayError>,
) -> Response {
    match relay_result {
        Ok(RelayOutcome::Committed(receipt)) => {
            if state
                .store
                .record_write_attempt(
                    action,
                    Some(member_id),
                    source_id,
                    &file_id.to_string(),
                    version,
                    Some(operation_id),
                    state.config.chain_id,
                    Some(receipt.block_number),
                    "committed",
                    None,
                )
                .await
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
            }
            (
                success_status,
                Json(WriteCommitResponse {
                    file_id: file_id.to_string(),
                    version_number: version,
                    transaction_hash: encode_hex(&receipt.transaction_hash),
                    block_number: receipt.block_number,
                    block_hash: receipt.block_hash,
                    gas_used: receipt.gas_used,
                }),
            )
                .into_response()
        }
        Ok(RelayOutcome::Reverted(receipt)) => {
            if state
                .store
                .record_write_attempt(
                    action,
                    Some(member_id),
                    source_id,
                    &file_id.to_string(),
                    version,
                    Some(operation_id),
                    state.config.chain_id,
                    Some(receipt.block_number),
                    "reverted",
                    Some("contract_reverted"),
                )
                .await
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
            }
            (
                StatusCode::CONFLICT,
                Json(RelayErrorResponse {
                    error: "contract_reverted",
                    transaction_hash: encode_hex(&receipt.transaction_hash),
                }),
            )
                .into_response()
        }
        Err(RelayError::ConfirmationTimedOut { tx_hash }) => {
            if state
                .store
                .record_write_attempt(
                    action,
                    Some(member_id),
                    source_id,
                    &file_id.to_string(),
                    version,
                    Some(operation_id),
                    state.config.chain_id,
                    None,
                    "pending_timeout",
                    Some("confirmation_timed_out"),
                )
                .await
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
            }
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(RelayErrorResponse {
                    error: "confirmation_timed_out",
                    transaction_hash: encode_hex(&tx_hash),
                }),
            )
                .into_response()
        }
        Err(_) => {
            write_attempt_failure(
                state,
                action,
                Some(member_id),
                source_id,
                file_id,
                version,
                Some(operation_id),
                None,
                "failed",
                "relay_failed",
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_attempt_failure(
    state: &AppState,
    action: &'static str,
    member_id: Option<&str>,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    operation_id: Option<&str>,
    block_number: Option<u64>,
    outcome: &'static str,
    reason: &'static str,
    status: StatusCode,
    public_error: &'static str,
) -> Response {
    match state
        .store
        .record_write_attempt(
            action,
            member_id,
            source_id,
            &file_id.to_string(),
            version,
            operation_id,
            state.config.chain_id,
            block_number,
            outcome,
            Some(reason),
        )
        .await
    {
        Ok(()) => error(status, public_error),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

fn parse_lowercase_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value != value.to_ascii_lowercase() {
        return None;
    }
    parse_fixed_hex::<N>(value)
}

enum BearerError {
    Unauthenticated,
    Unavailable,
}

async fn authenticate_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<MemberId, BearerError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(parse_fixed_hex::<32>)
        .ok_or(BearerError::Unauthenticated)?;
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

#[allow(clippy::too_many_arguments)]
async fn envelope_attempt_failure(
    state: &AppState,
    member_id: Option<&str>,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    block_number: Option<u64>,
    outcome: &'static str,
    reason: &'static str,
    status: StatusCode,
) -> Response {
    match state
        .store
        .record_envelope_attempt(
            member_id,
            source_id,
            &file_id.to_string(),
            version,
            state.config.chain_id,
            block_number,
            outcome,
            Some(reason),
        )
        .await
    {
        Ok(()) => error(
            status,
            if status == StatusCode::UNAUTHORIZED {
                "unauthorized"
            } else {
                "service_unavailable"
            },
        ),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn content_attempt_failure(
    state: &AppState,
    member_id: Option<&str>,
    source_id: &str,
    file_id: &FileId,
    version: u64,
    block_number: Option<u64>,
    outcome: &'static str,
    reason: &'static str,
    status: StatusCode,
) -> Response {
    match state
        .store
        .record_content_attempt(
            member_id,
            source_id,
            &file_id.to_string(),
            version,
            state.config.chain_id,
            block_number,
            outcome,
            Some(reason),
        )
        .await
    {
        Ok(()) => error(
            status,
            if status == StatusCode::UNAUTHORIZED {
                "unauthorized"
            } else {
                "service_unavailable"
            },
        ),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

#[allow(clippy::too_many_arguments)]
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

async fn upload_content_blob(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const ACTION: &str = "blob.content_upload";
    let source_id = source_identifier(&peer.ip().to_string());
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(member)) if member.active() => {}
        Ok(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthorized",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    let package = match decode_content_package_frame(&body) {
        Ok(package) => package,
        Err(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "invalid_package",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
        }
    };
    let file_id = package.manifest().file_id();
    let version = package.manifest().version_number().get();

    let stored = match state
        .blob_store
        .put_content(package, state.config.min_pin_replicas)
        .await
    {
        Ok(stored) if stored.replication.is_satisfied() => stored,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version,
                None,
                Some(finalized.number),
                "denied",
                "replication_insufficient",
                StatusCode::SERVICE_UNAVAILABLE,
                "replication_insufficient",
            )
            .await;
        }
        Err(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version,
                None,
                Some(finalized.number),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await;
        }
    };
    if state
        .store
        .record_write_attempt(
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id.to_string(),
            version,
            None,
            state.config.chain_id,
            Some(finalized.number),
            "pinned",
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }
    (
        StatusCode::CREATED,
        Json(BlobUploadResponse {
            cid: stored.cid.to_string(),
            bytes_written: stored.bytes_written,
            required_replicas: stored.replication.required_replicas,
            pinned_peers: stored.replication.pinned_peers,
        }),
    )
        .into_response()
}

async fn upload_envelope_blob(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const ACTION: &str = "blob.envelope_upload";
    let source_id = source_identifier(&peer.ip().to_string());
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthenticated",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let finalized = match state.chain.finalized_block().await {
        Ok(block) => block,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    match state
        .chain
        .member_identity(
            &state.config.access_governance,
            member_id.as_bytes(),
            finalized.number,
        )
        .await
    {
        Ok(Some(member)) if member.active() => {}
        Ok(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "unauthorized",
                None,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    let parsed = match KeyEnvelopeSet::parse_canonical(&body) {
        Ok(set) => set,
        Err(_) => {
            return failure(
                &state,
                ACTION,
                &source_id,
                "invalid_envelope_set",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_envelope_set",
            )
            .await;
        }
    };
    let file_id = parsed.file_id();
    let version = parsed.version_number().get();
    let Ok(byte_length) = u64::try_from(body.len()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let reader = Box::pin(std::io::Cursor::new(body.to_vec())) as StorageReader;
    let stored = match state
        .blob_store
        .put_envelope_set(reader, byte_length, state.config.min_pin_replicas)
        .await
    {
        Ok(stored) if stored.replication.is_satisfied() => stored,
        Ok(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version,
                None,
                Some(finalized.number),
                "denied",
                "replication_insufficient",
                StatusCode::SERVICE_UNAVAILABLE,
                "replication_insufficient",
            )
            .await;
        }
        Err(_) => {
            return write_attempt_failure(
                &state,
                ACTION,
                Some(&member_id_string),
                &source_id,
                &file_id,
                version,
                None,
                Some(finalized.number),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )
            .await;
        }
    };
    if state
        .store
        .record_write_attempt(
            ACTION,
            Some(&member_id_string),
            &source_id,
            &file_id.to_string(),
            version,
            None,
            state.config.chain_id,
            Some(finalized.number),
            "pinned",
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }
    (
        StatusCode::CREATED,
        Json(BlobUploadResponse {
            cid: stored.cid.to_string(),
            bytes_written: stored.bytes_written,
            required_replicas: stored.replication.required_replicas,
            pinned_peers: stored.replication.pinned_peers,
        }),
    )
        .into_response()
}

fn rate_limit_action(method: &str, path: &str) -> Option<&'static str> {
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

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

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

async fn request_id_and_logging(
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

async fn enforce_rate_limit(
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
    if let Some(token) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(parse_fixed_hex::<32>)
    {
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
async fn invalid_signature_failure(
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

    #[test]
    fn public_identity_response_exposes_only_canonical_public_fields() {
        let response = PublicIdentityResponse {
            member_id: format!("0x{}", "11".repeat(32)),
            organization_id: format!("0x{}", "22".repeat(32)),
            signing_address: format!("0x{}", "33".repeat(20)),
            signing_key_version: 2,
            encryption_key_version: 4,
            encryption_public_key: format!("0x{}", "44".repeat(32)),
            status: "active",
            finalized_block: 17,
            finalized_block_hash: format!("0x{}", "55".repeat(32)),
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["memberId"], format!("0x{}", "11".repeat(32)));
        assert_eq!(value["status"], "active");
        assert_eq!(value["signingKeyVersion"], 2);
        assert_eq!(value["encryptionKeyVersion"], 4);
        assert_eq!(value["finalizedBlock"], 17);
        assert!(value.get("signing_address").is_none());
        assert!(value.get("privateKey").is_none());
    }

    #[test]
    fn rate_limit_covers_all_protected_and_public_api_routes() {
        assert_eq!(
            rate_limit_action("GET", "/v1/identities/0x11"),
            Some("identity.lookup")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/auth/challenge"),
            Some("auth.challenge")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/auth/session"),
            Some("auth.session")
        );
        assert_eq!(
            rate_limit_action("GET", "/v1/auth/session"),
            Some("auth.session")
        );
        assert_eq!(
            rate_limit_action("DELETE", "/v1/auth/session"),
            Some("auth.session")
        );
        assert_eq!(rate_limit_action("GET", "/v1/files"), Some("file.list"));
        assert_eq!(rate_limit_action("POST", "/v1/files"), Some("file.create"));
        assert_eq!(
            rate_limit_action("GET", "/v1/files/0x11/versions"),
            Some("file.history")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/files/0x11/versions"),
            Some("file.version_append")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/files/0x11/versions/1/access"),
            Some("file.access")
        );
        assert_eq!(
            rate_limit_action("GET", "/v1/files/0x11/versions/1/content"),
            Some("file.content")
        );
        assert_eq!(
            rate_limit_action("GET", "/v1/files/0x11/versions/1/envelope"),
            Some("file.envelope")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/files/0x11/versions/1/envelopes"),
            Some("file.envelope_update")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/blobs/content"),
            Some("blob.content_upload")
        );
        assert_eq!(
            rate_limit_action("POST", "/v1/blobs/envelopes"),
            Some("blob.envelope_upload")
        );
        assert_eq!(rate_limit_action("GET", "/v1/audit"), Some("audit.query"));
        assert_eq!(rate_limit_action("GET", "/healthz"), None);
    }

    mod http_tests {
        use std::{
            collections::{HashMap, HashSet},
            io::Cursor,
            net::{IpAddr, Ipv4Addr},
            sync::Mutex,
        };

        use chain_adapter::{
            EnvelopeSetState, EvmTransactionReceipt, FileHeadState, FileVersionState,
            FinalizedBlock, MemberIdentityState,
        };
        use crypto::{
            DataEncryptionKey, KeyEnvelope, KeyEnvelopeEntry, KeyEnvelopeSet,
            LoginChallengeDigestInput, WrapContext, raw_sha256_cid,
        };
        use domain::EvmAddress;
        use key_custody::DevelopmentKeyCustody;
        use ports::{
            BlobStore, ContentPackage, KeyCustodyProvider, ReplicationReceipt, StorageCid,
            StorageError, StorageFuture, StorageReader, StoredContent, StoredEnvelopeSet,
        };
        use serde_json::json;

        use super::*;
        use crate::{
            ports::{ChainFuture, RelayFuture, StoreFuture},
            store::{FileListingResult, VersionHistoryResult},
        };

        #[derive(Clone, Default)]
        struct MockChain {
            state: Arc<Mutex<MockChainState>>,
        }

        #[derive(Default)]
        struct MockChainState {
            block_number: u64,
            block_hash: String,
            members: HashMap<[u8; 32], MemberIdentityState>,
            read_acl: HashSet<([u8; 32], [u8; 32])>,
            write_acl: HashSet<([u8; 32], [u8; 32])>,
            historical_read: HashSet<([u8; 32], [u8; 32], u64)>,
            heads: HashMap<[u8; 32], FileHeadState>,
            versions: HashMap<([u8; 32], u64), FileVersionState>,
            envelopes: HashMap<([u8; 32], u64), EnvelopeSetState>,
        }

        impl GatewayChainPort for MockChain {
            fn finalized_block(&self) -> ChainFuture<'_, FinalizedBlock> {
                let state = self.state.lock().unwrap();
                let block = FinalizedBlock {
                    number: state.block_number,
                    hash: state.block_hash.clone(),
                };
                Box::pin(async move { Ok(block) })
            }

            fn active_member_signer<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                member_id: &'a [u8; 32],
            ) -> ChainFuture<'a, Option<EvmAddress>> {
                let signer = self
                    .state
                    .lock()
                    .unwrap()
                    .members
                    .get(member_id)
                    .filter(|member| member.active())
                    .map(|member| member.signing_address);
                Box::pin(async move { Ok(signer) })
            }

            fn member_identity<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                member_id: &'a [u8; 32],
                _block_number: u64,
            ) -> ChainFuture<'a, Option<MemberIdentityState>> {
                let identity = self.state.lock().unwrap().members.get(member_id).cloned();
                Box::pin(async move { Ok(identity) })
            }

            fn has_read_access<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                member_id: &'a [u8; 32],
                file_id: &'a [u8; 32],
                _block_number: u64,
            ) -> ChainFuture<'a, bool> {
                let state = self.state.lock().unwrap();
                let allowed = state
                    .members
                    .get(member_id)
                    .is_some_and(MemberIdentityState::active)
                    && state.read_acl.contains(&(*member_id, *file_id));
                Box::pin(async move { Ok(allowed) })
            }

            fn has_write_access<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                member_id: &'a [u8; 32],
                file_id: &'a [u8; 32],
                _block_number: u64,
            ) -> ChainFuture<'a, bool> {
                let state = self.state.lock().unwrap();
                let allowed = state
                    .members
                    .get(member_id)
                    .is_some_and(MemberIdentityState::active)
                    && state.write_acl.contains(&(*member_id, *file_id));
                Box::pin(async move { Ok(allowed) })
            }

            fn has_historical_read_access<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                member_id: &'a [u8; 32],
                file_id: &'a [u8; 32],
                version_number: u64,
                _block_number: u64,
            ) -> ChainFuture<'a, bool> {
                let state = self.state.lock().unwrap();
                let allowed = state
                    .members
                    .get(member_id)
                    .is_some_and(MemberIdentityState::active)
                    && state.read_acl.contains(&(*member_id, *file_id))
                    && state
                        .historical_read
                        .contains(&(*member_id, *file_id, version_number));
                Box::pin(async move { Ok(allowed) })
            }

            fn file_head_at<'a>(
                &'a self,
                _file_registry: &'a EvmAddress,
                file_id: &'a [u8; 32],
                _block_number: u64,
            ) -> ChainFuture<'a, Option<FileHeadState>> {
                let head = self.state.lock().unwrap().heads.get(file_id).cloned();
                Box::pin(async move { Ok(head) })
            }

            fn file_version<'a>(
                &'a self,
                _file_registry: &'a EvmAddress,
                file_id: &'a [u8; 32],
                version_number: u64,
                _block_number: u64,
            ) -> ChainFuture<'a, Option<FileVersionState>> {
                let version = self
                    .state
                    .lock()
                    .unwrap()
                    .versions
                    .get(&(*file_id, version_number))
                    .cloned();
                Box::pin(async move { Ok(version) })
            }

            fn current_envelope_set<'a>(
                &'a self,
                _access_governance: &'a EvmAddress,
                file_id: &'a [u8; 32],
                version_number: u64,
                _block_number: u64,
            ) -> ChainFuture<'a, Option<EnvelopeSetState>> {
                let envelope = self
                    .state
                    .lock()
                    .unwrap()
                    .envelopes
                    .get(&(*file_id, version_number))
                    .cloned();
                Box::pin(async move { Ok(envelope) })
            }
        }

        #[derive(Clone, Default)]
        struct MockStore {
            state: Arc<Mutex<MockStoreState>>,
        }

        #[derive(Default)]
        struct MockStoreState {
            challenges: HashMap<(String, String), (LoginChallenge, bool)>,
            sessions: HashMap<[u8; 32], String>,
            used_access_nonces: HashSet<(String, [u8; 32])>,
            audit_actions: Vec<(Option<String>, String, String, Option<String>)>,
            fail_audit: bool,
            rate_limit_remaining: Option<u32>,
            bucket_limits: HashMap<String, u32>,
            listing_folders: Vec<ProjectedFolder>,
            listing_files: Vec<ProjectedFile>,
            history_versions: Vec<ProjectedVersion>,
        }

        impl GatewayStorePort for MockStore {
            fn take_rate_limit_token<'a>(
                &'a self,
                key: &'a str,
                _capacity: f64,
                _refill_per_second: f64,
            ) -> StoreFuture<'a, bool> {
                let mut state = self.state.lock().unwrap();
                if let Some(remaining) = state.bucket_limits.get_mut(key) {
                    let allowed = if *remaining > 0 {
                        *remaining -= 1;
                        true
                    } else {
                        false
                    };
                    return Box::pin(async move { Ok(allowed) });
                }
                let allowed = match state.rate_limit_remaining.as_mut() {
                    Some(remaining) if *remaining > 0 => {
                        *remaining -= 1;
                        true
                    }
                    Some(_) => false,
                    None => true,
                };
                Box::pin(async move { Ok(allowed) })
            }

            fn create_challenge<'a>(
                &'a self,
                challenge: &'a LoginChallenge,
                _source_id: &'a str,
                _chain_id: u64,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.challenges.insert(
                    (challenge.member_id.clone(), challenge.nonce.clone()),
                    (challenge.clone(), false),
                );
                state.audit_actions.push((
                    None,
                    "auth.challenge".to_owned(),
                    "issued".to_owned(),
                    None,
                ));
                Box::pin(async { Ok(()) })
            }

            fn record_auth_failure<'a>(
                &'a self,
                action: &'static str,
                _source_id: &'a str,
                reason_code: &'static str,
                _operation_id: Option<&'a str>,
                _chain_id: u64,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    None,
                    action.to_owned(),
                    "denied".to_owned(),
                    Some(reason_code.to_owned()),
                ));
                Box::pin(async { Ok(()) })
            }

            fn record_session_validation<'a>(
                &'a self,
                member_id: Option<&'a str>,
                _source_id: &'a str,
                outcome: &'static str,
                reason_code: Option<&'static str>,
                _chain_id: u64,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    member_id.map(str::to_owned),
                    "auth.session.validate".to_owned(),
                    outcome.to_owned(),
                    reason_code.map(str::to_owned),
                ));
                Box::pin(async { Ok(()) })
            }

            fn complete_login<'a>(
                &'a self,
                challenge: &'a LoginChallenge,
                token_hash: &'a [u8; 32],
                _session_expires_at: u64,
                _source_id: &'a str,
                _chain_id: u64,
            ) -> StoreFuture<'a, bool> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                let key = (challenge.member_id.clone(), challenge.nonce.clone());
                let Some((stored, consumed)) = state.challenges.get_mut(&key) else {
                    return Box::pin(async { Ok(false) });
                };
                if *consumed || stored != challenge {
                    return Box::pin(async { Ok(false) });
                }
                *consumed = true;
                state
                    .sessions
                    .insert(*token_hash, challenge.member_id.clone());
                state.audit_actions.push((
                    Some(challenge.member_id.clone()),
                    "auth.session".to_owned(),
                    "issued".to_owned(),
                    None,
                ));
                Box::pin(async { Ok(true) })
            }

            fn record_access_attempt<'a>(
                &'a self,
                member_id: &'a str,
                _source_id: &'a str,
                _file_id: &'a str,
                _version: u64,
                nonce: &'a [u8; 32],
                _deadline: u64,
                _chain_id: u64,
                _block_number: u64,
                authorized: bool,
                reason_code: Option<&'static str>,
            ) -> StoreFuture<'a, bool> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                let inserted = state
                    .used_access_nonces
                    .insert((member_id.to_owned(), *nonce));
                let replayed = !inserted;
                let ok = authorized && !replayed;
                state.audit_actions.push((
                    Some(member_id.to_owned()),
                    "file.access_lookup".to_owned(),
                    if ok { "authorized" } else { "denied" }.to_owned(),
                    if replayed {
                        Some("replay_detected".to_owned())
                    } else {
                        reason_code.map(str::to_owned)
                    },
                ));
                Box::pin(async move { Ok(ok) })
            }

            fn record_content_attempt<'a>(
                &'a self,
                member_id: Option<&'a str>,
                _source_id: &'a str,
                _file_id: &'a str,
                _version: u64,
                _chain_id: u64,
                _block_number: Option<u64>,
                outcome: &'static str,
                reason_code: Option<&'static str>,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    member_id.map(str::to_owned),
                    "file.content_retrieval".to_owned(),
                    outcome.to_owned(),
                    reason_code.map(str::to_owned),
                ));
                Box::pin(async { Ok(()) })
            }

            fn record_envelope_attempt<'a>(
                &'a self,
                member_id: Option<&'a str>,
                _source_id: &'a str,
                _file_id: &'a str,
                _version: u64,
                _chain_id: u64,
                _block_number: Option<u64>,
                outcome: &'static str,
                reason_code: Option<&'static str>,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    member_id.map(str::to_owned),
                    "file.envelope_retrieval".to_owned(),
                    outcome.to_owned(),
                    reason_code.map(str::to_owned),
                ));
                Box::pin(async { Ok(()) })
            }

            fn record_write_attempt<'a>(
                &'a self,
                action: &'static str,
                member_id: Option<&'a str>,
                _source_id: &'a str,
                _file_id: &'a str,
                _version: u64,
                _operation_id: Option<&'a str>,
                _chain_id: u64,
                _block_number: Option<u64>,
                outcome: &'static str,
                reason_code: Option<&'static str>,
            ) -> StoreFuture<'a, ()> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    member_id.map(str::to_owned),
                    action.to_owned(),
                    outcome.to_owned(),
                    reason_code.map(str::to_owned),
                ));
                Box::pin(async { Ok(()) })
            }

            fn active_session_member<'a>(
                &'a self,
                token_hash: &'a [u8; 32],
            ) -> StoreFuture<'a, Option<String>> {
                let member = self.state.lock().unwrap().sessions.get(token_hash).cloned();
                Box::pin(async move { Ok(member) })
            }

            fn revoke_session<'a>(
                &'a self,
                token_hash: &'a [u8; 32],
                _source_id: &'a str,
                _chain_id: u64,
            ) -> StoreFuture<'a, bool> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                let removed = state.sessions.remove(token_hash);
                if let Some(member_id) = removed {
                    state.audit_actions.push((
                        Some(member_id),
                        "auth.session.revoke".to_owned(),
                        "revoked".to_owned(),
                        None,
                    ));
                    Box::pin(async { Ok(true) })
                } else {
                    Box::pin(async { Ok(false) })
                }
            }

            fn list_files_and_folders<'a>(
                &'a self,
                _chain_id: u64,
                _member_id: &'a str,
                _organization_id: &'a str,
                _parent_folder_id: &'a str,
            ) -> StoreFuture<'a, FileListingResult> {
                let state = self.state.lock().unwrap();
                let result = FileListingResult {
                    indexed_block: Some(42),
                    indexed_block_hash: Some(format!("0x{}", "ab".repeat(32))),
                    folders: state.listing_folders.clone(),
                    files: state.listing_files.clone(),
                };
                Box::pin(async move { Ok(result) })
            }

            fn list_file_versions<'a>(
                &'a self,
                _chain_id: u64,
                _file_id: &'a str,
                _member_id: &'a str,
            ) -> StoreFuture<'a, VersionHistoryResult> {
                let state = self.state.lock().unwrap();
                let result = VersionHistoryResult {
                    indexed_block: Some(42),
                    indexed_block_hash: Some(format!("0x{}", "ab".repeat(32))),
                    versions: state.history_versions.clone(),
                };
                Box::pin(async move { Ok(result) })
            }

            fn query_member_audit_events<'a>(
                &'a self,
                member_id: &'a str,
                _source_id: &'a str,
                _chain_id: u64,
                _block_number: u64,
                action_filter: Option<&'a str>,
                limit: u32,
            ) -> StoreFuture<'a, Vec<AuditEventRecord>> {
                let mut state = self.state.lock().unwrap();
                if state.fail_audit {
                    return Box::pin(async { Err(sqlx::Error::Protocol("audit failed".into())) });
                }
                state.audit_actions.push((
                    Some(member_id.to_owned()),
                    "audit.query".to_owned(),
                    "authorized".to_owned(),
                    None,
                ));
                let events = state
                    .audit_actions
                    .iter()
                    .enumerate()
                    .filter(|(_, (actor, action, _, _))| {
                        actor.as_deref() == Some(member_id)
                            && action_filter.is_none_or(|filter| filter == action)
                    })
                    .rev()
                    .take(limit as usize)
                    .map(
                        |(index, (actor, action, outcome, reason))| AuditEventRecord {
                            sequence: (index + 1) as i64,
                            record: json!({
                                "actor_member_id": actor,
                                "action": action,
                                "outcome": outcome,
                                "reason_code": reason,
                            }),
                            previous_hash: format!("0x{}", "00".repeat(32)),
                            record_hash: format!("0x{:064x}", index + 1),
                        },
                    )
                    .collect();
                Box::pin(async move { Ok(events) })
            }
        }

        #[derive(Clone, Default)]
        struct MockBlobStore {
            contents: Arc<Mutex<HashMap<String, Vec<u8>>>>,
            envelopes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
            replicas: Arc<Mutex<HashMap<String, Vec<String>>>>,
            events: Arc<Mutex<Vec<String>>>,
        }

        impl BlobStore for MockBlobStore {
            fn put_content<'a>(
                &'a self,
                package: ContentPackage,
                min_replicas: usize,
            ) -> StorageFuture<'a, StoredContent> {
                Box::pin(async move {
                    let (manifest, chunks) = package.into_parts();
                    let manifest_bytes = manifest
                        .canonical_bytes()
                        .map_err(|_| StorageError::InvalidPackage)?;
                    let mut total = manifest_bytes.len() as u64;
                    for chunk in chunks {
                        let mut data = Vec::new();
                        chunk
                            .into_reader()
                            .read_to_end(&mut data)
                            .await
                            .map_err(|_| StorageError::TransportUnavailable)?;
                        total += data.len() as u64;
                    }
                    let cid = raw_sha256_cid(&manifest_bytes)
                        .map_err(|_| StorageError::IntegrityCheckFailed)?;
                    let peers = vec!["peer-1".to_owned(), "peer-2".to_owned()];
                    if peers.len() < min_replicas {
                        return Err(StorageError::ReplicationInsufficient);
                    }
                    self.contents
                        .lock()
                        .unwrap()
                        .insert(cid.to_string(), manifest_bytes);
                    self.replicas
                        .lock()
                        .unwrap()
                        .insert(cid.to_string(), peers.clone());
                    Ok(StoredContent {
                        cid: cid.clone(),
                        bytes_written: total,
                        replication: ReplicationReceipt {
                            cid: StorageCid::Content(cid),
                            required_replicas: min_replicas,
                            pinned_peers: peers,
                        },
                    })
                })
            }

            fn put_envelope_set<'a>(
                &'a self,
                mut reader: StorageReader,
                byte_length: u64,
                min_replicas: usize,
            ) -> StorageFuture<'a, StoredEnvelopeSet> {
                Box::pin(async move {
                    let mut bytes = Vec::new();
                    reader
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| StorageError::TransportUnavailable)?;
                    if bytes.len() as u64 != byte_length {
                        return Err(StorageError::InvalidPackage);
                    }
                    let cid = EnvelopeSetCid::parse(
                        &raw_sha256_cid(&bytes)
                            .map_err(|_| StorageError::IntegrityCheckFailed)?
                            .to_string(),
                    )
                    .map_err(|_| StorageError::InvalidCid)?;
                    let peers = vec!["peer-1".to_owned(), "peer-2".to_owned()];
                    if peers.len() < min_replicas {
                        return Err(StorageError::ReplicationInsufficient);
                    }
                    self.envelopes
                        .lock()
                        .unwrap()
                        .insert(cid.to_string(), bytes);
                    self.replicas
                        .lock()
                        .unwrap()
                        .insert(cid.to_string(), peers.clone());
                    Ok(StoredEnvelopeSet {
                        cid: cid.clone(),
                        bytes_written: byte_length,
                        replication: ReplicationReceipt {
                            cid: StorageCid::EnvelopeSet(cid),
                            required_replicas: min_replicas,
                            pinned_peers: peers,
                        },
                    })
                })
            }

            fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader> {
                let payload = self.contents.lock().unwrap().get(&cid.to_string()).cloned();
                Box::pin(async move {
                    let bytes = payload.ok_or(StorageError::TransportUnavailable)?;
                    Ok(Box::pin(Cursor::new(bytes)) as StorageReader)
                })
            }

            fn get_envelope_set<'a>(
                &'a self,
                cid: &'a EnvelopeSetCid,
            ) -> StorageFuture<'a, StorageReader> {
                let payload = self
                    .envelopes
                    .lock()
                    .unwrap()
                    .get(&cid.to_string())
                    .cloned();
                Box::pin(async move {
                    let bytes = payload.ok_or(StorageError::TransportUnavailable)?;
                    Ok(Box::pin(Cursor::new(bytes)) as StorageReader)
                })
            }

            fn ensure_replication<'a>(
                &'a self,
                cid: StorageCid,
                min_replicas: usize,
            ) -> StorageFuture<'a, ReplicationReceipt> {
                let cid_string = match &cid {
                    StorageCid::Content(value) => value.to_string(),
                    StorageCid::EnvelopeSet(value) => value.to_string(),
                };
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("pin:{cid_string}"));
                let peers = self
                    .replicas
                    .lock()
                    .unwrap()
                    .get(&cid_string)
                    .cloned()
                    .unwrap_or_default();
                Box::pin(async move {
                    if peers.len() < min_replicas {
                        return Err(StorageError::ReplicationInsufficient);
                    }
                    Ok(ReplicationReceipt {
                        cid,
                        required_replicas: min_replicas,
                        pinned_peers: peers,
                    })
                })
            }

            fn verify_retrievable<'a>(&'a self, _cid: StorageCid) -> StorageFuture<'a, ()> {
                Box::pin(async { Ok(()) })
            }
        }

        #[derive(Clone)]
        enum MockRelayBehavior {
            Commit(u64),
            Revert(u64),
            Timeout([u8; 32]),
        }

        #[derive(Clone)]
        struct MockRelayer {
            behavior: Arc<Mutex<MockRelayBehavior>>,
            events: Arc<Mutex<Vec<String>>>,
            calls: Arc<Mutex<Vec<String>>>,
        }

        impl MockRelayer {
            fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
                Self {
                    behavior: Arc::new(Mutex::new(MockRelayBehavior::Commit(43))),
                    events,
                    calls: Arc::new(Mutex::new(Vec::new())),
                }
            }

            fn execute(&self, label: &str) -> Result<RelayOutcome, RelayError> {
                self.events.lock().unwrap().push(format!("relay:{label}"));
                self.calls.lock().unwrap().push(label.to_owned());
                match self.behavior.lock().unwrap().clone() {
                    MockRelayBehavior::Commit(block) => {
                        Ok(RelayOutcome::Committed(EvmTransactionReceipt {
                            transaction_hash: [0xaa; 32],
                            block_number: block,
                            block_hash: format!("0x{}", "bb".repeat(32)),
                            status: true,
                            gas_used: 120_000,
                        }))
                    }
                    MockRelayBehavior::Revert(block) => {
                        Ok(RelayOutcome::Reverted(EvmTransactionReceipt {
                            transaction_hash: [0xdd; 32],
                            block_number: block,
                            block_hash: format!("0x{}", "ee".repeat(32)),
                            status: false,
                            gas_used: 85_000,
                        }))
                    }
                    MockRelayBehavior::Timeout(tx_hash) => {
                        Err(RelayError::ConfirmationTimedOut { tx_hash })
                    }
                }
            }
        }

        impl GatewayRelayerPort for MockRelayer {
            fn relay_create_file(
                &self,
                _call: VersionAppendCall,
                _display_name: String,
                _parent_folder_id: [u8; 32],
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let result = self.execute("createFile");
                Box::pin(async move { result })
            }

            fn relay_append_version(
                &self,
                _call: VersionAppendCall,
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let result = self.execute("appendVersion");
                Box::pin(async move { result })
            }

            fn relay_update_envelope_set(
                &self,
                _call: EnvelopeSetUpdateCall,
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let result = self.execute("updateEnvelopeSet");
                Box::pin(async move { result })
            }
        }

        struct TestServer {
            base_url: String,
            chain: MockChain,
            store: MockStore,
            blobs: MockBlobStore,
            relayer: Option<MockRelayer>,
            config: Arc<GatewayConfig>,
            _handle: tokio::task::JoinHandle<()>,
        }

        async fn spawn_server_with_relayer(with_relayer: bool) -> TestServer {
            let chain = MockChain::default();
            {
                let mut state = chain.state.lock().unwrap();
                state.block_number = 42;
                state.block_hash = format!("0x{}", "ab".repeat(32));
            }
            let store = MockStore::default();
            let blobs = MockBlobStore::default();
            let config = GatewayConfig {
                database_url: "postgres://unused".to_owned(),
                besu_rpc_url: "http://127.0.0.1:8545".to_owned(),
                chain_id: 1337,
                access_governance: EvmAddress::from_bytes([0x22; 20]),
                file_registry: EvmAddress::from_bytes([0x11; 20]),
                audience: "rrds-local".to_owned(),
                bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                challenge_ttl_seconds: 120,
                session_ttl_seconds: 900,
                rate_limit_capacity: 100,
                rate_limit_refill_per_second: 10.0,
                member_rate_limit_capacity: 100,
                member_rate_limit_refill_per_second: 10.0,
                invalid_sig_limit_capacity: 5,
                invalid_sig_limit_refill_per_second: 0.1,
                min_pin_replicas: 2,
                default_tx_gas_limit: 2_000_000,
                max_blob_upload_bytes: 8 * 1024 * 1024,
            };
            let mut state = AppState::new(store.clone(), chain.clone(), blobs.clone(), config);
            let relayer = if with_relayer {
                let mock_relayer = MockRelayer::new(blobs.events.clone());
                state = state.with_relayer(mock_relayer.clone());
                Some(mock_relayer)
            } else {
                None
            };
            let config_ref = state.config.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router(state).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
            TestServer {
                base_url: format!("http://{address}"),
                chain,
                store,
                blobs,
                relayer,
                config: config_ref,
                _handle: handle,
            }
        }

        async fn spawn_server() -> TestServer {
            spawn_server_with_relayer(true).await
        }

        async fn login_member(
            client: &reqwest::Client,
            server: &TestServer,
            custody: &DevelopmentKeyCustody,
        ) -> (LoginChallenge, String, String) {
            let identity = custody.public_identity().await.unwrap();
            let challenge: LoginChallenge = client
                .post(format!("{}/v1/auth/challenge", server.base_url))
                .json(&json!({ "memberId": identity.member_id.to_string() }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let nonce = OperationNonce::from_bytes(parse_nonce(&challenge.nonce).unwrap());
            let input = LoginChallengeDigestInput::new(
                identity.member_id,
                nonce,
                challenge.issued_at,
                challenge.expires_at,
                challenge.audience.clone(),
                challenge.protocol_version,
            )
            .unwrap();
            let domain = Eip712Domain::gateway(
                ChainId::from_u64(server.config.chain_id),
                server.config.access_governance,
            );
            let digest = input.digest(&domain).unwrap();
            let sig = custody
                .sign_typed_digest(&identity.signing_key_id, &digest)
                .await
                .unwrap();
            let sig_hex = encode_hex(sig.as_bytes());
            let response = client
                .post(format!("{}/v1/auth/session", server.base_url))
                .json(&json!({ "challenge": challenge, "signature": sig_hex }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let body: serde_json::Value = response.json().await.unwrap();
            let token = body["token"].as_str().unwrap().to_owned();
            (challenge, sig_hex, token)
        }

        #[tokio::test]
        async fn gateway_end_to_end_auth_access_content_envelope_listing_history_and_audit() {
            let server = spawn_server().await;
            let client = reqwest::Client::new();
            let member_id = MemberId::from_bytes([0x11; 32]);
            let file_id = FileId::from_bytes([0x22; 32]);
            let epoch_v1 = EpochId::from_bytes([0x33; 32]);
            let epoch_v2 = EpochId::from_bytes([0x44; 32]);
            let custody = DevelopmentKeyCustody::generate(
                member_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(2).unwrap(),
            )
            .unwrap();
            let pub_identity = custody.public_identity().await.unwrap();
            let mut enc_key = [0u8; 32];
            enc_key.copy_from_slice(&pub_identity.encryption_public_key.to_bytes());

            let content_v2_bytes = b"CAR-ENCRYPTED-V2-PAYLOAD".to_vec();
            let content_v2_cid = raw_sha256_cid(&content_v2_bytes).unwrap().to_string();
            let content_v1_cid = raw_sha256_cid(b"CAR-V1").unwrap().to_string();

            let dek = DataEncryptionKey::generate().unwrap();
            let wrapped_v2 = KeyEnvelope::wrap(
                &dek,
                &pub_identity.encryption_public_key,
                WrapContext::new(
                    file_id,
                    VersionNumber::new(2).unwrap(),
                    epoch_v2,
                    member_id,
                    KeyVersion::new(2).unwrap(),
                ),
            )
            .unwrap();
            let envelope_v2_set = KeyEnvelopeSet::new(
                file_id,
                VersionNumber::new(2).unwrap(),
                epoch_v2,
                1,
                vec![KeyEnvelopeEntry::new(
                    member_id,
                    KeyVersion::new(2).unwrap(),
                    wrapped_v2,
                )],
            )
            .unwrap();
            let envelope_v2_bytes = envelope_v2_set.canonical_bytes().unwrap();
            let envelope_v2_cid = raw_sha256_cid(&envelope_v2_bytes).unwrap().to_string();
            let envelope_v1_cid = raw_sha256_cid(b"envelope-v1").unwrap().to_string();

            {
                let mut chain = server.chain.state.lock().unwrap();
                chain.members.insert(
                    *member_id.as_bytes(),
                    MemberIdentityState {
                        organization_id: [0x01; 32],
                        signing_address: pub_identity.signing_address,
                        signing_key_version: 1,
                        encryption_key_version: 2,
                        encryption_public_key: enc_key,
                        status: 1,
                    },
                );
                chain
                    .read_acl
                    .insert((*member_id.as_bytes(), *file_id.as_bytes()));
                chain.heads.insert(
                    *file_id.as_bytes(),
                    FileHeadState {
                        status: 1,
                        version_number: 2,
                        manifest_hash: format!("0x{}", "ee".repeat(32)),
                    },
                );
                chain.versions.insert(
                    (*file_id.as_bytes(), 1),
                    FileVersionState {
                        content_cid: content_v1_cid.clone(),
                    },
                );
                chain.versions.insert(
                    (*file_id.as_bytes(), 2),
                    FileVersionState {
                        content_cid: content_v2_cid.clone(),
                    },
                );
                chain.envelopes.insert(
                    (*file_id.as_bytes(), 1),
                    EnvelopeSetState {
                        cid: envelope_v1_cid,
                        epoch_id: *epoch_v1.as_bytes(),
                        revision: 1,
                    },
                );
                chain.envelopes.insert(
                    (*file_id.as_bytes(), 2),
                    EnvelopeSetState {
                        cid: envelope_v2_cid.clone(),
                        epoch_id: *epoch_v2.as_bytes(),
                        revision: 1,
                    },
                );
            }
            server
                .blobs
                .contents
                .lock()
                .unwrap()
                .insert(content_v2_cid.clone(), content_v2_bytes.clone());
            server
                .blobs
                .envelopes
                .lock()
                .unwrap()
                .insert(envelope_v2_cid.clone(), envelope_v2_bytes.clone());
            {
                let mut store = server.store.state.lock().unwrap();
                store.listing_files.push(ProjectedFile {
                    file_id: file_id.to_string(),
                    organization_id: encode_hex(&[0x01; 32]),
                    creator_member_id: member_id.to_string(),
                    display_name: "report.pdf".to_owned(),
                    parent_folder_id: encode_hex(&[0; 32]),
                    file_status: 1,
                    current_version: 2,
                    current_head_manifest_hash: format!("0x{}", "ee".repeat(32)),
                    updated_block_number: 42,
                });
                store.history_versions.push(ProjectedVersion {
                    version_number: 2,
                    manifest_hash: format!("0x{}", "ee".repeat(32)),
                    parent_manifest_hash: format!("0x{}", "dd".repeat(32)),
                    epoch_id: epoch_v2.to_string(),
                    author_member_id: member_id.to_string(),
                    author_signing_address: pub_identity.signing_address.to_string(),
                    content_cid: content_v2_cid.clone(),
                    current_envelope_set_cid: envelope_v2_cid.clone(),
                    envelope_revision: 1,
                    historical_read_granted: false,
                    transaction_hash: format!("0x{}", "cc".repeat(32)),
                    block_number: 42,
                });
            }

            // 1. Public identity lookup (200 active, 404 unregistered, 400 invalid).
            let id_resp = client
                .get(format!("{}/v1/identities/{member_id}", server.base_url))
                .send()
                .await
                .unwrap();
            assert_eq!(id_resp.status(), reqwest::StatusCode::OK);
            let id_json: serde_json::Value = id_resp.json().await.unwrap();
            assert_eq!(id_json["status"], "active");
            assert_eq!(id_json["finalizedBlock"], 42);

            assert_eq!(
                client
                    .get(format!(
                        "{}/v1/identities/0x{}",
                        server.base_url,
                        "99".repeat(32)
                    ))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NOT_FOUND
            );
            assert_eq!(
                client
                    .get(format!("{}/v1/identities/not-a-member", server.base_url))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::BAD_REQUEST
            );

            // 2. Challenge-response login + replay rejection.
            let (challenge, sig_hex, token) = login_member(&client, &server, &custody).await;
            let replay = client
                .post(format!("{}/v1/auth/session", server.base_url))
                .json(&json!({ "challenge": challenge, "signature": sig_hex }))
                .send()
                .await
                .unwrap();
            assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);

            let whoami: serde_json::Value = client
                .get(format!("{}/v1/auth/session", server.base_url))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(whoami["memberId"], member_id.to_string());

            // 3. Signed access lookup: head (v2) allowed, historical (v1) denied until granted,
            // and operation nonce replay rejected.
            let sign_lookup = |version: u64, nonce_byte: u8| {
                let custody_ref = &custody;
                let config_ref = &server.config;
                async move {
                    let deadline = unix_seconds().unwrap() + 60;
                    let nonce = OperationNonce::from_bytes([nonce_byte; 32]);
                    let lookup = AccessLookup::new(
                        member_id,
                        file_id,
                        VersionNumber::new(version).unwrap(),
                        KeyVersion::new(2).unwrap(),
                        nonce,
                        UnixDeadline::from_unix_seconds(deadline).unwrap(),
                    )
                    .unwrap();
                    let domain = Eip712Domain::access_governance(
                        ChainId::from_u64(config_ref.chain_id),
                        config_ref.access_governance,
                    );
                    let digest = lookup.digest(&domain).unwrap();
                    let sig = custody_ref
                        .sign_typed_digest(&pub_identity.signing_key_id, &digest)
                        .await
                        .unwrap();
                    json!({
                        "encryptionKeyVersion": 2,
                        "operationNonce": nonce.to_string(),
                        "deadline": deadline,
                        "signature": encode_hex(sig.as_bytes()),
                    })
                }
            };

            let v2_body = sign_lookup(2, 0x71).await;
            let lookup_v2 = client
                .post(format!(
                    "{}/v1/files/{file_id}/versions/2/access",
                    server.base_url
                ))
                .bearer_auth(&token)
                .json(&v2_body)
                .send()
                .await
                .unwrap();
            assert_eq!(lookup_v2.status(), reqwest::StatusCode::OK);
            let lookup_v2_json: serde_json::Value = lookup_v2.json().await.unwrap();
            assert_eq!(lookup_v2_json["contentCid"], content_v2_cid);
            assert_eq!(lookup_v2_json["envelopeSetCid"], envelope_v2_cid);

            // Replayed nonce rejected.
            assert_eq!(
                client
                    .post(format!(
                        "{}/v1/files/{file_id}/versions/2/access",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .json(&v2_body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );

            // Historical V1 denied without explicit grant, then allowed after grant.
            assert_eq!(
                client
                    .post(format!(
                        "{}/v1/files/{file_id}/versions/1/access",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .json(&sign_lookup(1, 0x72).await)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            server.chain.state.lock().unwrap().historical_read.insert((
                *member_id.as_bytes(),
                *file_id.as_bytes(),
                1,
            ));
            assert_eq!(
                client
                    .post(format!(
                        "{}/v1/files/{file_id}/versions/1/access",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .json(&sign_lookup(1, 0x73).await)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::OK
            );

            // 4. Content & canonical envelope retrieval (with Cache-Control: no-store).
            let content_resp = client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/2/content",
                    server.base_url
                ))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap();
            assert_eq!(content_resp.status(), reqwest::StatusCode::OK);
            assert_eq!(content_resp.headers()["cache-control"], "no-store");
            assert_eq!(content_resp.bytes().await.unwrap(), content_v2_bytes);

            let env_resp = client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/2/envelope",
                    server.base_url
                ))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap();
            assert_eq!(env_resp.status(), reqwest::StatusCode::OK);
            assert_eq!(env_resp.headers()["cache-control"], "no-store");
            assert_eq!(env_resp.bytes().await.unwrap(), envelope_v2_bytes);

            // 5. File listing, version history, and self-audited audit query.
            let list_json: serde_json::Value = client
                .get(format!("{}/v1/files", server.base_url))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(list_json["authoritative"], false);
            assert_eq!(list_json["files"][0]["displayName"], "report.pdf");

            let history_json: serde_json::Value = client
                .get(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(history_json["currentVersion"], 2);
            assert_eq!(history_json["versions"][0]["contentCid"], content_v2_cid);

            let audit_json: serde_json::Value = client
                .get(format!("{}/v1/audit?limit=20", server.base_url))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let audit_events = audit_json["events"].as_array().unwrap();
            assert!(
                audit_events
                    .iter()
                    .any(|event| event["record"]["action"] == "audit.query")
            );
            assert!(
                audit_events
                    .iter()
                    .any(|event| event["record"]["action"] == "file.envelope_retrieval")
            );

            // 6. Fail closed when audit persistence fails (503, no envelope or CIDs released).
            server.store.state.lock().unwrap().fail_audit = true;
            assert_eq!(
                client
                    .get(format!(
                        "{}/v1/files/{file_id}/versions/2/envelope",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                client
                    .post(format!(
                        "{}/v1/files/{file_id}/versions/2/access",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .json(&sign_lookup(2, 0x74).await)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE
            );

            // 7. Rate limit enforces 429 on /access when bucket is exhausted.
            {
                let mut store = server.store.state.lock().unwrap();
                store.fail_audit = false;
                store.rate_limit_remaining = Some(0);
            }
            assert_eq!(
                client
                    .post(format!(
                        "{}/v1/files/{file_id}/versions/2/access",
                        server.base_url
                    ))
                    .bearer_auth(&token)
                    .json(&sign_lookup(2, 0x75).await)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::TOO_MANY_REQUESTS
            );
        }

        #[tokio::test]
        async fn gateway_write_routes_enforce_signatures_pin_quorum_stale_head_and_relay_outcomes()
        {
            let server = spawn_server().await;
            let client = reqwest::Client::new();
            let relayer = server.relayer.as_ref().unwrap().clone();

            let member_id = MemberId::from_bytes([0x11; 32]);
            let file_id = FileId::from_bytes([0x22; 32]);
            let epoch_v1 = EpochId::from_bytes([0x33; 32]);
            let epoch_v2 = EpochId::from_bytes([0x44; 32]);
            let manifest_v1 = ManifestHash::from_bytes([0x55; 32]);
            let manifest_v2 = ManifestHash::from_bytes([0x66; 32]);
            let custody = DevelopmentKeyCustody::generate(
                member_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
            )
            .unwrap();
            let pub_identity = custody.public_identity().await.unwrap();
            let mut enc_key = [0u8; 32];
            enc_key.copy_from_slice(&pub_identity.encryption_public_key.to_bytes());
            {
                let mut chain = server.chain.state.lock().unwrap();
                chain.members.insert(
                    *member_id.as_bytes(),
                    MemberIdentityState {
                        organization_id: [0x01; 32],
                        signing_address: pub_identity.signing_address,
                        signing_key_version: 1,
                        encryption_key_version: 1,
                        encryption_public_key: enc_key,
                        status: 1,
                    },
                );
            }
            let (_, _, token) = login_member(&client, &server, &custody).await;

            let make_env_cid = |bytes: &[u8]| {
                EnvelopeSetCid::parse(&raw_sha256_cid(bytes).unwrap().to_string()).unwrap()
            };
            let content_v1_cid = raw_sha256_cid(b"encrypted-content-v1").unwrap();
            let envelope_v1_cid = make_env_cid(b"envelope-set-v1");
            let content_v2_cid = raw_sha256_cid(b"encrypted-content-v2").unwrap();
            let envelope_v2_cid = make_env_cid(b"envelope-set-v2");

            let sign_version_append = |version: u64,
                                       parent: ManifestHash,
                                       manifest: ManifestHash,
                                       content: ContentCid,
                                       envelope: EnvelopeSetCid,
                                       epoch: EpochId,
                                       nonce_byte: u8| {
                let custody_ref = &custody;
                let config_ref = &server.config;
                async move {
                    let deadline = unix_seconds().unwrap() + 120;
                    let nonce = OperationNonce::from_bytes([nonce_byte; 32]);
                    let typed = VersionAppend::new(
                        file_id,
                        VersionNumber::new(version).unwrap(),
                        parent,
                        manifest,
                        content,
                        envelope,
                        epoch,
                        member_id,
                        pub_identity.signing_address,
                        nonce,
                        UnixDeadline::from_unix_seconds(deadline).unwrap(),
                    )
                    .unwrap();
                    let domain = Eip712Domain::file_registry(
                        ChainId::from_u64(config_ref.chain_id),
                        config_ref.file_registry,
                    );
                    let digest = typed.digest(&domain).unwrap();
                    let sig = custody_ref
                        .sign_typed_digest(&pub_identity.signing_key_id, &digest)
                        .await
                        .unwrap();
                    (nonce, deadline, encode_hex(sig.as_bytes()))
                }
            };

            // 1. POST /v1/files fails with 503 BEFORE relay if pin quorum (<2) is not met.
            let (nonce1, deadline1, sig1) = sign_version_append(
                1,
                ManifestHash::from_bytes([0; 32]),
                manifest_v1,
                content_v1_cid.clone(),
                envelope_v1_cid.clone(),
                epoch_v1,
                0x81,
            )
            .await;
            let create_body = json!({
                "fileId": file_id.to_string(),
                "displayName": "quarterly.pdf",
                "parentFolderId": encode_hex(&[0; 32]),
                "versionNumber": 1,
                "parentManifestHash": encode_hex(&[0; 32]),
                "manifestHash": manifest_v1.to_string(),
                "contentCid": content_v1_cid.to_string(),
                "envelopeSetCid": envelope_v1_cid.to_string(),
                "epochId": epoch_v1.to_string(),
                "operationNonce": nonce1.to_string(),
                "deadline": deadline1,
                "signature": sig1,
            });
            server.blobs.replicas.lock().unwrap().insert(
                content_v1_cid.to_string(),
                vec!["peer-1".to_owned()], // only 1 replica < min 2
            );
            let unpinned = client
                .post(format!("{}/v1/files", server.base_url))
                .bearer_auth(&token)
                .json(&create_body)
                .send()
                .await
                .unwrap();
            assert_eq!(unpinned.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                relayer.calls.lock().unwrap().is_empty(),
                "relayer must not be called before pin quorum is satisfied"
            );

            // 2. Invalid EIP-712 signature rejected with 401 before relay.
            let mut bad_sig_body = create_body.clone();
            bad_sig_body["displayName"] = json!("tampered.pdf");
            bad_sig_body["signature"] = json!(format!("0x{}1b", "01".repeat(64)));
            assert_eq!(
                client
                    .post(format!("{}/v1/files", server.base_url))
                    .bearer_auth(&token)
                    .json(&bad_sig_body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert!(relayer.calls.lock().unwrap().is_empty());

            // 3. POST /v1/files succeeds (201) once BOTH CIDs satisfy 2-peer quorum; pin check precedes relay.
            {
                let mut replicas = server.blobs.replicas.lock().unwrap();
                replicas.insert(
                    content_v1_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
                replicas.insert(
                    envelope_v1_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
            }
            server.blobs.events.lock().unwrap().clear();
            let created = client
                .post(format!("{}/v1/files", server.base_url))
                .bearer_auth(&token)
                .json(&create_body)
                .send()
                .await
                .unwrap();
            assert_eq!(created.status(), reqwest::StatusCode::CREATED);
            let created_json: serde_json::Value = created.json().await.unwrap();
            assert_eq!(created_json["blockNumber"], 43);
            assert_eq!(created_json["versionNumber"], 1);
            let order = server.blobs.events.lock().unwrap().clone();
            assert_eq!(
                order,
                vec![
                    format!("pin:{content_v1_cid}"),
                    format!("pin:{envelope_v1_cid}"),
                    "relay:createFile".to_owned(),
                ]
            );

            // Advance mock chain head to v1.
            {
                let mut chain = server.chain.state.lock().unwrap();
                chain.heads.insert(
                    *file_id.as_bytes(),
                    FileHeadState {
                        status: 1,
                        version_number: 1,
                        manifest_hash: manifest_v1.to_string(),
                    },
                );
                chain
                    .read_acl
                    .insert((*member_id.as_bytes(), *file_id.as_bytes()));
                chain.envelopes.insert(
                    (*file_id.as_bytes(), 1),
                    EnvelopeSetState {
                        cid: envelope_v1_cid.to_string(),
                        epoch_id: *epoch_v1.as_bytes(),
                        revision: 1,
                    },
                );
            }

            // Duplicate createFile returns 409 conflict.
            assert_eq!(
                client
                    .post(format!("{}/v1/files", server.base_url))
                    .bearer_auth(&token)
                    .json(&create_body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::CONFLICT
            );

            // 4. POST /v1/files/{fileId}/versions rejects caller without Write ACL (401).
            let (nonce2, deadline2, sig2) = sign_version_append(
                2,
                manifest_v1,
                manifest_v2,
                content_v2_cid.clone(),
                envelope_v2_cid.clone(),
                epoch_v2,
                0x82,
            )
            .await;
            let append_body = json!({
                "versionNumber": 2,
                "parentManifestHash": manifest_v1.to_string(),
                "manifestHash": manifest_v2.to_string(),
                "contentCid": content_v2_cid.to_string(),
                "envelopeSetCid": envelope_v2_cid.to_string(),
                "epochId": epoch_v2.to_string(),
                "operationNonce": nonce2.to_string(),
                "deadline": deadline2,
                "signature": sig2,
            });
            assert_eq!(
                client
                    .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                    .bearer_auth(&token)
                    .json(&append_body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );

            // Grant Write ACL; stale parentManifestHash returns 409 stale_head.
            server
                .chain
                .state
                .lock()
                .unwrap()
                .write_acl
                .insert((*member_id.as_bytes(), *file_id.as_bytes()));
            let mut stale_body = append_body.clone();
            stale_body["parentManifestHash"] = json!(format!("0x{}", "99".repeat(32)));
            let stale_resp = client
                .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&token)
                .json(&stale_body)
                .send()
                .await
                .unwrap();
            assert_eq!(stale_resp.status(), reqwest::StatusCode::CONFLICT);
            assert_eq!(
                stale_resp.json::<serde_json::Value>().await.unwrap()["error"],
                "stale_head"
            );

            // Pin v2 objects and verify appendVersion commits (201), reverts (409), and times out (504).
            {
                let mut replicas = server.blobs.replicas.lock().unwrap();
                replicas.insert(
                    content_v2_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
                replicas.insert(
                    envelope_v2_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
            }
            let appended = client
                .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&token)
                .json(&append_body)
                .send()
                .await
                .unwrap();
            assert_eq!(appended.status(), reqwest::StatusCode::CREATED);

            *relayer.behavior.lock().unwrap() = MockRelayBehavior::Revert(44);
            let reverted = client
                .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&token)
                .json(&append_body)
                .send()
                .await
                .unwrap();
            assert_eq!(reverted.status(), reqwest::StatusCode::CONFLICT);
            let rev_json: serde_json::Value = reverted.json().await.unwrap();
            assert_eq!(rev_json["error"], "contract_reverted");
            assert_eq!(rev_json["transactionHash"], encode_hex(&[0xdd; 32]));

            *relayer.behavior.lock().unwrap() = MockRelayBehavior::Timeout([0xfe; 32]);
            let timed_out = client
                .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&token)
                .json(&append_body)
                .send()
                .await
                .unwrap();
            assert_eq!(timed_out.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
            let timeout_json: serde_json::Value = timed_out.json().await.unwrap();
            assert_eq!(timeout_json["error"], "confirmation_timed_out");
            assert_eq!(timeout_json["transactionHash"], encode_hex(&[0xfe; 32]));

            // 5. POST /v1/files/{fileId}/versions/{version}/envelopes validates canonical envelope set at revision+1.
            *relayer.behavior.lock().unwrap() = MockRelayBehavior::Commit(45);
            let dek = DataEncryptionKey::generate().unwrap();
            let wrapped = KeyEnvelope::wrap(
                &dek,
                &pub_identity.encryption_public_key,
                WrapContext::new(
                    file_id,
                    VersionNumber::ONE,
                    epoch_v1,
                    member_id,
                    KeyVersion::new(1).unwrap(),
                ),
            )
            .unwrap();
            let valid_rev2 = KeyEnvelopeSet::new(
                file_id,
                VersionNumber::ONE,
                epoch_v1,
                2,
                vec![KeyEnvelopeEntry::new(
                    member_id,
                    KeyVersion::new(1).unwrap(),
                    wrapped,
                )],
            )
            .unwrap()
            .canonical_bytes()
            .unwrap();
            let new_env_cid = make_env_cid(&valid_rev2);
            let bad_env_bytes = b"{\"not\":\"a-valid-envelope-set\"}".to_vec();
            let bad_env_cid = make_env_cid(&bad_env_bytes);
            {
                let mut replicas = server.blobs.replicas.lock().unwrap();
                replicas.insert(
                    new_env_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
                replicas.insert(
                    bad_env_cid.to_string(),
                    vec!["peer-1".to_owned(), "peer-2".to_owned()],
                );
            }
            {
                let mut envelopes = server.blobs.envelopes.lock().unwrap();
                envelopes.insert(new_env_cid.to_string(), valid_rev2);
                envelopes.insert(bad_env_cid.to_string(), bad_env_bytes);
            }

            let sign_env_update =
                |old_cid: EnvelopeSetCid, new_cid: EnvelopeSetCid, nonce_b: u8| {
                    let custody_ref = &custody;
                    let config_ref = &server.config;
                    async move {
                        let deadline = unix_seconds().unwrap() + 120;
                        let nonce = OperationNonce::from_bytes([nonce_b; 32]);
                        let typed = EnvelopeSetUpdate::new(
                            file_id,
                            VersionNumber::ONE,
                            epoch_v1,
                            old_cid.clone(),
                            new_cid.clone(),
                            member_id,
                            ProposalId::from_bytes([0; 32]),
                            nonce,
                            UnixDeadline::from_unix_seconds(deadline).unwrap(),
                        )
                        .unwrap();
                        let domain = Eip712Domain::access_governance(
                            ChainId::from_u64(config_ref.chain_id),
                            config_ref.access_governance,
                        );
                        let digest = typed.digest(&domain).unwrap();
                        let sig = custody_ref
                            .sign_typed_digest(&pub_identity.signing_key_id, &digest)
                            .await
                            .unwrap();
                        json!({
                            "epochId": epoch_v1.to_string(),
                            "oldEnvelopeSetCid": old_cid.to_string(),
                            "newEnvelopeSetCid": new_cid.to_string(),
                            "proposalId": encode_hex(&[0; 32]),
                            "operationNonce": nonce.to_string(),
                            "deadline": deadline,
                            "signature": encode_hex(sig.as_bytes()),
                        })
                    }
                };

            // Malformed envelope JSON rejected with 400 before relay.
            let calls_before_bad = relayer.calls.lock().unwrap().len();
            let bad_env_resp = client
                .post(format!(
                    "{}/v1/files/{file_id}/versions/1/envelopes",
                    server.base_url
                ))
                .bearer_auth(&token)
                .json(&sign_env_update(envelope_v1_cid.clone(), bad_env_cid, 0x83).await)
                .send()
                .await
                .unwrap();
            assert_eq!(bad_env_resp.status(), reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(relayer.calls.lock().unwrap().len(), calls_before_bad);

            // Stale oldEnvelopeSetCid rejected with 409 before relay.
            let stale_env_resp = client
                .post(format!(
                    "{}/v1/files/{file_id}/versions/1/envelopes",
                    server.base_url
                ))
                .bearer_auth(&token)
                .json(&sign_env_update(envelope_v2_cid, new_env_cid.clone(), 0x84).await)
                .send()
                .await
                .unwrap();
            assert_eq!(stale_env_resp.status(), reqwest::StatusCode::CONFLICT);
            assert_eq!(relayer.calls.lock().unwrap().len(), calls_before_bad);

            // Valid canonical revision-2 envelope set succeeds (200 OK).
            let updated_env = client
                .post(format!(
                    "{}/v1/files/{file_id}/versions/1/envelopes",
                    server.base_url
                ))
                .bearer_auth(&token)
                .json(&sign_env_update(envelope_v1_cid, new_env_cid, 0x85).await)
                .send()
                .await
                .unwrap();
            assert_eq!(updated_env.status(), reqwest::StatusCode::OK);
            let updated_json: serde_json::Value = updated_env.json().await.unwrap();
            assert_eq!(updated_json["blockNumber"], 45);

            // Verify write audit trail recorded committed, reverted, and pending_timeout outcomes.
            let audits = server.store.state.lock().unwrap().audit_actions.clone();
            assert!(
                audits
                    .iter()
                    .any(|(_, a, o, _)| a == "file.create" && o == "committed")
            );
            assert!(
                audits
                    .iter()
                    .any(|(_, a, o, _)| a == "file.version_append" && o == "reverted")
            );
            assert!(
                audits
                    .iter()
                    .any(|(_, a, o, _)| a == "file.version_append" && o == "pending_timeout")
            );
            assert!(
                audits
                    .iter()
                    .any(|(_, a, o, _)| a == "file.envelope_update" && o == "committed")
            );

            // 6. POST /v1/blobs/envelopes & POST /v1/blobs/content validate canonical encrypted objects before pinning.
            let bad_blob_resp = client
                .post(format!("{}/v1/blobs/content", server.base_url))
                .bearer_auth(&token)
                .body(b"plaintext-must-be-rejected".to_vec())
                .send()
                .await
                .unwrap();
            assert_eq!(bad_blob_resp.status(), reqwest::StatusCode::BAD_REQUEST);

            let valid_env_bytes = KeyEnvelopeSet::new(
                file_id,
                VersionNumber::ONE,
                epoch_v1,
                1,
                vec![KeyEnvelopeEntry::new(
                    member_id,
                    KeyVersion::new(1).unwrap(),
                    KeyEnvelope::wrap(
                        &dek,
                        &pub_identity.encryption_public_key,
                        WrapContext::new(
                            file_id,
                            VersionNumber::ONE,
                            epoch_v1,
                            member_id,
                            KeyVersion::new(1).unwrap(),
                        ),
                    )
                    .unwrap(),
                )],
            )
            .unwrap()
            .canonical_bytes()
            .unwrap();
            let env_blob_resp = client
                .post(format!("{}/v1/blobs/envelopes", server.base_url))
                .bearer_auth(&token)
                .body(valid_env_bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(env_blob_resp.status(), reqwest::StatusCode::CREATED);
            let env_blob_json: serde_json::Value = env_blob_resp.json().await.unwrap();
            assert_eq!(env_blob_json["pinnedPeers"].as_array().unwrap().len(), 2);

            // 7. Read-only gateway without a relayer returns 503 on write routes.
            let readonly = spawn_server_with_relayer(false).await;
            {
                let mut chain = readonly.chain.state.lock().unwrap();
                chain.members.insert(
                    *member_id.as_bytes(),
                    MemberIdentityState {
                        organization_id: [0x01; 32],
                        signing_address: pub_identity.signing_address,
                        signing_key_version: 1,
                        encryption_key_version: 1,
                        encryption_public_key: enc_key,
                        status: 1,
                    },
                );
            }
            let (_, _, ro_token) = login_member(&client, &readonly, &custody).await;
            assert_eq!(
                client
                    .post(format!("{}/v1/files", readonly.base_url))
                    .bearer_auth(&ro_token)
                    .json(&create_body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE
            );
        }

        #[tokio::test]
        async fn gateway_enforces_request_ids_session_revocation_and_multi_budget_rate_limits() {
            let server = spawn_server().await;
            let client = reqwest::Client::new();

            let alice_id = MemberId::from_bytes([0x11; 32]);
            let bob_id = MemberId::from_bytes([0x22; 32]);
            let alice_custody = DevelopmentKeyCustody::generate(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
            )
            .unwrap();
            let bob_custody = DevelopmentKeyCustody::generate(
                bob_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
            )
            .unwrap();
            let alice_pub = alice_custody.public_identity().await.unwrap();
            let bob_pub = bob_custody.public_identity().await.unwrap();
            {
                let mut chain = server.chain.state.lock().unwrap();
                for (member_id, pub_id) in [(alice_id, &alice_pub), (bob_id, &bob_pub)] {
                    let mut enc_key = [0u8; 32];
                    enc_key.copy_from_slice(&pub_id.encryption_public_key.to_bytes());
                    chain.members.insert(
                        *member_id.as_bytes(),
                        MemberIdentityState {
                            organization_id: [0x01; 32],
                            signing_address: pub_id.signing_address,
                            signing_key_version: 1,
                            encryption_key_version: 1,
                            encryption_public_key: enc_key,
                            status: 1,
                        },
                    );
                }
            }

            // 1. X-Request-Id echoed when valid, generated when missing or malformed.
            let health_auto = client
                .get(format!("{}/healthz", server.base_url))
                .send()
                .await
                .unwrap();
            assert_eq!(health_auto.status(), reqwest::StatusCode::OK);
            let generated_id = health_auto.headers()["x-request-id"].to_str().unwrap();
            assert!(generated_id.starts_with("0x") && generated_id.len() == 34);

            let health_echo = client
                .get(format!("{}/healthz", server.base_url))
                .header("x-request-id", "req_test-12345")
                .send()
                .await
                .unwrap();
            assert_eq!(health_echo.headers()["x-request-id"], "req_test-12345");

            let health_sanitized = client
                .get(format!("{}/healthz", server.base_url))
                .header("x-request-id", "bad id with spaces!")
                .send()
                .await
                .unwrap();
            assert_ne!(
                health_sanitized.headers()["x-request-id"],
                "bad id with spaces!"
            );

            // 2. Explicit session revocation (DELETE /v1/auth/session) invalidates bearer token.
            let (_, _, alice_token) = login_member(&client, &server, &alice_custody).await;
            let (_, _, bob_token) = login_member(&client, &server, &bob_custody).await;

            assert_eq!(
                client
                    .get(format!("{}/v1/auth/session", server.base_url))
                    .bearer_auth(&alice_token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::OK
            );
            assert_eq!(
                client
                    .delete(format!("{}/v1/auth/session", server.base_url))
                    .bearer_auth(&alice_token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NO_CONTENT
            );
            // Revoked session is immediately rejected on GET and repeat DELETE.
            assert_eq!(
                client
                    .get(format!("{}/v1/auth/session", server.base_url))
                    .bearer_auth(&alice_token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .delete(format!("{}/v1/auth/session", server.base_url))
                    .bearer_auth(&alice_token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );

            // 3. Multi-budget rate limiting: exhausting Bob's member bucket does not block Alice.
            let (_, _, alice_token_2) = login_member(&client, &server, &alice_custody).await;
            server
                .store
                .state
                .lock()
                .unwrap()
                .bucket_limits
                .insert(format!("member:file.list:{bob_id}"), 0);
            assert_eq!(
                client
                    .get(format!("{}/v1/files", server.base_url))
                    .bearer_auth(&bob_token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                client
                    .get(format!("{}/v1/files", server.base_url))
                    .bearer_auth(&alice_token_2)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::OK
            );

            // 4. Separate invalid-signature source budget throttles spoofed claims with 429
            // without touching the victim's member bucket.
            let source_id = source_identifier("127.0.0.1");
            server
                .store
                .state
                .lock()
                .unwrap()
                .bucket_limits
                .insert(format!("invalid_sig_src:{source_id}"), 1);
            let challenge: LoginChallenge = client
                .post(format!("{}/v1/auth/challenge", server.base_url))
                .json(&json!({ "memberId": alice_id.to_string() }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let bogus_sig = format!("0x{}1b", "02".repeat(64));
            assert_eq!(
                client
                    .post(format!("{}/v1/auth/session", server.base_url))
                    .json(&json!({ "challenge": challenge, "signature": bogus_sig }))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .post(format!("{}/v1/auth/session", server.base_url))
                    .json(&json!({ "challenge": challenge, "signature": bogus_sig }))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::TOO_MANY_REQUESTS
            );
            // Alice's authenticated file listing bucket remains completely unaffected.
            assert_eq!(
                client
                    .get(format!("{}/v1/files", server.base_url))
                    .bearer_auth(&alice_token_2)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::OK
            );
        }
    }
}
