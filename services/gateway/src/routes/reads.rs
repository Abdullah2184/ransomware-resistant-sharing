use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use crypto::{AccessLookup, ChainId, Eip712Domain, KeyEnvelopeSet, UnixDeadline};
use domain::{ContentCid, EnvelopeSetCid, EpochId, KeyVersion, OperationNonce, VersionNumber};
use ports::StorageReader;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::OwnedSemaphorePermit,
};
use tokio_util::io::ReaderStream;

struct PermittedReader {
    inner: StorageReader,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for PermittedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

use super::{
    ActiveMemberError, AppState, BearerError, DEFAULT_AUDIT_LIMIT, EnvelopeReadError,
    MAX_AUDIT_LIMIT, VersionReadAuthError, authenticate_active_member, authenticate_bearer,
    authorize_version_read, error, failure, parse_nonzero_file_id, read_bounded_envelope_set,
    unix_seconds,
};
use crate::{
    auth::{parse_nonce, recover_signer},
    store::{
        AuditEventRecord, ProjectedFile, ProjectedFolder, ProjectedVersion, encode_hex,
        source_identifier,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessLookupRequest {
    encryption_key_version: u32,
    operation_nonce: String,
    deadline: u64,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessLookupResponse {
    file_id: String,
    version_number: u64,
    manifest_hash: String,
    content_cid: String,
    envelope_set_cid: String,
    epoch_id: String,
    envelope_revision: u32,
    finalized_block: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileListQuery {
    folder_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditQuery {
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
    file_status: u64,
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

struct SignedAccessAudit<'a> {
    state: &'a AppState,
    member_id: String,
    source_id: &'a str,
    file_id: String,
    version: u64,
    nonce: &'a [u8; 32],
    deadline: u64,
}

impl SignedAccessAudit<'_> {
    async fn deny(&self, block_number: Option<u64>, reason: &'static str) -> Response {
        let result = self
            .state
            .store
            .record_access_attempt(
                &self.member_id,
                self.source_id,
                &self.file_id,
                self.version,
                self.nonce,
                self.deadline,
                self.state.config.chain_id,
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
}

enum RetrievalKind {
    Content,
    Envelope,
}

struct RetrievalAudit<'a> {
    state: &'a AppState,
    kind: RetrievalKind,
    member_id: Option<&'a str>,
    source_id: &'a str,
    file_id: String,
    version: u64,
}

impl RetrievalAudit<'_> {
    async fn fail(
        &self,
        block_number: Option<u64>,
        outcome: &'static str,
        reason: &'static str,
        status: StatusCode,
    ) -> Response {
        let recorded = match self.kind {
            RetrievalKind::Content => {
                self.state
                    .store
                    .record_content_attempt(
                        self.member_id,
                        self.source_id,
                        &self.file_id,
                        self.version,
                        self.state.config.chain_id,
                        block_number,
                        outcome,
                        Some(reason),
                    )
                    .await
            }
            RetrievalKind::Envelope => {
                self.state
                    .store
                    .record_envelope_attempt(
                        self.member_id,
                        self.source_id,
                        &self.file_id,
                        self.version,
                        self.state.config.chain_id,
                        block_number,
                        outcome,
                        Some(reason),
                    )
                    .await
            }
        };
        match recorded {
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

    async fn map_auth_error(&self, err: VersionReadAuthError) -> Response {
        match err {
            VersionReadAuthError::ChainUnavailable(block) => {
                self.fail(
                    block,
                    "denied",
                    "chain_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await
            }
            VersionReadAuthError::Unauthorized(block)
            | VersionReadAuthError::InvalidSignature(block) => {
                self.fail(
                    Some(block),
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                )
                .await
            }
        }
    }
}

pub(crate) async fn access_lookup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
    body: Result<Json<AccessLookupRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.access_lookup";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Ok(version) = VersionNumber::new(version_number) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Ok(Json(request)) = body else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_request",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
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
    let Ok(nonce) = parse_nonce(&request.operation_nonce) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_operation",
            None,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Some(now) = unix_seconds() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
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
                ACTION,
                &source_id,
                "expired_operation",
                Some(&request.operation_nonce),
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
        }
    };
    let Ok(key_version) = KeyVersion::new(request.encryption_key_version) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_operation",
            Some(&request.operation_nonce),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Ok(operation) = AccessLookup::new(
        member_id,
        file_id,
        version,
        key_version,
        OperationNonce::from_bytes(nonce),
        deadline,
    ) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_operation",
            Some(&request.operation_nonce),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let domain = Eip712Domain::access_governance(
        ChainId::from_u64(state.config.chain_id),
        state.config.access_governance,
    );
    let Ok(digest) = operation.digest(&domain) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_operation",
            Some(&request.operation_nonce),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };
    let Ok(signer) = recover_signer(digest.as_bytes(), &request.signature) else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "invalid_signature",
            Some(&request.operation_nonce),
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
        .await;
    };

    let audit = SignedAccessAudit {
        state: &state,
        member_id: member_id.to_string(),
        source_id: &source_id,
        file_id: file_id.to_string(),
        version: version_number,
        nonce: &nonce,
        deadline: request.deadline,
    };

    let auth = match authorize_version_read(
        &state,
        member_id,
        &file_id,
        version_number,
        Some((signer, key_version)),
    )
    .await
    {
        Ok(auth) => auth,
        Err(VersionReadAuthError::ChainUnavailable(block)) => {
            return audit.deny(block, "chain_unavailable").await;
        }
        Err(VersionReadAuthError::Unauthorized(block)) => {
            return audit.deny(Some(block), "unauthorized").await;
        }
        Err(VersionReadAuthError::InvalidSignature(block)) => {
            return audit.deny(Some(block), "invalid_signature").await;
        }
    };
    let block = auth.finalized.number;

    let content = match state
        .chain
        .file_version(
            &state.config.file_registry,
            file_id.as_bytes(),
            version_number,
            block,
        )
        .await
    {
        Ok(Some(content)) => content,
        Ok(None) => return audit.deny(Some(block), "version_unavailable").await,
        Err(_) => return audit.deny(Some(block), "chain_unavailable").await,
    };
    let envelope = match state
        .chain
        .current_envelope_set(
            &state.config.access_governance,
            file_id.as_bytes(),
            version_number,
            block,
        )
        .await
    {
        Ok(Some(envelope)) => envelope,
        Ok(None) => return audit.deny(Some(block), "envelope_unavailable").await,
        Err(_) => return audit.deny(Some(block), "chain_unavailable").await,
    };

    match state
        .store
        .record_access_attempt(
            &audit.member_id,
            &source_id,
            &audit.file_id,
            version_number,
            &nonce,
            request.deadline,
            state.config.chain_id,
            block,
            true,
            None,
        )
        .await
    {
        Ok(true) => Json(AccessLookupResponse {
            file_id: audit.file_id,
            version_number,
            manifest_hash: encode_hex(&content.manifest_hash),
            content_cid: content.content_cid,
            envelope_set_cid: envelope.cid,
            epoch_id: encode_hex(&envelope.epoch_id),
            envelope_revision: envelope.revision,
            finalized_block: block,
        })
        .into_response(),
        Ok(false) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn retrieve_version_content(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
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
    };
    let file_id_str = file_id.to_string();
    let unauth_audit = RetrievalAudit {
        state: &state,
        kind: RetrievalKind::Content,
        member_id: None,
        source_id: &source_id,
        file_id: file_id_str.clone(),
        version: version_number,
    };
    if VersionNumber::new(version_number).is_err() {
        return unauth_audit
            .fail(None, "denied", "invalid_request", StatusCode::UNAUTHORIZED)
            .await;
    }
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return unauth_audit
                .fail(None, "denied", "unauthenticated", StatusCode::UNAUTHORIZED)
                .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let audit = RetrievalAudit {
        state: &state,
        kind: RetrievalKind::Content,
        member_id: Some(&member_id_string),
        source_id: &source_id,
        file_id: file_id_str,
        version: version_number,
    };

    let auth = match authorize_version_read(&state, member_id, &file_id, version_number, None).await
    {
        Ok(auth) => auth,
        Err(err) => return audit.map_auth_error(err).await,
    };
    let block = auth.finalized.number;

    let content = match state
        .chain
        .file_version(
            &state.config.file_registry,
            file_id.as_bytes(),
            version_number,
            block,
        )
        .await
    {
        Ok(Some(content)) => content,
        Ok(None) => {
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                )
                .await;
        }
        Err(_) => {
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "chain_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
        }
    };
    let Ok(content_cid) = ContentCid::parse(&content.content_cid) else {
        return audit
            .fail(
                Some(block),
                "denied",
                "invalid_chain_reference",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
    };
    let Ok(stream_permit) = state.stream_semaphore.clone().try_acquire_owned() else {
        return audit
            .fail(
                Some(block),
                "denied",
                "stream_concurrency_limited",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .await;
    };
    let Ok(reader) = state.blob_store.get_content(&content_cid).await else {
        return audit
            .fail(
                Some(block),
                "storage_failed",
                "storage_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
    };
    if state
        .store
        .record_content_attempt(
            Some(&member_id_string),
            &source_id,
            &audit.file_id,
            version_number,
            state.config.chain_id,
            Some(block),
            "authorized",
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }

    let permitted_reader = PermittedReader {
        inner: reader,
        _permit: stream_permit,
    };
    let mut response = Response::new(Body::from_stream(ReaderStream::new(permitted_reader)));
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

pub(crate) async fn retrieve_version_envelope(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
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
    };
    let file_id_str = file_id.to_string();
    let unauth_audit = RetrievalAudit {
        state: &state,
        kind: RetrievalKind::Envelope,
        member_id: None,
        source_id: &source_id,
        file_id: file_id_str.clone(),
        version: version_number,
    };
    let Ok(version) = VersionNumber::new(version_number) else {
        return unauth_audit
            .fail(None, "denied", "invalid_request", StatusCode::UNAUTHORIZED)
            .await;
    };
    let member_id = match authenticate_bearer(&state, &headers).await {
        Ok(member_id) => member_id,
        Err(BearerError::Unauthenticated) => {
            return unauth_audit
                .fail(None, "denied", "unauthenticated", StatusCode::UNAUTHORIZED)
                .await;
        }
        Err(BearerError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };
    let member_id_string = member_id.to_string();
    let audit = RetrievalAudit {
        state: &state,
        kind: RetrievalKind::Envelope,
        member_id: Some(&member_id_string),
        source_id: &source_id,
        file_id: file_id_str,
        version: version_number,
    };

    let auth = match authorize_version_read(&state, member_id, &file_id, version_number, None).await
    {
        Ok(auth) => auth,
        Err(err) => return audit.map_auth_error(err).await,
    };
    let block = auth.finalized.number;

    let pointer = match state
        .chain
        .current_envelope_set(
            &state.config.access_governance,
            file_id.as_bytes(),
            version_number,
            block,
        )
        .await
    {
        Ok(Some(pointer)) => pointer,
        Ok(None) => {
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "envelope_unavailable",
                    StatusCode::UNAUTHORIZED,
                )
                .await;
        }
        Err(_) => {
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "chain_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
        }
    };
    let Ok(envelope_cid) = EnvelopeSetCid::parse(&pointer.cid) else {
        return audit
            .fail(
                Some(block),
                "denied",
                "invalid_chain_reference",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
    };
    let envelope_bytes = match read_bounded_envelope_set(&state, &envelope_cid).await {
        Ok(bytes) => bytes,
        Err(EnvelopeReadError::StorageUnavailable) => {
            return audit
                .fail(
                    Some(block),
                    "storage_failed",
                    "storage_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
        }
        Err(EnvelopeReadError::InvalidEnvelopeSet) => {
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "invalid_envelope_set",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
        }
    };

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
            return audit
                .fail(
                    Some(block),
                    "denied",
                    "invalid_envelope_set",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .await;
        }
    };
    let has_recipient_envelope = parsed.envelopes().iter().any(|entry| {
        entry.member_id() == member_id
            && entry.encryption_key_version().get() == auth.member.encryption_key_version
    });
    if !has_recipient_envelope {
        return audit
            .fail(
                Some(block),
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
            &audit.file_id,
            version_number,
            state.config.chain_id,
            Some(block),
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

pub(crate) async fn list_files(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<FileListQuery>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let folder_id = match query.folder_id {
        Some(raw) => match domain::hex::parse_lowercase_fixed_hex::<32>(&raw) {
            Some(_) => raw,
            None => {
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

    let ctx = match authenticate_active_member(&state, &headers).await {
        Ok(ctx) => ctx,
        Err(ActiveMemberError::Unauthenticated) => {
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
        Err(ActiveMemberError::Unauthorized) => {
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
        Err(ActiveMemberError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    let organization_id = encode_hex(&ctx.member.organization_id);
    match state
        .store
        .list_files_and_folders(
            state.config.chain_id,
            &ctx.member_id_string,
            &organization_id,
            &folder_id,
        )
        .await
    {
        Ok(listing) => Json(FileListResponse {
            folder_id,
            folders: listing.folders,
            files: listing.files,
            finalized_block: ctx.finalized.number,
            finalized_block_hash: ctx.finalized.hash,
            indexed_block: listing.indexed_block,
            indexed_block_hash: listing.indexed_block_hash,
            authoritative: false,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn file_version_history(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_file_id): Path<String>,
) -> Response {
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
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
    };

    let ctx = match authenticate_active_member(&state, &headers).await {
        Ok(ctx) => ctx,
        Err(ActiveMemberError::Unauthenticated) => {
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
        Err(ActiveMemberError::Unauthorized) => {
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
        Err(ActiveMemberError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    let Ok(read_access) = state
        .chain
        .has_read_access(
            &state.config.access_governance,
            ctx.member_id.as_bytes(),
            file_id.as_bytes(),
            ctx.finalized.number,
        )
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let Ok(head) = state
        .chain
        .file_head_at(
            &state.config.file_registry,
            file_id.as_bytes(),
            ctx.finalized.number,
        )
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    let Some(head) = head.filter(|head| matches!(head.status, 1 | 2)) else {
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
            &ctx.member_id_string,
        )
        .await
    {
        Ok(history) => Json(VersionHistoryResponse {
            file_id: file_id.to_string(),
            file_status: head.status,
            current_version: head.version_number,
            current_head_manifest_hash: head.manifest_hash,
            finalized_block: ctx.finalized.number,
            finalized_block_hash: ctx.finalized.hash,
            indexed_block: history.indexed_block,
            indexed_block_hash: history.indexed_block_hash,
            versions: history.versions,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn query_audit(
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

    let ctx = match authenticate_active_member(&state, &headers).await {
        Ok(ctx) => ctx,
        Err(ActiveMemberError::Unauthenticated) => {
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
        Err(ActiveMemberError::Unauthorized) => {
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
        Err(ActiveMemberError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    match state
        .store
        .query_member_audit_events(
            &ctx.member_id_string,
            &source_id,
            state.config.chain_id,
            ctx.finalized.number,
            query.action.as_deref(),
            limit,
        )
        .await
    {
        Ok(events) => Json(AuditQueryResponse {
            member_id: ctx.member_id_string,
            finalized_block: ctx.finalized.number,
            events,
        })
        .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}
