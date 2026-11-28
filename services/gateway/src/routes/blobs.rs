use std::net::SocketAddr;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use crypto::KeyEnvelopeSet;
use domain::MemberId;
use ports::{ReplicationReceipt, StorageError, StorageReader, decode_content_package_frame};
use serde::Serialize;

use super::{
    ActiveMemberError, AppState, authenticate_active_member, error, failure,
    writes::WriteAuditContext,
};
use crate::store::source_identifier;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BlobUploadResponse {
    cid: String,
    bytes_written: u64,
    required_replicas: usize,
    pinned_peers: Vec<String>,
}

enum BlobStagingMode {
    CreateOrAppend,
    EnvelopeRevisionUpdate,
}

/// Pre-authorizes file state and Write/Read ACL BEFORE staging/pinning ciphertext
/// in IPFS Cluster so unauthorized callers cannot pin orphaned blobs (§10.4.1).
async fn authorize_blob_staging(
    audit: &WriteAuditContext<'_>,
    member_id: MemberId,
    mode: BlobStagingMode,
) -> Result<(), Box<Response>> {
    let block = audit.block_number.unwrap_or_default();
    let Ok(head) = audit
        .state
        .chain
        .file_head_at(
            &audit.state.config.file_registry,
            audit.file_id.as_bytes(),
            block,
        )
        .await
    else {
        return Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )));
    };

    match mode {
        BlobStagingMode::CreateOrAppend if audit.version == 1 => {
            if head.is_some() {
                return Err(Box::new(
                    audit
                        .fail(
                            "denied",
                            "file_already_exists",
                            StatusCode::CONFLICT,
                            "conflict",
                        )
                        .await,
                ));
            }
            Ok(())
        }
        BlobStagingMode::CreateOrAppend => {
            let Some(head) = head.filter(|h| h.status == 1) else {
                return Err(Box::new(
                    audit
                        .fail(
                            "denied",
                            "unauthorized",
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                        )
                        .await,
                ));
            };
            if head.version_number.checked_add(1) != Some(audit.version) {
                return Err(Box::new(
                    audit
                        .fail("denied", "stale_head", StatusCode::CONFLICT, "stale_head")
                        .await,
                ));
            }
            match audit
                .state
                .chain
                .has_write_access(
                    &audit.state.config.access_governance,
                    member_id.as_bytes(),
                    audit.file_id.as_bytes(),
                    block,
                )
                .await
            {
                Ok(true) => Ok(()),
                Ok(false) => Err(Box::new(
                    audit
                        .fail(
                            "denied",
                            "unauthorized",
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                        )
                        .await,
                )),
                Err(_) => Err(Box::new(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                ))),
            }
        }
        BlobStagingMode::EnvelopeRevisionUpdate => {
            let Some(_head) = head.filter(|h| h.status == 1 && audit.version <= h.version_number)
            else {
                return Err(Box::new(
                    audit
                        .fail(
                            "denied",
                            "unauthorized",
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                        )
                        .await,
                ));
            };
            match audit
                .state
                .chain
                .has_read_access(
                    &audit.state.config.access_governance,
                    member_id.as_bytes(),
                    audit.file_id.as_bytes(),
                    block,
                )
                .await
            {
                Ok(true) => Ok(()),
                Ok(false) => Err(Box::new(
                    audit
                        .fail(
                            "denied",
                            "unauthorized",
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                        )
                        .await,
                )),
                Err(_) => Err(Box::new(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                ))),
            }
        }
    }
}

async fn finalize_blob_upload(
    audit: &WriteAuditContext<'_>,
    result: Result<(String, u64, ReplicationReceipt), StorageError>,
) -> Response {
    let (cid, bytes_written, replication) = match result {
        Ok((cid, bytes_written, replication)) if replication.is_satisfied() => {
            (cid, bytes_written, replication)
        }
        Ok(_) | Err(StorageError::ReplicationInsufficient) => {
            return audit
                .fail(
                    "denied",
                    "replication_insufficient",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "replication_insufficient",
                )
                .await;
        }
        Err(_) => {
            return audit
                .fail(
                    "storage_failed",
                    "storage_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                )
                .await;
        }
    };
    if audit
        .state
        .store
        .record_write_attempt(
            audit.action,
            Some(audit.member_id),
            audit.source_id,
            &audit.file_id.to_string(),
            audit.version,
            None,
            audit.state.config.chain_id,
            audit.block_number,
            "pinned",
            None,
            None,
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    }
    let blob_kind = if audit.action == "blob.content_upload" {
        "content"
    } else {
        "envelope"
    };
    let _ = audit
        .state
        .store
        .record_orphan_blob_candidate(
            &cid,
            blob_kind,
            audit.member_id,
            Some(&audit.file_id.to_string()),
            Some(audit.version),
            None,
            "staged_uncommitted",
        )
        .await;
    (
        StatusCode::CREATED,
        Json(BlobUploadResponse {
            cid,
            bytes_written,
            required_replicas: replication.required_replicas,
            pinned_peers: replication.pinned_peers,
        }),
    )
        .into_response()
}

pub(crate) async fn upload_content_blob(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const ACTION: &str = "blob.content_upload";
    let source_id = source_identifier(&peer.ip().to_string());
    let ctx = match authenticate_active_member(&state, &headers).await {
        Ok(ctx) => ctx,
        Err(ActiveMemberError::Unauthenticated) => {
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
        Err(ActiveMemberError::Unauthorized) => {
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
        Err(ActiveMemberError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    let Ok(package) = decode_content_package_frame(&body) else {
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
    };
    let audit = WriteAuditContext {
        state: &state,
        action: ACTION,
        member_id: &ctx.member_id_string,
        source_id: &source_id,
        file_id: package.manifest().file_id(),
        version: package.manifest().version_number().get(),
        operation_id: None,
        block_number: Some(ctx.finalized.number),
        restored_from_version: None,
    };
    if let Err(response) =
        authorize_blob_staging(&audit, ctx.member_id, BlobStagingMode::CreateOrAppend).await
    {
        return *response;
    }

    let Ok(_stream_permit) = state.stream_semaphore.clone().try_acquire_owned() else {
        return audit
            .fail(
                "denied",
                "stream_concurrency_limited",
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            )
            .await;
    };

    let stored = state
        .blob_store
        .put_content(package, state.config.min_pin_replicas)
        .await
        .map(|stored| {
            (
                stored.cid.to_string(),
                stored.bytes_written,
                stored.replication,
            )
        });
    finalize_blob_upload(&audit, stored).await
}

pub(crate) async fn upload_envelope_blob(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const ACTION: &str = "blob.envelope_upload";
    let source_id = source_identifier(&peer.ip().to_string());
    let ctx = match authenticate_active_member(&state, &headers).await {
        Ok(ctx) => ctx,
        Err(ActiveMemberError::Unauthenticated) => {
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
        Err(ActiveMemberError::Unauthorized) => {
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
        Err(ActiveMemberError::Unavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
    };

    let Ok(parsed) = KeyEnvelopeSet::parse_canonical(&body) else {
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
    };
    let audit = WriteAuditContext {
        state: &state,
        action: ACTION,
        member_id: &ctx.member_id_string,
        source_id: &source_id,
        file_id: parsed.file_id(),
        version: parsed.version_number().get(),
        operation_id: None,
        block_number: Some(ctx.finalized.number),
        restored_from_version: None,
    };
    let mode = if parsed.revision() == 1 {
        BlobStagingMode::CreateOrAppend
    } else {
        BlobStagingMode::EnvelopeRevisionUpdate
    };
    if let Err(response) = authorize_blob_staging(&audit, ctx.member_id, mode).await {
        return *response;
    }

    let Ok(_stream_permit) = state.stream_semaphore.clone().try_acquire_owned() else {
        return audit
            .fail(
                "denied",
                "stream_concurrency_limited",
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
            )
            .await;
    };

    let Ok(byte_length) = u64::try_from(body.len()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let reader = Box::pin(std::io::Cursor::new(body.to_vec())) as StorageReader;
    let stored = state
        .blob_store
        .put_envelope_set(reader, byte_length, state.config.min_pin_replicas)
        .await
        .map(|stored| {
            (
                stored.cid.to_string(),
                stored.bytes_written,
                stored.replication,
            )
        });
    finalize_blob_upload(&audit, stored).await
}
