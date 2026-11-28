use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chain_adapter::{EnvelopeSetUpdateCall, RelayError, RelayOutcome, VersionAppendCall};
use crypto::{
    ChainId, Eip712Domain, EnvelopeSetUpdate, KeyEnvelopeSet, UnixDeadline, VersionAppend,
};
use domain::{
    ContentCid, EnvelopeSetCid, EpochId, FileId, ManifestHash, OperationNonce, ProposalId,
    VersionNumber,
};
use ports::StorageCid;
use serde::{Deserialize, Serialize};

use super::{
    AppState, BearerError, EnvelopeReadError, MAX_DISPLAY_NAME_BYTES, WriteDeadlineError,
    authenticate_bearer, error, failure, parse_nonzero_file_id, read_bounded_envelope_set,
    verify_write_deadline,
};
use crate::{
    auth::{parse_fixed_hex, recover_signer},
    store::{RelayedTransactionRecord, encode_hex, source_identifier},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateFileRequest {
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
pub(crate) struct AppendVersionRequest {
    version_number: u64,
    parent_manifest_hash: String,
    manifest_hash: String,
    content_cid: String,
    envelope_set_cid: String,
    epoch_id: String,
    operation_nonce: String,
    deadline: u64,
    signature: String,
    #[serde(default)]
    restored_from_version: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateEnvelopeSetRequest {
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

/// Shared audit and storage-verification context for write and blob-staging routes.
pub(crate) struct WriteAuditContext<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) action: &'static str,
    pub(crate) member_id: &'a str,
    pub(crate) source_id: &'a str,
    pub(crate) file_id: FileId,
    pub(crate) version: u64,
    pub(crate) operation_id: Option<&'a str>,
    pub(crate) block_number: Option<u64>,
    pub(crate) restored_from_version: Option<u64>,
}

impl WriteAuditContext<'_> {
    pub(crate) async fn fail(
        &self,
        outcome: &'static str,
        reason: &'static str,
        status: StatusCode,
        public_error: &'static str,
    ) -> Response {
        match self
            .state
            .store
            .record_write_attempt(
                self.action,
                Some(self.member_id),
                self.source_id,
                &self.file_id.to_string(),
                self.version,
                self.operation_id,
                self.state.config.chain_id,
                self.block_number,
                outcome,
                Some(reason),
                self.restored_from_version,
            )
            .await
        {
            Ok(()) => error(status, public_error),
            Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        }
    }

    async fn verify_pin_quorum(&self, cid: StorageCid) -> Result<(), Box<Response>> {
        match self
            .state
            .blob_store
            .ensure_replication(cid, self.state.config.min_pin_replicas)
            .await
        {
            Ok(receipt) if receipt.is_satisfied() => Ok(()),
            Ok(_) => Err(Box::new(
                self.fail(
                    "denied",
                    "replication_insufficient",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "replication_insufficient",
                )
                .await,
            )),
            Err(_) => Err(Box::new(
                self.fail(
                    "storage_failed",
                    "replication_insufficient",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "replication_insufficient",
                )
                .await,
            )),
        }
    }

    async fn verify_staged_envelope_set(
        &self,
        version: VersionNumber,
        expected_epoch_id: EpochId,
        expected_revision: u32,
        envelope_cid: &EnvelopeSetCid,
    ) -> Result<(), Box<Response>> {
        let envelope_bytes = match read_bounded_envelope_set(self.state, envelope_cid).await {
            Ok(bytes) => bytes,
            Err(EnvelopeReadError::StorageUnavailable) => {
                return Err(Box::new(
                    self.fail(
                        "storage_failed",
                        "storage_unavailable",
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                    )
                    .await,
                ));
            }
            Err(EnvelopeReadError::InvalidEnvelopeSet) => {
                return Err(Box::new(
                    self.fail(
                        "denied",
                        "invalid_envelope_set",
                        StatusCode::BAD_REQUEST,
                        "invalid_envelope_set",
                    )
                    .await,
                ));
            }
        };
        let valid = KeyEnvelopeSet::parse_canonical(&envelope_bytes).is_ok_and(|set| {
            set.file_id() == self.file_id
                && set.version_number() == version
                && set.epoch_id() == expected_epoch_id
                && set.revision() == expected_revision
        });
        if !valid {
            return Err(Box::new(
                self.fail(
                    "denied",
                    "invalid_envelope_set",
                    StatusCode::BAD_REQUEST,
                    "invalid_envelope_set",
                )
                .await,
            ));
        }
        Ok(())
    }

    async fn record_orphans(
        &self,
        content_cid: Option<&str>,
        envelope_set_cid: &str,
        tx_hash: Option<&str>,
        reason: &str,
    ) {
        let file_id_str = self.file_id.to_string();
        if let Some(cid) = content_cid {
            let _ = self
                .state
                .store
                .record_orphan_blob_candidate(
                    cid,
                    "content",
                    self.member_id,
                    Some(&file_id_str),
                    Some(self.version),
                    tx_hash,
                    reason,
                )
                .await;
        }
        let _ = self
            .state
            .store
            .record_orphan_blob_candidate(
                envelope_set_cid,
                "envelope",
                self.member_id,
                Some(&file_id_str),
                Some(self.version),
                tx_hash,
                reason,
            )
            .await;
    }

    async fn mark_blobs_referenced(&self, content_cid: Option<&str>, envelope_set_cid: &str) {
        if let Some(cid) = content_cid {
            let _ = self.state.store.mark_blob_referenced(cid).await;
        }
        let _ = self
            .state
            .store
            .mark_blob_referenced(envelope_set_cid)
            .await;
    }

    async fn persist_pending_and_confirm(
        &self,
        relayer: &dyn crate::ports::GatewayRelayerPort,
        success_status: StatusCode,
        content_cid: Option<&str>,
        envelope_set_cid: &str,
        submit_result: Result<[u8; 32], RelayError>,
    ) -> Response {
        let tx_hash = match submit_result {
            Ok(tx_hash) => tx_hash,
            Err(_) => {
                self.record_orphans(content_cid, envelope_set_cid, None, "relay_failed")
                    .await;
                return self
                    .fail(
                        "failed",
                        "relay_failed",
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                    )
                    .await;
            }
        };

        let file_id_str = self.file_id.to_string();
        let operation_id = self.operation_id.unwrap_or_default().to_owned();
        let tx_hash_hex = encode_hex(&tx_hash);

        // Durably persist `pending` metadata IMMEDIATELY after broadcast and BEFORE
        // polling for confirmation so a crash/restart mid-confirmation never loses
        // transaction reconciliation metadata (§10.4.7).
        if self
            .state
            .store
            .record_relayed_transaction(&RelayedTransactionRecord {
                tx_hash: tx_hash_hex.clone(),
                operation_kind: self.action.to_owned(),
                operation_id,
                actor_member_id: self.member_id.to_owned(),
                file_id: file_id_str.clone(),
                version_number: self.version,
                content_cid: content_cid.map(str::to_owned),
                envelope_set_cid: envelope_set_cid.to_owned(),
                chain_id: self.state.config.chain_id,
                status: "pending".to_owned(),
                block_number: None,
                block_hash: None,
                gas_used: None,
            })
            .await
            .is_err()
        {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }

        match relayer.wait_for_confirmation(tx_hash).await {
            Ok(RelayOutcome::Committed(receipt)) => {
                let confirmed_hash = encode_hex(&receipt.transaction_hash);
                if self
                    .state
                    .store
                    .update_relayed_transaction_status(
                        &confirmed_hash,
                        "confirmed",
                        Some(receipt.block_number),
                        Some(&receipt.block_hash),
                        Some(receipt.gas_used),
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                self.mark_blobs_referenced(content_cid, envelope_set_cid)
                    .await;
                if self
                    .state
                    .store
                    .record_write_attempt(
                        self.action,
                        Some(self.member_id),
                        self.source_id,
                        &file_id_str,
                        self.version,
                        self.operation_id,
                        self.state.config.chain_id,
                        Some(receipt.block_number),
                        "committed",
                        None,
                        self.restored_from_version,
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                (
                    success_status,
                    Json(WriteCommitResponse {
                        file_id: file_id_str,
                        version_number: self.version,
                        transaction_hash: confirmed_hash,
                        block_number: receipt.block_number,
                        block_hash: receipt.block_hash,
                        gas_used: receipt.gas_used,
                    }),
                )
                    .into_response()
            }
            Ok(RelayOutcome::Reverted(receipt)) => {
                let reverted_hash = encode_hex(&receipt.transaction_hash);
                if self
                    .state
                    .store
                    .update_relayed_transaction_status(
                        &reverted_hash,
                        "reverted",
                        Some(receipt.block_number),
                        Some(&receipt.block_hash),
                        Some(receipt.gas_used),
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                self.record_orphans(
                    content_cid,
                    envelope_set_cid,
                    Some(&reverted_hash),
                    "contract_reverted",
                )
                .await;
                if self
                    .state
                    .store
                    .record_write_attempt(
                        self.action,
                        Some(self.member_id),
                        self.source_id,
                        &file_id_str,
                        self.version,
                        self.operation_id,
                        self.state.config.chain_id,
                        Some(receipt.block_number),
                        "reverted",
                        Some("contract_reverted"),
                        self.restored_from_version,
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
                        transaction_hash: reverted_hash,
                    }),
                )
                    .into_response()
            }
            Err(RelayError::ConfirmationTimedOut { .. }) => {
                if self
                    .state
                    .store
                    .record_write_attempt(
                        self.action,
                        Some(self.member_id),
                        self.source_id,
                        &file_id_str,
                        self.version,
                        self.operation_id,
                        self.state.config.chain_id,
                        None,
                        "pending_timeout",
                        Some("confirmation_timed_out"),
                        self.restored_from_version,
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
                        transaction_hash: tx_hash_hex,
                    }),
                )
                    .into_response()
            }
            Err(_) => {
                // Transaction was already broadcast and persisted as `pending`; do NOT
                // falsely mark blobs as orphaned while confirmation is uncertain.
                self.fail(
                    "pending_uncertain",
                    "confirmation_unavailable",
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                )
                .await
            }
        }
    }
}

struct ParsedAppendFields {
    parent_manifest_bytes: [u8; 32],
    manifest_bytes: [u8; 32],
    epoch_bytes: [u8; 32],
    nonce_bytes: [u8; 32],
    content_cid: ContentCid,
    envelope_set_cid: EnvelopeSetCid,
    signature_bytes: [u8; 65],
    deadline: UnixDeadline,
}

struct RawAppendFields<'a> {
    parent_manifest_hash: &'a str,
    require_zero_parent: bool,
    manifest_hash: &'a str,
    epoch_id: &'a str,
    operation_nonce: &'a str,
    content_cid: &'a str,
    envelope_set_cid: &'a str,
    signature: &'a str,
    deadline: u64,
}

async fn parse_append_fields<'a>(
    audit: &mut WriteAuditContext<'a>,
    raw: RawAppendFields<'a>,
) -> Result<ParsedAppendFields, Box<Response>> {
    let parse_parent = domain::hex::parse_lowercase_fixed_hex::<32>(raw.parent_manifest_hash)
        .filter(|bytes| {
            if raw.require_zero_parent {
                *bytes == [0; 32]
            } else {
                *bytes != [0; 32]
            }
        });
    let Some(parent_manifest_bytes) = parse_parent else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_request",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let Some(manifest_bytes) =
        domain::hex::parse_lowercase_fixed_hex::<32>(raw.manifest_hash).filter(|b| *b != [0; 32])
    else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_request",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let Some(epoch_bytes) =
        domain::hex::parse_lowercase_fixed_hex::<32>(raw.epoch_id).filter(|b| *b != [0; 32])
    else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_request",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let Some(nonce_bytes) =
        domain::hex::parse_lowercase_fixed_hex::<32>(raw.operation_nonce).filter(|b| *b != [0; 32])
    else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_request",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    audit.operation_id = Some(raw.operation_nonce);

    let Ok(content_cid) = ContentCid::parse(raw.content_cid) else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_cid",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let Ok(envelope_set_cid) = EnvelopeSetCid::parse(raw.envelope_set_cid) else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_cid",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let Some(signature_bytes) = parse_fixed_hex::<65>(raw.signature) else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_signature",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await,
        ));
    };
    let deadline = match verify_write_deadline(raw.deadline) {
        Ok(deadline) => deadline,
        Err(WriteDeadlineError::ClockUnavailable) => {
            return Err(Box::new(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            )));
        }
        Err(WriteDeadlineError::Expired) => {
            return Err(Box::new(
                audit
                    .fail(
                        "denied",
                        "expired_operation",
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                    )
                    .await,
            ));
        }
    };

    Ok(ParsedAppendFields {
        parent_manifest_bytes,
        manifest_bytes,
        epoch_bytes,
        nonce_bytes,
        content_cid,
        envelope_set_cid,
        signature_bytes,
        deadline,
    })
}

async fn verify_version_append_signature(
    audit: &WriteAuditContext<'_>,
    version: VersionNumber,
    member_id: domain::MemberId,
    signer_address: domain::EvmAddress,
    fields: &ParsedAppendFields,
    raw_signature: &str,
) -> Result<(), Box<Response>> {
    let Ok(typed_append) = VersionAppend::new(
        audit.file_id,
        version,
        ManifestHash::from_bytes(fields.parent_manifest_bytes),
        ManifestHash::from_bytes(fields.manifest_bytes),
        fields.content_cid.clone(),
        fields.envelope_set_cid.clone(),
        EpochId::from_bytes(fields.epoch_bytes),
        member_id,
        signer_address,
        OperationNonce::from_bytes(fields.nonce_bytes),
        fields.deadline,
    ) else {
        return Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_operation",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await,
        ));
    };
    let domain = Eip712Domain::file_registry(
        ChainId::from_u64(audit.state.config.chain_id),
        audit.state.config.file_registry,
    );
    let Ok(digest) = typed_append.digest(&domain) else {
        return Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
        )));
    };
    match recover_signer(digest.as_bytes(), raw_signature) {
        Ok(recovered) if recovered == signer_address => Ok(()),
        _ => Err(Box::new(
            audit
                .fail(
                    "denied",
                    "invalid_signature",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await,
        )),
    }
}

pub(crate) async fn create_file(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<CreateFileRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.create";
    let source_id = source_identifier(&peer.ip().to_string());
    let Ok(Json(request)) = body else {
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

    let Some(file_id) = parse_nonzero_file_id(&request.file_id) else {
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
    let mut audit = WriteAuditContext {
        state: &state,
        action: ACTION,
        member_id: &member_id_string,
        source_id: &source_id,
        file_id,
        version: request.version_number,
        operation_id: None,
        block_number: None,
        restored_from_version: None,
    };

    if request.display_name.is_empty()
        || request.display_name.len() > MAX_DISPLAY_NAME_BYTES
        || request.display_name.chars().any(char::is_control)
        || request.version_number != 1
    {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    }
    let Some(parent_folder_id) =
        domain::hex::parse_lowercase_fixed_hex::<32>(&request.parent_folder_id)
    else {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };

    let fields = match parse_append_fields(
        &mut audit,
        RawAppendFields {
            parent_manifest_hash: &request.parent_manifest_hash,
            require_zero_parent: true,
            manifest_hash: &request.manifest_hash,
            epoch_id: &request.epoch_id,
            operation_nonce: &request.operation_nonce,
            content_cid: &request.content_cid,
            envelope_set_cid: &request.envelope_set_cid,
            signature: &request.signature,
            deadline: request.deadline,
        },
    )
    .await
    {
        Ok(fields) => fields,
        Err(response) => return *response,
    };

    let Ok(finalized) = state.chain.finalized_block().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    audit.block_number = Some(finalized.number);

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
            return audit
                .fail(
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };

    if let Err(response) = verify_version_append_signature(
        &audit,
        VersionNumber::ONE,
        member_id,
        member.signing_address,
        &fields,
        &request.signature,
    )
    .await
    {
        return *response;
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
            return audit
                .fail(
                    "denied",
                    "file_already_exists",
                    StatusCode::CONFLICT,
                    "conflict",
                )
                .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }

    if let Err(response) = audit
        .verify_pin_quorum(StorageCid::Content(fields.content_cid.clone()))
        .await
    {
        return *response;
    }
    if let Err(response) = audit
        .verify_pin_quorum(StorageCid::EnvelopeSet(fields.envelope_set_cid.clone()))
        .await
    {
        return *response;
    }
    if let Err(response) = audit
        .verify_staged_envelope_set(
            VersionNumber::ONE,
            EpochId::from_bytes(fields.epoch_bytes),
            1,
            &fields.envelope_set_cid,
        )
        .await
    {
        return *response;
    }

    let content_cid_str = fields.content_cid.to_string();
    let envelope_cid_str = fields.envelope_set_cid.to_string();
    let call = VersionAppendCall {
        file_id: *file_id.as_bytes(),
        version_number: 1,
        parent_manifest_hash: fields.parent_manifest_bytes,
        content_cid: content_cid_str.clone(),
        envelope_set_cid: envelope_cid_str.clone(),
        epoch_id: fields.epoch_bytes,
        manifest_hash: fields.manifest_bytes,
        member_id: *member_id.as_bytes(),
        signer_address: member.signing_address,
        operation_nonce: fields.nonce_bytes,
        deadline: request.deadline,
    };
    let submit_result = relayer
        .submit_create_file(
            call,
            request.display_name,
            parent_folder_id,
            fields.signature_bytes.to_vec(),
        )
        .await;
    audit
        .persist_pending_and_confirm(
            relayer.as_ref(),
            StatusCode::CREATED,
            Some(&content_cid_str),
            &envelope_cid_str,
            submit_result,
        )
        .await
}

pub(crate) async fn append_version(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_file_id): Path<String>,
    body: Result<Json<AppendVersionRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.version_append";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
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
    let Ok(Json(request)) = body else {
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

    let action = if request.restored_from_version.is_some() {
        "file.version_restore"
    } else {
        ACTION
    };
    let mut audit = WriteAuditContext {
        state: &state,
        action,
        member_id: &member_id_string,
        source_id: &source_id,
        file_id,
        version: request.version_number,
        operation_id: None,
        block_number: None,
        restored_from_version: request.restored_from_version,
    };

    let Ok(version) = VersionNumber::new(request.version_number) else {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    if let Some(source_version) = request.restored_from_version
        && (source_version == 0 || source_version >= request.version_number)
    {
        return audit
            .fail(
                "denied",
                "invalid_restore_source",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    }

    let fields = match parse_append_fields(
        &mut audit,
        RawAppendFields {
            parent_manifest_hash: &request.parent_manifest_hash,
            require_zero_parent: false,
            manifest_hash: &request.manifest_hash,
            epoch_id: &request.epoch_id,
            operation_nonce: &request.operation_nonce,
            content_cid: &request.content_cid,
            envelope_set_cid: &request.envelope_set_cid,
            signature: &request.signature,
            deadline: request.deadline,
        },
    )
    .await
    {
        Ok(fields) => fields,
        Err(response) => return *response,
    };

    let Ok(finalized) = state.chain.finalized_block().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    audit.block_number = Some(finalized.number);

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
            return audit
                .fail(
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };

    let Ok(write_access) = state
        .chain
        .has_write_access(
            &state.config.access_governance,
            member_id.as_bytes(),
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    if !write_access {
        return audit
            .fail(
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
            return audit
                .fail(
                    "denied",
                    "file_not_writable",
                    StatusCode::CONFLICT,
                    "conflict",
                )
                .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    if request.version_number != head.version_number.saturating_add(1)
        || request.parent_manifest_hash != head.manifest_hash
    {
        return audit
            .fail("denied", "stale_head", StatusCode::CONFLICT, "stale_head")
            .await;
    }

    if let Err(response) = verify_version_append_signature(
        &audit,
        version,
        member_id,
        member.signing_address,
        &fields,
        &request.signature,
    )
    .await
    {
        return *response;
    }

    if let Err(response) = audit
        .verify_pin_quorum(StorageCid::Content(fields.content_cid.clone()))
        .await
    {
        return *response;
    }
    if let Err(response) = audit
        .verify_pin_quorum(StorageCid::EnvelopeSet(fields.envelope_set_cid.clone()))
        .await
    {
        return *response;
    }
    if let Err(response) = audit
        .verify_staged_envelope_set(
            version,
            EpochId::from_bytes(fields.epoch_bytes),
            1,
            &fields.envelope_set_cid,
        )
        .await
    {
        return *response;
    }

    let content_cid_str = fields.content_cid.to_string();
    let envelope_cid_str = fields.envelope_set_cid.to_string();
    let call = VersionAppendCall {
        file_id: *file_id.as_bytes(),
        version_number: request.version_number,
        parent_manifest_hash: fields.parent_manifest_bytes,
        content_cid: content_cid_str.clone(),
        envelope_set_cid: envelope_cid_str.clone(),
        epoch_id: fields.epoch_bytes,
        manifest_hash: fields.manifest_bytes,
        member_id: *member_id.as_bytes(),
        signer_address: member.signing_address,
        operation_nonce: fields.nonce_bytes,
        deadline: request.deadline,
    };
    let submit_result = relayer
        .submit_append_version(call, fields.signature_bytes.to_vec())
        .await;
    audit
        .persist_pending_and_confirm(
            relayer.as_ref(),
            StatusCode::CREATED,
            Some(&content_cid_str),
            &envelope_cid_str,
            submit_result,
        )
        .await
}

pub(crate) async fn update_envelope_set(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((raw_file_id, version_number)): Path<(String, u64)>,
    body: Result<Json<UpdateEnvelopeSetRequest>, JsonRejection>,
) -> Response {
    const ACTION: &str = "file.envelope_update";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(file_id) = parse_nonzero_file_id(&raw_file_id) else {
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
    let Ok(Json(request)) = body else {
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

    let mut audit = WriteAuditContext {
        state: &state,
        action: ACTION,
        member_id: &member_id_string,
        source_id: &source_id,
        file_id,
        version: version_number,
        operation_id: None,
        block_number: None,
        restored_from_version: None,
    };

    let Some(epoch_bytes) =
        domain::hex::parse_lowercase_fixed_hex::<32>(&request.epoch_id).filter(|b| *b != [0; 32])
    else {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    let Some(proposal_bytes) = domain::hex::parse_lowercase_fixed_hex::<32>(&request.proposal_id)
    else {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    let Some(nonce_bytes) = domain::hex::parse_lowercase_fixed_hex::<32>(&request.operation_nonce)
        .filter(|b| *b != [0; 32])
    else {
        return audit
            .fail(
                "denied",
                "invalid_request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    audit.operation_id = Some(&request.operation_nonce);

    let Ok(old_cid) = EnvelopeSetCid::parse(&request.old_envelope_set_cid) else {
        return audit
            .fail(
                "denied",
                "invalid_cid",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    let Ok(new_cid) = EnvelopeSetCid::parse(&request.new_envelope_set_cid) else {
        return audit
            .fail(
                "denied",
                "invalid_cid",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    };
    if old_cid == new_cid {
        return audit
            .fail(
                "denied",
                "unchanged_envelope_set",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )
            .await;
    }
    let Some(signature_bytes) = parse_fixed_hex::<65>(&request.signature) else {
        return audit
            .fail(
                "denied",
                "invalid_signature",
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            )
            .await;
    };
    let deadline = match verify_write_deadline(request.deadline) {
        Ok(deadline) => deadline,
        Err(WriteDeadlineError::ClockUnavailable) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        }
        Err(WriteDeadlineError::Expired) => {
            return audit
                .fail(
                    "denied",
                    "expired_operation",
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                )
                .await;
        }
    };

    let Ok(finalized) = state.chain.finalized_block().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    audit.block_number = Some(finalized.number);

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
            return audit
                .fail(
                    "denied",
                    "unauthorized",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await;
        }
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    };
    let Ok(read_access) = state
        .chain
        .has_read_access(
            &state.config.access_governance,
            member_id.as_bytes(),
            file_id.as_bytes(),
            finalized.number,
        )
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
    };
    if !read_access {
        return audit
            .fail(
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
            return audit
                .fail(
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
        return audit
            .fail("denied", "stale_head", StatusCode::CONFLICT, "stale_head")
            .await;
    }
    let Some(expected_revision) = current.revision.checked_add(1) else {
        return audit
            .fail(
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
        return audit
            .fail(
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
            return audit
                .fail(
                    "denied",
                    "invalid_signature",
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                )
                .await;
        }
    }

    if let Err(response) = audit
        .verify_pin_quorum(StorageCid::EnvelopeSet(new_cid.clone()))
        .await
    {
        return *response;
    }
    if let Err(response) = audit
        .verify_staged_envelope_set(
            version,
            EpochId::from_bytes(epoch_bytes),
            expected_revision,
            &new_cid,
        )
        .await
    {
        return *response;
    }

    let new_cid_str = new_cid.to_string();
    let call = EnvelopeSetUpdateCall {
        file_id: *file_id.as_bytes(),
        version_number,
        epoch_id: epoch_bytes,
        old_envelope_set_cid: old_cid.to_string(),
        new_envelope_set_cid: new_cid_str.clone(),
        actor_member_id: *member_id.as_bytes(),
        proposal_id: proposal_bytes,
        operation_nonce: nonce_bytes,
        deadline: request.deadline,
    };
    let submit_result = relayer
        .submit_update_envelope_set(call, signature_bytes.to_vec())
        .await;
    audit
        .persist_pending_and_confirm(
            relayer.as_ref(),
            StatusCode::OK,
            None,
            &new_cid_str,
            submit_result,
        )
        .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionReconcileResponse {
    transaction_hash: String,
    operation_kind: String,
    file_id: String,
    version_number: u64,
    status: String,
    block_number: Option<u64>,
    block_hash: Option<String>,
    gas_used: Option<u64>,
}

/// Authenticated transaction reconciliation route (`TECHNICAL_SPECIFICATION.md` §§7.13, 10.4.7).
///
/// Survives gateway restarts by reading persisted `gateway_relayed_transactions`
/// state and querying Besu via `GatewayRelayerPort::reconcile_transaction` when
/// status is still `pending`.
pub(crate) async fn reconcile_transaction(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_tx_hash): Path<String>,
) -> Response {
    const ACTION: &str = "transaction.reconcile";
    let source_id = source_identifier(&peer.ip().to_string());
    let Some(tx_hash_bytes) = domain::hex::parse_lowercase_fixed_hex::<32>(&raw_tx_hash) else {
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

    let Ok(Some(mut record)) = state.store.get_relayed_transaction(&raw_tx_hash).await else {
        return failure(
            &state,
            ACTION,
            &source_id,
            "not_found",
            None,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
    };
    // Prevent cross-member probing of unrelated transaction hashes (§8.2).
    if record.actor_member_id != member_id_string {
        return failure(
            &state,
            ACTION,
            &source_id,
            "not_found",
            None,
            StatusCode::NOT_FOUND,
            "not_found",
        )
        .await;
    }

    if record.status == "pending" {
        let Some(relayer) = state.relayer.as_ref() else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
        };
        match relayer.reconcile_transaction(tx_hash_bytes).await {
            Ok(Some(RelayOutcome::Committed(receipt))) => {
                if state
                    .store
                    .update_relayed_transaction_status(
                        &record.tx_hash,
                        "confirmed",
                        Some(receipt.block_number),
                        Some(&receipt.block_hash),
                        Some(receipt.gas_used),
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                if let Some(cid) = record.content_cid.as_deref() {
                    let _ = state.store.mark_blob_referenced(cid).await;
                }
                let _ = state
                    .store
                    .mark_blob_referenced(&record.envelope_set_cid)
                    .await;
                if state
                    .store
                    .record_write_attempt(
                        ACTION,
                        Some(&member_id_string),
                        &source_id,
                        &record.file_id,
                        record.version_number,
                        Some(&record.operation_id),
                        state.config.chain_id,
                        Some(receipt.block_number),
                        "committed",
                        None,
                        None,
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                record.status = "confirmed".to_owned();
                record.block_number = Some(receipt.block_number);
                record.block_hash = Some(receipt.block_hash);
                record.gas_used = Some(receipt.gas_used);
            }
            Ok(Some(RelayOutcome::Reverted(receipt))) => {
                if state
                    .store
                    .update_relayed_transaction_status(
                        &record.tx_hash,
                        "reverted",
                        Some(receipt.block_number),
                        Some(&receipt.block_hash),
                        Some(receipt.gas_used),
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                if let Some(cid) = record.content_cid.as_deref() {
                    let _ = state
                        .store
                        .record_orphan_blob_candidate(
                            cid,
                            "content",
                            &member_id_string,
                            Some(&record.file_id),
                            Some(record.version_number),
                            Some(&record.tx_hash),
                            "contract_reverted",
                        )
                        .await;
                }
                let _ = state
                    .store
                    .record_orphan_blob_candidate(
                        &record.envelope_set_cid,
                        "envelope",
                        &member_id_string,
                        Some(&record.file_id),
                        Some(record.version_number),
                        Some(&record.tx_hash),
                        "contract_reverted",
                    )
                    .await;
                if state
                    .store
                    .record_write_attempt(
                        ACTION,
                        Some(&member_id_string),
                        &source_id,
                        &record.file_id,
                        record.version_number,
                        Some(&record.operation_id),
                        state.config.chain_id,
                        Some(receipt.block_number),
                        "reverted",
                        Some("contract_reverted"),
                        None,
                    )
                    .await
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");
                }
                record.status = "reverted".to_owned();
                record.block_number = Some(receipt.block_number);
                record.block_hash = Some(receipt.block_hash);
                record.gas_used = Some(receipt.gas_used);
            }
            Ok(None) => {}
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        }
    }

    (
        StatusCode::OK,
        Json(TransactionReconcileResponse {
            transaction_hash: record.tx_hash,
            operation_kind: record.operation_kind,
            file_id: record.file_id,
            version_number: record.version_number,
            status: record.status,
            block_number: record.block_number,
            block_hash: record.block_hash,
            gas_used: record.gas_used,
        }),
    )
        .into_response()
}
