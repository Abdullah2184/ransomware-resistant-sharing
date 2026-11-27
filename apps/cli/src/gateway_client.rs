//! HTTP adapter implementing `GatewayAuthPort`, `LedgerPort`, and `BlobStore`
//! strictly against the documented RRDS Gateway HTTP API.
//!
//! Client endpoints never connect directly to Besu RPC, PostgreSQL, Kubo, or
//! IPFS Cluster admin APIs.

use std::{
    collections::HashMap,
    fmt,
    io::Cursor,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use application::EncryptedPackageBytes;
use domain::{
    AccessReference, ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId,
    FileStatus, FolderId, KeyVersion, LoginChallenge, ManifestHash, MemberId, MemberStatus,
    OperationNonce, OrganizationId, PublicMemberIdentity, TransactionReceipt, VersionNumber,
};
use ports::{
    AuthenticatedSession, BlobStore, ContentPackage, EvmSignature, GatewayAuthPort, HeadState,
    LedgerPort, PortFuture, ReplicationReceipt, SignedAccessLookupRequest,
    SignedAppendVersionRequest, SignedCreateFileRequest, SignedEnvelopeUpdateRequest, StorageCid,
    StorageError, StorageFuture, StorageReader, StoredContent, StoredEnvelopeSet,
    encode_content_package_frame,
};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::car::extract_package_from_car;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPLOAD_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTENT_CAR_BYTES: usize = MAX_UPLOAD_FRAME_BYTES + 4 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 512 * 1024;
const MAX_JSON_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
const MAX_AUTHORIZED_CACHE_ENTRIES: usize = 1024;

#[derive(Clone)]
pub struct GatewayHttpClient {
    base_url: Url,
    client: Client,
    token: Arc<Mutex<Option<Zeroizing<String>>>>,
    authorized_envelopes: Arc<Mutex<HashMap<String, (FileId, VersionNumber)>>>,
    authorized_contents: Arc<Mutex<HashMap<String, (FileId, VersionNumber)>>>,
}

impl fmt::Debug for GatewayHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayHttpClient")
            .field("base_url", &self.base_url.as_str())
            .field("authenticated", &lock_unpoisoned(&self.token).is_some())
            .finish()
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl GatewayHttpClient {
    #[cfg(test)]
    pub fn new(base_url: &str) -> Result<Self, String> {
        Self::new_with_insecure_http_opt_in(base_url, false)
    }

    pub fn new_with_insecure_http_opt_in(
        base_url: &str,
        allow_insecure_http: bool,
    ) -> Result<Self, String> {
        let base_url = validate_base_url_with_policy(base_url, allow_insecure_http)?;
        let client = Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|_| "could not initialize the HTTP client".to_owned())?;
        Ok(Self {
            base_url,
            client,
            token: Arc::new(Mutex::new(None)),
            authorized_envelopes: Arc::new(Mutex::new(HashMap::new())),
            authorized_contents: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn set_bearer_token(&self, token: String) {
        *lock_unpoisoned(&self.token) = Some(Zeroizing::new(token));
    }

    pub fn endpoint_url(&self, relative_path: &str) -> String {
        let mut url = self.base_url.clone();
        let base = url.path().trim_end_matches('/');
        url.set_path(&format!("{base}{relative_path}"));
        url.to_string()
    }

    pub async fn check_health(&self) -> Result<StatusCode, String> {
        let client = Client::builder()
            .timeout(HEALTH_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|_| "could not initialize the HTTP client".to_owned())?;
        let response = client
            .get(self.endpoint_url("/healthz"))
            .send()
            .await
            .map_err(|_| "could not reach the configured gateway health endpoint".to_owned())?;
        Ok(response.status())
    }

    pub async fn whoami(&self) -> Result<String, DomainError> {
        let bearer = self.require_bearer()?;
        let response = self
            .client
            .get(self.endpoint_url("/v1/auth/session"))
            .bearer_auth(&*bearer)
            .send()
            .await
            .map_err(|_| DomainError::Internal)?;
        let body: SessionIdentityDto = decode_json_response(response).await?;
        Ok(body.member_id)
    }

    pub async fn logout(&self) -> Result<(), DomainError> {
        let bearer = self.require_bearer()?;
        let response = self
            .client
            .delete(self.endpoint_url("/v1/auth/session"))
            .bearer_auth(&*bearer)
            .send()
            .await
            .map_err(|_| DomainError::Internal)?;
        let status = response.status();
        if status.is_success() {
            *lock_unpoisoned(&self.token) = None;
            return Ok(());
        }
        let code = read_error_code(response).await;
        Err(map_http_error(status, code.as_deref()))
    }

    pub async fn list_files(
        &self,
        folder_id: Option<FolderId>,
    ) -> Result<FileListView, DomainError> {
        let bearer = self.require_bearer()?;
        let mut request = self
            .client
            .get(self.endpoint_url("/v1/files"))
            .bearer_auth(&*bearer);
        if let Some(folder_id) = folder_id {
            request = request.query(&[("folderId", folder_id.to_string())]);
        }
        let response = request.send().await.map_err(|_| DomainError::Internal)?;
        decode_json_response(response).await
    }

    pub async fn version_history(
        &self,
        file_id: FileId,
    ) -> Result<VersionHistoryView, DomainError> {
        let bearer = self.require_bearer()?;
        let response = self
            .client
            .get(self.endpoint_url(&format!("/v1/files/{file_id}/versions")))
            .bearer_auth(&*bearer)
            .send()
            .await
            .map_err(|_| DomainError::Internal)?;
        decode_json_response(response).await
    }

    pub async fn query_audit(
        &self,
        action: Option<&str>,
        limit: Option<u32>,
    ) -> Result<AuditQueryView, DomainError> {
        let bearer = self.require_bearer()?;
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(action) = action {
            params.push(("action", action.to_owned()));
        }
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }
        let response = self
            .client
            .get(self.endpoint_url("/v1/audit"))
            .bearer_auth(&*bearer)
            .query(&params)
            .send()
            .await
            .map_err(|_| DomainError::Internal)?;
        decode_json_response(response).await
    }

    /// Downloads the CARv1 ciphertext stream for an already-authorized version
    /// within a hard memory bound and extracts the verified `EncryptedPackageBytes`.
    pub async fn fetch_content_package(
        &self,
        access: &AccessReference,
    ) -> Result<EncryptedPackageBytes, DomainError> {
        let bearer = self.require_bearer()?;
        let response = self
            .client
            .get(self.endpoint_url(&format!(
                "/v1/files/{}/versions/{}/content",
                access.file_id,
                access.version_number.get()
            )))
            .bearer_auth(&*bearer)
            .send()
            .await
            .map_err(|_| DomainError::StorageUnavailable)?;
        let status = response.status();
        if !status.is_success() {
            let code = read_error_code(response).await;
            return Err(map_http_error(status, code.as_deref()));
        }
        let car_bytes = read_response_bytes_bounded(response, MAX_CONTENT_CAR_BYTES)
            .await
            .map_err(|err| match err {
                BoundedReadError::SizeLimitExceeded => DomainError::InvalidManifest,
                BoundedReadError::Transport => DomainError::StorageUnavailable,
            })?;
        extract_package_from_car(&car_bytes, access)
    }

    fn require_bearer(&self) -> Result<Zeroizing<String>, DomainError> {
        lock_unpoisoned(&self.token)
            .clone()
            .ok_or(DomainError::Unauthenticated)
    }

    fn cache_authorized_refs(&self, access: &AccessReference) {
        let mut envelopes = lock_unpoisoned(&self.authorized_envelopes);
        if envelopes.len() >= MAX_AUTHORIZED_CACHE_ENTRIES {
            envelopes.clear();
        }
        envelopes.insert(
            access.envelope_set_cid.to_string(),
            (access.file_id, access.version_number),
        );
        drop(envelopes);

        let mut contents = lock_unpoisoned(&self.authorized_contents);
        if contents.len() >= MAX_AUTHORIZED_CACHE_ENTRIES {
            contents.clear();
        }
        contents.insert(
            access.content_cid.to_string(),
            (access.file_id, access.version_number),
        );
    }
}

impl GatewayAuthPort for GatewayHttpClient {
    fn request_challenge(&self, member_id: MemberId) -> PortFuture<'_, LoginChallenge> {
        Box::pin(async move {
            let response = self
                .client
                .post(self.endpoint_url("/v1/auth/challenge"))
                .json(&serde_json::json!({ "memberId": member_id.to_string() }))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: ChallengeDto = decode_json_response(response).await?;
            Ok(LoginChallenge {
                member_id: MemberId::from_bytes(parse_hex_32(&dto.member_id)?),
                nonce: OperationNonce::from_bytes(parse_hex_32(&dto.nonce)?),
                issued_at: dto.issued_at,
                expires_at: dto.expires_at,
                audience: dto.audience,
                protocol_version: dto.protocol_version,
            })
        })
    }

    fn exchange_challenge<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        signature: &'a EvmSignature,
    ) -> PortFuture<'a, AuthenticatedSession> {
        Box::pin(async move {
            let payload = SessionExchangeRequest {
                challenge: ChallengeDto {
                    member_id: challenge.member_id.to_string(),
                    nonce: challenge.nonce.to_string(),
                    issued_at: challenge.issued_at,
                    expires_at: challenge.expires_at,
                    audience: challenge.audience.clone(),
                    protocol_version: challenge.protocol_version,
                },
                signature: encode_hex(signature.as_bytes()),
            };
            let response = self
                .client
                .post(self.endpoint_url("/v1/auth/session"))
                .json(&payload)
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: SessionResponseDto = decode_json_response(response).await?;
            self.set_bearer_token(dto.token.clone());
            Ok(AuthenticatedSession::new(
                dto.token,
                challenge.member_id,
                dto.expires_at,
            ))
        })
    }
}

impl LedgerPort for GatewayHttpClient {
    fn get_member(&self, member_id: MemberId) -> PortFuture<'_, Option<PublicMemberIdentity>> {
        Box::pin(async move {
            let response = self
                .client
                .get(self.endpoint_url(&format!("/v1/identities/{member_id}")))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let dto: PublicIdentityDto = decode_json_response(response).await?;
            let status = match dto.status.as_str() {
                "active" => MemberStatus::Active,
                "suspended" => MemberStatus::Suspended,
                "revoked" => MemberStatus::Revoked,
                _ => return Err(DomainError::Internal),
            };
            Ok(Some(PublicMemberIdentity {
                member_id: MemberId::from_bytes(parse_hex_32(&dto.member_id)?),
                organization_id: OrganizationId::from_bytes(parse_hex_32(&dto.organization_id)?),
                signing_address: EvmAddress::from_bytes(parse_hex_20(&dto.signing_address)?),
                signing_key_version: KeyVersion::new(dto.signing_key_version)?,
                encryption_key_version: KeyVersion::new(dto.encryption_key_version)?,
                encryption_public_key: parse_hex_32(&dto.encryption_public_key)?,
                status,
                finalized_block: dto.finalized_block,
            }))
        })
    }

    fn get_file_head(&self, file_id: FileId) -> PortFuture<'_, Option<HeadState>> {
        Box::pin(async move {
            let bearer = self.require_bearer()?;
            let response = self
                .client
                .get(self.endpoint_url(&format!("/v1/files/{file_id}/versions")))
                .bearer_auth(&*bearer)
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let history: VersionHistoryView = decode_json_response(response).await?;
            let status = match history.file_status {
                1 => FileStatus::Active,
                2 => FileStatus::Archived,
                _ => return Err(DomainError::Internal),
            };
            let current_version = VersionNumber::new(history.current_version)?;
            let current_head_manifest_hash =
                ManifestHash::from_bytes(parse_hex_32(&history.current_head_manifest_hash)?);
            Ok(Some(HeadState {
                file_id,
                status,
                current_version,
                current_head_manifest_hash,
            }))
        })
    }

    fn authorize_read<'a>(
        &'a self,
        request: &'a SignedAccessLookupRequest,
    ) -> PortFuture<'a, AccessReference> {
        Box::pin(async move {
            let bearer = self.require_bearer()?;
            let response = self
                .client
                .post(self.endpoint_url(&format!(
                    "/v1/files/{}/versions/{}/access",
                    request.file_id,
                    request.version_number.get()
                )))
                .bearer_auth(&*bearer)
                .json(&serde_json::json!({
                    "encryptionKeyVersion": request.encryption_key_version.get(),
                    "operationNonce": request.operation_nonce.to_string(),
                    "deadline": request.deadline,
                    "signature": encode_hex(request.signature.as_bytes()),
                }))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: AccessLookupDto = decode_json_response(response).await?;
            let manifest_hash = ManifestHash::from_bytes(parse_hex_32(&dto.manifest_hash)?);
            if manifest_hash == ManifestHash::ZERO {
                return Err(DomainError::IntegrityCheckFailed);
            }
            let access = AccessReference {
                file_id: FileId::from_bytes(parse_hex_32(&dto.file_id)?),
                version_number: VersionNumber::new(dto.version_number)?,
                manifest_hash,
                content_cid: ContentCid::parse(&dto.content_cid)?,
                envelope_set_cid: EnvelopeSetCid::parse(&dto.envelope_set_cid)?,
                epoch_id: EpochId::from_bytes(parse_hex_32(&dto.epoch_id)?),
                envelope_revision: dto.envelope_revision,
                finalized_block: dto.finalized_block,
            };
            self.cache_authorized_refs(&access);
            Ok(access)
        })
    }

    fn create_file<'a>(
        &'a self,
        request: &'a SignedCreateFileRequest,
    ) -> PortFuture<'a, TransactionReceipt> {
        Box::pin(async move {
            let bearer = self.require_bearer()?;
            let response = self
                .client
                .post(self.endpoint_url("/v1/files"))
                .bearer_auth(&*bearer)
                .json(&serde_json::json!({
                    "fileId": request.file_id.to_string(),
                    "displayName": request.display_name,
                    "parentFolderId": request.parent_folder_id.to_string(),
                    "versionNumber": request.version_number.get(),
                    "parentManifestHash": request.parent_manifest_hash.to_string(),
                    "manifestHash": request.manifest_hash.to_string(),
                    "contentCid": request.content_cid.to_string(),
                    "envelopeSetCid": request.envelope_set_cid.to_string(),
                    "epochId": request.epoch_id.to_string(),
                    "operationNonce": request.operation_nonce.to_string(),
                    "deadline": request.deadline,
                    "signature": encode_hex(request.signature.as_bytes()),
                }))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: WriteCommitDto = decode_json_response(response).await?;
            Ok(TransactionReceipt {
                transaction_hash: parse_hex_32(&dto.transaction_hash)?,
                block_number: dto.block_number,
                finalized: true,
                succeeded: true,
            })
        })
    }

    fn append_version<'a>(
        &'a self,
        request: &'a SignedAppendVersionRequest,
    ) -> PortFuture<'a, TransactionReceipt> {
        Box::pin(async move {
            let bearer = self.require_bearer()?;
            let response = self
                .client
                .post(self.endpoint_url(&format!("/v1/files/{}/versions", request.file_id)))
                .bearer_auth(&*bearer)
                .json(&serde_json::json!({
                    "versionNumber": request.version_number.get(),
                    "parentManifestHash": request.parent_manifest_hash.to_string(),
                    "manifestHash": request.manifest_hash.to_string(),
                    "contentCid": request.content_cid.to_string(),
                    "envelopeSetCid": request.envelope_set_cid.to_string(),
                    "epochId": request.epoch_id.to_string(),
                    "operationNonce": request.operation_nonce.to_string(),
                    "deadline": request.deadline,
                    "signature": encode_hex(request.signature.as_bytes()),
                }))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: WriteCommitDto = decode_json_response(response).await?;
            Ok(TransactionReceipt {
                transaction_hash: parse_hex_32(&dto.transaction_hash)?,
                block_number: dto.block_number,
                finalized: true,
                succeeded: true,
            })
        })
    }

    fn update_envelope_set<'a>(
        &'a self,
        request: &'a SignedEnvelopeUpdateRequest,
    ) -> PortFuture<'a, TransactionReceipt> {
        Box::pin(async move {
            let bearer = self.require_bearer()?;
            let response = self
                .client
                .post(self.endpoint_url(&format!(
                    "/v1/files/{}/versions/{}/envelopes",
                    request.file_id,
                    request.version_number.get()
                )))
                .bearer_auth(&*bearer)
                .json(&serde_json::json!({
                    "epochId": request.epoch_id.to_string(),
                    "oldEnvelopeSetCid": request.old_envelope_set_cid.to_string(),
                    "newEnvelopeSetCid": request.new_envelope_set_cid.to_string(),
                    "proposalId": request.proposal_id.to_string(),
                    "operationNonce": request.operation_nonce.to_string(),
                    "deadline": request.deadline,
                    "signature": encode_hex(request.signature.as_bytes()),
                }))
                .send()
                .await
                .map_err(|_| DomainError::Internal)?;
            let dto: WriteCommitDto = decode_json_response(response).await?;
            Ok(TransactionReceipt {
                transaction_hash: parse_hex_32(&dto.transaction_hash)?,
                block_number: dto.block_number,
                finalized: true,
                succeeded: true,
            })
        })
    }
}

impl BlobStore for GatewayHttpClient {
    fn put_content<'a>(
        &'a self,
        package: ContentPackage,
        min_replicas: usize,
    ) -> StorageFuture<'a, StoredContent> {
        Box::pin(async move {
            let bearer = self
                .require_bearer()
                .map_err(|_| StorageError::TransportUnavailable)?;
            let frame = encode_content_package_frame(package, MAX_UPLOAD_FRAME_BYTES).await?;
            let response = self
                .client
                .post(self.endpoint_url("/v1/blobs/content"))
                .bearer_auth(&*bearer)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(frame)
                .send()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            let dto: BlobUploadDto = decode_blob_response(response).await?;
            let cid = ContentCid::parse(&dto.cid).map_err(|_| StorageError::InvalidCid)?;
            if dto.pinned_peers.len() < min_replicas {
                return Err(StorageError::ReplicationInsufficient);
            }
            Ok(StoredContent {
                cid: cid.clone(),
                bytes_written: dto.bytes_written,
                replication: ReplicationReceipt {
                    cid: StorageCid::Content(cid),
                    required_replicas: min_replicas,
                    pinned_peers: dto.pinned_peers,
                },
            })
        })
    }

    fn put_envelope_set<'a>(
        &'a self,
        reader: StorageReader,
        byte_length: u64,
        min_replicas: usize,
    ) -> StorageFuture<'a, StoredEnvelopeSet> {
        Box::pin(async move {
            let bearer = self
                .require_bearer()
                .map_err(|_| StorageError::TransportUnavailable)?;
            if byte_length > MAX_ENVELOPE_BYTES as u64 {
                return Err(StorageError::SizeLimitExceeded);
            }
            let mut bytes = Vec::with_capacity(byte_length as usize);
            reader
                .take(byte_length.saturating_add(1))
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            if bytes.len() as u64 != byte_length {
                return Err(StorageError::InvalidPackage);
            }
            let response = self
                .client
                .post(self.endpoint_url("/v1/blobs/envelopes"))
                .bearer_auth(&*bearer)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes)
                .send()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            let dto: BlobUploadDto = decode_blob_response(response).await?;
            let cid = EnvelopeSetCid::parse(&dto.cid).map_err(|_| StorageError::InvalidCid)?;
            if dto.pinned_peers.len() < min_replicas {
                return Err(StorageError::ReplicationInsufficient);
            }
            Ok(StoredEnvelopeSet {
                cid: cid.clone(),
                bytes_written: dto.bytes_written,
                replication: ReplicationReceipt {
                    cid: StorageCid::EnvelopeSet(cid),
                    required_replicas: min_replicas,
                    pinned_peers: dto.pinned_peers,
                },
            })
        })
    }

    fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader> {
        Box::pin(async move {
            let bearer = self
                .require_bearer()
                .map_err(|_| StorageError::TransportUnavailable)?;
            let (file_id, version) = lock_unpoisoned(&self.authorized_contents)
                .get(&cid.to_string())
                .copied()
                .ok_or(StorageError::TransportUnavailable)?;
            let response = self
                .client
                .get(self.endpoint_url(&format!(
                    "/v1/files/{file_id}/versions/{}/content",
                    version.get()
                )))
                .bearer_auth(&*bearer)
                .send()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            if !response.status().is_success() {
                return Err(StorageError::TransportUnavailable);
            }
            let bytes = read_response_bytes_bounded(response, MAX_CONTENT_CAR_BYTES)
                .await
                .map_err(map_bounded_read_to_storage)?;
            Ok(Box::pin(Cursor::new(bytes)) as StorageReader)
        })
    }

    fn get_envelope_set<'a>(&'a self, cid: &'a EnvelopeSetCid) -> StorageFuture<'a, StorageReader> {
        Box::pin(async move {
            let bearer = self
                .require_bearer()
                .map_err(|_| StorageError::TransportUnavailable)?;
            let (file_id, version) = lock_unpoisoned(&self.authorized_envelopes)
                .get(&cid.to_string())
                .copied()
                .ok_or(StorageError::TransportUnavailable)?;
            let response = self
                .client
                .get(self.endpoint_url(&format!(
                    "/v1/files/{file_id}/versions/{}/envelope",
                    version.get()
                )))
                .bearer_auth(&*bearer)
                .send()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            if !response.status().is_success() {
                return Err(StorageError::TransportUnavailable);
            }
            let bytes = read_response_bytes_bounded(response, MAX_ENVELOPE_BYTES)
                .await
                .map_err(map_bounded_read_to_storage)?;
            Ok(Box::pin(Cursor::new(bytes)) as StorageReader)
        })
    }

    fn ensure_replication<'a>(
        &'a self,
        _cid: StorageCid,
        _min_replicas: usize,
    ) -> StorageFuture<'a, ReplicationReceipt> {
        Box::pin(async { Err(StorageError::TransportUnavailable) })
    }

    fn verify_retrievable<'a>(&'a self, _cid: StorageCid) -> StorageFuture<'a, ()> {
        Box::pin(async { Err(StorageError::TransportUnavailable) })
    }
}

#[cfg(test)]
pub fn validate_base_url(base_url: &str) -> Result<Url, String> {
    validate_base_url_with_policy(base_url, false)
}

pub fn validate_base_url_with_policy(
    base_url: &str,
    allow_insecure_http: bool,
) -> Result<Url, String> {
    let url = Url::parse(base_url)
        .map_err(|_| "gateway URL must be a valid absolute HTTP or HTTPS URL".to_owned())?;
    let Some(host) = url.host_str() else {
        return Err("gateway URL must include an HTTP or HTTPS host".into());
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Err("gateway URL must include an HTTP or HTTPS host".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("gateway URL must not contain credentials, a query, or a fragment".into());
    }
    if url.scheme() == "http" && !is_loopback_host(host) && !allow_insecure_http {
        return Err(
            "gateway URL must use https:// for non-loopback hosts (set RRDS_ALLOW_INSECURE_HTTP=true only for isolated testing)"
                .into(),
        );
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_start_matches('[').trim_end_matches(']');
    if normalized.eq_ignore_ascii_case("localhost") {
        return true;
    }
    normalized
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedReadError {
    SizeLimitExceeded,
    Transport,
}

fn map_bounded_read_to_storage(err: BoundedReadError) -> StorageError {
    match err {
        BoundedReadError::SizeLimitExceeded => StorageError::SizeLimitExceeded,
        BoundedReadError::Transport => StorageError::TransportUnavailable,
    }
}

async fn read_response_bytes_bounded(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    if let Some(content_length) = response.content_length()
        && content_length > max_bytes as u64
    {
        return Err(BoundedReadError::SizeLimitExceeded);
    }
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BoundedReadError::Transport)?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(BoundedReadError::SizeLimitExceeded);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_error_code(response: reqwest::Response) -> Option<String> {
    let bytes = read_response_bytes_bounded(response, MAX_ERROR_BODY_BYTES)
        .await
        .ok()?;
    serde_json::from_slice::<GatewayErrorDto>(&bytes)
        .ok()
        .map(|dto| dto.error)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeDto {
    member_id: String,
    nonce: String,
    issued_at: u64,
    expires_at: u64,
    audience: String,
    protocol_version: u32,
}

#[derive(Serialize)]
struct SessionExchangeRequest {
    challenge: ChallengeDto,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponseDto {
    token: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionIdentityDto {
    member_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentityDto {
    member_id: String,
    organization_id: String,
    signing_address: String,
    signing_key_version: u32,
    encryption_key_version: u32,
    encryption_public_key: String,
    status: String,
    finalized_block: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessLookupDto {
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
struct WriteCommitDto {
    transaction_hash: String,
    block_number: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobUploadDto {
    cid: String,
    bytes_written: u64,
    pinned_peers: Vec<String>,
}

#[derive(Deserialize)]
struct GatewayErrorDto {
    error: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedFolderView {
    pub folder_id: String,
    pub display_name: String,
    pub updated_block_number: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedFileView {
    pub file_id: String,
    pub display_name: String,
    pub current_version: u64,
    pub current_head_manifest_hash: String,
    pub file_status: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileListView {
    pub folder_id: String,
    pub folders: Vec<ProjectedFolderView>,
    pub files: Vec<ProjectedFileView>,
    pub finalized_block: u64,
    pub indexed_block: Option<u64>,
    pub authoritative: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedVersionView {
    pub version_number: u64,
    pub manifest_hash: String,
    pub parent_manifest_hash: String,
    pub author_member_id: String,
    pub content_cid: String,
    pub current_envelope_set_cid: String,
    pub envelope_revision: u32,
    pub historical_read_granted: bool,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionHistoryView {
    pub file_id: String,
    pub file_status: u64,
    pub current_version: u64,
    pub current_head_manifest_hash: String,
    pub finalized_block: u64,
    pub indexed_block: Option<u64>,
    pub versions: Vec<ProjectedVersionView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    pub sequence: i64,
    pub record: serde_json::Value,
    pub record_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQueryView {
    pub member_id: String,
    pub finalized_block: u64,
    pub events: Vec<AuditEventView>,
}

async fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, DomainError> {
    let status = response.status();
    if status.is_success() {
        let bytes = read_response_bytes_bounded(response, MAX_JSON_RESPONSE_BYTES)
            .await
            .map_err(|err| match err {
                BoundedReadError::SizeLimitExceeded => DomainError::InvalidManifest,
                BoundedReadError::Transport => DomainError::Internal,
            })?;
        return serde_json::from_slice(&bytes).map_err(|_| DomainError::Internal);
    }
    let error_code = read_error_code(response).await;
    Err(map_http_error(status, error_code.as_deref()))
}

async fn decode_blob_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, StorageError> {
    let status = response.status();
    if status.is_success() {
        let bytes = read_response_bytes_bounded(response, MAX_JSON_RESPONSE_BYTES)
            .await
            .map_err(map_bounded_read_to_storage)?;
        return serde_json::from_slice(&bytes).map_err(|_| StorageError::InvalidResponse);
    }
    let error_code = read_error_code(response).await;
    Err(match (status, error_code.as_deref()) {
        (_, Some("replication_insufficient")) => StorageError::ReplicationInsufficient,
        (_, Some("integrity_check_failed")) => StorageError::IntegrityCheckFailed,
        (StatusCode::PAYLOAD_TOO_LARGE, _) => StorageError::SizeLimitExceeded,
        (StatusCode::GATEWAY_TIMEOUT, _) => StorageError::TimedOut,
        (StatusCode::BAD_REQUEST, _) => StorageError::InvalidPackage,
        _ => StorageError::TransportUnavailable,
    })
}

pub(crate) fn map_http_error(status: StatusCode, code: Option<&str>) -> DomainError {
    match (status, code) {
        (StatusCode::UNAUTHORIZED, Some("unauthenticated")) => DomainError::Unauthenticated,
        (StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN, Some("member_suspended")) => {
            DomainError::MemberSuspended
        }
        (StatusCode::UNAUTHORIZED, _) | (StatusCode::FORBIDDEN, _) => DomainError::Unauthorized,
        (StatusCode::NOT_FOUND, _) => DomainError::ContractRejected,
        (StatusCode::CONFLICT, Some("stale_head")) => DomainError::StaleHead,
        (StatusCode::CONFLICT, Some("replay_detected")) => DomainError::ReplayDetected,
        (StatusCode::CONFLICT, Some("expired_request")) => DomainError::ExpiredRequest,
        (StatusCode::CONFLICT, Some("member_suspended")) => DomainError::MemberSuspended,
        (StatusCode::CONFLICT, _) => DomainError::ContractRejected,
        (StatusCode::PAYLOAD_TOO_LARGE, _) => DomainError::InvalidManifest,
        (StatusCode::TOO_MANY_REQUESTS, _) => DomainError::RateLimited,
        (StatusCode::SERVICE_UNAVAILABLE, Some("replication_insufficient")) => {
            DomainError::ReplicationInsufficient
        }
        (StatusCode::SERVICE_UNAVAILABLE, Some("storage_unavailable" | "blob_unavailable")) => {
            DomainError::StorageUnavailable
        }
        (StatusCode::GATEWAY_TIMEOUT, _) | (StatusCode::SERVICE_UNAVAILABLE, _) => {
            DomainError::Internal
        }
        (StatusCode::BAD_REQUEST, Some("expired_request")) => DomainError::ExpiredRequest,
        (StatusCode::BAD_REQUEST, Some("invalid_signature")) => DomainError::InvalidSignature,
        (StatusCode::BAD_REQUEST, _) => DomainError::InvalidManifest,
        _ => DomainError::Internal,
    }
}

pub fn parse_hex_32(value: &str) -> Result<[u8; 32], DomainError> {
    parse_hex_fixed::<32>(value).ok_or(DomainError::InvalidIdentifier)
}

pub fn parse_hex_20(value: &str) -> Result<[u8; 20], DomainError> {
    parse_hex_fixed::<20>(value).ok_or(DomainError::InvalidIdentifier)
}

pub fn parse_hex_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let hex = value.strip_prefix("0x")?;
    if hex.len() != N * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).ok()?;
    }
    Some(out)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
