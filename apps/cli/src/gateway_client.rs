//! HTTP adapter implementing `GatewayAuthPort`, `LedgerPort`, and `BlobStore`
//! strictly against the documented RRDS Gateway HTTP API.
//!
//! Client endpoints never connect directly to Besu RPC, PostgreSQL, Kubo, or
//! IPFS Cluster admin APIs.

use std::{
    collections::HashMap,
    fmt,
    io::Cursor,
    sync::{Arc, Mutex},
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
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::car::extract_package_from_car;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPLOAD_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 512 * 1024;

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
            .field("authenticated", &self.token.lock().unwrap().is_some())
            .finish()
    }
}

impl GatewayHttpClient {
    pub fn new(base_url: &str) -> Result<Self, String> {
        let base_url = validate_base_url(base_url)?;
        let client = Client::builder()
            .timeout(HTTP_TIMEOUT)
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
        *self.token.lock().unwrap() = Some(Zeroizing::new(token));
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
    /// and extracts the verified `EncryptedPackageBytes` (manifest + chunks).
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
        if !response.status().is_success() {
            return Err(map_http_error(response.status(), None));
        }
        let car_bytes = response
            .bytes()
            .await
            .map_err(|_| DomainError::StorageUnavailable)?;
        extract_package_from_car(&car_bytes, access)
    }

    fn require_bearer(&self) -> Result<Zeroizing<String>, DomainError> {
        self.token
            .lock()
            .unwrap()
            .clone()
            .ok_or(DomainError::Unauthenticated)
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
            let history = self.version_history(file_id).await?;
            let current_version = VersionNumber::new(history.current_version)?;
            let current_head_manifest_hash =
                ManifestHash::from_bytes(parse_hex_32(&history.current_head_manifest_hash)?);
            Ok(Some(HeadState {
                file_id,
                status: FileStatus::Active,
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
            let access = AccessReference {
                file_id: FileId::from_bytes(parse_hex_32(&dto.file_id)?),
                version_number: VersionNumber::new(dto.version_number)?,
                content_cid: ContentCid::parse(&dto.content_cid)?,
                envelope_set_cid: EnvelopeSetCid::parse(&dto.envelope_set_cid)?,
                epoch_id: EpochId::from_bytes(parse_hex_32(&dto.epoch_id)?),
                envelope_revision: dto.envelope_revision,
                finalized_block: dto.finalized_block,
            };
            self.authorized_envelopes.lock().unwrap().insert(
                access.envelope_set_cid.to_string(),
                (access.file_id, access.version_number),
            );
            self.authorized_contents.lock().unwrap().insert(
                access.content_cid.to_string(),
                (access.file_id, access.version_number),
            );
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
        mut reader: StorageReader,
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
            let (file_id, version) = self
                .authorized_contents
                .lock()
                .unwrap()
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
            let bytes = response
                .bytes()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            Ok(Box::pin(Cursor::new(bytes.to_vec())) as StorageReader)
        })
    }

    fn get_envelope_set<'a>(&'a self, cid: &'a EnvelopeSetCid) -> StorageFuture<'a, StorageReader> {
        Box::pin(async move {
            let bearer = self
                .require_bearer()
                .map_err(|_| StorageError::TransportUnavailable)?;
            let (file_id, version) = self
                .authorized_envelopes
                .lock()
                .unwrap()
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
            let bytes = response
                .bytes()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            Ok(Box::pin(Cursor::new(bytes.to_vec())) as StorageReader)
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

pub fn validate_base_url(base_url: &str) -> Result<Url, String> {
    let url = Url::parse(base_url)
        .map_err(|_| "gateway URL must be a valid absolute HTTP or HTTPS URL".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("gateway URL must include an HTTP or HTTPS host".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("gateway URL must not contain credentials, a query, or a fragment".into());
    }
    Ok(url)
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
        return response.json().await.map_err(|_| DomainError::Internal);
    }
    let error_code = response
        .json::<GatewayErrorDto>()
        .await
        .ok()
        .map(|dto| dto.error);
    Err(map_http_error(status, error_code.as_deref()))
}

async fn decode_blob_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, StorageError> {
    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .await
            .map_err(|_| StorageError::InvalidResponse);
    }
    let error_code = response
        .json::<GatewayErrorDto>()
        .await
        .ok()
        .map(|dto| dto.error);
    Err(match (status, error_code.as_deref()) {
        (_, Some("replication_insufficient")) => StorageError::ReplicationInsufficient,
        (StatusCode::BAD_REQUEST, _) => StorageError::InvalidPackage,
        _ => StorageError::TransportUnavailable,
    })
}

fn map_http_error(status: StatusCode, code: Option<&str>) -> DomainError {
    match (status, code) {
        (StatusCode::UNAUTHORIZED, _) => DomainError::Unauthorized,
        (StatusCode::CONFLICT, Some("stale_head")) => DomainError::StaleHead,
        (StatusCode::CONFLICT, _) => DomainError::ContractRejected,
        (StatusCode::TOO_MANY_REQUESTS, _) => DomainError::RateLimited,
        (StatusCode::SERVICE_UNAVAILABLE, Some("replication_insufficient")) => {
            DomainError::ReplicationInsufficient
        }
        (StatusCode::GATEWAY_TIMEOUT, _) | (StatusCode::SERVICE_UNAVAILABLE, _) => {
            DomainError::Internal
        }
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
