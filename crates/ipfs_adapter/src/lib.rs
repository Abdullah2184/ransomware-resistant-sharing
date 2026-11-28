//! Kubo and IPFS Cluster adapter for the approved UnixFS directory profile
//! (`docs/adr/content-package-unixfs-profile.md`).

use std::{collections::HashMap, env, fmt, io, time::Duration};

use crypto::{EncryptedFileManifest, verify_sha256_cid};
use domain::{ContentCid, EnvelopeSetCid};
use futures_util::{StreamExt, TryStreamExt};
use ports::{
    BlobStore, ContentPackage, ReplicationReceipt, StorageCid, StorageError, StorageFuture,
    StorageReader, StoredContent, StoredEnvelopeSet,
};
use reqwest::{
    Client, Response, StatusCode, Url,
    multipart::{Form, Part},
    redirect::Policy,
};
use serde::Deserialize;
use tokio::{
    io::AsyncReadExt,
    time::{Instant, sleep, timeout},
};
use tokio_util::io::{ReaderStream, StreamReader};

const ADD_RESPONSE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const PIN_STATUS_LIMIT_BYTES: usize = 1024 * 1024;
const ROOT_BLOCK_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const MAX_REPLICA_COUNT: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TRANSIENT_ATTEMPTS: usize = 3;
const RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(50);

fn is_retryable_http_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

#[derive(Clone)]
pub struct ClusterCredentials {
    username: String,
    password: String,
}

impl ClusterCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for ClusterCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub struct IpfsConfig {
    pub kubo_api_urls: Vec<String>,
    pub cluster_api_urls: Vec<String>,
    pub cluster_credentials: ClusterCredentials,
    pub request_timeout: Duration,
    pub replication_timeout: Duration,
    pub replication_poll_interval: Duration,
    pub max_upload_bytes: u64,
}

impl IpfsConfig {
    pub fn from_env() -> Result<Self, StorageError> {
        let kubo_api_urls = parse_csv_env("IPFS_API_URLS", "IPFS_API_URL")?;
        let cluster_api_urls = parse_csv_env("IPFS_CLUSTER_API_URLS", "IPFS_CLUSTER_API_URL")?;
        let username =
            env::var("IPFS_CLUSTER_USERNAME").map_err(|_| StorageError::TransportUnavailable)?;
        let password_path = env::var("IPFS_CLUSTER_PASSWORD_FILE")
            .map_err(|_| StorageError::TransportUnavailable)?;
        let password = std::fs::read_to_string(password_path)
            .map_err(|_| StorageError::TransportUnavailable)?;
        let credentials = ClusterCredentials::new(username, password.trim_end().to_owned());

        Ok(Self {
            kubo_api_urls,
            cluster_api_urls,
            cluster_credentials: credentials,
            request_timeout: Duration::from_secs(env_u64("IPFS_REQUEST_TIMEOUT_SECONDS", 120)?),
            replication_timeout: Duration::from_secs(env_u64(
                "IPFS_REPLICATION_TIMEOUT_SECONDS",
                120,
            )?),
            replication_poll_interval: Duration::from_millis(env_u64(
                "IPFS_REPLICATION_POLL_MILLISECONDS",
                500,
            )?),
            max_upload_bytes: env_u64("MAX_UPLOAD_BYTES", 1_073_741_824)?,
        })
    }
}

fn parse_csv_env(primary: &str, fallback: &str) -> Result<Vec<String>, StorageError> {
    let raw = env::var(primary)
        .or_else(|_| env::var(fallback))
        .map_err(|_| StorageError::TransportUnavailable)?;
    let urls = raw
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if urls.is_empty() {
        return Err(StorageError::InvalidPackage);
    }
    Ok(urls)
}

pub struct IpfsClusterStore {
    client: Client,
    probe_client: Client,
    kubo_api_urls: Vec<Url>,
    cluster_api_urls: Vec<Url>,
    credentials: ClusterCredentials,
    replication_timeout: Duration,
    replication_poll_interval: Duration,
    max_upload_bytes: u64,
}

impl fmt::Debug for IpfsClusterStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpfsClusterStore")
            .field("kubo_api_urls", &self.kubo_api_urls.len())
            .field("cluster_api_urls", &self.cluster_api_urls.len())
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl IpfsClusterStore {
    pub fn new(config: IpfsConfig) -> Result<Self, StorageError> {
        if config.kubo_api_urls.is_empty()
            || config.cluster_api_urls.is_empty()
            || config.max_upload_bytes == 0
            || config.request_timeout.is_zero()
            || config.replication_timeout.is_zero()
            || config.replication_poll_interval.is_zero()
            || config.cluster_credentials.username.is_empty()
            || config.cluster_credentials.password.is_empty()
        {
            return Err(StorageError::InvalidPackage);
        }

        let kubo_api_urls = config
            .kubo_api_urls
            .iter()
            .map(|url| parse_http_url(url))
            .collect::<Result<Vec<_>, _>>()?;
        let cluster_api_urls = config
            .cluster_api_urls
            .iter()
            .map(|url| parse_http_url(url))
            .collect::<Result<Vec<_>, _>>()?;

        let connect_timeout = CONNECT_TIMEOUT.min(config.request_timeout);
        let probe_timeout = HEALTH_PROBE_TIMEOUT.min(config.request_timeout);

        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(config.request_timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| StorageError::TransportUnavailable)?;
        let probe_client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(probe_timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| StorageError::TransportUnavailable)?;

        Ok(Self {
            client,
            probe_client,
            kubo_api_urls,
            cluster_api_urls,
            credentials: config.cluster_credentials,
            replication_timeout: config.replication_timeout,
            replication_poll_interval: config.replication_poll_interval,
            max_upload_bytes: config.max_upload_bytes,
        })
    }

    async fn select_healthy_kubo_url(&self) -> Result<&Url, StorageError> {
        if self.kubo_api_urls.len() == 1 {
            return self
                .kubo_api_urls
                .first()
                .ok_or(StorageError::TransportUnavailable);
        }
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            for base in &self.kubo_api_urls {
                let Ok(url) = base.join("api/v0/id") else {
                    continue;
                };
                if let Ok(response) = self.probe_client.post(url).send().await
                    && response.status().is_success()
                {
                    return Ok(base);
                }
            }
            if attempt + 1 < MAX_TRANSIENT_ATTEMPTS {
                sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
        }
        Err(StorageError::TransportUnavailable)
    }

    async fn add_to_peer(
        &self,
        base: &Url,
        form: Form,
        wrap_with_directory: bool,
        expected_content: Option<(&EncryptedFileManifest, &str)>,
    ) -> Result<String, (StorageError, bool)> {
        let url = base
            .join("api/v0/add")
            .map_err(|_| (StorageError::InvalidPackage, false))?;
        let response = self
            .client
            .post(url)
            .query(&[
                ("cid-version", "1"),
                ("hash", "sha2-256"),
                ("chunker", "size-1048592"),
                ("raw-leaves", "true"),
                (
                    "wrap-with-directory",
                    if wrap_with_directory { "true" } else { "false" },
                ),
                ("pin", "false"),
                ("progress", "false"),
                ("preserve-mode", "false"),
                ("preserve-mtime", "false"),
            ])
            .multipart(form)
            .send()
            .await
            .map_err(|_| (StorageError::TransportUnavailable, true))?;
        let status = response.status();
        if !status.is_success() {
            return Err((
                StorageError::TransportUnavailable,
                is_retryable_http_status(status),
            ));
        }

        let output = bounded_response_body(response, ADD_RESPONSE_LIMIT_BYTES)
            .await
            .map_err(|err| (err, false))?;
        parse_add_output(&output, wrap_with_directory, expected_content).map_err(|err| (err, false))
    }

    async fn delete_pin(&self, cid_text: &str) -> Result<(), StorageError> {
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let mut saw_retryable = false;
            for base in &self.cluster_api_urls {
                let url = base
                    .join(&format!("pins/{cid_text}"))
                    .map_err(|_| StorageError::InvalidCid)?;
                let response = match self
                    .client
                    .delete(url)
                    .basic_auth(&self.credentials.username, Some(&self.credentials.password))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        saw_retryable = true;
                        continue;
                    }
                };
                let status = response.status();
                if status.is_success()
                    || status == StatusCode::ACCEPTED
                    || status == StatusCode::NOT_FOUND
                {
                    return Ok(());
                }
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(StorageError::TransportUnavailable);
                }
                if is_retryable_http_status(status) {
                    saw_retryable = true;
                }
            }
            if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                break;
            }
            sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        Err(StorageError::TransportUnavailable)
    }

    async fn probe_storage_health(&self) -> ports::StorageHealthStatus {
        let mut healthy_kubo_peers = 0usize;
        for base in &self.kubo_api_urls {
            if let Ok(url) = base.join("api/v0/id")
                && let Ok(response) = self.probe_client.post(url).send().await
                && response.status().is_success()
            {
                healthy_kubo_peers += 1;
            }
        }
        let mut healthy_cluster_peers = 0usize;
        for base in &self.cluster_api_urls {
            if let Ok(url) = base.join("id")
                && let Ok(response) = self
                    .probe_client
                    .get(url)
                    .basic_auth(&self.credentials.username, Some(&self.credentials.password))
                    .send()
                    .await
                && response.status().is_success()
            {
                healthy_cluster_peers += 1;
            }
        }
        ports::StorageHealthStatus {
            healthy_kubo_peers,
            total_kubo_peers: self.kubo_api_urls.len(),
            healthy_cluster_peers,
            total_cluster_peers: self.cluster_api_urls.len(),
        }
    }

    async fn post_pin(&self, cid_text: &str, min_replicas: usize) -> Result<(), StorageError> {
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let mut saw_retryable = false;
            for base in &self.cluster_api_urls {
                let url = base
                    .join(&format!("pins/{cid_text}"))
                    .map_err(|_| StorageError::InvalidCid)?;
                let response = match self
                    .client
                    .post(url)
                    .query(&[
                        ("replication-min", min_replicas.to_string()),
                        ("replication-max", min_replicas.to_string()),
                    ])
                    .basic_auth(&self.credentials.username, Some(&self.credentials.password))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        saw_retryable = true;
                        continue;
                    }
                };
                let status = response.status();
                if status.is_success() || status == StatusCode::ACCEPTED {
                    return Ok(());
                }
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(StorageError::TransportUnavailable);
                }
                if is_retryable_http_status(status) {
                    saw_retryable = true;
                }
            }
            if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                break;
            }
            sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        Err(StorageError::TransportUnavailable)
    }

    async fn fetch_pin_status(
        &self,
        cid_text: &str,
    ) -> Result<Option<ClusterPinStatus>, StorageError> {
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let mut not_found = false;
            let mut saw_retryable = false;
            for base in &self.cluster_api_urls {
                let status_url = base
                    .join(&format!("pins/{cid_text}"))
                    .map_err(|_| StorageError::InvalidCid)?;
                let response = match self
                    .client
                    .get(status_url)
                    .basic_auth(&self.credentials.username, Some(&self.credentials.password))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        saw_retryable = true;
                        continue;
                    }
                };
                let status = response.status();
                if status.is_success() {
                    let body = bounded_response_body(response, PIN_STATUS_LIMIT_BYTES).await?;
                    let parsed: ClusterPinStatus =
                        serde_json::from_slice(&body).map_err(|_| StorageError::InvalidResponse)?;
                    if parsed.cid != cid_text {
                        return Err(StorageError::InvalidResponse);
                    }
                    return Ok(Some(parsed));
                }
                if status == StatusCode::NOT_FOUND {
                    not_found = true;
                    continue;
                }
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(StorageError::TransportUnavailable);
                }
                if is_retryable_http_status(status) {
                    saw_retryable = true;
                }
            }
            if not_found {
                return Ok(None);
            }
            if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                break;
            }
            sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        Err(StorageError::TransportUnavailable)
    }

    async fn pin_and_wait(
        &self,
        cid: StorageCid,
        min_replicas: usize,
    ) -> Result<ReplicationReceipt, StorageError> {
        if min_replicas == 0 || min_replicas > MAX_REPLICA_COUNT {
            return Err(StorageError::InvalidReplicaCount);
        }
        let cid_text = storage_cid_string(&cid);
        self.post_pin(&cid_text, min_replicas).await?;

        let wait_result = timeout(
            self.replication_timeout,
            self.wait_for_replication(cid, min_replicas),
        )
        .await;
        match wait_result {
            Ok(result) => result,
            Err(_) => Err(StorageError::TimedOut),
        }
    }

    async fn wait_for_replication(
        &self,
        cid: StorageCid,
        min_replicas: usize,
    ) -> Result<ReplicationReceipt, StorageError> {
        let cid_text = storage_cid_string(&cid);
        let deadline = Instant::now() + self.replication_timeout;
        let mut delay = Duration::from_millis(250);

        loop {
            if let Some(status) = self.fetch_pin_status(&cid_text).await? {
                let pinned_peers = extract_pinned_peers(status);
                if pinned_peers.len() >= min_replicas {
                    return Ok(ReplicationReceipt {
                        cid,
                        required_replicas: min_replicas,
                        pinned_peers,
                    });
                }
            }

            if Instant::now() >= deadline {
                return Err(StorageError::ReplicationInsufficient);
            }
            sleep(delay.min(self.replication_poll_interval)).await;
            delay = delay.saturating_mul(2).min(Duration::from_secs(2));
        }
    }

    /// Checks existing Cluster pin quorum and root-block integrity without
    /// initiating a new pin for an unvalidated caller-supplied CID.
    async fn verify_existing_replication(
        &self,
        cid: StorageCid,
        min_replicas: usize,
    ) -> Result<ReplicationReceipt, StorageError> {
        if min_replicas == 0 || min_replicas > MAX_REPLICA_COUNT {
            return Err(StorageError::InvalidReplicaCount);
        }
        let cid_text = storage_cid_string(&cid);
        let Some(status) = self.fetch_pin_status(&cid_text).await? else {
            return Err(StorageError::ReplicationInsufficient);
        };
        let pinned_peers = extract_pinned_peers(status);
        if pinned_peers.len() < min_replicas {
            return Err(StorageError::ReplicationInsufficient);
        }
        self.verify_root_block(&cid_text).await?;
        Ok(ReplicationReceipt {
            cid,
            required_replicas: min_replicas,
            pinned_peers,
        })
    }

    async fn open_reader(&self, command: &str, cid: &str) -> Result<StorageReader, StorageError> {
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let mut saw_retryable = false;
            for base in &self.kubo_api_urls {
                let url = base
                    .join(&format!("api/v0/{command}"))
                    .map_err(|_| StorageError::InvalidPackage)?;
                let response = match self.client.post(url).query(&[("arg", cid)]).send().await {
                    Ok(response) => response,
                    Err(_) => {
                        saw_retryable = true;
                        continue;
                    }
                };
                let status = response.status();
                if !status.is_success() {
                    if is_retryable_http_status(status) {
                        saw_retryable = true;
                    }
                    continue;
                }
                let stream = response
                    .bytes_stream()
                    .map_err(|error| io::Error::other(error.to_string()));
                let reader = StreamReader::new(stream);
                return Ok(Box::pin(reader));
            }
            if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                break;
            }
            sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        Err(StorageError::TransportUnavailable)
    }

    async fn verify_cid_retrievable(&self, cid: &StorageCid) -> Result<(), StorageError> {
        let cid_text = storage_cid_string(cid);
        let command = match cid {
            StorageCid::Content(_) => "dag/export",
            StorageCid::EnvelopeSet(_) => "cat",
        };
        let mut reader = self.open_reader(command, &cid_text).await?;
        let mut total_bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|_| StorageError::IntegrityCheckFailed)?;
            if read == 0 {
                break;
            }
            total_bytes = total_bytes
                .checked_add(read as u64)
                .ok_or(StorageError::SizeLimitExceeded)?;
            if total_bytes > self.max_upload_bytes.saturating_add(4 * 1024 * 1024) {
                return Err(StorageError::SizeLimitExceeded);
            }
        }
        if total_bytes == 0 {
            return Err(StorageError::IntegrityCheckFailed);
        }
        self.verify_root_block(&cid_text).await
    }

    async fn verify_root_block(&self, cid_text: &str) -> Result<(), StorageError> {
        let expected = cid::Cid::try_from(cid_text).map_err(|_| StorageError::InvalidCid)?;
        let mut backoff = RETRY_INITIAL_BACKOFF;
        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let mut invalid_block = false;
            let mut saw_retryable = false;
            for base in &self.kubo_api_urls {
                let url = base
                    .join("api/v0/block/get")
                    .map_err(|_| StorageError::InvalidPackage)?;
                let response = match self
                    .client
                    .post(url)
                    .query(&[("arg", cid_text)])
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        saw_retryable = true;
                        continue;
                    }
                };
                let status = response.status();
                if !status.is_success() {
                    if is_retryable_http_status(status) {
                        saw_retryable = true;
                    }
                    continue;
                }
                let block = bounded_response_body(response, ROOT_BLOCK_LIMIT_BYTES).await?;
                if verify_sha256_cid(&expected, &block) {
                    return Ok(());
                }
                invalid_block = true;
            }
            if invalid_block {
                return Err(StorageError::IntegrityCheckFailed);
            }
            if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                break;
            }
            sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        Err(StorageError::TransportUnavailable)
    }
}

impl BlobStore for IpfsClusterStore {
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
            let manifest_cid = raw_chunk_cid(&manifest_bytes)?;
            let mut bytes_written =
                u64::try_from(manifest_bytes.len()).map_err(|_| StorageError::SizeLimitExceeded)?;
            let mut form = Form::new().part(
                "file",
                Part::bytes(manifest_bytes)
                    .file_name("manifest.json")
                    .mime_str("application/json")
                    .map_err(|_| StorageError::InvalidPackage)?,
            );

            for chunk in chunks {
                bytes_written = bytes_written
                    .checked_add(chunk.ciphertext_bytes())
                    .ok_or(StorageError::SizeLimitExceeded)?;
                if bytes_written > self.max_upload_bytes {
                    return Err(StorageError::SizeLimitExceeded);
                }
                let filename = format!("chunks/{:08}", chunk.index());
                let ciphertext_bytes = chunk.ciphertext_bytes();
                let reader = chunk.into_reader().take(ciphertext_bytes.saturating_add(1));
                let stream = ReaderStream::with_capacity(reader, 64 * 1024);
                let body = reqwest::Body::wrap_stream(stream);
                let part = Part::stream_with_length(body, ciphertext_bytes)
                    .file_name(filename)
                    .mime_str("application/octet-stream")
                    .map_err(|_| StorageError::InvalidPackage)?;
                form = form.part("file", part);
            }
            if bytes_written > self.max_upload_bytes {
                return Err(StorageError::SizeLimitExceeded);
            }

            let peer = self.select_healthy_kubo_url().await?;
            let root_cid = self
                .add_to_peer(peer, form, true, Some((&manifest, &manifest_cid)))
                .await
                .map_err(|(err, _)| err)?;
            let cid = ContentCid::parse(&root_cid).map_err(|_| StorageError::InvalidCid)?;
            let replication = self
                .pin_and_wait(StorageCid::Content(cid.clone()), min_replicas)
                .await?;
            self.verify_root_block(&cid.to_string()).await?;
            Ok(StoredContent {
                cid,
                bytes_written,
                replication,
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
            if byte_length == 0 || byte_length > self.max_upload_bytes {
                return Err(StorageError::SizeLimitExceeded);
            }
            let mut bytes = Vec::with_capacity(usize::try_from(byte_length).unwrap_or(0));
            reader
                .take(byte_length.saturating_add(1))
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| StorageError::InvalidPackage)?;
            if bytes.len() as u64 != byte_length {
                return Err(StorageError::InvalidPackage);
            }
            // Envelope sets are single raw-leaf objects under `chunker=size-1048592`
            // (<= 512 KiB), so Kubo must return the exact raw SHA-256 CID.
            let expected_cid = raw_chunk_cid(&bytes)?;

            let mut uploaded_cid = None;
            let mut backoff = RETRY_INITIAL_BACKOFF;
            'attempts: for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
                let mut saw_retryable = false;
                for peer in &self.kubo_api_urls {
                    let part = Part::bytes(bytes.clone())
                        .file_name("envelope-set.json")
                        .mime_str("application/json")
                        .map_err(|_| StorageError::InvalidPackage)?;
                    let form = Form::new().part("file", part);
                    match self.add_to_peer(peer, form, false, None).await {
                        Ok(cid) => {
                            if cid != expected_cid {
                                return Err(StorageError::IntegrityCheckFailed);
                            }
                            uploaded_cid = Some(cid);
                            break 'attempts;
                        }
                        Err((StorageError::TransportUnavailable, retryable)) => {
                            if retryable {
                                saw_retryable = true;
                            }
                            continue;
                        }
                        Err((other, _)) => return Err(other),
                    }
                }
                if !saw_retryable || attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
                    break;
                }
                sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
            let cid = uploaded_cid.ok_or(StorageError::TransportUnavailable)?;
            let cid = EnvelopeSetCid::parse(&cid).map_err(|_| StorageError::InvalidCid)?;
            let replication = self
                .pin_and_wait(StorageCid::EnvelopeSet(cid.clone()), min_replicas)
                .await?;
            self.verify_root_block(&cid.to_string()).await?;
            Ok(StoredEnvelopeSet {
                cid,
                bytes_written: byte_length,
                replication,
            })
        })
    }

    fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader> {
        Box::pin(async move { self.open_reader("dag/export", &cid.to_string()).await })
    }

    fn get_envelope_set<'a>(&'a self, cid: &'a EnvelopeSetCid) -> StorageFuture<'a, StorageReader> {
        Box::pin(async move { self.open_reader("cat", &cid.to_string()).await })
    }

    fn ensure_replication<'a>(
        &'a self,
        cid: StorageCid,
        min_replicas: usize,
    ) -> StorageFuture<'a, ReplicationReceipt> {
        Box::pin(async move { self.verify_existing_replication(cid, min_replicas).await })
    }

    fn verify_retrievable<'a>(&'a self, cid: StorageCid) -> StorageFuture<'a, ()> {
        Box::pin(async move { self.verify_cid_retrievable(&cid).await })
    }

    fn unpin<'a>(&'a self, cid: StorageCid) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            let cid_text = storage_cid_string(&cid);
            self.delete_pin(&cid_text).await
        })
    }

    fn health_status<'a>(&'a self) -> StorageFuture<'a, ports::StorageHealthStatus> {
        Box::pin(async move { Ok(self.probe_storage_health().await) })
    }
}

fn extract_pinned_peers(status: ClusterPinStatus) -> Vec<String> {
    let mut pinned_peers = status
        .peer_map
        .into_iter()
        .filter_map(|(peer_id, peer)| {
            (!peer_id.is_empty() && peer.status.eq_ignore_ascii_case("pinned")).then_some(peer_id)
        })
        .collect::<Vec<_>>();
    pinned_peers.sort();
    pinned_peers.dedup();
    pinned_peers
}

fn parse_add_output(
    output: &[u8],
    wrap_with_directory: bool,
    expected_content: Option<(&EncryptedFileManifest, &str)>,
) -> Result<String, StorageError> {
    let mut root = None;
    let mut files = HashMap::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let entry: AddResponseLine =
            serde_json::from_slice(line).map_err(|_| StorageError::InvalidResponse)?;
        let cid = ContentCid::parse(&entry.hash).map_err(|_| StorageError::InvalidCid)?;
        if entry.name.is_empty() {
            if root.replace(cid.to_string()).is_some() {
                return Err(StorageError::InvalidResponse);
            }
        } else if files.insert(entry.name, cid).is_some() {
            return Err(StorageError::InvalidResponse);
        }
    }

    let root_cid = if wrap_with_directory {
        root.ok_or(StorageError::InvalidResponse)?
    } else {
        if root.is_some() {
            return Err(StorageError::InvalidResponse);
        }
        let cid = files
            .remove("envelope-set.json")
            .ok_or(StorageError::InvalidResponse)?
            .to_string();
        if !files.is_empty() {
            return Err(StorageError::InvalidResponse);
        }
        cid
    };

    if let Some((manifest, expected_manifest_cid)) = expected_content {
        let returned_manifest = files
            .remove("manifest.json")
            .ok_or(StorageError::InvalidResponse)?;
        if returned_manifest.to_string() != expected_manifest_cid {
            return Err(StorageError::IntegrityCheckFailed);
        }
        for chunk in manifest.chunks() {
            let name = format!("chunks/{:08}", chunk.index());
            let returned = files.remove(&name).ok_or(StorageError::InvalidResponse)?;
            if returned != *chunk.cid() {
                return Err(StorageError::IntegrityCheckFailed);
            }
        }
        if !manifest.chunks().is_empty() {
            // Kubo emits an intermediate UnixFS directory entry for `chunks`
            // when wrapping `chunks/00000001..N` with a root directory.
            files.remove("chunks");
        }
        if !files.is_empty() {
            return Err(StorageError::InvalidResponse);
        }
    }

    let root_cid = ContentCid::parse(&root_cid).map_err(|_| StorageError::InvalidCid)?;
    Ok(root_cid.to_string())
}

async fn bounded_response_body(
    response: Response,
    max_bytes: usize,
) -> Result<Vec<u8>, StorageError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(StorageError::InvalidResponse);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StorageError::TransportUnavailable)?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(StorageError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn storage_cid_string(cid: &StorageCid) -> String {
    match cid {
        StorageCid::Content(cid) => cid.to_string(),
        StorageCid::EnvelopeSet(cid) => cid.to_string(),
    }
}

fn parse_http_url(value: &str) -> Result<Url, StorageError> {
    let mut url = Url::parse(value).map_err(|_| StorageError::InvalidPackage)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(StorageError::InvalidPackage);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(StorageError::InvalidPackage);
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn env_u64(name: &str, default: u64) -> Result<u64, StorageError> {
    env::var(name).map_or(Ok(default), |value| {
        value.parse().map_err(|_| StorageError::InvalidPackage)
    })
}

fn raw_chunk_cid(bytes: &[u8]) -> Result<String, StorageError> {
    crypto::raw_sha256_cid(bytes)
        .map(|cid| cid.to_string())
        .map_err(|_| StorageError::IntegrityCheckFailed)
}

#[derive(Deserialize)]
struct AddResponseLine {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hash")]
    hash: String,
}

#[derive(Deserialize)]
struct ClusterPinStatus {
    cid: String,
    peer_map: HashMap<String, ClusterPeerStatus>,
}

#[derive(Deserialize)]
struct ClusterPeerStatus {
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{EncryptedChunkRef, NoncePrefix};
    use domain::{EpochId, FileId, ManifestHash, VersionNumber};
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    #[test]
    fn storage_debug_redacts_credentials_and_addresses() {
        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec!["http://localhost:5001".to_owned()],
            cluster_api_urls: vec!["http://localhost:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("rrfs-admin", "secret"),
            request_timeout: Duration::from_secs(1),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(50),
            max_upload_bytes: 1024,
        })
        .unwrap();
        let debug = format!("{store:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("localhost"));
    }

    #[test]
    fn rejects_non_http_endpoints_embedded_credentials_and_invalid_quorum_configuration() {
        for bad_url in [
            "file:///tmp/ipfs",
            "http://user:secret@localhost:5001",
            "http://localhost:5001/?token=abc",
            "http://localhost:5001/#frag",
        ] {
            assert!(
                IpfsClusterStore::new(IpfsConfig {
                    kubo_api_urls: vec![bad_url.to_owned()],
                    cluster_api_urls: vec!["http://localhost:9094".to_owned()],
                    cluster_credentials: ClusterCredentials::new("user", "password"),
                    request_timeout: Duration::from_secs(1),
                    replication_timeout: Duration::from_secs(1),
                    replication_poll_interval: Duration::from_millis(50),
                    max_upload_bytes: 1024,
                })
                .is_err()
            );
        }
        assert!(
            IpfsClusterStore::new(IpfsConfig {
                kubo_api_urls: vec!["http://localhost:5001".to_owned()],
                cluster_api_urls: vec![],
                cluster_credentials: ClusterCredentials::new("user", "password"),
                request_timeout: Duration::from_secs(1),
                replication_timeout: Duration::from_secs(1),
                replication_poll_interval: Duration::from_millis(50),
                max_upload_bytes: 1024,
            })
            .is_err()
        );
        assert!(
            IpfsClusterStore::new(IpfsConfig {
                kubo_api_urls: vec!["http://localhost:5001".to_owned()],
                cluster_api_urls: vec!["http://localhost:9094".to_owned()],
                cluster_credentials: ClusterCredentials::new("", "password"),
                request_timeout: Duration::from_secs(1),
                replication_timeout: Duration::from_secs(1),
                replication_poll_interval: Duration::from_millis(50),
                max_upload_bytes: 1024,
            })
            .is_err()
        );
        assert!(
            IpfsClusterStore::new(IpfsConfig {
                kubo_api_urls: vec!["http://localhost:5001".to_owned()],
                cluster_api_urls: vec!["http://localhost:9094".to_owned()],
                cluster_credentials: ClusterCredentials::new("user", "password"),
                request_timeout: Duration::ZERO,
                replication_timeout: Duration::from_secs(1),
                replication_poll_interval: Duration::from_millis(50),
                max_upload_bytes: 1024,
            })
            .is_err()
        );
    }

    #[test]
    fn accepts_add_responses_only_when_root_and_chunk_cids_are_canonical() {
        let cid = ContentCid::parse(
            &cid::Cid::new_v1(
                0x55,
                cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap(),
            )
            .to_string(),
        )
        .unwrap();
        let line =
            format!("{{\"Name\":\"envelope-set.json\",\"Hash\":\"{cid}\",\"Size\":\"3\"}}\n");
        assert_eq!(
            parse_add_output(line.as_bytes(), false, None).unwrap(),
            cid.to_string()
        );
    }

    #[tokio::test]
    async fn retries_retrieval_on_the_next_kubo_node_after_http_failure() {
        let failed_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let failed_address = failed_node.local_addr().unwrap();
        let failed_server = tokio::spawn(async move {
            let (mut socket, _) = failed_node.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let healthy_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy_address = healthy_node.local_addr().unwrap();
        let healthy_server = tokio::spawn(async move {
            let (mut socket, _) = healthy_node.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
                )
                .await
                .unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![
                format!("http://{failed_address}"),
                format!("http://{healthy_address}"),
            ],
            cluster_api_urls: vec!["http://127.0.0.1:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        let mut reader = store.open_reader("cat", "bafy-test").await.unwrap();
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"payload");

        failed_server.await.unwrap();
        healthy_server.await.unwrap();
    }

    #[tokio::test]
    async fn pin_wait_requires_distinct_authenticated_cluster_peers_and_fails_over() {
        let bad_cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_cluster_addr = bad_cluster.local_addr().unwrap();
        let bad_cluster_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = bad_cluster.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cid = ContentCid::parse(&raw_chunk_cid(b"pinned payload").unwrap()).unwrap();
        let cid_text = cid.to_string();
        let server_cid = cid_text.clone();
        let server = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_mock_http_request(&mut socket).await;
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: basic")
                );
                assert!(request.contains("dXNlcjpwYXNzd29yZA=="));
                if request_index == 0 {
                    assert!(request.starts_with("POST /pins/"));
                    assert!(request.contains("replication-min=2"));
                    assert!(request.contains("replication-max=2"));
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    assert!(request.starts_with(&format!("GET /pins/{server_cid} ")));
                    let body = serde_json::json!({
                        "cid": server_cid,
                        "peer_map": {
                            "peer-one": { "status": "pinned" },
                            "peer-two": { "status": "pinned" },
                            "peer-three": { "status": "pin_error" }
                        }
                    })
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                }
            }
        });
        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec!["http://127.0.0.1:5001".to_owned()],
            cluster_api_urls: vec![
                format!("http://{bad_cluster_addr}"),
                format!("http://{address}"),
            ],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();

        let receipt = store
            .pin_and_wait(StorageCid::Content(cid), 2)
            .await
            .unwrap();
        assert_eq!(receipt.required_replicas, 2);
        assert_eq!(receipt.pinned_peers, vec!["peer-one", "peer-two"]);
        bad_cluster_server.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_http_redirects_on_authenticated_cluster_requests() {
        let redirect_cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = redirect_cluster.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = redirect_cluster.accept().await.unwrap();
            let _ = read_mock_http_request(&mut socket).await;
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec!["http://127.0.0.1:5001".to_owned()],
            cluster_api_urls: vec![format!("http://{addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        let cid = ContentCid::parse(&raw_chunk_cid(b"x").unwrap()).unwrap();
        assert_eq!(
            store.pin_and_wait(StorageCid::Content(cid), 2).await,
            Err(StorageError::TransportUnavailable)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ensure_replication_verifies_existing_pins_and_root_block_without_blind_repin() {
        let payload = b"verified-root-block".to_vec();
        let cid = ContentCid::parse(&raw_chunk_cid(&payload).unwrap()).unwrap();
        let cid_str = cid.to_string();

        let cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cluster_addr = cluster.local_addr().unwrap();
        let cluster_cid = cid_str.clone();
        let cluster_server = tokio::spawn(async move {
            // Request 1: 404 (not pinned) -> ensure_replication must fail with ReplicationInsufficient (NOT POST /pins).
            let (mut s1, _) = cluster.accept().await.unwrap();
            let req1 = read_mock_http_request(&mut s1).await;
            assert!(req1.starts_with(&format!("GET /pins/{cluster_cid} ")));
            s1.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

            // Request 2: only 1 peer pinned (< 2) -> ReplicationInsufficient.
            let (mut s2, _) = cluster.accept().await.unwrap();
            let req2 = read_mock_http_request(&mut s2).await;
            assert!(req2.starts_with(&format!("GET /pins/{cluster_cid} ")));
            let body2 = serde_json::json!({
                "cid": cluster_cid,
                "peer_map": { "peer-1": { "status": "pinned" } }
            })
            .to_string();
            s2.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body2.len(),
                    body2
                )
                .as_bytes(),
            )
            .await
            .unwrap();

            // Request 3: 2 peers pinned -> succeeds once Kubo root block verifies.
            let (mut s3, _) = cluster.accept().await.unwrap();
            let req3 = read_mock_http_request(&mut s3).await;
            assert!(req3.starts_with(&format!("GET /pins/{cluster_cid} ")));
            let body3 = serde_json::json!({
                "cid": cluster_cid,
                "peer_map": {
                    "peer-1": { "status": "pinned" },
                    "peer-2": { "status": "pinned" }
                }
            })
            .to_string();
            s3.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body3.len(),
                    body3
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });

        let kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubo_addr = kubo.local_addr().unwrap();
        let kubo_payload = payload.clone();
        let kubo_server = tokio::spawn(async move {
            let (mut s, _) = kubo.accept().await.unwrap();
            let req = read_mock_http_request(&mut s).await;
            assert!(req.starts_with("POST /api/v0/block/get?"));
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    kubo_payload.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            s.write_all(&kubo_payload).await.unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{kubo_addr}")],
            cluster_api_urls: vec![format!("http://{cluster_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();

        assert_eq!(
            store
                .ensure_replication(StorageCid::Content(cid.clone()), 2)
                .await,
            Err(StorageError::ReplicationInsufficient)
        );
        assert_eq!(
            store
                .ensure_replication(StorageCid::Content(cid.clone()), 2)
                .await,
            Err(StorageError::ReplicationInsufficient)
        );
        let receipt = store
            .ensure_replication(StorageCid::Content(cid), 2)
            .await
            .unwrap();
        assert_eq!(receipt.pinned_peers, vec!["peer-1", "peer-2"]);

        cluster_server.await.unwrap();
        kubo_server.await.unwrap();
    }

    #[tokio::test]
    async fn put_envelope_set_rejects_mismatched_cid_from_kubo() {
        let envelope_bytes = b"{\"schema\":\"rrds.key-envelope-set.v1\"}".to_vec();
        let wrong_cid = raw_chunk_cid(b"completely-different-bytes").unwrap();

        let kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubo_addr = kubo.local_addr().unwrap();
        let kubo_server = tokio::spawn(async move {
            let (mut s, _) = kubo.accept().await.unwrap();
            let _ = read_mock_http_request(&mut s).await;
            let body = format!("{{\"Name\":\"envelope-set.json\",\"Hash\":\"{wrong_cid}\"}}\n");
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{kubo_addr}")],
            cluster_api_urls: vec!["http://127.0.0.1:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();

        assert_eq!(
            store
                .put_envelope_set(
                    Box::pin(std::io::Cursor::new(envelope_bytes.clone())),
                    envelope_bytes.len() as u64,
                    2
                )
                .await,
            Err(StorageError::IntegrityCheckFailed)
        );
        kubo_server.await.unwrap();
    }

    #[test]
    fn rejects_content_add_responses_with_manifest_or_chunk_cid_mismatches() {
        let ciphertext = [0xa5; 17];
        let chunk_cid = ContentCid::parse(&raw_chunk_cid(&ciphertext).unwrap()).unwrap();
        let manifest = EncryptedFileManifest::new(
            FileId::from_bytes([1; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([2; 32]),
            NoncePrefix::from_bytes([3; 8]),
            crypto::DEFAULT_CHUNK_SIZE_BYTES as u32,
            vec![EncryptedChunkRef::new(1, chunk_cid.clone(), ciphertext.len() as u64).unwrap()],
            None,
        )
        .unwrap();
        let manifest_cid = raw_chunk_cid(&manifest.canonical_bytes().unwrap()).unwrap();
        let root_cid = cid::Cid::new_v1(
            0x70,
            cid::multihash::Multihash::<64>::wrap(0x12, &[9; 32]).unwrap(),
        );
        let valid = format!(
            "{{\"Name\":\"\",\"Hash\":\"{root_cid}\"}}\n\
             {{\"Name\":\"manifest.json\",\"Hash\":\"{manifest_cid}\"}}\n\
             {{\"Name\":\"chunks/00000001\",\"Hash\":\"{chunk_cid}\"}}\n\
             {{\"Name\":\"chunks\",\"Hash\":\"{root_cid}\"}}\n"
        );
        assert!(parse_add_output(valid.as_bytes(), true, Some((&manifest, &manifest_cid))).is_ok());

        let wrong_manifest = format!(
            "{{\"Name\":\"\",\"Hash\":\"{root_cid}\"}}\n\
             {{\"Name\":\"manifest.json\",\"Hash\":\"{root_cid}\"}}\n\
             {{\"Name\":\"chunks/00000001\",\"Hash\":\"{chunk_cid}\"}}\n"
        );
        assert_eq!(
            parse_add_output(
                wrong_manifest.as_bytes(),
                true,
                Some((&manifest, &manifest_cid))
            )
            .unwrap_err(),
            StorageError::IntegrityCheckFailed
        );

        let wrong_chunk = format!(
            "{{\"Name\":\"\",\"Hash\":\"{root_cid}\"}}\n\
             {{\"Name\":\"manifest.json\",\"Hash\":\"{manifest_cid}\"}}\n\
             {{\"Name\":\"chunks/00000001\",\"Hash\":\"{root_cid}\"}}\n"
        );
        assert_eq!(
            parse_add_output(
                wrong_chunk.as_bytes(),
                true,
                Some((&manifest, &manifest_cid))
            )
            .unwrap_err(),
            StorageError::IntegrityCheckFailed
        );
    }

    #[test]
    fn computes_raw_sha256_cid_for_a_ciphertext_chunk() {
        let payload = [0xabu8; 17];
        let cid = raw_chunk_cid(&payload).unwrap();
        assert_eq!(
            cid,
            "bafkreiewgvgk44czrxzm3u42r3ypxj76o6uebclaabcq7wsnlgaotpvcx4"
        );
        let cid = cid::Cid::try_from(cid.as_str()).unwrap();
        assert!(verify_sha256_cid(&cid, &payload));
        assert!(!verify_sha256_cid(&cid, b"different block"));
    }

    #[test]
    fn bounds_and_validates_cluster_pin_status_peers() {
        let status: ClusterPinStatus = serde_json::from_value(serde_json::json!({
            "cid": "bafy-test",
            "peer_map": {
                "peer-a": { "status": "pinned" },
                "peer-b": { "status": "PINNED" },
                "peer-c": { "status": "pin_error" }
            }
        }))
        .unwrap();
        assert_eq!(extract_pinned_peers(status), vec!["peer-a", "peer-b"]);
    }

    async fn read_mock_http_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end;
        loop {
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let headers = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = socket.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        headers
    }

    async fn spawn_mock_cluster(
        expected_cid: String,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let headers = read_mock_http_request(&mut socket).await;
                if request_index == 0 {
                    assert!(headers.starts_with(&format!("POST /pins/{expected_cid}")));
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    assert!(headers.starts_with(&format!("GET /pins/{expected_cid} ")));
                    let body = serde_json::json!({
                        "cid": expected_cid,
                        "peer_map": {
                            "peer-one": { "status": "pinned" },
                            "peer-two": { "status": "pinned" }
                        }
                    })
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn put_envelope_set_fails_over_across_kubo_peers_and_pins() {
        let envelope_bytes = b"{\"schema\":\"rrds.key-envelope-set.v1\"}".to_vec();
        let expected_cid = raw_chunk_cid(&envelope_bytes).unwrap();

        let bad_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_kubo.local_addr().unwrap();
        let bad_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = bad_kubo.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });

        let good_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_kubo.local_addr().unwrap();
        let good_cid = expected_cid.clone();
        let good_bytes = envelope_bytes.clone();
        let good_server = tokio::spawn(async move {
            let (mut socket, _) = good_kubo.accept().await.unwrap();
            let headers = read_mock_http_request(&mut socket).await;
            assert!(headers.starts_with("POST /api/v0/add?"));
            let add_body = format!("{{\"Name\":\"envelope-set.json\",\"Hash\":\"{good_cid}\"}}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                add_body.len(),
                add_body
            );
            socket.write_all(response.as_bytes()).await.unwrap();

            let (mut socket, _) = good_kubo.accept().await.unwrap();
            let headers = read_mock_http_request(&mut socket).await;
            assert!(headers.starts_with("POST /api/v0/block/get?"));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                good_bytes.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(&good_bytes).await.unwrap();
        });

        let (cluster_addr, cluster_server) = spawn_mock_cluster(expected_cid.clone()).await;

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{bad_addr}"), format!("http://{good_addr}")],
            cluster_api_urls: vec![format!("http://{cluster_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(2),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024 * 1024,
        })
        .unwrap();

        let stored = store
            .put_envelope_set(
                Box::pin(std::io::Cursor::new(envelope_bytes.clone())),
                envelope_bytes.len() as u64,
                2,
            )
            .await
            .unwrap();
        assert_eq!(stored.cid.to_string(), expected_cid);
        assert_eq!(
            stored.replication.pinned_peers,
            vec!["peer-one", "peer-two"]
        );

        bad_server.await.unwrap();
        good_server.await.unwrap();
        cluster_server.await.unwrap();
    }

    #[tokio::test]
    async fn put_content_fails_over_via_health_probe_to_second_kubo_peer() {
        let ciphertext = vec![0x5cu8; 32];
        let chunk_cid = ContentCid::parse(&raw_chunk_cid(&ciphertext).unwrap()).unwrap();
        let manifest = EncryptedFileManifest::new(
            FileId::from_bytes([4; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([5; 32]),
            NoncePrefix::from_bytes([6; 8]),
            crypto::DEFAULT_CHUNK_SIZE_BYTES as u32,
            vec![EncryptedChunkRef::new(1, chunk_cid.clone(), ciphertext.len() as u64).unwrap()],
            None,
        )
        .unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let manifest_cid = raw_chunk_cid(&manifest_bytes).unwrap();
        let root_block = b"mock-unixfs-root-dir-block".to_vec();
        let root_cid = raw_chunk_cid(&root_block).unwrap();

        let bad_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_kubo.local_addr().unwrap();
        let bad_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = bad_kubo.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });

        let good_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_kubo.local_addr().unwrap();
        let good_root_cid = root_cid.clone();
        let good_manifest_cid = manifest_cid.clone();
        let good_chunk_cid = chunk_cid.to_string();
        let good_root_block = root_block.clone();
        let good_server = tokio::spawn(async move {
            let (mut socket, _) = good_kubo.accept().await.unwrap();
            let headers = read_mock_http_request(&mut socket).await;
            assert!(headers.starts_with("POST /api/v0/id"));
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"ID\":\"k2\"}\r\n",
                )
                .await
                .unwrap();

            let (mut socket, _) = good_kubo.accept().await.unwrap();
            let headers = read_mock_http_request(&mut socket).await;
            assert!(headers.starts_with("POST /api/v0/add?"));
            let add_body = format!(
                "{{\"Name\":\"\",\"Hash\":\"{good_root_cid}\"}}\n\
                 {{\"Name\":\"manifest.json\",\"Hash\":\"{good_manifest_cid}\"}}\n\
                 {{\"Name\":\"chunks/00000001\",\"Hash\":\"{good_chunk_cid}\"}}\n"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                add_body.len(),
                add_body
            );
            socket.write_all(response.as_bytes()).await.unwrap();

            let (mut socket, _) = good_kubo.accept().await.unwrap();
            let headers = read_mock_http_request(&mut socket).await;
            assert!(headers.starts_with("POST /api/v0/block/get?"));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                good_root_block.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(&good_root_block).await.unwrap();
        });

        let (cluster_addr, cluster_server) = spawn_mock_cluster(root_cid.clone()).await;

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{bad_addr}"), format!("http://{good_addr}")],
            cluster_api_urls: vec![format!("http://{cluster_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(2),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024 * 1024,
        })
        .unwrap();

        let package = ContentPackage::new(
            manifest,
            vec![ports::ContentChunk::new(
                1,
                ciphertext.len() as u64,
                Box::pin(std::io::Cursor::new(ciphertext)),
            )],
        )
        .unwrap();
        let stored = store.put_content(package, 2).await.unwrap();
        assert_eq!(stored.cid.to_string(), root_cid);
        assert_eq!(
            stored.replication.pinned_peers,
            vec!["peer-one", "peer-two"]
        );

        bad_server.await.unwrap();
        good_server.await.unwrap();
        cluster_server.await.unwrap();
    }

    #[tokio::test]
    async fn verify_retrievable_handles_failover_corrupted_root_block_and_empty_stream() {
        let valid_payload = b"retrievable-root-block".to_vec();
        let cid = ContentCid::parse(&raw_chunk_cid(&valid_payload).unwrap()).unwrap();

        // 1. Failing node 1 (500 on both dag/export and block/get) + healthy node 2 -> succeeds on failover.
        let bad_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_node.local_addr().unwrap();
        let bad_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = bad_node.accept().await.unwrap();
                let _ = read_mock_http_request(&mut s).await;
                s.write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            }
        });

        let good_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_node.local_addr().unwrap();
        let good_payload = valid_payload.clone();
        let good_server = tokio::spawn(async move {
            let (mut s1, _) = good_node.accept().await.unwrap();
            let req1 = read_mock_http_request(&mut s1).await;
            assert!(req1.starts_with("POST /api/v0/dag/export?"));
            s1.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ncar-bytes",
            )
            .await
            .unwrap();

            let (mut s2, _) = good_node.accept().await.unwrap();
            let req2 = read_mock_http_request(&mut s2).await;
            assert!(req2.starts_with("POST /api/v0/block/get?"));
            s2.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    good_payload.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            s2.write_all(&good_payload).await.unwrap();
        });

        let failover_store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{bad_addr}"), format!("http://{good_addr}")],
            cluster_api_urls: vec!["http://127.0.0.1:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        failover_store
            .verify_retrievable(StorageCid::Content(cid.clone()))
            .await
            .expect("verify_retrievable should fail over to healthy Kubo node");
        bad_server.await.unwrap();
        good_server.await.unwrap();

        // 2. Non-empty stream + corrupted root block bytes -> IntegrityCheckFailed.
        let corrupt_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let corrupt_addr = corrupt_node.local_addr().unwrap();
        let corrupt_server = tokio::spawn(async move {
            let (mut s1, _) = corrupt_node.accept().await.unwrap();
            let req1 = read_mock_http_request(&mut s1).await;
            assert!(req1.starts_with("POST /api/v0/dag/export?"));
            s1.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ncar-bytes",
            )
            .await
            .unwrap();

            let (mut s2, _) = corrupt_node.accept().await.unwrap();
            let req2 = read_mock_http_request(&mut s2).await;
            assert!(req2.starts_with("POST /api/v0/block/get?"));
            let tampered = b"tampered-root-block!!!";
            s2.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    tampered.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            s2.write_all(tampered).await.unwrap();
        });
        let corrupt_store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{corrupt_addr}")],
            cluster_api_urls: vec!["http://127.0.0.1:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        assert_eq!(
            corrupt_store
                .verify_retrievable(StorageCid::Content(cid.clone()))
                .await,
            Err(StorageError::IntegrityCheckFailed)
        );
        corrupt_server.await.unwrap();

        // 3. Empty stream on dag/export -> IntegrityCheckFailed, and HTTP 503 -> TransportUnavailable.
        let empty_node = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let empty_addr = empty_node.local_addr().unwrap();
        let empty_server = tokio::spawn(async move {
            let (mut s, _) = empty_node.accept().await.unwrap();
            let req = read_mock_http_request(&mut s).await;
            assert!(req.starts_with("POST /api/v0/dag/export?"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let (mut s2, _) = empty_node.accept().await.unwrap();
            let _ = read_mock_http_request(&mut s2).await;
            s2.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });
        let empty_store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{empty_addr}")],
            cluster_api_urls: vec!["http://127.0.0.1:9094".to_owned()],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        assert_eq!(
            empty_store
                .verify_retrievable(StorageCid::Content(cid.clone()))
                .await,
            Err(StorageError::IntegrityCheckFailed)
        );
        assert_eq!(
            empty_store
                .verify_retrievable(StorageCid::Content(cid))
                .await,
            Err(StorageError::TransportUnavailable)
        );
        empty_server.await.unwrap();
    }

    #[tokio::test]
    async fn unpin_handles_success_idempotent_404_and_auth_failure() {
        let cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cluster_addr = cluster.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // 1. 200 OK
            let (mut s1, _) = cluster.accept().await.unwrap();
            let req1 = read_mock_http_request(&mut s1).await;
            assert!(req1.starts_with("DELETE /pins/"));
            s1.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            // 2. 404 Not Found -> idempotent Ok
            let (mut s2, _) = cluster.accept().await.unwrap();
            let req2 = read_mock_http_request(&mut s2).await;
            assert!(req2.starts_with("DELETE /pins/"));
            s2.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

            // 3. 401 Unauthorized -> TransportUnavailable
            let (mut s3, _) = cluster.accept().await.unwrap();
            let req3 = read_mock_http_request(&mut s3).await;
            assert!(req3.starts_with("DELETE /pins/"));
            s3.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec!["http://127.0.0.1:15001".to_owned()],
            cluster_api_urls: vec![format!("http://{cluster_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        let cid = ContentCid::parse(&raw_chunk_cid(b"orphan-blob").unwrap()).unwrap();
        store
            .unpin(StorageCid::Content(cid.clone()))
            .await
            .expect("200 OK unpin");
        store
            .unpin(StorageCid::Content(cid.clone()))
            .await
            .expect("404 Not Found unpin should be idempotent");
        assert_eq!(
            store.unpin(StorageCid::Content(cid)).await,
            Err(StorageError::TransportUnavailable)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn health_status_reports_degraded_and_healthy_kubo_and_cluster_peers() {
        let kubo_ok = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubo_ok_addr = kubo_ok.local_addr().unwrap();
        let kubo_down = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubo_down_addr = kubo_down.local_addr().unwrap();
        let cluster_ok = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cluster_ok_addr = cluster_ok.local_addr().unwrap();

        let s1 = tokio::spawn(async move {
            let (mut s, _) = kubo_ok.accept().await.unwrap();
            let req = read_mock_http_request(&mut s).await;
            assert!(req.starts_with("POST /api/v0/id"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });
        let s2 = tokio::spawn(async move {
            let (mut s, _) = kubo_down.accept().await.unwrap();
            let _ = read_mock_http_request(&mut s).await;
            s.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });
        let s3 = tokio::spawn(async move {
            let (mut s, _) = cluster_ok.accept().await.unwrap();
            let req = read_mock_http_request(&mut s).await;
            assert!(req.starts_with("GET /id"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![
                format!("http://{kubo_ok_addr}"),
                format!("http://{kubo_down_addr}"),
            ],
            cluster_api_urls: vec![format!("http://{cluster_ok_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();

        let health = store.health_status().await.unwrap();
        assert_eq!(health.healthy_kubo_peers, 1);
        assert_eq!(health.total_kubo_peers, 2);
        assert_eq!(health.healthy_cluster_peers, 1);
        assert_eq!(health.total_cluster_peers, 1);
        assert!(health.is_healthy());
        assert!(health.is_degraded());

        s1.await.unwrap();
        s2.await.unwrap();
        s3.await.unwrap();
    }

    #[tokio::test]
    async fn retries_single_kubo_and_cluster_peer_with_bounds_on_transient_503() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        // 1. Single Kubo peer returns 503 twice, then 200 OK on attempt 3.
        let kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubo_addr = kubo.local_addr().unwrap();
        let kubo_attempts = Arc::new(AtomicUsize::new(0));
        let kubo_attempts_srv = Arc::clone(&kubo_attempts);
        let kubo_srv = tokio::spawn(async move {
            for i in 0..3 {
                let (mut socket, _) = kubo.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                kubo_attempts_srv.fetch_add(1, Ordering::SeqCst);
                if i < 2 {
                    socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered",
                        )
                        .await
                        .unwrap();
                }
            }
        });

        // 2. Single Cluster peer returns 503 twice on POST /pins, then 202 Accepted on attempt 3.
        let cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cluster_addr = cluster.local_addr().unwrap();
        let cluster_attempts = Arc::new(AtomicUsize::new(0));
        let cluster_attempts_srv = Arc::clone(&cluster_attempts);
        let cluster_srv = tokio::spawn(async move {
            for i in 0..3 {
                let (mut socket, _) = cluster.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                cluster_attempts_srv.fetch_add(1, Ordering::SeqCst);
                if i < 2 {
                    socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
            }
        });

        let store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{kubo_addr}")],
            cluster_api_urls: vec![format!("http://{cluster_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();

        let mut reader = store.open_reader("cat", "bafy-retry").await.unwrap();
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"recovered");
        assert_eq!(kubo_attempts.load(Ordering::SeqCst), 3);

        let cid = raw_chunk_cid(b"retry-pin").unwrap();
        store.post_pin(&cid, 2).await.unwrap();
        assert_eq!(cluster_attempts.load(Ordering::SeqCst), 3);

        kubo_srv.await.unwrap();
        cluster_srv.await.unwrap();

        // 3. Persistent 503 stops cleanly at MAX_TRANSIENT_ATTEMPTS (3).
        let fail_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fail_kubo_addr = fail_kubo.local_addr().unwrap();
        let fail_attempts = Arc::new(AtomicUsize::new(0));
        let fail_attempts_srv = Arc::clone(&fail_attempts);
        let fail_srv = tokio::spawn(async move {
            for _ in 0..MAX_TRANSIENT_ATTEMPTS {
                let (mut socket, _) = fail_kubo.accept().await.unwrap();
                let _ = read_mock_http_request(&mut socket).await;
                fail_attempts_srv.fetch_add(1, Ordering::SeqCst);
                socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });
        let fail_store = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: vec![format!("http://{fail_kubo_addr}")],
            cluster_api_urls: vec![format!("http://{fail_kubo_addr}")],
            cluster_credentials: ClusterCredentials::new("user", "password"),
            request_timeout: Duration::from_secs(2),
            replication_timeout: Duration::from_secs(1),
            replication_poll_interval: Duration::from_millis(10),
            max_upload_bytes: 1024,
        })
        .unwrap();
        assert!(matches!(
            fail_store.open_reader("cat", "bafy-fail").await,
            Err(StorageError::TransportUnavailable)
        ));
        assert_eq!(fail_attempts.load(Ordering::SeqCst), MAX_TRANSIENT_ATTEMPTS);
        fail_srv.await.unwrap();
    }
}
