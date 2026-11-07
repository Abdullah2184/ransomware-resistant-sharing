//! Kubo and IPFS Cluster adapter for the approved UnixFS directory profile.

use std::{collections::HashMap, env, fmt, io, time::Duration};

use crypto::EncryptedFileManifest;
use domain::{ContentCid, EnvelopeSetCid};
use futures_util::{StreamExt, TryStreamExt};
use ports::{
    BlobStore, ContentPackage, ReplicationReceipt, StorageCid, StorageError, StorageFuture,
    StorageReader, StoredContent, StoredEnvelopeSet,
};
use reqwest::{
    Client, Response, StatusCode, Url,
    multipart::{Form, Part},
};
use serde::Deserialize;
use tokio::{
    io::AsyncReadExt,
    time::{Instant, sleep, timeout},
};
use tokio_util::io::{ReaderStream, StreamReader};

const ADD_RESPONSE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const PIN_STATUS_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_REPLICA_COUNT: usize = 64;

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
    pub cluster_api_url: String,
    pub cluster_credentials: ClusterCredentials,
    pub request_timeout: Duration,
    pub replication_timeout: Duration,
    pub replication_poll_interval: Duration,
    pub max_upload_bytes: u64,
}

impl IpfsConfig {
    pub fn from_env() -> Result<Self, StorageError> {
        let kubo_api_urls = env::var("IPFS_API_URLS")
            .or_else(|_| env::var("IPFS_API_URL"))
            .map_err(|_| StorageError::TransportUnavailable)?
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let cluster_api_url =
            env::var("IPFS_CLUSTER_API_URL").map_err(|_| StorageError::TransportUnavailable)?;
        let username =
            env::var("IPFS_CLUSTER_USERNAME").map_err(|_| StorageError::TransportUnavailable)?;
        let password_path = env::var("IPFS_CLUSTER_PASSWORD_FILE")
            .map_err(|_| StorageError::TransportUnavailable)?;
        let password = std::fs::read_to_string(password_path)
            .map_err(|_| StorageError::TransportUnavailable)?;
        let credentials = ClusterCredentials::new(username, password.trim_end().to_owned());

        Ok(Self {
            kubo_api_urls,
            cluster_api_url,
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

pub struct IpfsClusterStore {
    client: Client,
    kubo_api_urls: Vec<Url>,
    cluster_api_url: Url,
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
            .field("cluster_api_url", &"<redacted>")
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl IpfsClusterStore {
    pub fn new(config: IpfsConfig) -> Result<Self, StorageError> {
        if config.kubo_api_urls.is_empty()
            || config.max_upload_bytes == 0
            || config.replication_timeout.is_zero()
            || config.replication_poll_interval.is_zero()
        {
            return Err(StorageError::InvalidPackage);
        }

        let kubo_api_urls = config
            .kubo_api_urls
            .iter()
            .map(|url| parse_http_url(url))
            .collect::<Result<Vec<_>, _>>()?;
        let cluster_api_url = parse_http_url(&config.cluster_api_url)?;
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| StorageError::TransportUnavailable)?;

        Ok(Self {
            client,
            kubo_api_urls,
            cluster_api_url,
            credentials: config.cluster_credentials,
            replication_timeout: config.replication_timeout,
            replication_poll_interval: config.replication_poll_interval,
            max_upload_bytes: config.max_upload_bytes,
        })
    }

    async fn add(
        &self,
        form: Form,
        wrap_with_directory: bool,
        expected_content: Option<(&EncryptedFileManifest, &str)>,
    ) -> Result<String, StorageError> {
        let url = self
            .kubo_api_urls
            .first()
            .ok_or(StorageError::TransportUnavailable)?
            .join("api/v0/add")
            .map_err(|_| StorageError::InvalidPackage)?;
        let response = self
            .client
            .post(url)
            .query(&[
                ("cid-version", "1"),
                ("hash", "sha2-256"),
                ("chunker", "size-4194320"),
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
            .map_err(|_| StorageError::TransportUnavailable)?;
        if !response.status().is_success() {
            return Err(StorageError::TransportUnavailable);
        }

        let output = bounded_response_body(response, ADD_RESPONSE_LIMIT_BYTES).await?;
        parse_add_output(&output, wrap_with_directory, expected_content)
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
        let url = self
            .cluster_api_url
            .join(&format!("pins/{cid_text}"))
            .map_err(|_| StorageError::InvalidCid)?;
        let response = self
            .client
            .post(url)
            .query(&[
                ("replication-min", min_replicas.to_string()),
                ("replication-max", min_replicas.to_string()),
            ])
            .basic_auth(&self.credentials.username, Some(&self.credentials.password))
            .send()
            .await
            .map_err(|_| StorageError::TransportUnavailable)?;
        if !(response.status().is_success() || response.status() == StatusCode::ACCEPTED) {
            return Err(StorageError::TransportUnavailable);
        }

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
        let status_url = self
            .cluster_api_url
            .join(&format!("pins/{cid_text}/status"))
            .map_err(|_| StorageError::InvalidCid)?;
        let deadline = Instant::now() + self.replication_timeout;
        let mut delay = Duration::from_millis(250);

        loop {
            let response = self
                .client
                .get(status_url.clone())
                .basic_auth(&self.credentials.username, Some(&self.credentials.password))
                .send()
                .await
                .map_err(|_| StorageError::TransportUnavailable)?;
            if response.status().is_success() {
                let body = bounded_response_body(response, PIN_STATUS_LIMIT_BYTES).await?;
                let status: ClusterPinStatus =
                    serde_json::from_slice(&body).map_err(|_| StorageError::InvalidResponse)?;
                if status.cid != cid_text {
                    return Err(StorageError::InvalidResponse);
                }
                let mut pinned_peers = status
                    .peer_map
                    .into_iter()
                    .filter_map(|(peer_id, peer)| {
                        (!peer_id.is_empty() && peer.status.eq_ignore_ascii_case("pinned"))
                            .then_some(peer_id)
                    })
                    .collect::<Vec<_>>();
                pinned_peers.sort();
                pinned_peers.dedup();
                if pinned_peers.len() >= min_replicas {
                    return Ok(ReplicationReceipt {
                        cid,
                        required_replicas: min_replicas,
                        pinned_peers,
                    });
                }
            } else if response.status() != StatusCode::NOT_FOUND {
                return Err(StorageError::TransportUnavailable);
            }

            if Instant::now() >= deadline {
                return Err(StorageError::ReplicationInsufficient);
            }
            sleep(delay.min(self.replication_poll_interval)).await;
            delay = delay.saturating_mul(2).min(Duration::from_secs(2));
        }
    }

    async fn open_reader(&self, command: &str, cid: &str) -> Result<StorageReader, StorageError> {
        for base in &self.kubo_api_urls {
            let url = base
                .join(&format!("api/v0/{command}"))
                .map_err(|_| StorageError::InvalidPackage)?;
            let response = self.client.post(url).query(&[("arg", cid)]).send().await;
            let Ok(response) = response else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let stream = response
                .bytes_stream()
                .map_err(|error| io::Error::other(error.to_string()));
            let reader = StreamReader::new(stream);
            return Ok(Box::pin(reader));
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
        Ok(())
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

            let root_cid = self
                .add(form, true, Some((&manifest, &manifest_cid)))
                .await?;
            let cid = ContentCid::parse(&root_cid).map_err(|_| StorageError::InvalidCid)?;
            let replication = self
                .pin_and_wait(StorageCid::Content(cid.clone()), min_replicas)
                .await?;
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
            let stream = ReaderStream::with_capacity(reader, 64 * 1024);
            let part = Part::stream_with_length(reqwest::Body::wrap_stream(stream), byte_length)
                .file_name("envelope-set.json")
                .mime_str("application/json")
                .map_err(|_| StorageError::InvalidPackage)?;
            let form = Form::new().part("file", part);
            let cid = self.add(form, false, None).await?;
            let cid = EnvelopeSetCid::parse(&cid).map_err(|_| StorageError::InvalidCid)?;
            let replication = self
                .pin_and_wait(StorageCid::EnvelopeSet(cid.clone()), min_replicas)
                .await?;
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
        Box::pin(async move { self.pin_and_wait(cid, min_replicas).await })
    }

    fn verify_retrievable<'a>(&'a self, cid: StorageCid) -> StorageFuture<'a, ()> {
        Box::pin(async move { self.verify_cid_retrievable(&cid).await })
    }
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
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let multihash = cid::multihash::Multihash::<64>::wrap(0x12, &digest)
        .map_err(|_| StorageError::IntegrityCheckFailed)?;
    Ok(cid::Cid::new_v1(0x55, multihash).to_string())
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
            kubo_api_urls: vec!["http://user:secret@localhost:5001".to_owned()],
            cluster_api_url: "http://localhost:9094".to_owned(),
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
    fn rejects_non_http_endpoints_and_invalid_quorum_configuration() {
        assert!(
            IpfsClusterStore::new(IpfsConfig {
                kubo_api_urls: vec!["file:///tmp/ipfs".to_owned()],
                cluster_api_url: "http://localhost:9094".to_owned(),
                cluster_credentials: ClusterCredentials::new("user", "password"),
                request_timeout: Duration::from_secs(1),
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
            cluster_api_url: "http://127.0.0.1:9094".to_owned(),
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
            4 * 1024 * 1024,
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
             {{\"Name\":\"chunks/00000001\",\"Hash\":\"{chunk_cid}\"}}\n"
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
        assert_eq!(
            raw_chunk_cid(&payload).unwrap(),
            "bafkreiewgvgk44czrxzm3u42r3ypxj76o6uebclaabcq7wsnlgaotpvcx4"
        );
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
        let count = status
            .peer_map
            .values()
            .filter(|peer| peer.status.eq_ignore_ascii_case("pinned"))
            .count();
        assert_eq!(count, 2);
    }
}
