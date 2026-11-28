use super::*;
use crate::auth::LoginChallenge;

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
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use chain_adapter::{
        EnvelopeSetState, EnvelopeSetUpdateCall, EvmTransactionReceipt, FileHeadState,
        FileVersionState, FinalizedBlock, MemberIdentityState, RelayError, RelayOutcome,
        VersionAppendCall,
    };
    use crypto::{
        AccessLookup, ChainId, DataEncryptionKey, Eip712Domain, EnvelopeSetUpdate, KeyEnvelope,
        KeyEnvelopeEntry, KeyEnvelopeSet, LoginChallengeDigestInput, UnixDeadline, VersionAppend,
        WrapContext, raw_sha256_cid,
    };
    use domain::{
        ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash,
        MemberId, OperationNonce, ProposalId, VersionNumber,
    };
    use key_custody::DevelopmentKeyCustody;
    use ports::{
        BlobStore, ContentPackage, KeyCustodyProvider, ReplicationReceipt, StorageCid,
        StorageError, StorageFuture, StorageReader, StoredContent, StoredEnvelopeSet,
    };
    use serde_json::json;

    use super::*;
    use crate::{
        auth::parse_nonce,
        config::GatewayConfig,
        ports::{GatewayChainPort, GatewayRelayerPort, GatewayStorePort},
        store::{
            AuditEventRecord, ProjectedFile, ProjectedFolder, ProjectedVersion, encode_hex,
            source_identifier,
        },
    };
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
            _block_number: u64,
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
        fail_replication: Arc<Mutex<bool>>,
    }

    impl BlobStore for MockBlobStore {
        fn put_content<'a>(
            &'a self,
            package: ContentPackage,
            min_replicas: usize,
        ) -> StorageFuture<'a, StoredContent> {
            Box::pin(async move {
                if *self.fail_replication.lock().unwrap() {
                    return Err(StorageError::ReplicationInsufficient);
                }
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
                if *self.fail_replication.lock().unwrap() {
                    return Err(StorageError::ReplicationInsufficient);
                }
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

        fn reconcile_transaction(
            &self,
            _tx_hash: [u8; 32],
        ) -> RelayFuture<'_, Option<RelayOutcome>> {
            let result = self.execute("reconcileTransaction").map(Some);
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
            transaction_confirmation_timeout_seconds: 30,
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
                    manifest_hash: [0xdd; 32],
                },
            );
            chain.versions.insert(
                (*file_id.as_bytes(), 2),
                FileVersionState {
                    content_cid: content_v2_cid.clone(),
                    manifest_hash: [0xee; 32],
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
    async fn gateway_write_routes_enforce_signatures_pin_quorum_stale_head_and_relay_outcomes() {
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
        let stage_dek = DataEncryptionKey::generate().unwrap();
        let make_canonical_env = |ver: u64, epoch: EpochId, rev: u32| {
            let version = VersionNumber::new(ver).unwrap();
            let env_set = KeyEnvelopeSet::new(
                file_id,
                version,
                epoch,
                rev,
                vec![KeyEnvelopeEntry::new(
                    member_id,
                    KeyVersion::new(1).unwrap(),
                    KeyEnvelope::wrap(
                        &stage_dek,
                        &pub_identity.encryption_public_key,
                        WrapContext::new(
                            file_id,
                            version,
                            epoch,
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
            let cid = make_env_cid(&env_set);
            (cid, env_set)
        };
        let content_v1_cid = raw_sha256_cid(b"encrypted-content-v1").unwrap();
        let (envelope_v1_cid, envelope_v1_bytes) = make_canonical_env(1, epoch_v1, 1);
        let content_v2_cid = raw_sha256_cid(b"encrypted-content-v2").unwrap();
        let (envelope_v2_cid, envelope_v2_bytes) = make_canonical_env(2, epoch_v2, 1);
        {
            let mut envs = server.blobs.envelopes.lock().unwrap();
            envs.insert(envelope_v1_cid.to_string(), envelope_v1_bytes);
            envs.insert(envelope_v2_cid.to_string(), envelope_v2_bytes);
        }

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

        let sign_env_update = |old_cid: EnvelopeSetCid, new_cid: EnvelopeSetCid, nonce_b: u8| {
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

        let fresh_file_id = FileId::from_bytes([0x99; 32]);
        let valid_env_bytes = KeyEnvelopeSet::new(
            fresh_file_id,
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
                        fresh_file_id,
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

    #[tokio::test]
    async fn gateway_enforces_upload_download_acls_suspension_and_envelope_integrity() {
        let server = spawn_server().await;
        let client = reqwest::Client::new();

        let alice_id = MemberId::from_bytes([0x41; 32]);
        let bob_id = MemberId::from_bytes([0x42; 32]);
        let file_id = FileId::from_bytes([0x51; 32]);
        let epoch_v1 = EpochId::from_bytes([0x61; 32]);
        let epoch_v2 = EpochId::from_bytes([0x62; 32]);

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
        let mut alice_enc = [0u8; 32];
        alice_enc.copy_from_slice(&alice_pub.encryption_public_key.to_bytes());
        let mut bob_enc = [0u8; 32];
        bob_enc.copy_from_slice(&bob_pub.encryption_public_key.to_bytes());

        let dek = DataEncryptionKey::generate().unwrap();
        let env_v1_bytes = KeyEnvelopeSet::new(
            file_id,
            VersionNumber::ONE,
            epoch_v1,
            1,
            vec![KeyEnvelopeEntry::new(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyEnvelope::wrap(
                    &dek,
                    &alice_pub.encryption_public_key,
                    WrapContext::new(
                        file_id,
                        VersionNumber::ONE,
                        epoch_v1,
                        alice_id,
                        KeyVersion::new(1).unwrap(),
                    ),
                )
                .unwrap(),
            )],
        )
        .unwrap()
        .canonical_bytes()
        .unwrap();
        let env_v1_cid =
            EnvelopeSetCid::parse(&raw_sha256_cid(&env_v1_bytes).unwrap().to_string()).unwrap();
        let content_v1_bytes = b"car-stream-bytes".to_vec();
        let content_v1_cid = raw_sha256_cid(&content_v1_bytes).unwrap();
        let manifest_v1_hash = ManifestHash::from_bytes([0x88; 32]);

        {
            let mut chain = server.chain.state.lock().unwrap();
            chain.members.insert(
                *alice_id.as_bytes(),
                MemberIdentityState {
                    organization_id: [1; 32],
                    signing_address: alice_pub.signing_address,
                    signing_key_version: 1,
                    encryption_key_version: 1,
                    encryption_public_key: alice_enc,
                    status: 1,
                },
            );
            chain.members.insert(
                *bob_id.as_bytes(),
                MemberIdentityState {
                    organization_id: [1; 32],
                    signing_address: bob_pub.signing_address,
                    signing_key_version: 1,
                    encryption_key_version: 1,
                    encryption_public_key: bob_enc,
                    status: 1,
                },
            );
            chain.heads.insert(
                *file_id.as_bytes(),
                FileHeadState {
                    status: 1,
                    version_number: 1,
                    manifest_hash: manifest_v1_hash.to_string(),
                },
            );
            chain
                .read_acl
                .insert((*alice_id.as_bytes(), *file_id.as_bytes()));
            chain.versions.insert(
                (*file_id.as_bytes(), 1),
                FileVersionState {
                    content_cid: content_v1_cid.to_string(),
                    manifest_hash: [0x88; 32],
                },
            );
            chain.envelopes.insert(
                (*file_id.as_bytes(), 1),
                EnvelopeSetState {
                    cid: env_v1_cid.to_string(),
                    epoch_id: *epoch_v1.as_bytes(),
                    revision: 1,
                },
            );
        }
        {
            server
                .blobs
                .contents
                .lock()
                .unwrap()
                .insert(content_v1_cid.to_string(), content_v1_bytes);
            server
                .blobs
                .envelopes
                .lock()
                .unwrap()
                .insert(env_v1_cid.to_string(), env_v1_bytes.clone());
        }

        let (_, _, alice_token) = login_member(&client, &server, &alice_custody).await;
        let (_, _, bob_token) = login_member(&client, &server, &bob_custody).await;

        // 1. Active Alice can retrieve both /content and /envelope.
        assert_eq!(
            client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/1/content",
                    server.base_url
                ))
                .bearer_auth(&alice_token)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/1/envelope",
                    server.base_url
                ))
                .bearer_auth(&alice_token)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );

        // 2. Tampered envelope bytes in storage (CID mismatch) fail closed on /envelope (503).
        server
            .blobs
            .envelopes
            .lock()
            .unwrap()
            .insert(env_v1_cid.to_string(), b"{\"forged\":true}".to_vec());
        assert_eq!(
            client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/1/envelope",
                    server.base_url
                ))
                .bearer_auth(&alice_token)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        server
            .blobs
            .envelopes
            .lock()
            .unwrap()
            .insert(env_v1_cid.to_string(), env_v1_bytes.clone());

        // 3. Emergency suspension of Alice immediately blocks BOTH /content AND /envelope even with active session!
        server
            .chain
            .state
            .lock()
            .unwrap()
            .members
            .get_mut(alice_id.as_bytes())
            .unwrap()
            .status = 2; // Suspended
        assert_eq!(
            client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/1/content",
                    server.base_url
                ))
                .bearer_auth(&alice_token)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .get(format!(
                    "{}/v1/files/{file_id}/versions/1/envelope",
                    server.base_url
                ))
                .bearer_auth(&alice_token)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );

        // 4. Unauthorized Bob (no Write ACL / no Read ACL) cannot stage V2 content or envelopes for file_id!
        let chunk = vec![0x99u8; 32];
        let chunk_cid = raw_sha256_cid(&chunk).unwrap();
        let v2_manifest = crypto::EncryptedFileManifest::new(
            file_id,
            VersionNumber::new(2).unwrap(),
            manifest_v1_hash,
            epoch_v2,
            crypto::NoncePrefix::from_bytes([0x12; 8]),
            64,
            vec![crypto::EncryptedChunkRef::new(1, chunk_cid, 32).unwrap()],
            None,
        )
        .unwrap();
        let v2_pkg = ContentPackage::new(
            v2_manifest,
            vec![ports::ContentChunk::new(
                1,
                32,
                Box::pin(Cursor::new(chunk)) as StorageReader,
            )],
        )
        .unwrap();
        let v2_frame = ports::encode_content_package_frame(v2_pkg, 1024 * 1024)
            .await
            .unwrap();

        let contents_before = server.blobs.contents.lock().unwrap().len();
        assert_eq!(
            client
                .post(format!("{}/v1/blobs/content", server.base_url))
                .bearer_auth(&bob_token)
                .body(v2_frame.clone())
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(server.blobs.contents.lock().unwrap().len(), contents_before);

        // Unauthorized Bob also cannot stage revision-2 share envelope set without Read ACL.
        let share_env_bytes = KeyEnvelopeSet::new(
            file_id,
            VersionNumber::ONE,
            epoch_v1,
            2,
            vec![KeyEnvelopeEntry::new(
                bob_id,
                KeyVersion::new(1).unwrap(),
                KeyEnvelope::wrap(
                    &dek,
                    &bob_pub.encryption_public_key,
                    WrapContext::new(
                        file_id,
                        VersionNumber::ONE,
                        epoch_v1,
                        bob_id,
                        KeyVersion::new(1).unwrap(),
                    ),
                )
                .unwrap(),
            )],
        )
        .unwrap()
        .canonical_bytes()
        .unwrap();
        assert_eq!(
            client
                .post(format!("{}/v1/blobs/envelopes", server.base_url))
                .bearer_auth(&bob_token)
                .body(share_env_bytes)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );

        // Duplicate V1 envelope staging for already-existing file_id returns 409 Conflict.
        assert_eq!(
            client
                .post(format!("{}/v1/blobs/envelopes", server.base_url))
                .bearer_auth(&bob_token)
                .body(env_v1_bytes)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::CONFLICT
        );

        // 5. ReplicationInsufficient on blob staging maps to 503 {"error":"replication_insufficient"}.
        server
            .chain
            .state
            .lock()
            .unwrap()
            .write_acl
            .insert((*bob_id.as_bytes(), *file_id.as_bytes()));
        *server.blobs.fail_replication.lock().unwrap() = true;
        let repl_resp = client
            .post(format!("{}/v1/blobs/content", server.base_url))
            .bearer_auth(&bob_token)
            .body(v2_frame)
            .send()
            .await
            .unwrap();
        assert_eq!(repl_resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            repl_resp.json::<serde_json::Value>().await.unwrap()["error"],
            "replication_insufficient"
        );
        *server.blobs.fail_replication.lock().unwrap() = false;

        // 6. POST /v1/files rejects mismatched/non-canonical envelope_set_cid content (400) before relay!
        let bad_file_id = FileId::from_bytes([0x59; 32]);
        let bad_epoch = EpochId::from_bytes([0x69; 32]);
        let bad_manifest = ManifestHash::from_bytes([0x89; 32]);
        let forged_env_bytes = b"not-a-canonical-envelope-set".to_vec();
        let forged_env_cid =
            EnvelopeSetCid::parse(&raw_sha256_cid(&forged_env_bytes).unwrap().to_string()).unwrap();
        {
            server
                .blobs
                .envelopes
                .lock()
                .unwrap()
                .insert(forged_env_cid.to_string(), forged_env_bytes);
            let mut replicas = server.blobs.replicas.lock().unwrap();
            replicas.insert(
                content_v1_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
            replicas.insert(
                forged_env_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
        }
        let deadline = unix_seconds().unwrap() + 120;
        let nonce = OperationNonce::from_bytes([0xab; 32]);
        let typed = VersionAppend::new(
            bad_file_id,
            VersionNumber::ONE,
            ManifestHash::ZERO,
            bad_manifest,
            content_v1_cid.clone(),
            forged_env_cid.clone(),
            bad_epoch,
            bob_id,
            bob_pub.signing_address,
            nonce,
            UnixDeadline::from_unix_seconds(deadline).unwrap(),
        )
        .unwrap();
        let domain = Eip712Domain::file_registry(
            ChainId::from_u64(server.config.chain_id),
            server.config.file_registry,
        );
        let sig = bob_custody
            .sign_typed_digest(&bob_pub.signing_key_id, &typed.digest(&domain).unwrap())
            .await
            .unwrap();
        let bad_create_resp = client
            .post(format!("{}/v1/files", server.base_url))
            .bearer_auth(&bob_token)
            .json(&json!({
                "fileId": bad_file_id.to_string(),
                "displayName": "forged-env.txt",
                "parentFolderId": encode_hex(&[0; 32]),
                "versionNumber": 1,
                "parentManifestHash": encode_hex(&[0; 32]),
                "manifestHash": bad_manifest.to_string(),
                "contentCid": content_v1_cid.to_string(),
                "envelopeSetCid": forged_env_cid.to_string(),
                "epochId": bad_epoch.to_string(),
                "operationNonce": nonce.to_string(),
                "deadline": deadline,
                "signature": encode_hex(sig.as_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(bad_create_resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(
            bad_create_resp.json::<serde_json::Value>().await.unwrap()["error"],
            "invalid_envelope_set"
        );
        assert!(
            server
                .relayer
                .as_ref()
                .unwrap()
                .calls
                .lock()
                .unwrap()
                .is_empty(),
            "relayer must not submit tx when envelope_set_cid fails validation"
        );
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL (PostgreSQL)"]
    async fn gateway_http_router_runs_auth_access_revocation_and_audit_chain_on_postgres() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running ignored PostgreSQL gateway HTTP tests");
        let metadata = metadata_store::PostgresStore::connect(&database_url)
            .await
            .expect("connect to PostgreSQL for gateway HTTP test");
        metadata
            .migrate()
            .await
            .expect("apply migrations for gateway HTTP test");
        let pool = metadata.pool().clone();
        let store = crate::store::GatewayStore::new(pool.clone());

        let run_tag = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut member_bytes = [0x91u8; 32];
        member_bytes[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let member_id = MemberId::from_bytes(member_bytes);
        let mut file_bytes = [0x92u8; 32];
        file_bytes[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let file_id = FileId::from_bytes(file_bytes);
        let manifest_hash = [0x93u8; 32];
        let epoch_id = [0x94u8; 32];

        let custody = DevelopmentKeyCustody::generate(
            member_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
        )
        .unwrap();
        let identity = custody.public_identity().await.unwrap();
        let content_cid = raw_sha256_cid(b"pg-http-content").unwrap().to_string();
        let envelope_cid = raw_sha256_cid(b"pg-http-envelope").unwrap().to_string();

        let chain = MockChain::default();
        {
            let mut state = chain.state.lock().unwrap();
            state.block_number = 500;
            state.block_hash = encode_hex(&[0xaa; 32]);
            state.members.insert(
                member_bytes,
                MemberIdentityState {
                    organization_id: [0x10; 32],
                    signing_address: identity.signing_address,
                    signing_key_version: 1,
                    encryption_key_version: 1,
                    encryption_public_key: identity
                        .encryption_public_key
                        .to_bytes()
                        .try_into()
                        .unwrap(),
                    status: 1,
                },
            );
            state.read_acl.insert((member_bytes, file_bytes));
            state.heads.insert(
                file_bytes,
                FileHeadState {
                    version_number: 1,
                    manifest_hash: encode_hex(&manifest_hash),
                    status: 1,
                },
            );
            state.versions.insert(
                (file_bytes, 1),
                FileVersionState {
                    manifest_hash,
                    content_cid: content_cid.clone(),
                },
            );
            state.envelopes.insert(
                (file_bytes, 1),
                EnvelopeSetState {
                    epoch_id,
                    cid: envelope_cid.clone(),
                    revision: 1,
                },
            );
        }

        let chain_id = 1337u64;
        let access_governance = EvmAddress::from_bytes([0x33; 20]);
        let config = GatewayConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            database_url,
            besu_rpc_url: "http://127.0.0.1:8545".to_owned(),
            chain_id,
            access_governance,
            file_registry: EvmAddress::from_bytes([0x44; 20]),
            audience: "rrds-pg-http-test".to_owned(),
            challenge_ttl_seconds: 120,
            session_ttl_seconds: 900,
            rate_limit_capacity: 100,
            rate_limit_refill_per_second: 10.0,
            member_rate_limit_capacity: 100,
            member_rate_limit_refill_per_second: 10.0,
            invalid_sig_limit_capacity: 20,
            invalid_sig_limit_refill_per_second: 5.0,
            min_pin_replicas: 2,
            default_tx_gas_limit: 500_000,
            transaction_confirmation_timeout_seconds: 30,
            max_blob_upload_bytes: 64 * 1024 * 1024,
        };
        let state = AppState::new(store, chain, MockBlobStore::default(), config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let base_url = format!("http://{addr}");
        let client = reqwest::Client::new();

        // 1. Challenge -> EIP-712 login -> Bearer session persisted in real PostgreSQL.
        let challenge_resp = client
            .post(format!("{base_url}/v1/auth/challenge"))
            .header("x-request-id", "pg-http-e2e-1")
            .json(&json!({ "memberId": member_id.to_string() }))
            .send()
            .await
            .unwrap();
        assert_eq!(challenge_resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            challenge_resp
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("pg-http-e2e-1")
        );
        let challenge: LoginChallenge = challenge_resp.json().await.unwrap();
        let challenge_nonce = OperationNonce::from_bytes(parse_nonce(&challenge.nonce).unwrap());
        let digest_input = LoginChallengeDigestInput::new(
            identity.member_id,
            challenge_nonce,
            challenge.issued_at,
            challenge.expires_at,
            challenge.audience.clone(),
            challenge.protocol_version,
        )
        .unwrap();
        let gw_domain = Eip712Domain::gateway(ChainId::from_u64(chain_id), access_governance);
        let sig = custody
            .sign_typed_digest(
                &identity.signing_key_id,
                &digest_input.digest(&gw_domain).unwrap(),
            )
            .await
            .unwrap();
        let session_resp = client
            .post(format!("{base_url}/v1/auth/session"))
            .json(&json!({
                "challenge": challenge,
                "signature": encode_hex(sig.as_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(session_resp.status(), reqwest::StatusCode::OK);
        let session_body: serde_json::Value = session_resp.json().await.unwrap();
        let token = session_body["token"].as_str().unwrap().to_owned();

        // 2. Signed AccessLookup succeeds once and rejects replay on the same nonce in PostgreSQL.
        let mut op_nonce_bytes = [0x97u8; 32];
        op_nonce_bytes[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let op_nonce = OperationNonce::from_bytes(op_nonce_bytes);
        let deadline = unix_seconds().unwrap() + 60;
        let lookup = AccessLookup::new(
            member_id,
            file_id,
            VersionNumber::ONE,
            KeyVersion::new(1).unwrap(),
            op_nonce,
            UnixDeadline::from_unix_seconds(deadline).unwrap(),
        )
        .unwrap();
        let domain =
            Eip712Domain::access_governance(ChainId::from_u64(chain_id), access_governance);
        let lookup_sig = custody
            .sign_typed_digest(&identity.signing_key_id, &lookup.digest(&domain).unwrap())
            .await
            .unwrap();
        let lookup_payload = json!({
            "encryptionKeyVersion": 1,
            "operationNonce": op_nonce.to_string(),
            "deadline": deadline,
            "signature": encode_hex(lookup_sig.as_bytes()),
        });
        let first_lookup = client
            .post(format!("{base_url}/v1/files/{}/versions/1/access", file_id))
            .bearer_auth(&token)
            .json(&lookup_payload)
            .send()
            .await
            .unwrap();
        assert_eq!(first_lookup.status(), reqwest::StatusCode::OK);
        let first_json: serde_json::Value = first_lookup.json().await.unwrap();
        assert_eq!(first_json["contentCid"], content_cid);
        assert_eq!(first_json["envelopeSetCid"], envelope_cid);

        let replayed_lookup = client
            .post(format!("{base_url}/v1/files/{}/versions/1/access", file_id))
            .bearer_auth(&token)
            .json(&lookup_payload)
            .send()
            .await
            .unwrap();
        assert_eq!(replayed_lookup.status(), reqwest::StatusCode::UNAUTHORIZED);

        // 3. Self-audited GET /v1/audit returns the member's real PostgreSQL audit events,
        //    including the pinned QBFT finalized block on the auth.session login event.
        let audit_resp = client
            .get(format!("{base_url}/v1/audit?limit=10"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(audit_resp.status(), reqwest::StatusCode::OK);
        let audit_json: serde_json::Value = audit_resp.json().await.unwrap();
        assert_eq!(audit_json["memberId"], member_id.to_string());
        let events = audit_json["events"].as_array().unwrap();
        assert!(!events.is_empty());
        assert!(
            events.iter().any(|e| {
                e["record"]["action"] == "auth.session"
                    && e["record"]["outcome"] == "issued"
                    && e["record"]["block_number"] == 500
            }),
            "auth.session audit row must record the pinned QBFT finalized block number"
        );

        // 4. DELETE /v1/auth/session revokes the token in PostgreSQL; subsequent GET returns 401.
        let revoke_resp = client
            .delete(format!("{base_url}/v1/auth/session"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(revoke_resp.status(), reqwest::StatusCode::NO_CONTENT);

        let after_revoke = client
            .get(format!("{base_url}/v1/auth/session"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(after_revoke.status(), reqwest::StatusCode::UNAUTHORIZED);

        server_task.abort();

        // Clean up mutable operational rows (append-only audit rows remain intact).
        let member_str = member_id.to_string();
        for sql in [
            "DELETE FROM gateway_login_challenges WHERE member_id = $1",
            "DELETE FROM gateway_sessions WHERE member_id = $1",
            "DELETE FROM gateway_used_access_nonces WHERE member_id = $1",
        ] {
            let _ = sqlx::query(sql).bind(&member_str).execute(&pool).await;
        }
        let _ = sqlx::query("DELETE FROM gateway_rate_buckets WHERE bucket_key LIKE $1")
            .bind(format!("member:%:{member_str}"))
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn option_b_envelope_update_rejects_unauthorized_actors_and_forwards_signed_call() {
        let server = spawn_server_with_relayer(true).await;
        let relayer = server.relayer.as_ref().unwrap();
        let member_id = MemberId::from_bytes([0x61; 32]);
        let custody = DevelopmentKeyCustody::generate(
            member_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
        )
        .unwrap();
        let pub_identity = custody.public_identity().await.unwrap();
        let wrong_custody = DevelopmentKeyCustody::generate(
            member_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
        )
        .unwrap();
        let wrong_identity = wrong_custody.public_identity().await.unwrap();

        let file_id = FileId::from_bytes([0x62; 32]);
        let epoch_v1 = EpochId::from_bytes([0x63; 32]);
        let old_env_cid =
            EnvelopeSetCid::parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
                .unwrap();
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
        let rev2_bytes = KeyEnvelopeSet::new(
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
        let new_env_cid =
            EnvelopeSetCid::parse(&crypto::raw_sha256_cid(&rev2_bytes).unwrap().to_string())
                .unwrap();

        {
            let mut chain = server.chain.state.lock().unwrap();
            chain.members.insert(
                *member_id.as_bytes(),
                MemberIdentityState {
                    organization_id: [0x10; 32],
                    signing_address: pub_identity.signing_address,
                    signing_key_version: 1,
                    encryption_key_version: 1,
                    encryption_public_key: pub_identity
                        .encryption_public_key
                        .to_bytes()
                        .try_into()
                        .unwrap(),
                    status: 1,
                },
            );
            chain.envelopes.insert(
                (*file_id.as_bytes(), 1),
                EnvelopeSetState {
                    cid: old_env_cid.to_string(),
                    epoch_id: *epoch_v1.as_bytes(),
                    revision: 1,
                },
            );
        }
        {
            server.blobs.replicas.lock().unwrap().insert(
                new_env_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
            server
                .blobs
                .envelopes
                .lock()
                .unwrap()
                .insert(new_env_cid.to_string(), rev2_bytes);
        }

        let client = reqwest::Client::new();
        let (_, _, token) = login_member(&client, &server, &custody).await;

        #[allow(clippy::too_many_arguments)]
        async fn build_payload(
            config: &GatewayConfig,
            file_id: FileId,
            epoch_v1: EpochId,
            member_id: MemberId,
            signer_custody: &DevelopmentKeyCustody,
            key_id: &ports::KeyId,
            old_cid: &EnvelopeSetCid,
            new_cid: &EnvelopeSetCid,
            nonce_byte: u8,
            deadline: u64,
        ) -> serde_json::Value {
            let nonce = OperationNonce::from_bytes([nonce_byte; 32]);
            let typed = EnvelopeSetUpdate::new(
                file_id,
                VersionNumber::ONE,
                epoch_v1,
                old_cid.clone(),
                new_cid.clone(),
                member_id,
                ProposalId::from_bytes([0x55; 32]),
                nonce,
                UnixDeadline::from_unix_seconds(deadline).unwrap(),
            )
            .unwrap();
            let domain = Eip712Domain::access_governance(
                ChainId::from_u64(config.chain_id),
                config.access_governance,
            );
            let digest = typed.digest(&domain).unwrap();
            let sig = signer_custody
                .sign_typed_digest(key_id, &digest)
                .await
                .unwrap();
            json!({
                "epochId": epoch_v1.to_string(),
                "oldEnvelopeSetCid": old_cid.to_string(),
                "newEnvelopeSetCid": new_cid.to_string(),
                "proposalId": encode_hex(&[0x55; 32]),
                "operationNonce": nonce.to_string(),
                "deadline": deadline,
                "signature": encode_hex(sig.as_bytes()),
            })
        }

        let url = format!(
            "{}/v1/files/{file_id}/versions/1/envelopes",
            server.base_url
        );
        let future_deadline = unix_seconds().unwrap() + 120;

        // 1. Missing Read ACL -> 401 before touching relayer.
        let no_acl_resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(
                &build_payload(
                    &server.config,
                    file_id,
                    epoch_v1,
                    member_id,
                    &custody,
                    &pub_identity.signing_key_id,
                    &old_env_cid,
                    &new_env_cid,
                    0x11,
                    future_deadline,
                )
                .await,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(no_acl_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(relayer.calls.lock().unwrap().is_empty());

        // Grant Read ACL, then test wrong signer, expired deadline, unchanged CID, and suspended member.
        server
            .chain
            .state
            .lock()
            .unwrap()
            .read_acl
            .insert((*member_id.as_bytes(), *file_id.as_bytes()));

        // 2. Wrong EIP-712 signer -> 401 before relay.
        let wrong_sig_resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(
                &build_payload(
                    &server.config,
                    file_id,
                    epoch_v1,
                    member_id,
                    &wrong_custody,
                    &wrong_identity.signing_key_id,
                    &old_env_cid,
                    &new_env_cid,
                    0x12,
                    future_deadline,
                )
                .await,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_sig_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(relayer.calls.lock().unwrap().is_empty());

        // 3. Unchanged CID -> 400 before relay.
        let unchanged_resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(&json!({
                "epochId": epoch_v1.to_string(),
                "oldEnvelopeSetCid": old_env_cid.to_string(),
                "newEnvelopeSetCid": old_env_cid.to_string(),
                "proposalId": encode_hex(&[0x55; 32]),
                "operationNonce": encode_hex(&[0x13; 32]),
                "deadline": future_deadline,
                "signature": encode_hex(&[0xab; 65]),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(unchanged_resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert!(relayer.calls.lock().unwrap().is_empty());

        // 4. Suspended member (even with valid bearer token + Read ACL) -> 401 before relay.
        server
            .chain
            .state
            .lock()
            .unwrap()
            .members
            .get_mut(member_id.as_bytes())
            .unwrap()
            .status = 2;
        let suspended_resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(
                &build_payload(
                    &server.config,
                    file_id,
                    epoch_v1,
                    member_id,
                    &custody,
                    &pub_identity.signing_key_id,
                    &old_env_cid,
                    &new_env_cid,
                    0x14,
                    future_deadline,
                )
                .await,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(suspended_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(relayer.calls.lock().unwrap().is_empty());

        // 5. Reinstated active Read-authorized member succeeds via Option B relayer -> 200 OK.
        server
            .chain
            .state
            .lock()
            .unwrap()
            .members
            .get_mut(member_id.as_bytes())
            .unwrap()
            .status = 1;
        *relayer.behavior.lock().unwrap() = MockRelayBehavior::Commit(77);
        let ok_resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(
                &build_payload(
                    &server.config,
                    file_id,
                    epoch_v1,
                    member_id,
                    &custody,
                    &pub_identity.signing_key_id,
                    &old_env_cid,
                    &new_env_cid,
                    0x15,
                    future_deadline,
                )
                .await,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            relayer.calls.lock().unwrap().as_slice(),
            &["updateEnvelopeSet"]
        );
    }

    #[tokio::test]
    #[ignore = "requires live Besu QBFT RPC (BESU_RPC_URL)"]
    async fn gateway_http_router_queries_live_besu_qbft_identities_and_fails_closed() {
        let rpc_url =
            std::env::var("BESU_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_owned());
        let access_governance = EvmAddress::from_bytes(
            domain::hex::parse_fixed_hex::<20>(
                &std::env::var("CONTRACT_ACCESS_GOVERNANCE_ADDRESS")
                    .unwrap_or_else(|_| "0x1efe4b8d6076a0ca115241346f8d7da516ce4055".to_owned()),
            )
            .expect("valid AccessGovernance address"),
        );
        let file_registry = EvmAddress::from_bytes(
            domain::hex::parse_fixed_hex::<20>(
                &std::env::var("CONTRACT_FILE_REGISTRY_ADDRESS")
                    .unwrap_or_else(|_| "0x7ba5ef0f4c923942554c8b5788578280f7451f2d".to_owned()),
            )
            .expect("valid FileRegistry address"),
        );

        let chain = chain_adapter::BesuClient::new(&rpc_url).expect("BesuClient");
        let store = MockStore::default();
        let config = GatewayConfig {
            database_url: "postgres://unused".to_owned(),
            besu_rpc_url: rpc_url,
            chain_id: 1337,
            access_governance,
            file_registry,
            audience: "rrds-live-besu-test".to_owned(),
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            challenge_ttl_seconds: 120,
            session_ttl_seconds: 900,
            rate_limit_capacity: 100,
            rate_limit_refill_per_second: 10.0,
            member_rate_limit_capacity: 100,
            member_rate_limit_refill_per_second: 10.0,
            invalid_sig_limit_capacity: 10,
            invalid_sig_limit_refill_per_second: 1.0,
            min_pin_replicas: 2,
            default_tx_gas_limit: 2_000_000,
            transaction_confirmation_timeout_seconds: 30,
            max_blob_upload_bytes: 8 * 1024 * 1024,
        };
        let config_arc = Arc::new(GatewayConfig {
            database_url: config.database_url.clone(),
            besu_rpc_url: config.besu_rpc_url.clone(),
            chain_id: config.chain_id,
            access_governance: config.access_governance,
            file_registry: config.file_registry,
            audience: config.audience.clone(),
            bind: config.bind,
            challenge_ttl_seconds: config.challenge_ttl_seconds,
            session_ttl_seconds: config.session_ttl_seconds,
            rate_limit_capacity: config.rate_limit_capacity,
            rate_limit_refill_per_second: config.rate_limit_refill_per_second,
            member_rate_limit_capacity: config.member_rate_limit_capacity,
            member_rate_limit_refill_per_second: config.member_rate_limit_refill_per_second,
            invalid_sig_limit_capacity: config.invalid_sig_limit_capacity,
            invalid_sig_limit_refill_per_second: config.invalid_sig_limit_refill_per_second,
            min_pin_replicas: config.min_pin_replicas,
            default_tx_gas_limit: config.default_tx_gas_limit,
            transaction_confirmation_timeout_seconds: config
                .transaction_confirmation_timeout_seconds,
            max_blob_upload_bytes: config.max_blob_upload_bytes,
        });
        let state = AppState::new(store, chain, MockBlobStore::default(), config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let base_url = format!("http://{addr}");
        let client = reqwest::Client::new();
        let unregistered = MemberId::from_bytes([0xde; 32]);

        // 1. Live Besu GET /v1/identities/{unregistered} -> 404 not_found (proving real eth_call + block pin).
        let id_resp = client
            .get(format!("{base_url}/v1/identities/{unregistered}"))
            .send()
            .await
            .unwrap();
        assert_eq!(id_resp.status(), reqwest::StatusCode::NOT_FOUND);

        // 2. Live Besu POST /v1/auth/session with valid challenge signature from unregistered member -> 401 unauthorized.
        let custody = DevelopmentKeyCustody::generate(
            unregistered,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
        )
        .unwrap();
        let challenge_resp = client
            .post(format!("{base_url}/v1/auth/challenge"))
            .json(&json!({ "memberId": unregistered.to_string() }))
            .send()
            .await
            .unwrap();
        assert_eq!(challenge_resp.status(), reqwest::StatusCode::OK);
        let challenge: LoginChallenge = challenge_resp.json().await.unwrap();
        let nonce_bytes = domain::hex::parse_fixed_hex::<32>(&challenge.nonce).unwrap();
        let digest = crypto::LoginChallengeDigestInput::new(
            unregistered,
            OperationNonce::from_bytes(nonce_bytes),
            challenge.issued_at,
            challenge.expires_at,
            challenge.audience.clone(),
            challenge.protocol_version,
        )
        .unwrap()
        .digest(&Eip712Domain::gateway(
            ChainId::from_u64(config_arc.chain_id),
            config_arc.access_governance,
        ))
        .unwrap();
        let pub_id = custody.public_identity().await.unwrap();
        let sig = custody
            .sign_typed_digest(&pub_id.signing_key_id, &digest)
            .await
            .unwrap();
        let login_resp = client
            .post(format!("{base_url}/v1/auth/session"))
            .json(&json!({
                "challenge": challenge,
                "signature": encode_hex(sig.as_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(login_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        server_task.abort();
    }
}
