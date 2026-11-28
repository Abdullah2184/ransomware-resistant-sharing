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
        restore_audit_sources: Vec<Option<u64>>,
        fail_audit: bool,
        rate_limit_remaining: Option<u32>,
        bucket_limits: HashMap<String, u32>,
        listing_folders: Vec<ProjectedFolder>,
        listing_files: Vec<ProjectedFile>,
        history_versions: Vec<ProjectedVersion>,
        member_orgs: HashMap<String, String>,
        relayed_txs: HashMap<String, crate::store::RelayedTransactionRecord>,
        orphan_blobs: HashMap<String, (crate::store::OrphanBlobCandidate, String)>,
        referenced_projection_cids: HashSet<String>,
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
            restored_from_version: Option<u64>,
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
            if action == "file.version_restore" {
                state.restore_audit_sources.push(restored_from_version);
            }
            Box::pin(async { Ok(()) })
        }

        fn member_organization_id<'a>(
            &'a self,
            member_id: &'a str,
        ) -> StoreFuture<'a, Option<String>> {
            let org = self
                .state
                .lock()
                .unwrap()
                .member_orgs
                .get(member_id)
                .cloned();
            Box::pin(async move { Ok(org) })
        }

        fn record_relayed_transaction<'a>(
            &'a self,
            record: &'a crate::store::RelayedTransactionRecord,
        ) -> StoreFuture<'a, ()> {
            self.state
                .lock()
                .unwrap()
                .relayed_txs
                .insert(record.tx_hash.clone(), record.clone());
            Box::pin(async { Ok(()) })
        }

        fn get_relayed_transaction<'a>(
            &'a self,
            tx_hash: &'a str,
        ) -> StoreFuture<'a, Option<crate::store::RelayedTransactionRecord>> {
            let record = self.state.lock().unwrap().relayed_txs.get(tx_hash).cloned();
            Box::pin(async move { Ok(record) })
        }

        fn update_relayed_transaction_status<'a>(
            &'a self,
            tx_hash: &'a str,
            status: &'a str,
            block_number: Option<u64>,
            block_hash: Option<&'a str>,
            gas_used: Option<u64>,
        ) -> StoreFuture<'a, ()> {
            if let Some(entry) = self.state.lock().unwrap().relayed_txs.get_mut(tx_hash) {
                entry.status = status.to_owned();
                if block_number.is_some() {
                    entry.block_number = block_number;
                }
                if let Some(hash) = block_hash {
                    entry.block_hash = Some(hash.to_owned());
                }
                if gas_used.is_some() {
                    entry.gas_used = gas_used;
                }
            }
            Box::pin(async { Ok(()) })
        }

        fn record_orphan_blob_candidate<'a>(
            &'a self,
            cid: &'a str,
            blob_kind: &'a str,
            uploader_member_id: &'a str,
            file_id: Option<&'a str>,
            version_number: Option<u64>,
            tx_hash: Option<&'a str>,
            reason: &'a str,
        ) -> StoreFuture<'a, ()> {
            let mut state = self.state.lock().unwrap();
            let entry = state.orphan_blobs.entry(cid.to_owned()).or_insert_with(|| {
                (
                    crate::store::OrphanBlobCandidate {
                        cid: cid.to_owned(),
                        blob_kind: blob_kind.to_owned(),
                        uploader_member_id: uploader_member_id.to_owned(),
                        file_id: file_id.map(str::to_owned),
                        version_number,
                        tx_hash: tx_hash.map(str::to_owned),
                        reason: reason.to_owned(),
                    },
                    "candidate".to_owned(),
                )
            });
            if entry.1 != "referenced" {
                entry.0.file_id = file_id.map(str::to_owned).or(entry.0.file_id.clone());
                entry.0.version_number = version_number.or(entry.0.version_number);
                entry.0.tx_hash = tx_hash.map(str::to_owned).or(entry.0.tx_hash.clone());
                entry.0.reason = reason.to_owned();
            }
            Box::pin(async { Ok(()) })
        }

        fn mark_blob_referenced<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()> {
            if let Some(entry) = self.state.lock().unwrap().orphan_blobs.get_mut(cid) {
                entry.1 = "referenced".to_owned();
            }
            Box::pin(async { Ok(()) })
        }

        fn is_cid_referenced_in_projections<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, bool> {
            let referenced = self
                .state
                .lock()
                .unwrap()
                .referenced_projection_cids
                .contains(cid);
            Box::pin(async move { Ok(referenced) })
        }

        fn list_eligible_orphan_candidates<'a>(
            &'a self,
            _min_age_seconds: u64,
            limit: u32,
        ) -> StoreFuture<'a, Vec<crate::store::OrphanBlobCandidate>> {
            let state = self.state.lock().unwrap();
            let list = state
                .orphan_blobs
                .values()
                .filter(|(c, status)| {
                    status == "candidate" && !state.referenced_projection_cids.contains(&c.cid)
                })
                .take(limit as usize)
                .map(|(c, _)| c.clone())
                .collect();
            Box::pin(async move { Ok(list) })
        }

        fn mark_orphan_blob_unpinned<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()> {
            if let Some(entry) = self.state.lock().unwrap().orphan_blobs.get_mut(cid)
                && entry.1 == "candidate"
            {
                entry.1 = "unpinned".to_owned();
            }
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
        unpinned_cids: Arc<Mutex<Vec<String>>>,
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

        fn unpin<'a>(&'a self, cid: StorageCid) -> StorageFuture<'a, ()> {
            let cid_string = match cid {
                StorageCid::Content(value) => value.to_string(),
                StorageCid::EnvelopeSet(value) => value.to_string(),
            };
            self.unpinned_cids.lock().unwrap().push(cid_string);
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
            let behavior = self.behavior.lock().unwrap().clone();
            match behavior {
                MockRelayBehavior::Timeout(_) => {
                    self.calls
                        .lock()
                        .unwrap()
                        .push("reconcileTransaction".to_owned());
                    Box::pin(async { Ok(None) })
                }
                _ => {
                    let result = self.execute("reconcileTransaction").map(Some);
                    Box::pin(async move { result })
                }
            }
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
            environment: crate::config::RuntimeEnvironment::Development,
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
            org_rate_limit_capacity: 300,
            org_rate_limit_refill_per_second: 10.0,
            invalid_sig_limit_capacity: 5,
            invalid_sig_limit_refill_per_second: 0.1,
            max_concurrent_streams: 32,
            min_pin_replicas: 2,
            default_tx_gas_limit: 2_000_000,
            transaction_confirmation_timeout_seconds: 30,
            orphan_retention_seconds: 3600,
            storage_health_interval_seconds: 30,
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
            environment: crate::config::RuntimeEnvironment::Development,
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
            org_rate_limit_capacity: 300,
            org_rate_limit_refill_per_second: 10.0,
            invalid_sig_limit_capacity: 20,
            invalid_sig_limit_refill_per_second: 5.0,
            max_concurrent_streams: 32,
            min_pin_replicas: 2,
            default_tx_gas_limit: 500_000,
            transaction_confirmation_timeout_seconds: 30,
            orphan_retention_seconds: 3600,
            storage_health_interval_seconds: 30,
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
                    .unwrap_or_else(|_| "0x04ec7bde5732ca6c5e04709641c53a564e1c5472".to_owned()),
            )
            .expect("valid AccessGovernance address"),
        );
        let file_registry = EvmAddress::from_bytes(
            domain::hex::parse_fixed_hex::<20>(
                &std::env::var("CONTRACT_FILE_REGISTRY_ADDRESS")
                    .unwrap_or_else(|_| "0xeae1730d50eb47b7573c682afa2ee4995ba1968d".to_owned()),
            )
            .expect("valid FileRegistry address"),
        );

        let chain = chain_adapter::BesuClient::new(&rpc_url).expect("BesuClient");
        let store = MockStore::default();
        let config = GatewayConfig {
            environment: crate::config::RuntimeEnvironment::Development,
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
            org_rate_limit_capacity: 300,
            org_rate_limit_refill_per_second: 10.0,
            invalid_sig_limit_capacity: 10,
            invalid_sig_limit_refill_per_second: 1.0,
            max_concurrent_streams: 32,
            min_pin_replicas: 2,
            default_tx_gas_limit: 2_000_000,
            transaction_confirmation_timeout_seconds: 30,
            orphan_retention_seconds: 3600,
            storage_health_interval_seconds: 30,
            max_blob_upload_bytes: 8 * 1024 * 1024,
        };
        let state = AppState::new(store, chain, MockBlobStore::default(), config);
        let config_arc = state.config.clone();
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

    async fn register_test_member(
        server: &TestServer,
        member_id: MemberId,
        enc_key_version: u32,
    ) -> DevelopmentKeyCustody {
        let custody = DevelopmentKeyCustody::generate(
            member_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(enc_key_version).unwrap(),
        )
        .unwrap();
        let pub_id = custody.public_identity().await.unwrap();
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&pub_id.encryption_public_key.to_bytes());
        server.chain.state.lock().unwrap().members.insert(
            *member_id.as_bytes(),
            MemberIdentityState {
                organization_id: [0x10; 32],
                signing_address: pub_id.signing_address,
                encryption_public_key: enc_key,
                signing_key_version: 1,
                encryption_key_version: enc_key_version,
                status: 1,
            },
        );
        custody
    }

    async fn build_test_envelope_set(
        file_id: FileId,
        version: u64,
        epoch_id: EpochId,
        revision: u32,
        member_id: MemberId,
        custody: &DevelopmentKeyCustody,
    ) -> Vec<u8> {
        let pub_id = custody.public_identity().await.unwrap();
        let dek = DataEncryptionKey::generate().unwrap();
        let wrapped = KeyEnvelope::wrap(
            &dek,
            &pub_id.encryption_public_key,
            WrapContext::new(
                file_id,
                VersionNumber::new(version).unwrap(),
                epoch_id,
                member_id,
                pub_id.encryption_key_version,
            ),
        )
        .unwrap();
        KeyEnvelopeSet::new(
            file_id,
            VersionNumber::new(version).unwrap(),
            epoch_id,
            revision,
            vec![KeyEnvelopeEntry::new(
                member_id,
                pub_id.encryption_key_version,
                wrapped,
            )],
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
    }

    #[tokio::test]
    async fn gateway_persists_timed_out_tx_reconciles_and_isolates_members() {
        let server = spawn_server_with_relayer(true).await;
        let client = reqwest::Client::new();
        let relayer = server.relayer.clone().unwrap();
        let alice = MemberId::from_bytes([0x51; 32]);
        let bob = MemberId::from_bytes([0x52; 32]);
        let alice_custody = register_test_member(&server, alice, 1).await;
        let bob_custody = register_test_member(&server, bob, 1).await;
        let (_, _, alice_token) = login_member(&client, &server, &alice_custody).await;
        let (_, _, bob_token) = login_member(&client, &server, &bob_custody).await;

        let file_id = FileId::from_bytes([0x61; 32]);
        let epoch_id = EpochId::from_bytes([0x62; 32]);
        let content_cid = raw_sha256_cid(b"timed-out-content").unwrap();
        let envelope_bytes =
            build_test_envelope_set(file_id, 1, epoch_id, 1, alice, &alice_custody).await;
        let envelope_cid =
            EnvelopeSetCid::parse(&raw_sha256_cid(&envelope_bytes).unwrap().to_string()).unwrap();
        {
            let mut replicas = server.blobs.replicas.lock().unwrap();
            replicas.insert(
                content_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
            replicas.insert(
                envelope_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
        }
        server
            .blobs
            .envelopes
            .lock()
            .unwrap()
            .insert(envelope_cid.to_string(), envelope_bytes);

        let pending_tx_hash = [0x77; 32];
        let pending_tx_hex = encode_hex(&pending_tx_hash);
        *relayer.behavior.lock().unwrap() = MockRelayBehavior::Timeout(pending_tx_hash);

        let nonce = OperationNonce::from_bytes([0x63; 32]);
        let deadline = unix_seconds().unwrap() + 120;
        let manifest_hash = ManifestHash::from_bytes([0x64; 32]);
        let pub_id = alice_custody.public_identity().await.unwrap();
        let typed = VersionAppend::new(
            file_id,
            VersionNumber::new(1).unwrap(),
            ManifestHash::from_bytes([0; 32]),
            manifest_hash,
            content_cid.clone(),
            envelope_cid.clone(),
            epoch_id,
            alice,
            pub_id.signing_address,
            nonce,
            UnixDeadline::from_unix_seconds(deadline).unwrap(),
        )
        .unwrap();
        let digest = typed
            .digest(&Eip712Domain::file_registry(
                ChainId::from_u64(server.config.chain_id),
                server.config.file_registry,
            ))
            .unwrap();
        let sig = alice_custody
            .sign_typed_digest(&pub_id.signing_key_id, &digest)
            .await
            .unwrap();

        let create_resp = client
            .post(format!("{}/v1/files", server.base_url))
            .bearer_auth(&alice_token)
            .json(&json!({
                "fileId": file_id.to_string(),
                "displayName": "pending.txt",
                "parentFolderId": format!("0x{}", "00".repeat(32)),
                "versionNumber": 1,
                "parentManifestHash": format!("0x{}", "00".repeat(32)),
                "manifestHash": manifest_hash.to_string(),
                "contentCid": content_cid.to_string(),
                "envelopeSetCid": envelope_cid.to_string(),
                "epochId": epoch_id.to_string(),
                "operationNonce": nonce.to_string(),
                "deadline": deadline,
                "signature": encode_hex(sig.as_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(create_resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
        let timeout_body: serde_json::Value = create_resp.json().await.unwrap();
        assert_eq!(timeout_body["transactionHash"], pending_tx_hex);

        // Cross-member isolation: Bob must get 404 probing Alice's tx hash.
        let bob_probe = client
            .get(format!(
                "{}/v1/transactions/{pending_tx_hex}",
                server.base_url
            ))
            .bearer_auth(&bob_token)
            .send()
            .await
            .unwrap();
        assert_eq!(bob_probe.status(), reqwest::StatusCode::NOT_FOUND);

        // While still pending on Besu, Alice sees `status: "pending"`.
        let still_pending = client
            .get(format!(
                "{}/v1/transactions/{pending_tx_hex}",
                server.base_url
            ))
            .bearer_auth(&alice_token)
            .send()
            .await
            .unwrap();
        assert_eq!(still_pending.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value = still_pending.json().await.unwrap();
        assert_eq!(body["status"], "pending");

        // Once Besu finalizes the transaction, reconciliation transitions it to `confirmed`
        // and marks associated blobs referenced.
        *relayer.behavior.lock().unwrap() = MockRelayBehavior::Commit(55);
        let confirmed = client
            .get(format!(
                "{}/v1/transactions/{pending_tx_hex}",
                server.base_url
            ))
            .bearer_auth(&alice_token)
            .send()
            .await
            .unwrap();
        assert_eq!(confirmed.status(), reqwest::StatusCode::OK);
        let confirmed_body: serde_json::Value = confirmed.json().await.unwrap();
        assert_eq!(confirmed_body["status"], "confirmed");
        assert_eq!(confirmed_body["blockNumber"], 55);
        assert_eq!(confirmed_body["gasUsed"], 120_000);
        assert_eq!(
            server
                .store
                .state
                .lock()
                .unwrap()
                .relayed_txs
                .get(&pending_tx_hex)
                .unwrap()
                .status,
            "confirmed"
        );
    }

    #[tokio::test]
    async fn orphan_blob_cleaner_refuses_referenced_blobs_and_unpins_true_orphans() {
        let server = spawn_server_with_relayer(false).await;
        let file_id = FileId::from_bytes([0x81; 32]);
        let onchain_cid = raw_sha256_cid(b"referenced-on-chain").unwrap().to_string();
        let projected_cid = raw_sha256_cid(b"referenced-in-projection")
            .unwrap()
            .to_string();
        let true_orphan_cid = raw_sha256_cid(b"true-unreferenced-orphan")
            .unwrap()
            .to_string();

        // Record version 1 on-chain referencing `onchain_cid`.
        server.chain.state.lock().unwrap().versions.insert(
            (*file_id.as_bytes(), 1),
            FileVersionState {
                manifest_hash: [0x11; 32],
                content_cid: onchain_cid.clone(),
            },
        );
        // Mark `projected_cid` referenced in projections.
        server
            .store
            .state
            .lock()
            .unwrap()
            .referenced_projection_cids
            .insert(projected_cid.clone());

        let member = format!("0x{}", "55".repeat(32));
        for (cid, version) in [
            (&onchain_cid, 1u64),
            (&projected_cid, 2u64),
            (&true_orphan_cid, 3u64),
        ] {
            server
                .store
                .record_orphan_blob_candidate(
                    cid,
                    "content",
                    &member,
                    Some(&file_id.to_string()),
                    Some(version),
                    None,
                    "contract_reverted",
                )
                .await
                .unwrap();
        }

        let state = AppState::new(
            server.store.clone(),
            server.chain.clone(),
            server.blobs.clone(),
            GatewayConfig {
                environment: crate::config::RuntimeEnvironment::Development,
                database_url: "postgres://unused".to_owned(),
                besu_rpc_url: "http://127.0.0.1:8545".to_owned(),
                chain_id: 1337,
                access_governance: server.config.access_governance,
                file_registry: server.config.file_registry,
                audience: "rrds-local".to_owned(),
                bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                challenge_ttl_seconds: 120,
                session_ttl_seconds: 900,
                rate_limit_capacity: 100,
                rate_limit_refill_per_second: 10.0,
                member_rate_limit_capacity: 100,
                member_rate_limit_refill_per_second: 10.0,
                org_rate_limit_capacity: 300,
                org_rate_limit_refill_per_second: 10.0,
                invalid_sig_limit_capacity: 5,
                invalid_sig_limit_refill_per_second: 0.1,
                max_concurrent_streams: 32,
                min_pin_replicas: 2,
                default_tx_gas_limit: 2_000_000,
                transaction_confirmation_timeout_seconds: 30,
                orphan_retention_seconds: 3600,
                storage_health_interval_seconds: 30,
                max_blob_upload_bytes: 8 * 1024 * 1024,
            },
        );

        let summary = crate::maintenance::cleanup_orphan_blobs_once(&state, 0, 50)
            .await
            .unwrap();
        assert_eq!(summary.unpinned, 1);
        assert_eq!(summary.marked_referenced, 1);
        assert_eq!(summary.skipped_due_to_error, 0);
        assert_eq!(
            server.blobs.unpinned_cids.lock().unwrap().as_slice(),
            std::slice::from_ref(&true_orphan_cid)
        );
        // Verify on-chain referenced CID transitioned to `referenced` and was NEVER unpinned.
        assert_eq!(
            server
                .store
                .state
                .lock()
                .unwrap()
                .orphan_blobs
                .get(&onchain_cid)
                .unwrap()
                .1,
            "referenced"
        );
    }

    #[tokio::test]
    async fn gateway_validates_restore_source_and_enforces_org_rate_limit() {
        let server = spawn_server_with_relayer(true).await;
        let client = reqwest::Client::new();
        let alice = MemberId::from_bytes([0x91; 32]);
        let alice_custody = register_test_member(&server, alice, 1).await;
        let (_, _, alice_token) = login_member(&client, &server, &alice_custody).await;

        let file_id = FileId::from_bytes([0x92; 32]);
        let parent_hash = ManifestHash::from_bytes([0x93; 32]);
        let new_manifest = ManifestHash::from_bytes([0x94; 32]);
        let epoch_id = EpochId::from_bytes([0x95; 32]);
        let content_cid = raw_sha256_cid(b"restored-v2-content").unwrap();
        let envelope_bytes =
            build_test_envelope_set(file_id, 2, epoch_id, 1, alice, &alice_custody).await;
        let envelope_cid =
            EnvelopeSetCid::parse(&raw_sha256_cid(&envelope_bytes).unwrap().to_string()).unwrap();

        {
            let mut chain = server.chain.state.lock().unwrap();
            chain
                .write_acl
                .insert((*alice.as_bytes(), *file_id.as_bytes()));
            chain.heads.insert(
                *file_id.as_bytes(),
                FileHeadState {
                    version_number: 1,
                    manifest_hash: parent_hash.to_string(),
                    status: 1,
                },
            );
        }
        {
            let mut replicas = server.blobs.replicas.lock().unwrap();
            replicas.insert(
                content_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
            replicas.insert(
                envelope_cid.to_string(),
                vec!["peer-1".to_owned(), "peer-2".to_owned()],
            );
        }
        server
            .blobs
            .envelopes
            .lock()
            .unwrap()
            .insert(envelope_cid.to_string(), envelope_bytes);

        let nonce = OperationNonce::from_bytes([0x96; 32]);
        let deadline = unix_seconds().unwrap() + 120;
        let pub_id = alice_custody.public_identity().await.unwrap();
        let typed = VersionAppend::new(
            file_id,
            VersionNumber::new(2).unwrap(),
            parent_hash,
            new_manifest,
            content_cid.clone(),
            envelope_cid.clone(),
            epoch_id,
            alice,
            pub_id.signing_address,
            nonce,
            UnixDeadline::from_unix_seconds(deadline).unwrap(),
        )
        .unwrap();
        let digest = typed
            .digest(&Eip712Domain::file_registry(
                ChainId::from_u64(server.config.chain_id),
                server.config.file_registry,
            ))
            .unwrap();
        let sig = alice_custody
            .sign_typed_digest(&pub_id.signing_key_id, &digest)
            .await
            .unwrap();

        // Invalid restoredFromVersion (must be >= 1 and < versionNumber) -> 400 Bad Request.
        for bad_source in [0u64, 2u64] {
            let bad_resp = client
                .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
                .bearer_auth(&alice_token)
                .json(&json!({
                    "versionNumber": 2,
                    "parentManifestHash": parent_hash.to_string(),
                    "manifestHash": new_manifest.to_string(),
                    "contentCid": content_cid.to_string(),
                    "envelopeSetCid": envelope_cid.to_string(),
                    "epochId": epoch_id.to_string(),
                    "operationNonce": nonce.to_string(),
                    "deadline": deadline,
                    "signature": encode_hex(sig.as_bytes()),
                    "restoredFromVersion": bad_source,
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(bad_resp.status(), reqwest::StatusCode::BAD_REQUEST);
        }

        // Valid restoredFromVersion=1 -> 201 Created and audited as `file.version_restore`.
        let ok_resp = client
            .post(format!("{}/v1/files/{file_id}/versions", server.base_url))
            .bearer_auth(&alice_token)
            .json(&json!({
                "versionNumber": 2,
                "parentManifestHash": parent_hash.to_string(),
                "manifestHash": new_manifest.to_string(),
                "contentCid": content_cid.to_string(),
                "envelopeSetCid": envelope_cid.to_string(),
                "epochId": epoch_id.to_string(),
                "operationNonce": nonce.to_string(),
                "deadline": deadline,
                "signature": encode_hex(sig.as_bytes()),
                "restoredFromVersion": 1,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), reqwest::StatusCode::CREATED);
        assert_eq!(
            server.store.state.lock().unwrap().restore_audit_sources,
            vec![Some(0), Some(2), Some(1)]
        );

        // Per-organization rate-limit bucket exhaustion -> 429 Too Many Requests.
        let org_id = format!("0x{}", "a1".repeat(32));
        {
            let mut st = server.store.state.lock().unwrap();
            st.member_orgs.insert(alice.to_string(), org_id.clone());
            st.bucket_limits
                .insert(format!("org:file.list:{org_id}"), 0);
        }
        let limited = client
            .get(format!("{}/v1/files", server.base_url))
            .bearer_auth(&alice_token)
            .send()
            .await
            .unwrap();
        assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    #[ignore = "requires live dual-node Kubo + IPFS Cluster and compiled cli binary"]
    async fn cli_binary_through_real_gateway_to_live_dual_node_ipfs_cluster_end_to_end() {
        use ipfs_adapter::{ClusterCredentials, IpfsClusterStore, IpfsConfig};
        use std::path::PathBuf;
        use std::time::Duration;

        // 1. Resolve workspace root, compiled `cli` binary, and live dual-node IPFS Cluster config.
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let cli_bin = workspace_root.join("target/debug/cli");
        assert!(
            cli_bin.is_file(),
            "compiled CLI binary not found at {}; build with `cargo build -p cli`",
            cli_bin.display()
        );

        let kubo_urls: Vec<String> = std::env::var("IPFS_API_URLS")
            .unwrap_or_else(|_| "http://127.0.0.1:15001,http://127.0.0.1:15002".to_owned())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        assert!(kubo_urls.len() >= 2, "requires >= 2 live Kubo peers");
        let cluster_urls: Vec<String> = std::env::var("IPFS_CLUSTER_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9094".to_owned())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let cluster_user =
            std::env::var("IPFS_CLUSTER_USERNAME").unwrap_or_else(|_| "rrfs-admin".to_owned());
        let raw_pw_file = std::env::var("IPFS_CLUSTER_PASSWORD_FILE")
            .unwrap_or_else(|_| "infra/ipfs-cluster/secrets/cluster-api-password".to_owned());
        let pw_path = if PathBuf::from(&raw_pw_file).is_file() {
            PathBuf::from(&raw_pw_file)
        } else {
            workspace_root.join(&raw_pw_file)
        };
        let cluster_password = std::fs::read_to_string(&pw_path)
            .expect("read local IPFS Cluster password file")
            .trim()
            .to_owned();

        let live_ipfs = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: kubo_urls.clone(),
            cluster_api_urls: cluster_urls.clone(),
            cluster_credentials: ClusterCredentials::new(
                cluster_user.clone(),
                cluster_password.clone(),
            ),
            request_timeout: Duration::from_secs(30),
            replication_timeout: Duration::from_secs(20),
            replication_poll_interval: Duration::from_millis(250),
            max_upload_bytes: 32 * 1024 * 1024,
        })
        .expect("build live IpfsClusterStore");

        // Verify live Kubo + Cluster health monitor sees both peers healthy.
        let health = crate::maintenance::check_storage_health_once(&live_ipfs)
            .await
            .expect("live storage health probe");
        assert!(
            health.healthy_kubo_peers >= 2 && health.healthy_cluster_peers >= 1,
            "expected >=2 healthy Kubo and >=1 healthy Cluster peers, got {health:?}"
        );
        assert!(!health.is_degraded());

        // 2. Stateful chain/relayer backing a REAL Axum gateway router + REAL IpfsClusterStore.
        #[derive(Clone)]
        struct StatefulRelayer {
            chain: MockChain,
            force_revert: Arc<Mutex<bool>>,
        }
        impl GatewayRelayerPort for StatefulRelayer {
            fn relay_create_file(
                &self,
                call: VersionAppendCall,
                _display_name: String,
                _parent_folder_id: [u8; 32],
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let chain = self.chain.clone();
                let revert = *self.force_revert.lock().unwrap();
                Box::pin(async move {
                    let mut st = chain.state.lock().unwrap();
                    st.block_number += 1;
                    let block = st.block_number;
                    if revert {
                        return Ok(RelayOutcome::Reverted(EvmTransactionReceipt {
                            transaction_hash: [0xee; 32],
                            block_number: block,
                            block_hash: st.block_hash.clone(),
                            status: false,
                            gas_used: 90_000,
                        }));
                    }
                    st.heads.insert(
                        call.file_id,
                        FileHeadState {
                            version_number: 1,
                            manifest_hash: encode_hex(&call.manifest_hash),
                            status: 1,
                        },
                    );
                    st.versions.insert(
                        (call.file_id, 1),
                        FileVersionState {
                            manifest_hash: call.manifest_hash,
                            content_cid: call.content_cid,
                        },
                    );
                    st.envelopes.insert(
                        (call.file_id, 1),
                        EnvelopeSetState {
                            cid: call.envelope_set_cid,
                            epoch_id: call.epoch_id,
                            revision: 1,
                        },
                    );
                    st.read_acl.insert((call.member_id, call.file_id));
                    st.write_acl.insert((call.member_id, call.file_id));
                    Ok(RelayOutcome::Committed(EvmTransactionReceipt {
                        transaction_hash: [0xa1; 32],
                        block_number: block,
                        block_hash: st.block_hash.clone(),
                        status: true,
                        gas_used: 180_000,
                    }))
                })
            }

            fn relay_append_version(
                &self,
                call: VersionAppendCall,
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let chain = self.chain.clone();
                let revert = *self.force_revert.lock().unwrap();
                Box::pin(async move {
                    let mut st = chain.state.lock().unwrap();
                    st.block_number += 1;
                    let block = st.block_number;
                    if revert {
                        return Ok(RelayOutcome::Reverted(EvmTransactionReceipt {
                            transaction_hash: [0xef; 32],
                            block_number: block,
                            block_hash: st.block_hash.clone(),
                            status: false,
                            gas_used: 95_000,
                        }));
                    }
                    st.heads.insert(
                        call.file_id,
                        FileHeadState {
                            version_number: call.version_number,
                            manifest_hash: encode_hex(&call.manifest_hash),
                            status: 1,
                        },
                    );
                    st.versions.insert(
                        (call.file_id, call.version_number),
                        FileVersionState {
                            manifest_hash: call.manifest_hash,
                            content_cid: call.content_cid,
                        },
                    );
                    st.envelopes.insert(
                        (call.file_id, call.version_number),
                        EnvelopeSetState {
                            cid: call.envelope_set_cid,
                            epoch_id: call.epoch_id,
                            revision: 1,
                        },
                    );
                    Ok(RelayOutcome::Committed(EvmTransactionReceipt {
                        transaction_hash: [0xa2; 32],
                        block_number: block,
                        block_hash: st.block_hash.clone(),
                        status: true,
                        gas_used: 150_000,
                    }))
                })
            }

            fn relay_update_envelope_set(
                &self,
                call: EnvelopeSetUpdateCall,
                _signature: Vec<u8>,
            ) -> RelayFuture<'_, RelayOutcome> {
                let chain = self.chain.clone();
                let revert = *self.force_revert.lock().unwrap();
                Box::pin(async move {
                    let mut st = chain.state.lock().unwrap();
                    st.block_number += 1;
                    let block = st.block_number;
                    if revert {
                        return Ok(RelayOutcome::Reverted(EvmTransactionReceipt {
                            transaction_hash: [0xed; 32],
                            block_number: block,
                            block_hash: st.block_hash.clone(),
                            status: false,
                            gas_used: 70_000,
                        }));
                    }
                    let next_rev = st
                        .envelopes
                        .get(&(call.file_id, call.version_number))
                        .map(|e| e.revision + 1)
                        .unwrap_or(2);
                    st.envelopes.insert(
                        (call.file_id, call.version_number),
                        EnvelopeSetState {
                            cid: call.new_envelope_set_cid,
                            epoch_id: call.epoch_id,
                            revision: next_rev,
                        },
                    );
                    Ok(RelayOutcome::Committed(EvmTransactionReceipt {
                        transaction_hash: [0xa3; 32],
                        block_number: block,
                        block_hash: st.block_hash.clone(),
                        status: true,
                        gas_used: 110_000,
                    }))
                })
            }

            fn reconcile_transaction(
                &self,
                _tx_hash: [u8; 32],
            ) -> RelayFuture<'_, Option<RelayOutcome>> {
                Box::pin(async { Ok(None) })
            }
        }

        let chain = MockChain::default();
        {
            let mut st = chain.state.lock().unwrap();
            st.block_number = 100;
            st.block_hash = format!("0x{}", "cd".repeat(32));
        }
        let store = MockStore::default();
        let force_revert = Arc::new(Mutex::new(false));
        let relayer = StatefulRelayer {
            chain: chain.clone(),
            force_revert: force_revert.clone(),
        };

        let access_gov = EvmAddress::from_bytes([0x22; 20]);
        let file_reg = EvmAddress::from_bytes([0x11; 20]);
        let gateway_config = GatewayConfig {
            environment: crate::config::RuntimeEnvironment::Development,
            database_url: "postgres://unused".to_owned(),
            besu_rpc_url: "http://127.0.0.1:8545".to_owned(),
            chain_id: 1337,
            access_governance: access_gov,
            file_registry: file_reg,
            audience: "rrds-live-cli-e2e".to_owned(),
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            challenge_ttl_seconds: 120,
            session_ttl_seconds: 900,
            rate_limit_capacity: 500,
            rate_limit_refill_per_second: 50.0,
            member_rate_limit_capacity: 500,
            member_rate_limit_refill_per_second: 50.0,
            org_rate_limit_capacity: 500,
            org_rate_limit_refill_per_second: 50.0,
            invalid_sig_limit_capacity: 50,
            invalid_sig_limit_refill_per_second: 5.0,
            max_concurrent_streams: 32,
            min_pin_replicas: 2,
            default_tx_gas_limit: 2_000_000,
            transaction_confirmation_timeout_seconds: 30,
            orphan_retention_seconds: 3600,
            storage_health_interval_seconds: 30,
            max_blob_upload_bytes: 32 * 1024 * 1024,
        };

        let app_state = AppState::new(store.clone(), chain.clone(), live_ipfs, gateway_config)
            .with_relayer(relayer);
        let cleanup_state = app_state.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = listener.local_addr().unwrap();
        let gw_url = format!("http://{gw_addr}");
        let gw_handle = tokio::spawn(async move {
            axum::serve(
                listener,
                router(app_state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Register deterministic Alice and Bob identities on MockChain.
        let alice_id = MemberId::from_bytes([0x31; 32]);
        let alice_sign_sk = [0x41; 32];
        let alice_enc_seed = [0x51; 32];
        let bob_id = MemberId::from_bytes([0x32; 32]);
        let bob_sign_sk = [0x42; 32];
        let bob_enc_seed = [0x52; 32];
        for (mid, sign_sk, enc_seed) in [
            (alice_id, alice_sign_sk, alice_enc_seed),
            (bob_id, bob_sign_sk, bob_enc_seed),
        ] {
            let custody = DevelopmentKeyCustody::from_dev_secrets(
                mid,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
                sign_sk,
                enc_seed,
            )
            .unwrap();
            let pub_id = custody.public_identity().await.unwrap();
            let mut enc_pub = [0u8; 32];
            enc_pub.copy_from_slice(&pub_id.encryption_public_key.to_bytes());
            chain.state.lock().unwrap().members.insert(
                *mid.as_bytes(),
                MemberIdentityState {
                    organization_id: [0x10; 32],
                    signing_address: pub_id.signing_address,
                    encryption_public_key: enc_pub,
                    signing_key_version: 1,
                    encryption_key_version: 1,
                    status: 1,
                },
            );
        }

        // Helper to invoke the REAL compiled `cli` binary with isolated env.
        let tmp_dir =
            std::env::temp_dir().join(format!("rrds-live-cli-gw-ipfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let alice_session_file = tmp_dir.join("alice.session");
        let bob_session_file = tmp_dir.join("bob.session");

        let run_cli = |gateway: &str,
                       member: MemberId,
                       sign_sk: [u8; 32],
                       enc_seed: [u8; 32],
                       session_file: &std::path::Path,
                       min_replicas: &str,
                       args: &[&str]| {
            let cli_bin = cli_bin.clone();
            let gateway = gateway.to_owned();
            let session_file = session_file.to_path_buf();
            let min_replicas = min_replicas.to_owned();
            let owned_args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            async move {
                tokio::task::spawn_blocking(move || {
                    std::process::Command::new(&cli_bin)
                        .args(&owned_args)
                        .env_clear()
                        .env("GATEWAY_URL", gateway)
                        .env("GATEWAY_AUDIENCE", "rrds-live-cli-e2e")
                        .env("BESU_CHAIN_ID", "1337")
                        .env("CONTRACT_ACCESS_GOVERNANCE_ADDRESS", access_gov.to_string())
                        .env("CONTRACT_FILE_REGISTRY_ADDRESS", file_reg.to_string())
                        .env("MIN_PIN_REPLICAS", min_replicas)
                        .env("RRDS_ALLOW_UNSAFE_DEV_CUSTODY", "true")
                        .env("RRDS_DEV_MEMBER_ID", member.to_string())
                        .env("RRDS_DEV_SIGNING_KEY", encode_hex(&sign_sk))
                        .env("RRDS_DEV_ENCRYPTION_SEED", encode_hex(&enc_seed))
                        .env("RRDS_DEV_SIGNING_KEY_VERSION", "1")
                        .env("RRDS_DEV_ENCRYPTION_KEY_VERSION", "1")
                        .env("RRDS_SESSION_FILE", &session_file)
                        .output()
                        .expect("spawn cli binary")
                })
                .await
                .expect("cli blocking task")
            }
        };

        let parse_kv = |stdout: &str, key: &str| -> String {
            stdout
                .split_whitespace()
                .find_map(|tok| tok.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing `{key}=` in CLI output:\n{stdout}"))
                .to_owned()
        };

        // Track all pinned CIDs to verify replication and cleanly unpin at teardown.
        let mut committed_cids: Vec<StorageCid> = Vec::new();
        let file_id = FileId::from_bytes([0xab; 32]);
        let file_id_str = file_id.to_string();

        // 3. Alice logs in via real CLI binary -> real Gateway.
        let health_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["health"],
        )
        .await;
        assert!(
            health_out.status.success(),
            "cli health failed: {}",
            String::from_utf8_lossy(&health_out.stderr)
        );
        let login_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &[
                "login",
                "--session-file",
                alice_session_file.to_str().unwrap(),
            ],
        )
        .await;
        assert!(
            login_out.status.success(),
            "cli login failed: {}",
            String::from_utf8_lossy(&login_out.stderr)
        );
        let whoami_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["whoami"],
        )
        .await;
        assert!(whoami_out.status.success());
        assert!(String::from_utf8_lossy(&whoami_out.stdout).contains(&alice_id.to_string()));

        // 4. Multi-chunk (>1 MiB -> 2 AES-256-GCM chunks) upload via real CLI -> Gateway -> live 2-peer IPFS Cluster!
        let mut v1_plaintext = vec![0u8; 1_150_000];
        for (i, byte) in v1_plaintext.iter_mut().enumerate() {
            *byte = ((i * 31 + 17) % 251) as u8;
        }
        let v1_input = tmp_dir.join("v1-multi-chunk.bin");
        std::fs::write(&v1_input, &v1_plaintext).unwrap();
        let upload_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &[
                "upload",
                v1_input.to_str().unwrap(),
                "--name",
                "v1-multi-chunk.bin",
                "--file-id",
                &file_id_str,
            ],
        )
        .await;
        assert!(
            upload_out.status.success(),
            "cli upload V1 failed: {}",
            String::from_utf8_lossy(&upload_out.stderr)
        );
        let upload_stdout = String::from_utf8_lossy(&upload_out.stdout);
        assert_eq!(parse_kv(&upload_stdout, "contentReplicas"), "2");
        assert_eq!(parse_kv(&upload_stdout, "envelopeReplicas"), "2");
        let v1_content_cid = ContentCid::parse(&parse_kv(&upload_stdout, "contentCid")).unwrap();
        let v1_env_cid =
            EnvelopeSetCid::parse(&parse_kv(&upload_stdout, "envelopeSetCid")).unwrap();
        committed_cids.push(StorageCid::Content(v1_content_cid.clone()));
        committed_cids.push(StorageCid::EnvelopeSet(v1_env_cid.clone()));

        // Verify live 2-peer Cluster pinning directly through IpfsClusterStore.
        let v1_pin = cleanup_state
            .blob_store
            .ensure_replication(StorageCid::Content(v1_content_cid.clone()), 2)
            .await
            .expect("V1 content must be pinned on >= 2 live Cluster peers");
        assert!(v1_pin.pinned_peers.len() >= 2);

        // 5. Alice downloads V1 via real CLI -> real Gateway -> live Kubo and verifies byte-for-byte!
        let v1_downloaded = tmp_dir.join("v1-downloaded.bin");
        let dl_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &[
                "download",
                &file_id_str,
                "1",
                v1_downloaded.to_str().unwrap(),
            ],
        )
        .await;
        assert!(
            dl_out.status.success(),
            "cli download V1 failed: {}",
            String::from_utf8_lossy(&dl_out.stderr)
        );
        assert_eq!(std::fs::read(&v1_downloaded).unwrap(), v1_plaintext);

        // 6. Alice modifies V1 -> simulated ransomware V2 via real CLI -> live 2-peer Cluster!
        let v2_input = tmp_dir.join("v2-corrupted.bin");
        std::fs::write(&v2_input, b"RANSOMWARE_ENCRYPTED_CORRUPT_V2").unwrap();
        let mod_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["modify", &file_id_str, v2_input.to_str().unwrap()],
        )
        .await;
        assert!(
            mod_out.status.success(),
            "cli modify V2 failed: {}",
            String::from_utf8_lossy(&mod_out.stderr)
        );
        let mod_stdout = String::from_utf8_lossy(&mod_out.stdout);
        assert_eq!(parse_kv(&mod_stdout, "version"), "2");
        let v2_content_cid = ContentCid::parse(&parse_kv(&mod_stdout, "contentCid")).unwrap();
        let v2_env_cid = EnvelopeSetCid::parse(&parse_kv(&mod_stdout, "envelopeSetCid")).unwrap();
        assert_ne!(v2_content_cid, v1_content_cid);
        committed_cids.push(StorageCid::Content(v2_content_cid));
        committed_cids.push(StorageCid::EnvelopeSet(v2_env_cid));

        // 7. Historical access invariant: once V2 is current head, V1 is historical and
        //    even Alice cannot access V1 for share/restore until Safe grants historical read!
        let denied_share = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["share", &file_id_str, "1", &bob_id.to_string()],
        )
        .await;
        assert!(
            !denied_share.status.success(),
            "historical V1 share must fail closed before explicit historical read grant"
        );

        // Safe grants Read + Historical Read (V1) for Bob and Historical Read (V1) for Alice,
        // then Alice runs `cli share` (Option B) and Bob downloads V1 byte-for-byte!
        {
            let mut st = chain.state.lock().unwrap();
            st.read_acl
                .insert((*bob_id.as_bytes(), *file_id.as_bytes()));
            st.historical_read
                .insert((*alice_id.as_bytes(), *file_id.as_bytes(), 1));
            st.historical_read
                .insert((*bob_id.as_bytes(), *file_id.as_bytes(), 1));
        }
        let share_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["share", &file_id_str, "1", &bob_id.to_string()],
        )
        .await;
        assert!(
            share_out.status.success(),
            "cli share V1 to Bob failed: {}",
            String::from_utf8_lossy(&share_out.stderr)
        );
        let share_stdout = String::from_utf8_lossy(&share_out.stdout);
        let v1_env_rev2_cid =
            EnvelopeSetCid::parse(&parse_kv(&share_stdout, "newEnvelopeCid")).unwrap();
        committed_cids.push(StorageCid::EnvelopeSet(v1_env_rev2_cid));

        let bob_login = run_cli(
            &gw_url,
            bob_id,
            bob_sign_sk,
            bob_enc_seed,
            &bob_session_file,
            "2",
            &[
                "login",
                "--session-file",
                bob_session_file.to_str().unwrap(),
            ],
        )
        .await;
        assert!(bob_login.status.success());
        let bob_v1_out = tmp_dir.join("bob-v1.bin");
        let bob_dl = run_cli(
            &gw_url,
            bob_id,
            bob_sign_sk,
            bob_enc_seed,
            &bob_session_file,
            "2",
            &["download", &file_id_str, "1", bob_v1_out.to_str().unwrap()],
        )
        .await;
        assert!(
            bob_dl.status.success(),
            "Bob cli download V1 failed: {}",
            String::from_utf8_lossy(&bob_dl.stderr)
        );
        assert_eq!(std::fs::read(&bob_v1_out).unwrap(), v1_plaintext);

        // 8. Alice runs `cli restore <id> 1 --reader <bob>` -> appends V3 (fresh DEK, 2 live Cluster replicas)
        //    and records `restored_from_version = Some(1)` in gateway audit; Bob downloads V3!
        let restore_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &[
                "restore",
                &file_id_str,
                "1",
                "--reader",
                &bob_id.to_string(),
            ],
        )
        .await;
        assert!(
            restore_out.status.success(),
            "cli restore V1->V3 failed: {}",
            String::from_utf8_lossy(&restore_out.stderr)
        );
        let restore_stdout = String::from_utf8_lossy(&restore_out.stdout);
        let v3_content_cid = ContentCid::parse(&parse_kv(&restore_stdout, "contentCid")).unwrap();
        let v3_env_cid =
            EnvelopeSetCid::parse(&parse_kv(&restore_stdout, "envelopeSetCid")).unwrap();
        assert_ne!(v3_content_cid, v1_content_cid);
        committed_cids.push(StorageCid::Content(v3_content_cid));
        committed_cids.push(StorageCid::EnvelopeSet(v3_env_cid));
        assert_eq!(
            store.state.lock().unwrap().restore_audit_sources,
            vec![Some(1)],
            "restore must record source version 1 in file.version_restore audit"
        );

        let bob_v3_out = tmp_dir.join("bob-v3.bin");
        let bob_dl_v3 = run_cli(
            &gw_url,
            bob_id,
            bob_sign_sk,
            bob_enc_seed,
            &bob_session_file,
            "2",
            &["download", &file_id_str, "3", bob_v3_out.to_str().unwrap()],
        )
        .await;
        assert!(bob_dl_v3.status.success());
        assert_eq!(std::fs::read(&bob_v3_out).unwrap(), v1_plaintext);

        // 9. BAD CASE A: Raw plaintext posted to /v1/blobs/content -> 400 Bad Request (rejected before IPFS).
        let alice_bearer = std::fs::read_to_string(&alice_session_file)
            .unwrap()
            .trim()
            .to_owned();
        let http = reqwest::Client::new();
        let plaintext_resp = http
            .post(format!("{gw_url}/v1/blobs/content"))
            .bearer_auth(&alice_bearer)
            .body(b"UNENCRYPTED PLAINTEXT MUST BE REJECTED".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(plaintext_resp.status(), reqwest::StatusCode::BAD_REQUEST);

        // 10. BAD CASE B: Bob (Read-only, NOT in Write ACL) runs `cli modify` -> rejected BEFORE pinning!
        let bob_bad_mod = run_cli(
            &gw_url,
            bob_id,
            bob_sign_sk,
            bob_enc_seed,
            &bob_session_file,
            "2",
            &["modify", &file_id_str, v2_input.to_str().unwrap()],
        )
        .await;
        assert!(
            !bob_bad_mod.status.success(),
            "read-only Bob must NOT be allowed to modify or pin blobs"
        );

        // 11. BAD CASE C: Impossible MIN_PIN_REPLICAS=5 against 2-peer Cluster fails closed!
        let strict_ipfs = IpfsClusterStore::new(IpfsConfig {
            kubo_api_urls: kubo_urls,
            cluster_api_urls: cluster_urls,
            cluster_credentials: ClusterCredentials::new(cluster_user, cluster_password),
            request_timeout: Duration::from_secs(10),
            replication_timeout: Duration::from_secs(3),
            replication_poll_interval: Duration::from_millis(250),
            max_upload_bytes: 32 * 1024 * 1024,
        })
        .unwrap();
        let strict_state = AppState::new(
            store.clone(),
            chain.clone(),
            strict_ipfs,
            GatewayConfig {
                environment: crate::config::RuntimeEnvironment::Development,
                database_url: "postgres://unused".to_owned(),
                besu_rpc_url: "http://127.0.0.1:8545".to_owned(),
                chain_id: 1337,
                access_governance: access_gov,
                file_registry: file_reg,
                audience: "rrds-live-cli-e2e".to_owned(),
                bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                challenge_ttl_seconds: 120,
                session_ttl_seconds: 900,
                rate_limit_capacity: 500,
                rate_limit_refill_per_second: 50.0,
                member_rate_limit_capacity: 500,
                member_rate_limit_refill_per_second: 50.0,
                org_rate_limit_capacity: 500,
                org_rate_limit_refill_per_second: 50.0,
                invalid_sig_limit_capacity: 50,
                invalid_sig_limit_refill_per_second: 5.0,
                max_concurrent_streams: 32,
                min_pin_replicas: 5,
                default_tx_gas_limit: 2_000_000,
                transaction_confirmation_timeout_seconds: 30,
                orphan_retention_seconds: 3600,
                storage_health_interval_seconds: 30,
                max_blob_upload_bytes: 32 * 1024 * 1024,
            },
        );
        let strict_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let strict_url = format!("http://{}", strict_listener.local_addr().unwrap());
        let strict_handle = tokio::spawn(async move {
            axum::serve(
                strict_listener,
                router(strict_state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let strict_upload = run_cli(
            &strict_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "5",
            &[
                "upload",
                v2_input.to_str().unwrap(),
                "--name",
                "impossible-quorum.bin",
                "--file-id",
                &FileId::from_bytes([0xac; 32]).to_string(),
            ],
        )
        .await;
        assert!(
            !strict_upload.status.success(),
            "MIN_PIN_REPLICAS=5 against 2 live Cluster peers must fail closed"
        );
        strict_handle.abort();

        // 12. BAD CASE D: Reverted V4 write -> OrphanBlobCleaner live DELETE /pins/{cid} on Cluster!
        //     Committed V1/V2/V3 CIDs MUST remain pinned on 2 peers; reverted V4 CIDs MUST be unpinned.
        *force_revert.lock().unwrap() = true;
        let v4_input = tmp_dir.join("v4-reverted.bin");
        std::fs::write(&v4_input, b"V4_REVERTED_ORPHAN_CLEANUP_PAYLOAD").unwrap();
        let reverted_mod = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &["modify", &file_id_str, v4_input.to_str().unwrap()],
        )
        .await;
        assert!(
            !reverted_mod.status.success(),
            "reverted V4 modify must report failure to CLI"
        );
        *force_revert.lock().unwrap() = false;

        let candidate_cids: Vec<String> = store
            .state
            .lock()
            .unwrap()
            .orphan_blobs
            .iter()
            .filter_map(|(cid, (_, status))| (status == "candidate").then_some(cid.clone()))
            .collect();
        assert_eq!(
            candidate_cids.len(),
            2,
            "reverted V4 upload should leave exactly 2 orphan candidates (content + envelope), got {candidate_cids:?}"
        );

        let cleanup_summary = crate::maintenance::cleanup_orphan_blobs_once(&cleanup_state, 0, 50)
            .await
            .expect("run live OrphanBlobCleaner");
        assert_eq!(cleanup_summary.unpinned, 2);
        assert_eq!(cleanup_summary.skipped_due_to_error, 0);

        // Verify V1 content CID is STILL pinned on 2 live Cluster peers after cleanup!
        let still_pinned = cleanup_state
            .blob_store
            .ensure_replication(StorageCid::Content(v1_content_cid.clone()), 2)
            .await
            .expect("committed V1 content must remain pinned after orphan cleanup");
        assert!(still_pinned.pinned_peers.len() >= 2);

        // 13. Session revocation (`cli logout`) invalidates session immediately.
        let logout_out = run_cli(
            &gw_url,
            alice_id,
            alice_sign_sk,
            alice_enc_seed,
            &alice_session_file,
            "2",
            &[
                "logout",
                "--session-file",
                alice_session_file.to_str().unwrap(),
            ],
        )
        .await;
        assert!(logout_out.status.success());

        // Teardown: cleanly unpin temporary test objects from local Cluster and remove tmp dir.
        for cid in committed_cids {
            let _ = cleanup_state.blob_store.unpin(cid).await;
        }
        gw_handle.abort();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
