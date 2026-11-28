//! Operational maintenance workers for the RRDS gateway:
//! - Safe orphan blob cleanup (`TECHNICAL_SPECIFICATION.md` §§7.13, 9.2 #10):
//!   verifies a candidate CID is unreferenced in BOTH PostgreSQL projections
//!   and authoritative on-chain contract state before unpinning from IPFS Cluster.
//! - Background storage peer/Cluster health monitor (`TECHNICAL_SPECIFICATION.md` §9.9 B).

use std::{sync::Arc, time::Duration};

use chain_adapter::RelayOutcome;
use domain::{ContentCid, EnvelopeSetCid, FileId};
use ports::{BlobStore, StorageCid, StorageError, StorageHealthStatus};
use tokio::sync::watch;

use crate::routes::AppState;

/// Summary of one pending relayed-transaction reconciliation pass
/// (`TECHNICAL_SPECIFICATION.md` §10.4.7).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingTxReconcileSummary {
    pub inspected: usize,
    pub confirmed: usize,
    pub reverted: usize,
    pub still_pending: usize,
    pub skipped_due_to_error: usize,
}

/// Reconciles persisted `pending` relayed transactions against Besu receipts.
///
/// Runs immediately at gateway startup and periodically in the background so
/// transactions interrupted by a crash, restart, or confirmation timeout
/// automatically transition to `confirmed` or `reverted` and update blob
/// reference/orphan state cleanly.
pub async fn reconcile_pending_transactions_once(
    state: &AppState,
    batch_limit: u32,
) -> Result<PendingTxReconcileSummary, String> {
    let Some(relayer) = state.relayer.as_ref() else {
        return Ok(PendingTxReconcileSummary::default());
    };
    let pending = state
        .store
        .list_pending_relayed_transactions(batch_limit)
        .await
        .map_err(|err| format!("failed to list pending relayed transactions: {err}"))?;
    if pending.is_empty() {
        return Ok(PendingTxReconcileSummary::default());
    }

    let mut summary = PendingTxReconcileSummary {
        inspected: pending.len(),
        ..PendingTxReconcileSummary::default()
    };

    for record in pending {
        let Some(tx_hash_bytes) = domain::hex::parse_lowercase_fixed_hex::<32>(&record.tx_hash)
        else {
            summary.skipped_due_to_error += 1;
            continue;
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
                    summary.skipped_due_to_error += 1;
                    continue;
                }
                if let Some(cid) = record.content_cid.as_deref() {
                    let _ = state.store.mark_blob_referenced(cid).await;
                }
                let _ = state
                    .store
                    .mark_blob_referenced(&record.envelope_set_cid)
                    .await;
                let _ = state
                    .store
                    .record_write_attempt(
                        "transaction.reconcile",
                        Some(&record.actor_member_id),
                        "system:reconciler",
                        &record.file_id,
                        record.version_number,
                        Some(&record.operation_id),
                        record.chain_id,
                        Some(receipt.block_number),
                        "committed",
                        None,
                        None,
                    )
                    .await;
                summary.confirmed += 1;
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
                    summary.skipped_due_to_error += 1;
                    continue;
                }
                if let Some(cid) = record.content_cid.as_deref() {
                    let _ = state
                        .store
                        .record_orphan_blob_candidate(
                            cid,
                            "content",
                            &record.actor_member_id,
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
                        &record.actor_member_id,
                        Some(&record.file_id),
                        Some(record.version_number),
                        Some(&record.tx_hash),
                        "contract_reverted",
                    )
                    .await;
                let _ = state
                    .store
                    .record_write_attempt(
                        "transaction.reconcile",
                        Some(&record.actor_member_id),
                        "system:reconciler",
                        &record.file_id,
                        record.version_number,
                        Some(&record.operation_id),
                        record.chain_id,
                        Some(receipt.block_number),
                        "reverted",
                        Some("contract_reverted"),
                        None,
                    )
                    .await;
                summary.reverted += 1;
            }
            Ok(None) => {
                summary.still_pending += 1;
            }
            Err(_) => {
                summary.skipped_due_to_error += 1;
            }
        }
    }

    Ok(summary)
}

/// Spawns a cancellable startup + periodic reconciler for persisted `pending`
/// relayed transactions (`TECHNICAL_SPECIFICATION.md` §10.4.7).
#[allow(dead_code)]
pub fn spawn_pending_transaction_reconciler(
    state: AppState,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match reconcile_pending_transactions_once(&state, 50).await {
                        Ok(summary) if summary.confirmed > 0 || summary.reverted > 0 || summary.skipped_due_to_error > 0 => {
                            let report = serde_json::json!({
                                "event": "relayer.pending_reconciliation",
                                "inspected": summary.inspected,
                                "confirmed": summary.confirmed,
                                "reverted": summary.reverted,
                                "stillPending": summary.still_pending,
                                "skippedDueToError": summary.skipped_due_to_error,
                            });
                            eprintln!("{report}");
                        }
                        Ok(_) => {}
                        Err(err) => {
                            let alert = serde_json::json!({
                                "event": "relayer.pending_reconciliation_failed",
                                "error": err,
                            });
                            eprintln!("{alert}");
                        }
                    }
                }
            }
        }
    })
}

/// Summary of one safe orphan blob cleanup pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrphanCleanupSummary {
    pub inspected: usize,
    pub unpinned: usize,
    pub marked_referenced: usize,
    pub skipped_due_to_error: usize,
}

/// Executes a single safe orphan cleanup pass against candidates older than
/// `min_age_seconds`.
///
/// Safety invariant (§7.13, §9.2 #10):
/// - Never unpins a CID if PostgreSQL projections reference it.
/// - Never unpins a CID if authoritative on-chain Besu state references it
///   (instead transitions the candidate row to `referenced`).
/// - Fails closed (skips unpinning) if Besu RPC is unavailable or if the
///   candidate metadata cannot be verified cleanly.
pub async fn cleanup_orphan_blobs_once(
    state: &AppState,
    min_age_seconds: u64,
    batch_limit: u32,
) -> Result<OrphanCleanupSummary, String> {
    let candidates = state
        .store
        .list_eligible_orphan_candidates(min_age_seconds, batch_limit)
        .await
        .map_err(|err| format!("failed to list orphan candidates: {err}"))?;
    if candidates.is_empty() {
        return Ok(OrphanCleanupSummary::default());
    }

    let finalized = state
        .chain
        .finalized_block()
        .await
        .map_err(|_| "chain unavailable for authoritative orphan verification".to_owned())?;

    let mut summary = OrphanCleanupSummary {
        inspected: candidates.len(),
        ..OrphanCleanupSummary::default()
    };

    for candidate in candidates {
        let storage_cid = match candidate.blob_kind.as_str() {
            "content" => match ContentCid::parse(&candidate.cid) {
                Ok(cid) => StorageCid::Content(cid),
                Err(_) => {
                    summary.skipped_due_to_error += 1;
                    continue;
                }
            },
            "envelope" => match EnvelopeSetCid::parse(&candidate.cid) {
                Ok(cid) => StorageCid::EnvelopeSet(cid),
                Err(_) => {
                    summary.skipped_due_to_error += 1;
                    continue;
                }
            },
            _ => {
                summary.skipped_due_to_error += 1;
                continue;
            }
        };

        // Re-check authoritative on-chain state when (file_id, version_number) is known.
        if let (Some(raw_file_id), Some(version_number)) =
            (candidate.file_id.as_deref(), candidate.version_number)
        {
            let Some(file_id_bytes) = domain::hex::parse_lowercase_fixed_hex::<32>(raw_file_id)
            else {
                summary.skipped_due_to_error += 1;
                continue;
            };
            let file_id = FileId::from_bytes(file_id_bytes);
            match is_referenced_on_chain(
                state,
                &file_id,
                version_number,
                &candidate.blob_kind,
                &candidate.cid,
                finalized.number,
            )
            .await
            {
                Ok(true) => {
                    if state
                        .store
                        .mark_blob_referenced(&candidate.cid)
                        .await
                        .is_ok()
                    {
                        summary.marked_referenced += 1;
                    } else {
                        summary.skipped_due_to_error += 1;
                    }
                    continue;
                }
                Ok(false) => {}
                Err(()) => {
                    // Fail closed if authoritative Besu query fails.
                    summary.skipped_due_to_error += 1;
                    continue;
                }
            }
        }

        // Double-check projection state immediately before unpinning to narrow race windows.
        match state
            .store
            .is_cid_referenced_in_projections(&candidate.cid)
            .await
        {
            Ok(true) => {
                if state
                    .store
                    .mark_blob_referenced(&candidate.cid)
                    .await
                    .is_ok()
                {
                    summary.marked_referenced += 1;
                } else {
                    summary.skipped_due_to_error += 1;
                }
                continue;
            }
            Ok(false) => {}
            Err(_) => {
                summary.skipped_due_to_error += 1;
                continue;
            }
        }

        match state.blob_store.unpin(storage_cid).await {
            Ok(()) => {
                if state
                    .store
                    .mark_orphan_blob_unpinned(&candidate.cid)
                    .await
                    .is_ok()
                {
                    summary.unpinned += 1;
                } else {
                    summary.skipped_due_to_error += 1;
                }
            }
            Err(_) => {
                summary.skipped_due_to_error += 1;
            }
        }
    }

    Ok(summary)
}

async fn is_referenced_on_chain(
    state: &AppState,
    file_id: &FileId,
    version_number: u64,
    blob_kind: &str,
    cid: &str,
    block_number: u64,
) -> Result<bool, ()> {
    if blob_kind == "content" {
        let version = state
            .chain
            .file_version(
                &state.config.file_registry,
                file_id.as_bytes(),
                version_number,
                block_number,
            )
            .await
            .map_err(|_| ())?;
        if let Some(version) = version
            && version.content_cid == cid
        {
            return Ok(true);
        }
    }

    if blob_kind == "envelope" {
        let current = state
            .chain
            .current_envelope_set(
                &state.config.access_governance,
                file_id.as_bytes(),
                version_number,
                block_number,
            )
            .await
            .map_err(|_| ())?;
        if let Some(current) = current
            && current.cid == cid
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Spawns a cancellable periodic orphan blob cleanup task (`TECHNICAL_SPECIFICATION.md` §§7.13, 9.2 #10).
pub fn spawn_orphan_blob_cleaner(
    state: AppState,
    retention_seconds: u64,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match cleanup_orphan_blobs_once(&state, retention_seconds, 50).await {
                        Ok(summary) if summary.unpinned > 0 || summary.marked_referenced > 0 || summary.skipped_due_to_error > 0 => {
                            let report = serde_json::json!({
                                "event": "storage.orphan_cleanup",
                                "inspected": summary.inspected,
                                "unpinned": summary.unpinned,
                                "markedReferenced": summary.marked_referenced,
                                "skippedDueToError": summary.skipped_due_to_error,
                            });
                            eprintln!("{report}");
                        }
                        Ok(_) => {}
                        Err(err) => {
                            let alert = serde_json::json!({
                                "event": "storage.orphan_cleanup_failed",
                                "error": err,
                            });
                            eprintln!("{alert}");
                        }
                    }
                }
            }
        }
    })
}

/// Runs a single storage peer / Cluster health probe (`TECHNICAL_SPECIFICATION.md` §9.9 B).
pub async fn check_storage_health_once(
    blob_store: &dyn BlobStore,
) -> Result<StorageHealthStatus, StorageError> {
    blob_store.health_status().await
}

/// Spawns a cancellable background monitoring loop that checks IPFS / Cluster
/// peer health and emits structured JSON alerts whenever peers are degraded or
/// unreachable (`TECHNICAL_SPECIFICATION.md` §9.9 B).
#[allow(dead_code)]
pub fn spawn_storage_health_monitor(
    blob_store: Arc<dyn BlobStore>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate first tick so startup does not spam before listener bind.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match check_storage_health_once(blob_store.as_ref()).await {
                        Ok(status) if status.is_degraded() || !status.is_healthy() => {
                            let alert = serde_json::json!({
                                "event": "storage.health_degraded",
                                "healthyKuboPeers": status.healthy_kubo_peers,
                                "totalKuboPeers": status.total_kubo_peers,
                                "healthyClusterPeers": status.healthy_cluster_peers,
                                "totalClusterPeers": status.total_cluster_peers,
                            });
                            eprintln!("{alert}");
                        }
                        Ok(_) => {}
                        Err(_) => {
                            let alert = serde_json::json!({
                                "event": "storage.health_probe_failed",
                            });
                            eprintln!("{alert}");
                        }
                    }
                }
            }
        }
    })
}
