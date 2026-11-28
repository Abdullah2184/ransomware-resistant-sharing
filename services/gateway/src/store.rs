use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha3::{Digest, Keccak256};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::auth::LoginChallenge;

const AUDIT_STREAM_LOCK: i64 = 0x5252_4653;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedFolder {
    pub folder_id: String,
    pub organization_id: String,
    pub parent_folder_id: String,
    pub display_name: String,
    pub updated_block_number: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedFile {
    pub file_id: String,
    pub organization_id: String,
    pub creator_member_id: String,
    pub display_name: String,
    pub parent_folder_id: String,
    pub file_status: u64,
    pub current_version: u64,
    pub current_head_manifest_hash: String,
    pub updated_block_number: u64,
}

#[derive(Clone, Debug)]
pub struct FileListingResult {
    pub indexed_block: Option<u64>,
    pub indexed_block_hash: Option<String>,
    pub folders: Vec<ProjectedFolder>,
    pub files: Vec<ProjectedFile>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedVersion {
    pub version_number: u64,
    pub manifest_hash: String,
    pub parent_manifest_hash: String,
    pub epoch_id: String,
    pub author_member_id: String,
    pub author_signing_address: String,
    pub content_cid: String,
    pub current_envelope_set_cid: String,
    pub envelope_revision: u32,
    pub historical_read_granted: bool,
    pub transaction_hash: String,
    pub block_number: u64,
}

#[derive(Clone, Debug)]
pub struct VersionHistoryResult {
    pub indexed_block: Option<u64>,
    pub indexed_block_hash: Option<String>,
    pub versions: Vec<ProjectedVersion>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventRecord {
    pub sequence: i64,
    pub record: serde_json::Value,
    pub previous_hash: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayedTransactionRecord {
    pub tx_hash: String,
    pub operation_kind: String,
    pub operation_id: String,
    pub actor_member_id: String,
    pub file_id: String,
    pub version_number: u64,
    pub content_cid: Option<String>,
    pub envelope_set_cid: String,
    pub chain_id: u64,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub gas_used: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanBlobCandidate {
    pub cid: String,
    pub blob_kind: String,
    pub uploader_member_id: String,
    pub file_id: Option<String>,
    pub version_number: Option<u64>,
    pub tx_hash: Option<String>,
    pub reason: String,
}

#[derive(Clone)]
pub struct GatewayStore {
    pool: PgPool,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    occurred_at_unix_ms: u128,
    action: &'a str,
    actor_member_id: Option<&'a str>,
    source_id: &'a str,
    outcome: &'a str,
    reason_code: Option<&'a str>,
    operation_id: Option<&'a str>,
    resource_type: Option<&'a str>,
    resource_id: Option<&'a str>,
    resource_version: Option<u64>,
    chain_id: u64,
    block_number: Option<u64>,
}

#[derive(Serialize)]
struct WriteAuditRecord<'a> {
    occurred_at_unix_ms: u128,
    action: &'a str,
    actor_member_id: Option<&'a str>,
    source_id: &'a str,
    outcome: &'a str,
    reason_code: Option<&'a str>,
    operation_id: Option<&'a str>,
    resource_type: Option<&'a str>,
    resource_id: Option<&'a str>,
    resource_version: Option<u64>,
    chain_id: u64,
    block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restored_from_version: Option<u64>,
}

impl GatewayStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn take_rate_limit_token(
        &self,
        key: &str,
        capacity: f64,
        refill_per_second: f64,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let allowed = take_rate_limit_token_in_transaction(
            &mut transaction,
            key,
            capacity,
            refill_per_second,
        )
        .await?;
        transaction.commit().await?;
        Ok(allowed)
    }

    async fn create_challenge_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        challenge: &LoginChallenge,
        source_id: &str,
        chain_id: u64,
    ) -> Result<(), sqlx::Error> {
        let member_id = challenge.member_id.as_str();
        let nonce = decode_nonce(&challenge.nonce).ok_or(sqlx::Error::Protocol(
            "invalid canonical challenge nonce".into(),
        ))?;

        sqlx::query("DELETE FROM gateway_login_challenges WHERE expires_at <= $1")
            .bind(unix_seconds()? as i64)
            .execute(&mut **transaction)
            .await?;
        sqlx::query(
            "INSERT INTO gateway_login_challenges \
             (member_id, nonce, issued_at, expires_at, audience, protocol_version) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(member_id)
        .bind(nonce.as_slice())
        .bind(challenge.issued_at as i64)
        .bind(challenge.expires_at as i64)
        .bind(&challenge.audience)
        .bind(challenge.protocol_version as i32)
        .execute(&mut **transaction)
        .await?;
        append_audit(
            transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "auth.challenge",
                actor_member_id: None,
                source_id,
                outcome: "issued",
                reason_code: None,
                operation_id: Some(&challenge.nonce),
                resource_type: None,
                resource_id: None,
                resource_version: None,
                chain_id,
                block_number: None,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_login_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        challenge: &LoginChallenge,
        token_hash: &[u8; 32],
        session_expires_at: u64,
        source_id: &str,
        chain_id: u64,
        block_number: u64,
    ) -> Result<bool, sqlx::Error> {
        let nonce = decode_nonce(&challenge.nonce).ok_or(sqlx::Error::Protocol(
            "invalid canonical challenge nonce".into(),
        ))?;
        let consumed = sqlx::query_scalar::<_, String>(
            "UPDATE gateway_login_challenges \
             SET consumed_at = clock_timestamp() \
             WHERE member_id = $1 AND nonce = $2 AND issued_at = $3 \
               AND expires_at = $4 AND audience = $5 AND protocol_version = $6 \
               AND consumed_at IS NULL AND expires_at > $7 \
             RETURNING member_id",
        )
        .bind(&challenge.member_id)
        .bind(nonce.as_slice())
        .bind(challenge.issued_at as i64)
        .bind(challenge.expires_at as i64)
        .bind(&challenge.audience)
        .bind(challenge.protocol_version as i32)
        .bind(unix_seconds()? as i64)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(member_id) = consumed else {
            return Ok(false);
        };

        sqlx::query("DELETE FROM gateway_sessions WHERE expires_at <= $1")
            .bind(unix_seconds()? as i64)
            .execute(&mut **transaction)
            .await?;
        sqlx::query(
            "INSERT INTO gateway_sessions (token_hash, member_id, expires_at) \
             VALUES ($1, $2, $3)",
        )
        .bind(token_hash.as_slice())
        .bind(&member_id)
        .bind(session_expires_at as i64)
        .execute(&mut **transaction)
        .await?;
        append_audit(
            transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "auth.session",
                actor_member_id: Some(&member_id),
                source_id,
                outcome: "issued",
                reason_code: None,
                operation_id: Some(&challenge.nonce),
                resource_type: None,
                resource_id: None,
                resource_version: None,
                chain_id,
                block_number: Some(block_number),
            },
        )
        .await?;
        Ok(true)
    }

    pub async fn create_challenge(
        &self,
        challenge: &LoginChallenge,
        source_id: &str,
        chain_id: u64,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        self.create_challenge_in_transaction(&mut transaction, challenge, source_id, chain_id)
            .await?;
        transaction.commit().await
    }

    pub async fn record_auth_failure(
        &self,
        action: &'static str,
        source_id: &str,
        reason_code: &'static str,
        operation_id: Option<&str>,
        chain_id: u64,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action,
                actor_member_id: None,
                source_id,
                outcome: "denied",
                reason_code: Some(reason_code),
                operation_id,
                resource_type: None,
                resource_id: None,
                resource_version: None,
                chain_id,
                block_number: None,
            },
        )
        .await?;
        transaction.commit().await
    }

    pub async fn record_session_validation(
        &self,
        member_id: Option<&str>,
        source_id: &str,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        chain_id: u64,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "auth.session.validate",
                actor_member_id: member_id,
                source_id,
                outcome,
                reason_code,
                operation_id: None,
                resource_type: None,
                resource_id: None,
                resource_version: None,
                chain_id,
                block_number: None,
            },
        )
        .await?;
        transaction.commit().await
    }

    pub async fn complete_login(
        &self,
        challenge: &LoginChallenge,
        token_hash: &[u8; 32],
        session_expires_at: u64,
        source_id: &str,
        chain_id: u64,
        block_number: u64,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let completed = self
            .complete_login_in_transaction(
                &mut transaction,
                challenge,
                token_hash,
                session_expires_at,
                source_id,
                chain_id,
                block_number,
            )
            .await?;
        if completed {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(completed)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_access_attempt(
        &self,
        member_id: &str,
        source_id: &str,
        file_id: &str,
        version: u64,
        nonce: &[u8; 32],
        deadline: u64,
        chain_id: u64,
        block_number: u64,
        authorized: bool,
        reason_code: Option<&'static str>,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM gateway_used_access_nonces WHERE expires_at <= $1")
            .bind(unix_seconds()? as i64)
            .execute(&mut *transaction)
            .await?;
        let inserted = sqlx::query(
            "INSERT INTO gateway_used_access_nonces \
             (member_id, operation_nonce, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT (member_id, operation_nonce) DO NOTHING",
        )
        .bind(member_id)
        .bind(nonce.as_slice())
        .bind(deadline as i64)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        let replayed = !inserted;
        let outcome = if authorized && !replayed {
            "authorized"
        } else {
            "denied"
        };
        let reason = if replayed {
            Some("replay_detected")
        } else {
            reason_code
        };
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "file.access_lookup",
                actor_member_id: Some(member_id),
                source_id,
                outcome,
                reason_code: reason,
                operation_id: Some(&encode_hex(nonce)),
                resource_type: Some("file-version"),
                resource_id: Some(file_id),
                resource_version: Some(version),
                chain_id,
                block_number: Some(block_number),
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(authorized && !replayed)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_content_attempt(
        &self,
        member_id: Option<&str>,
        source_id: &str,
        file_id: &str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "file.content_retrieval",
                actor_member_id: member_id,
                source_id,
                outcome,
                reason_code,
                operation_id: None,
                resource_type: Some("file-version"),
                resource_id: Some(file_id),
                resource_version: Some(version),
                chain_id,
                block_number,
            },
        )
        .await?;
        transaction.commit().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_envelope_attempt(
        &self,
        member_id: Option<&str>,
        source_id: &str,
        file_id: &str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "file.envelope_retrieval",
                actor_member_id: member_id,
                source_id,
                outcome,
                reason_code,
                operation_id: None,
                resource_type: Some("file-version"),
                resource_id: Some(file_id),
                resource_version: Some(version),
                chain_id,
                block_number,
            },
        )
        .await?;
        transaction.commit().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_write_attempt_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        action: &'static str,
        member_id: Option<&str>,
        source_id: &str,
        file_id: &str,
        version: u64,
        operation_id: Option<&str>,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        restored_from_version: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        append_audit_entry(
            transaction,
            &WriteAuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action,
                actor_member_id: member_id,
                source_id,
                outcome,
                reason_code,
                operation_id,
                resource_type: Some("file-version"),
                resource_id: Some(file_id),
                resource_version: Some(version),
                chain_id,
                block_number,
                restored_from_version,
            },
            Some("file-version"),
            Some(file_id),
            Some(version),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_write_attempt(
        &self,
        action: &'static str,
        member_id: Option<&str>,
        source_id: &str,
        file_id: &str,
        version: u64,
        operation_id: Option<&str>,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        restored_from_version: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        self.record_write_attempt_in_transaction(
            &mut transaction,
            action,
            member_id,
            source_id,
            file_id,
            version,
            operation_id,
            chain_id,
            block_number,
            outcome,
            reason_code,
            restored_from_version,
        )
        .await?;
        transaction.commit().await
    }

    pub async fn member_organization_id(
        &self,
        member_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT organization_id FROM members_projection WHERE member_id = $1")
            .bind(member_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn record_relayed_transaction(
        &self,
        record: &RelayedTransactionRecord,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO gateway_relayed_transactions \
             (tx_hash, operation_kind, operation_id, actor_member_id, file_id, version_number, \
              content_cid, envelope_set_cid, chain_id, status, block_number, block_hash, gas_used, \
              updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now()) \
             ON CONFLICT (tx_hash) DO UPDATE SET \
               status = EXCLUDED.status, \
               block_number = COALESCE(EXCLUDED.block_number, gateway_relayed_transactions.block_number), \
               block_hash = COALESCE(EXCLUDED.block_hash, gateway_relayed_transactions.block_hash), \
               gas_used = COALESCE(EXCLUDED.gas_used, gateway_relayed_transactions.gas_used), \
               updated_at = now()",
        )
        .bind(&record.tx_hash)
        .bind(&record.operation_kind)
        .bind(&record.operation_id)
        .bind(&record.actor_member_id)
        .bind(&record.file_id)
        .bind(record.version_number as i64)
        .bind(record.content_cid.as_deref())
        .bind(&record.envelope_set_cid)
        .bind(record.chain_id as i64)
        .bind(&record.status)
        .bind(record.block_number.map(|value| value as i64))
        .bind(record.block_hash.as_deref())
        .bind(record.gas_used.map(|value| value as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_relayed_transaction(
        &self,
        tx_hash: &str,
    ) -> Result<Option<RelayedTransactionRecord>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT tx_hash, operation_kind, operation_id, actor_member_id, file_id, \
                    version_number, content_cid, envelope_set_cid, chain_id, status, \
                    block_number, block_hash, gas_used \
             FROM gateway_relayed_transactions \
             WHERE tx_hash = $1",
        )
        .bind(tx_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(RelayedTransactionRecord {
                tx_hash: row.try_get("tx_hash")?,
                operation_kind: row.try_get("operation_kind")?,
                operation_id: row.try_get("operation_id")?,
                actor_member_id: row.try_get("actor_member_id")?,
                file_id: row.try_get("file_id")?,
                version_number: u64::try_from(row.try_get::<i64, _>("version_number")?)
                    .unwrap_or(0),
                content_cid: row.try_get("content_cid")?,
                envelope_set_cid: row.try_get("envelope_set_cid")?,
                chain_id: u64::try_from(row.try_get::<i64, _>("chain_id")?).unwrap_or(0),
                status: row.try_get("status")?,
                block_number: row
                    .try_get::<Option<i64>, _>("block_number")?
                    .and_then(|v| u64::try_from(v).ok()),
                block_hash: row.try_get("block_hash")?,
                gas_used: row
                    .try_get::<Option<i64>, _>("gas_used")?
                    .and_then(|v| u64::try_from(v).ok()),
            })
        })
        .transpose()
    }

    pub async fn update_relayed_transaction_status(
        &self,
        tx_hash: &str,
        status: &str,
        block_number: Option<u64>,
        block_hash: Option<&str>,
        gas_used: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE gateway_relayed_transactions \
             SET status = $2, \
                 block_number = COALESCE($3, block_number), \
                 block_hash = COALESCE($4, block_hash), \
                 gas_used = COALESCE($5, gas_used), \
                 updated_at = now() \
             WHERE tx_hash = $1",
        )
        .bind(tx_hash)
        .bind(status)
        .bind(block_number.map(|value| value as i64))
        .bind(block_hash)
        .bind(gas_used.map(|value| value as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_orphan_blob_candidate(
        &self,
        cid: &str,
        blob_kind: &str,
        uploader_member_id: &str,
        file_id: Option<&str>,
        version_number: Option<u64>,
        tx_hash: Option<&str>,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO gateway_orphan_blobs \
             (cid, blob_kind, uploader_member_id, file_id, version_number, tx_hash, reason, status, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'candidate', now()) \
             ON CONFLICT (cid) DO UPDATE SET \
               file_id = COALESCE(EXCLUDED.file_id, gateway_orphan_blobs.file_id), \
               version_number = COALESCE(EXCLUDED.version_number, gateway_orphan_blobs.version_number), \
               tx_hash = COALESCE(EXCLUDED.tx_hash, gateway_orphan_blobs.tx_hash), \
               reason = CASE \
                 WHEN gateway_orphan_blobs.status = 'referenced' THEN gateway_orphan_blobs.reason \
                 ELSE EXCLUDED.reason \
               END, \
               updated_at = now()",
        )
        .bind(cid)
        .bind(blob_kind)
        .bind(uploader_member_id)
        .bind(file_id)
        .bind(version_number.map(|v| v as i64))
        .bind(tx_hash)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_blob_referenced(&self, cid: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE gateway_orphan_blobs SET status = 'referenced', updated_at = now() \
             WHERE cid = $1",
        )
        .bind(cid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_cid_referenced_in_projections(&self, cid: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT EXISTS ( \
                SELECT 1 FROM versions_projection \
                WHERE content_cid = $1 OR initial_envelope_set_cid = $1 \
             ) OR EXISTS ( \
                SELECT 1 FROM envelope_sets_projection \
                WHERE envelope_set_cid = $1 \
             )",
        )
        .bind(cid)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_eligible_orphan_candidates(
        &self,
        min_age_seconds: u64,
        limit: u32,
    ) -> Result<Vec<OrphanBlobCandidate>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT o.cid, o.blob_kind, o.uploader_member_id, o.file_id, o.version_number, \
                    o.tx_hash, o.reason \
             FROM gateway_orphan_blobs o \
             WHERE o.status = 'candidate' \
               AND o.created_at <= now() - make_interval(secs => $1::double precision) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM versions_projection v \
                   WHERE v.content_cid = o.cid OR v.initial_envelope_set_cid = o.cid \
               ) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM envelope_sets_projection e \
                   WHERE e.envelope_set_cid = o.cid \
               ) \
             ORDER BY o.created_at ASC \
             LIMIT $2",
        )
        .bind(min_age_seconds as f64)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(OrphanBlobCandidate {
                cid: row.try_get("cid")?,
                blob_kind: row.try_get("blob_kind")?,
                uploader_member_id: row.try_get("uploader_member_id")?,
                file_id: row.try_get("file_id")?,
                version_number: row
                    .try_get::<Option<i64>, _>("version_number")?
                    .and_then(|v| u64::try_from(v).ok()),
                tx_hash: row.try_get("tx_hash")?,
                reason: row.try_get("reason")?,
            });
        }
        Ok(out)
    }

    pub async fn mark_orphan_blob_unpinned(&self, cid: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE gateway_orphan_blobs SET status = 'unpinned', updated_at = now() \
             WHERE cid = $1 AND status = 'candidate'",
        )
        .bind(cid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn active_session_member(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT member_id FROM gateway_sessions \
             WHERE token_hash = $1 AND expires_at > $2 AND revoked_at IS NULL",
        )
        .bind(token_hash.as_slice())
        .bind(unix_seconds()? as i64)
        .fetch_optional(&self.pool)
        .await
    }

    async fn revoke_session_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        token_hash: &[u8; 32],
        source_id: &str,
        chain_id: u64,
    ) -> Result<bool, sqlx::Error> {
        let member_id = sqlx::query_scalar::<_, String>(
            "UPDATE gateway_sessions \
             SET revoked_at = clock_timestamp() \
             WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2 \
             RETURNING member_id",
        )
        .bind(token_hash.as_slice())
        .bind(unix_seconds()? as i64)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(member_id) = member_id else {
            return Ok(false);
        };
        append_audit(
            transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "auth.session.revoke",
                actor_member_id: Some(member_id.trim()),
                source_id,
                outcome: "revoked",
                reason_code: None,
                operation_id: None,
                resource_type: None,
                resource_id: None,
                resource_version: None,
                chain_id,
                block_number: None,
            },
        )
        .await?;
        Ok(true)
    }

    pub async fn revoke_session(
        &self,
        token_hash: &[u8; 32],
        source_id: &str,
        chain_id: u64,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let revoked = self
            .revoke_session_in_transaction(&mut transaction, token_hash, source_id, chain_id)
            .await?;
        if revoked {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        Ok(revoked)
    }

    pub async fn list_files_and_folders(
        &self,
        chain_id: u64,
        member_id: &str,
        organization_id: &str,
        parent_folder_id: &str,
    ) -> Result<FileListingResult, sqlx::Error> {
        let checkpoint = read_indexer_checkpoint(&self.pool, chain_id).await?;
        let folder_rows = sqlx::query(
            "SELECT folder_id, organization_id, parent_folder_id, display_name, updated_block_number \
             FROM folders_projection \
             WHERE organization_id = $1 AND parent_folder_id = $2 \
             ORDER BY display_name ASC, folder_id ASC",
        )
        .bind(organization_id)
        .bind(parent_folder_id)
        .fetch_all(&self.pool)
        .await?;

        let mut folders = Vec::with_capacity(folder_rows.len());
        for row in folder_rows {
            folders.push(ProjectedFolder {
                folder_id: row.try_get::<String, _>("folder_id")?.trim().to_owned(),
                organization_id: row
                    .try_get::<String, _>("organization_id")?
                    .trim()
                    .to_owned(),
                parent_folder_id: row
                    .try_get::<String, _>("parent_folder_id")?
                    .trim()
                    .to_owned(),
                display_name: row.try_get("display_name")?,
                updated_block_number: u64::try_from(row.try_get::<i64, _>("updated_block_number")?)
                    .unwrap_or_default(),
            });
        }

        let file_rows = sqlx::query(
            "SELECT f.file_id, f.organization_id, f.creator_member_id, f.display_name, \
                    f.parent_folder_id, f.file_status, f.current_version, \
                    f.current_head_manifest_hash, f.updated_block_number \
             FROM files_projection f \
             INNER JOIN access_projection a \
                ON a.file_id = f.file_id AND a.member_id = $1 AND a.permission = 0 AND a.granted = TRUE \
             WHERE f.organization_id = $2 AND f.parent_folder_id = $3 \
               AND f.display_name IS NOT NULL AND f.current_version IS NOT NULL \
               AND f.current_head_manifest_hash IS NOT NULL \
             ORDER BY f.display_name ASC, f.file_id ASC",
        )
        .bind(member_id)
        .bind(organization_id)
        .bind(parent_folder_id)
        .fetch_all(&self.pool)
        .await?;

        let mut files = Vec::with_capacity(file_rows.len());
        for row in file_rows {
            files.push(ProjectedFile {
                file_id: row.try_get::<String, _>("file_id")?.trim().to_owned(),
                organization_id: row
                    .try_get::<String, _>("organization_id")?
                    .trim()
                    .to_owned(),
                creator_member_id: row
                    .try_get::<String, _>("creator_member_id")?
                    .trim()
                    .to_owned(),
                display_name: row.try_get("display_name")?,
                parent_folder_id: row
                    .try_get::<String, _>("parent_folder_id")?
                    .trim()
                    .to_owned(),
                file_status: u64::try_from(row.try_get::<i16, _>("file_status")?)
                    .unwrap_or_default(),
                current_version: u64::try_from(row.try_get::<i64, _>("current_version")?)
                    .unwrap_or_default(),
                current_head_manifest_hash: row
                    .try_get::<String, _>("current_head_manifest_hash")?
                    .trim()
                    .to_owned(),
                updated_block_number: u64::try_from(row.try_get::<i64, _>("updated_block_number")?)
                    .unwrap_or_default(),
            });
        }

        Ok(FileListingResult {
            indexed_block: checkpoint.as_ref().map(|(block, _)| *block),
            indexed_block_hash: checkpoint.map(|(_, hash)| hash),
            folders,
            files,
        })
    }

    pub async fn list_file_versions(
        &self,
        chain_id: u64,
        file_id: &str,
        member_id: &str,
    ) -> Result<VersionHistoryResult, sqlx::Error> {
        let checkpoint = read_indexer_checkpoint(&self.pool, chain_id).await?;
        let rows = sqlx::query(
            "SELECT v.version_number, v.manifest_hash, v.parent_manifest_hash, v.epoch_id, \
                    v.author_member_id, v.author_signing_address, v.content_cid, \
                    COALESCE(e.envelope_set_cid, v.initial_envelope_set_cid) AS current_envelope_set_cid, \
                    COALESCE(e.revision, 1) AS envelope_revision, \
                    COALESCE(h.granted, FALSE) AS historical_read_granted, \
                    v.transaction_hash, v.block_number \
             FROM versions_projection v \
             LEFT JOIN envelope_sets_projection e \
                ON e.file_id = v.file_id AND e.version_number = v.version_number \
             LEFT JOIN historical_read_access_projection h \
                ON h.file_id = v.file_id AND h.version_number = v.version_number AND h.member_id = $2 \
             WHERE v.file_id = $1 \
             ORDER BY v.version_number ASC",
        )
        .bind(file_id)
        .bind(member_id)
        .fetch_all(&self.pool)
        .await?;

        let mut versions = Vec::with_capacity(rows.len());
        for row in rows {
            versions.push(ProjectedVersion {
                version_number: u64::try_from(row.try_get::<i64, _>("version_number")?)
                    .unwrap_or_default(),
                manifest_hash: row.try_get::<String, _>("manifest_hash")?.trim().to_owned(),
                parent_manifest_hash: row
                    .try_get::<String, _>("parent_manifest_hash")?
                    .trim()
                    .to_owned(),
                epoch_id: row.try_get::<String, _>("epoch_id")?.trim().to_owned(),
                author_member_id: row
                    .try_get::<String, _>("author_member_id")?
                    .trim()
                    .to_owned(),
                author_signing_address: row
                    .try_get::<String, _>("author_signing_address")?
                    .trim()
                    .to_owned(),
                content_cid: row.try_get("content_cid")?,
                current_envelope_set_cid: row.try_get("current_envelope_set_cid")?,
                envelope_revision: u32::try_from(row.try_get::<i32, _>("envelope_revision")?)
                    .unwrap_or(1),
                historical_read_granted: row.try_get("historical_read_granted")?,
                transaction_hash: row
                    .try_get::<String, _>("transaction_hash")?
                    .trim()
                    .to_owned(),
                block_number: u64::try_from(row.try_get::<i64, _>("block_number")?)
                    .unwrap_or_default(),
            });
        }

        Ok(VersionHistoryResult {
            indexed_block: checkpoint.as_ref().map(|(block, _)| *block),
            indexed_block_hash: checkpoint.map(|(_, hash)| hash),
            versions,
        })
    }

    pub async fn query_member_audit_events(
        &self,
        member_id: &str,
        source_id: &str,
        chain_id: u64,
        block_number: u64,
        action_filter: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        append_audit(
            &mut transaction,
            AuditRecord {
                occurred_at_unix_ms: unix_millis()?,
                action: "audit.query",
                actor_member_id: Some(member_id),
                source_id,
                outcome: "authorized",
                reason_code: None,
                operation_id: None,
                resource_type: Some("audit-stream"),
                resource_id: Some(member_id),
                resource_version: None,
                chain_id,
                block_number: Some(block_number),
            },
        )
        .await?;

        let rows = sqlx::query(
            "SELECT sequence, record, previous_hash, record_hash \
             FROM gateway_audit_events \
             WHERE record->>'actor_member_id' = $1 \
               AND ($2::text IS NULL OR record->>'action' = $2) \
             ORDER BY sequence DESC \
             LIMIT $3",
        )
        .bind(member_id)
        .bind(action_filter)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let previous_hash: Vec<u8> = row.try_get("previous_hash")?;
            let record_hash: Vec<u8> = row.try_get("record_hash")?;
            events.push(AuditEventRecord {
                sequence: row.try_get("sequence")?,
                record: row.try_get("record")?,
                previous_hash: encode_hex(&previous_hash),
                record_hash: encode_hex(&record_hash),
            });
        }
        Ok(events)
    }
}

async fn read_indexer_checkpoint(
    pool: &PgPool,
    chain_id: u64,
) -> Result<Option<(u64, String)>, sqlx::Error> {
    let Ok(chain_id) = i64::try_from(chain_id) else {
        return Ok(None);
    };
    let row =
        sqlx::query("SELECT block_number, block_hash FROM indexer_checkpoints WHERE chain_id = $1")
            .bind(chain_id)
            .fetch_optional(pool)
            .await?;
    row.map(|row| {
        let block_number = u64::try_from(row.try_get::<i64, _>("block_number")?).unwrap_or(0);
        let block_hash = row.try_get::<String, _>("block_hash")?.trim().to_owned();
        Ok((block_number, block_hash))
    })
    .transpose()
}

async fn take_rate_limit_token_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    capacity: f64,
    refill_per_second: f64,
) -> Result<bool, sqlx::Error> {
    if !capacity.is_finite() || capacity < 1.0 || !refill_per_second.is_finite() {
        return Ok(false);
    }
    let refill_rate = refill_per_second.max(0.0);
    sqlx::query(
        "INSERT INTO gateway_rate_buckets (bucket_key, tokens, updated_at) \
         VALUES ($1, $2, clock_timestamp()) \
         ON CONFLICT (bucket_key) DO NOTHING",
    )
    .bind(key)
    .bind(capacity)
    .execute(&mut **transaction)
    .await?;

    let (stored_tokens, elapsed_seconds): (f64, f64) = sqlx::query_as(
        "SELECT tokens, \
                GREATEST(0.0, EXTRACT(EPOCH FROM (clock_timestamp() - updated_at))::double precision) \
         FROM gateway_rate_buckets \
         WHERE bucket_key = $1 \
         FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut **transaction)
    .await?;

    let available = (stored_tokens.max(0.0) + elapsed_seconds * refill_rate).min(capacity);
    let (allowed, next_tokens) = if available >= 1.0 {
        (true, available - 1.0)
    } else {
        (false, available)
    };
    sqlx::query(
        "UPDATE gateway_rate_buckets \
         SET tokens = $2, updated_at = clock_timestamp() \
         WHERE bucket_key = $1",
    )
    .bind(key)
    .bind(next_tokens)
    .execute(&mut **transaction)
    .await?;
    Ok(allowed)
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    record: AuditRecord<'_>,
) -> Result<(), sqlx::Error> {
    append_audit_entry(
        transaction,
        &record,
        record.resource_type,
        record.resource_id,
        record.resource_version,
    )
    .await
}

async fn append_audit_entry<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    record: &T,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    resource_version: Option<u64>,
) -> Result<(), sqlx::Error> {
    let canonical =
        serde_json::to_string(record).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let json: serde_json::Value = serde_json::from_str(&canonical)
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_STREAM_LOCK)
        .execute(&mut **transaction)
        .await?;
    let previous = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT record_hash FROM gateway_audit_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await?
    .unwrap_or_else(|| vec![0; 32]);
    if previous.len() != 32 {
        return Err(sqlx::Error::Protocol(
            "gateway audit chain has an invalid predecessor hash".into(),
        ));
    }
    let mut hasher = Keccak256::new();
    hasher.update(&previous);
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    sqlx::query(
        "INSERT INTO gateway_audit_events \
         (record, record_canonical, resource_type, resource_id, resource_version, \
          previous_hash, record_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(json)
    .bind(canonical)
    .bind(resource_type)
    .bind(resource_id)
    .bind(resource_version.map(|version| version as i64))
    .bind(previous)
    .bind(&hash[..])
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub fn hash_session_token(token: &[u8; 32]) -> [u8; 32] {
    crypto::keccak256(token)
}

pub fn source_identifier(source: &str) -> String {
    domain::hex::encode_prefixed_hex(&crypto::keccak256(source.as_bytes()))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    domain::hex::encode_prefixed_hex(bytes)
}

fn decode_nonce(value: &str) -> Option<[u8; 32]> {
    domain::hex::parse_fixed_hex::<32>(value)
}

fn unix_seconds() -> Result<u64, sqlx::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

fn unix_millis() -> Result<u128, sqlx::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use metadata_store::PostgresStore;

    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    #[ignore = "requires DATABASE_URL (PostgreSQL)"]
    async fn challenge_session_rate_limit_and_audit_are_transactional() {
        let _guard = TEST_LOCK.lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running ignored gateway PostgreSQL tests");
        let metadata = PostgresStore::connect(&database_url)
            .await
            .expect("connect to PostgreSQL for gateway test");
        metadata
            .migrate()
            .await
            .expect("apply gateway test migrations");
        let pool = metadata.pool().clone();
        let store = GatewayStore::new(pool.clone());
        let mut transaction = pool.begin().await.expect("begin rollback-only test");

        let challenge = LoginChallenge {
            member_id: format!("0x{}", "ab".repeat(32)),
            nonce: format!("0x{}", "cd".repeat(32)),
            issued_at: unix_seconds().unwrap(),
            expires_at: unix_seconds().unwrap() + 120,
            audience: "gateway-test".to_owned(),
            protocol_version: 1,
        };
        store
            .create_challenge_in_transaction(&mut transaction, &challenge, "test-source", 1337)
            .await
            .expect("persist issued challenge and audit record");

        let token = [0x55; 32];
        let token_hash = hash_session_token(&token);
        assert!(
            store
                .complete_login_in_transaction(
                    &mut transaction,
                    &challenge,
                    &token_hash,
                    challenge.expires_at + 900,
                    "test-source",
                    1337,
                    100,
                )
                .await
                .expect("consume challenge once")
        );
        assert!(
            !store
                .complete_login_in_transaction(
                    &mut transaction,
                    &challenge,
                    &token_hash,
                    challenge.expires_at + 900,
                    "test-source",
                    1337,
                    100,
                )
                .await
                .expect("reject challenge replay")
        );

        let persisted_hash: Vec<u8> =
            sqlx::query_scalar("SELECT token_hash FROM gateway_sessions WHERE token_hash = $1")
                .bind(token_hash.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .expect("verify only hashed token is present");
        assert_eq!(persisted_hash, token_hash);
        assert_ne!(persisted_hash.as_slice(), token.as_slice());

        for expected_allowed in [true, true, false] {
            assert_eq!(
                take_rate_limit_token_in_transaction(
                    &mut transaction,
                    "gateway-test-bucket",
                    2.0,
                    0.01,
                )
                .await
                .expect("atomically update test rate bucket"),
                expected_allowed
            );
        }

        let audit_rows = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
            "SELECT record_canonical, previous_hash, record_hash \
             FROM gateway_audit_events WHERE record->>'operation_id' = $1 \
             ORDER BY sequence",
        )
        .bind(&challenge.nonce)
        .fetch_all(&mut *transaction)
        .await
        .expect("read test audit chain entries");
        assert_eq!(audit_rows.len(), 2);
        for (index, (canonical, previous, record_hash)) in audit_rows.iter().enumerate() {
            let mut hasher = Keccak256::new();
            hasher.update(previous);
            hasher.update(canonical.as_bytes());
            assert_eq!(&hasher.finalize()[..], record_hash);
            if index == 1 {
                assert_eq!(previous, &audit_rows[0].2);
            }
        }

        let write_op_id = format!("0x{}", "ef".repeat(32));
        store
            .record_write_attempt_in_transaction(
                &mut transaction,
                "file.create",
                Some(&challenge.member_id),
                "test-source",
                &format!("0x{}", "22".repeat(32)),
                1,
                Some(&write_op_id),
                1337,
                Some(42),
                "committed",
                None,
                None,
            )
            .await
            .expect("persist write attempt audit record");
        let write_row: (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT record_canonical, previous_hash, record_hash \
             FROM gateway_audit_events WHERE record->>'operation_id' = $1",
        )
        .bind(&write_op_id)
        .fetch_one(&mut *transaction)
        .await
        .expect("read write attempt audit record");
        assert_eq!(write_row.1, audit_rows[1].2);
        let mut write_hasher = Keccak256::new();
        write_hasher.update(&write_row.1);
        write_hasher.update(write_row.0.as_bytes());
        assert_eq!(&write_hasher.finalize()[..], write_row.2);

        assert!(
            store
                .revoke_session_in_transaction(&mut transaction, &token_hash, "test-source", 1337)
                .await
                .expect("revoke active session once")
        );
        assert!(
            !store
                .revoke_session_in_transaction(&mut transaction, &token_hash, "test-source", 1337)
                .await
                .expect("reject double session revocation")
        );
        let active_after_revoke: Option<String> = sqlx::query_scalar(
            "SELECT member_id FROM gateway_sessions \
             WHERE token_hash = $1 AND expires_at > $2 AND revoked_at IS NULL",
        )
        .bind(token_hash.as_slice())
        .bind(unix_seconds().unwrap() as i64)
        .fetch_optional(&mut *transaction)
        .await
        .expect("verify revoked session is inactive");
        assert!(active_after_revoke.is_none());
        let revoke_row: (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT record_canonical, previous_hash, record_hash \
             FROM gateway_audit_events \
             WHERE record->>'action' = 'auth.session.revoke' \
             ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_one(&mut *transaction)
        .await
        .expect("read revoke audit record");
        assert_eq!(revoke_row.1, write_row.2);
        let mut revoke_hasher = Keccak256::new();
        revoke_hasher.update(&revoke_row.1);
        revoke_hasher.update(revoke_row.0.as_bytes());
        assert_eq!(&revoke_hasher.finalize()[..], revoke_row.2);

        // Burst denial recovery test: 10 consecutive denied requests must NOT accumulate
        // negative token debt; a single token refill interval must allow the next request.
        for _ in 0..2 {
            assert!(
                take_rate_limit_token_in_transaction(
                    &mut transaction,
                    "gateway-burst-recovery-bucket",
                    2.0,
                    20.0,
                )
                .await
                .expect("consume initial burst capacity")
            );
        }
        for _ in 0..10 {
            assert!(
                !take_rate_limit_token_in_transaction(
                    &mut transaction,
                    "gateway-burst-recovery-bucket",
                    2.0,
                    20.0,
                )
                .await
                .expect("deny requests beyond burst capacity")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        assert!(
            take_rate_limit_token_in_transaction(
                &mut transaction,
                "gateway-burst-recovery-bucket",
                2.0,
                20.0,
            )
            .await
            .expect("allow request immediately after 1 token refills (no negative debt)")
        );

        // Expired challenge & session pruning on new auth activity.
        let expired_nonce = [0xee_u8; 32];
        sqlx::query(
            "INSERT INTO gateway_login_challenges \
             (member_id, nonce, issued_at, expires_at, audience, protocol_version) \
             VALUES ($1, $2, 100, 200, 'gateway-test', 1)",
        )
        .bind(&challenge.member_id)
        .bind(expired_nonce.as_slice())
        .execute(&mut *transaction)
        .await
        .expect("seed expired login challenge");
        let expired_session_hash = [0xed_u8; 32];
        sqlx::query(
            "INSERT INTO gateway_sessions (token_hash, member_id, expires_at) \
             VALUES ($1, $2, 200)",
        )
        .bind(expired_session_hash.as_slice())
        .bind(&challenge.member_id)
        .execute(&mut *transaction)
        .await
        .expect("seed expired session");
        let fresh_challenge = LoginChallenge {
            member_id: challenge.member_id.clone(),
            nonce: format!("0x{}", "de".repeat(32)),
            issued_at: unix_seconds().unwrap(),
            expires_at: unix_seconds().unwrap() + 120,
            audience: "gateway-test".to_owned(),
            protocol_version: 1,
        };
        store
            .create_challenge_in_transaction(
                &mut transaction,
                &fresh_challenge,
                "test-source",
                1337,
            )
            .await
            .expect("create challenge triggers expired challenge pruning");
        let expired_challenge_remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM gateway_login_challenges WHERE nonce = $1")
                .bind(expired_nonce.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .expect("check expired challenge pruned");
        assert_eq!(expired_challenge_remaining, 0);

        let fresh_token_hash = hash_session_token(&[0x56; 32]);
        assert!(
            store
                .complete_login_in_transaction(
                    &mut transaction,
                    &fresh_challenge,
                    &fresh_token_hash,
                    fresh_challenge.expires_at + 900,
                    "test-source",
                    1337,
                    100,
                )
                .await
                .expect("complete fresh login triggers expired session pruning")
        );
        let expired_session_remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM gateway_sessions WHERE token_hash = $1")
                .bind(expired_session_hash.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .expect("check expired session pruned");
        assert_eq!(expired_session_remaining, 0);

        let audit_sequence: i64 = sqlx::query_scalar(
            "SELECT sequence FROM gateway_audit_events \
             WHERE record->>'operation_id' = $1 ORDER BY sequence DESC LIMIT 1",
        )
        .bind(&challenge.nonce)
        .fetch_one(&mut *transaction)
        .await
        .expect("find test audit entry");

        // Verify UPDATE, DELETE, and TRUNCATE are all blocked by DB triggers.
        sqlx::query("SAVEPOINT sp_audit_update")
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            sqlx::query("UPDATE gateway_audit_events SET record = record WHERE sequence = $1")
                .bind(audit_sequence)
                .execute(&mut *transaction)
                .await
                .is_err(),
            "audit rows reject UPDATE"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT sp_audit_update")
            .execute(&mut *transaction)
            .await
            .unwrap();

        sqlx::query("SAVEPOINT sp_audit_delete")
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            sqlx::query("DELETE FROM gateway_audit_events WHERE sequence = $1")
                .bind(audit_sequence)
                .execute(&mut *transaction)
                .await
                .is_err(),
            "audit rows reject DELETE"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT sp_audit_delete")
            .execute(&mut *transaction)
            .await
            .unwrap();

        sqlx::query("SAVEPOINT sp_audit_truncate")
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            sqlx::query("TRUNCATE TABLE gateway_audit_events")
                .execute(&mut *transaction)
                .await
                .is_err(),
            "audit table rejects TRUNCATE"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT sp_audit_truncate")
            .execute(&mut *transaction)
            .await
            .unwrap();

        transaction
            .rollback()
            .await
            .expect("rollback gateway test records");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL (PostgreSQL)"]
    async fn concurrent_challenges_nonces_rate_limits_and_audit_chain_are_race_free() {
        let _guard = TEST_LOCK.lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running ignored gateway PostgreSQL tests");
        let pool_config = metadata_store::PostgresPoolConfig {
            max_connections: 12,
            acquire_timeout: std::time::Duration::from_secs(10),
        };
        let metadata = PostgresStore::connect_with_config(&database_url, pool_config)
            .await
            .expect("connect to PostgreSQL for concurrency test");
        metadata
            .migrate()
            .await
            .expect("apply migrations for concurrency test");
        let store = GatewayStore::new(metadata.pool().clone());

        let run_tag = unix_millis().unwrap() as u64;
        let mut member_bytes = [0x41u8; 32];
        member_bytes[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let member_id = encode_hex(&member_bytes);

        let mut challenge_nonce_bytes = [0x42u8; 32];
        challenge_nonce_bytes[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let now = unix_seconds().unwrap();
        let challenge = LoginChallenge {
            member_id: member_id.clone(),
            nonce: encode_hex(&challenge_nonce_bytes),
            issued_at: now,
            expires_at: now + 120,
            audience: "gateway-concurrency-test".to_owned(),
            protocol_version: 1,
        };
        store
            .create_challenge(&challenge, "concurrency-src", 1337)
            .await
            .expect("insert shared challenge");

        // 1. 8 concurrent login attempts against the same one-time challenge -> exactly 1 succeeds.
        let mut login_handles = Vec::new();
        for idx in 0..8u8 {
            let s = store.clone();
            let c = challenge.clone();
            login_handles.push(tokio::spawn(async move {
                let mut raw_token = [idx.wrapping_add(1); 32];
                raw_token[24..32].copy_from_slice(&run_tag.to_be_bytes());
                let token_hash = hash_session_token(&raw_token);
                s.complete_login(&c, &token_hash, now + 900, "concurrency-src", 1337, 100)
                    .await
                    .expect("complete_login must not error under concurrency")
            }));
        }
        let mut login_wins = 0usize;
        for h in login_handles {
            if h.await.unwrap() {
                login_wins += 1;
            }
        }
        assert_eq!(
            login_wins, 1,
            "exactly one concurrent login must consume challenge"
        );

        // 2. 8 concurrent AccessLookup attempts with the same nonce -> exactly 1 authorized, 7 replayed,
        //    and all 8 serialized cleanly in the Keccak-256 audit hash chain.
        let mut access_nonce = [0x43u8; 32];
        access_nonce[24..32].copy_from_slice(&run_tag.to_be_bytes());
        let file_id = format!("0x{}", "5a".repeat(32));
        let mut access_handles = Vec::new();
        for _ in 0..8 {
            let s = store.clone();
            let m = member_id.clone();
            let f = file_id.clone();
            access_handles.push(tokio::spawn(async move {
                s.record_access_attempt(
                    &m,
                    "concurrency-src",
                    &f,
                    1,
                    &access_nonce,
                    now + 120,
                    1337,
                    500,
                    true,
                    None,
                )
                .await
                .expect("record_access_attempt must not error under concurrency")
            }));
        }
        let mut access_wins = 0usize;
        for h in access_handles {
            if h.await.unwrap() {
                access_wins += 1;
            }
        }
        assert_eq!(
            access_wins, 1,
            "exactly one concurrent access lookup must succeed"
        );

        let access_op_id = encode_hex(&access_nonce);
        let audit_chain: Vec<(i64, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT sequence, record_canonical, previous_hash, record_hash \
             FROM gateway_audit_events \
             WHERE record->>'operation_id' = $1 \
             ORDER BY sequence ASC",
        )
        .bind(&access_op_id)
        .fetch_all(metadata.pool())
        .await
        .expect("fetch concurrent audit entries");
        assert_eq!(audit_chain.len(), 8);
        for (i, (_, canonical, prev, hash)) in audit_chain.iter().enumerate() {
            let mut hasher = Keccak256::new();
            hasher.update(prev);
            hasher.update(canonical.as_bytes());
            assert_eq!(&hasher.finalize()[..], hash.as_slice());
            if i > 0 {
                assert_eq!(prev, &audit_chain[i - 1].3);
            }
        }

        // 3. 8 concurrent rate-limit acquisitions against capacity 3.0 -> exactly 3 allowed.
        let bucket_key = format!("concurrency-bucket-{run_tag}");
        let mut rate_handles = Vec::new();
        for _ in 0..8 {
            let s = store.clone();
            let key = bucket_key.clone();
            rate_handles.push(tokio::spawn(async move {
                s.take_rate_limit_token(&key, 3.0, 0.0001)
                    .await
                    .expect("take_rate_limit_token must serialize cleanly")
            }));
        }
        let mut rate_wins = 0usize;
        for h in rate_handles {
            if h.await.unwrap() {
                rate_wins += 1;
            }
        }
        assert_eq!(
            rate_wins, 3,
            "FOR UPDATE bucket must enforce exact capacity under concurrency"
        );

        // Clean up mutable operational rows (audit events are intentionally append-only).
        let _ = sqlx::query("DELETE FROM gateway_login_challenges WHERE member_id = $1")
            .bind(&member_id)
            .execute(metadata.pool())
            .await;
        let _ = sqlx::query("DELETE FROM gateway_sessions WHERE member_id = $1")
            .bind(&member_id)
            .execute(metadata.pool())
            .await;
        let _ = sqlx::query("DELETE FROM gateway_used_access_nonces WHERE member_id = $1")
            .bind(&member_id)
            .execute(metadata.pool())
            .await;
        let _ = sqlx::query("DELETE FROM gateway_rate_buckets WHERE bucket_key = $1")
            .bind(&bucket_key)
            .execute(metadata.pool())
            .await;
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL (PostgreSQL)"]
    async fn projection_listings_version_history_and_self_audited_queries_execute_on_postgres() {
        let _guard = TEST_LOCK.lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running ignored gateway PostgreSQL tests");
        let metadata = PostgresStore::connect(&database_url)
            .await
            .expect("connect to PostgreSQL");
        metadata.migrate().await.expect("apply migrations");
        let pool = metadata.pool();
        let store = GatewayStore::new(pool.clone());

        let chain_id = 99_1337u64;
        let org_id = format!("0x{}", "a1".repeat(32));
        let alice = format!("0x{}", "b1".repeat(32));
        let mallory = format!("0x{}", "b2".repeat(32));
        let root_folder = format!("0x{}", "00".repeat(32));
        let sub_folder = format!("0x{}", "c1".repeat(32));
        let file_id = format!("0x{}", "d1".repeat(32));
        let head_hash = format!("0x{}", "e2".repeat(32));
        let block_hash = format!("0x{}", "f1".repeat(32));

        sqlx::query(
            "INSERT INTO indexer_checkpoints (chain_id, block_number, block_hash) \
             VALUES ($1, 777, $2) ON CONFLICT (chain_id) DO UPDATE \
             SET block_number = EXCLUDED.block_number, block_hash = EXCLUDED.block_hash",
        )
        .bind(chain_id as i64)
        .bind(&block_hash)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO folders_projection (folder_id, organization_id, parent_folder_id, display_name, updated_block_number) \
             VALUES ($1, $2, $3, 'Finance', 770) ON CONFLICT (folder_id) DO UPDATE SET display_name = EXCLUDED.display_name",
        )
        .bind(&sub_folder)
        .bind(&org_id)
        .bind(&root_folder)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO files_projection \
             (file_id, organization_id, creator_member_id, display_name, parent_folder_id, file_status, current_version, current_head_manifest_hash, updated_block_number) \
             VALUES ($1, $2, $3, 'ledger.pdf', $4, 1, 2, $5, 777) \
             ON CONFLICT (file_id) DO UPDATE SET current_version = EXCLUDED.current_version",
        )
        .bind(&file_id)
        .bind(&org_id)
        .bind(&alice)
        .bind(&root_folder)
        .bind(&head_hash)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO access_projection \
             (file_id, member_id, permission, granted, actor, proposal_id, updated_block_number) \
             VALUES ($1, $2, 0, TRUE, $3, $4, 771) \
             ON CONFLICT (file_id, member_id, permission) DO UPDATE SET granted = TRUE",
        )
        .bind(&file_id)
        .bind(&alice)
        .bind(format!("0x{}", "12".repeat(20)))
        .bind(&root_folder)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO versions_projection \
             (file_id, version_number, manifest_hash, parent_manifest_hash, epoch_id, author_member_id, author_signing_address, content_cid, initial_envelope_set_cid, transaction_hash, block_number) \
             VALUES \
             ($1, 1, $2, $3, $4, $5, $6, 'bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq', 'bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau', $7, 771), \
             ($1, 2, $8, $2, $9, $5, $6, 'bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau', 'bafkreiambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq', $7, 777) \
             ON CONFLICT (file_id, version_number) DO NOTHING",
        )
        .bind(&file_id)
        .bind(format!("0x{}", "e1".repeat(32)))
        .bind(&root_folder)
        .bind(format!("0x{}", "aa".repeat(32)))
        .bind(&alice)
        .bind(format!("0x{}", "12".repeat(20)))
        .bind(format!("0x{}", "99".repeat(32)))
        .bind(&head_hash)
        .bind(format!("0x{}", "bb".repeat(32)))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO envelope_sets_projection \
             (file_id, version_number, epoch_id, envelope_set_cid, revision, updated_block_number) \
             VALUES ($1, 1, $2, 'bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu', 2, 775) \
             ON CONFLICT (file_id, version_number) DO UPDATE SET revision = 2, envelope_set_cid = EXCLUDED.envelope_set_cid",
        )
        .bind(&file_id)
        .bind(format!("0x{}", "aa".repeat(32)))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO historical_read_access_projection \
             (file_id, version_number, member_id, granted, actor, proposal_id, updated_block_number) \
             VALUES ($1, 1, $2, TRUE, $3, $4, 775) \
             ON CONFLICT (file_id, version_number, member_id) DO UPDATE SET granted = TRUE",
        )
        .bind(&file_id)
        .bind(&alice)
        .bind(format!("0x{}", "12".repeat(20)))
        .bind(&root_folder)
        .execute(pool)
        .await
        .unwrap();

        // Authorized reader sees folder + file; unauthorized member sees folder only (0 files).
        let alice_list = store
            .list_files_and_folders(chain_id, &alice, &org_id, &root_folder)
            .await
            .expect("alice file listing");
        assert_eq!(alice_list.indexed_block, Some(777));
        assert_eq!(alice_list.folders.len(), 1);
        assert_eq!(alice_list.folders[0].display_name, "Finance");
        assert_eq!(alice_list.files.len(), 1);
        assert_eq!(alice_list.files[0].display_name, "ledger.pdf");

        let mallory_list = store
            .list_files_and_folders(chain_id, &mallory, &org_id, &root_folder)
            .await
            .expect("mallory file listing");
        assert!(mallory_list.files.is_empty());

        // Version history reflects updated envelope revision on V1 + historical_read_granted flag.
        let history = store
            .list_file_versions(chain_id, &file_id, &alice)
            .await
            .expect("version history query");
        assert_eq!(history.versions.len(), 2);
        assert_eq!(history.versions[0].version_number, 1);
        assert_eq!(history.versions[0].envelope_revision, 2);
        assert_eq!(
            history.versions[0].current_envelope_set_cid,
            "bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu"
        );
        assert!(history.versions[0].historical_read_granted);
        assert_eq!(history.versions[1].version_number, 2);
        assert_eq!(history.versions[1].envelope_revision, 1);
        assert!(!history.versions[1].historical_read_granted);

        // Self-audited query records its own `audit.query` entry and filters by member + action.
        let audit_events = store
            .query_member_audit_events(
                &alice,
                "proj-test-src",
                chain_id,
                777,
                Some("audit.query"),
                10,
            )
            .await
            .expect("self-audited query");
        assert!(!audit_events.is_empty());
        assert_eq!(audit_events[0].record["action"], "audit.query");
        assert_eq!(audit_events[0].record["actor_member_id"], alice);

        // Clean up temporary projection fixture rows.
        for sql in [
            "DELETE FROM historical_read_access_projection WHERE file_id = $1",
            "DELETE FROM envelope_sets_projection WHERE file_id = $1",
            "DELETE FROM versions_projection WHERE file_id = $1",
            "DELETE FROM access_projection WHERE file_id = $1",
            "DELETE FROM files_projection WHERE file_id = $1",
        ] {
            let _ = sqlx::query(sql).bind(&file_id).execute(pool).await;
        }
        let _ = sqlx::query("DELETE FROM folders_projection WHERE folder_id = $1")
            .bind(&sub_folder)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM indexer_checkpoints WHERE chain_id = $1")
            .bind(chain_id as i64)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL (PostgreSQL)"]
    async fn gateway_store_persists_relayed_transactions_and_orphan_blob_lifecycle() {
        let _guard = TEST_LOCK.lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running ignored gateway PostgreSQL tests");
        let metadata = PostgresStore::connect(&database_url)
            .await
            .expect("connect to PostgreSQL");
        metadata.migrate().await.expect("run migrations");
        let store = GatewayStore::new(metadata.pool().clone());

        let tx_hash = format!("0x{}", "8c".repeat(32));
        let op_id = format!("0x{}", "8d".repeat(32));
        let actor = format!("0x{}", "8e".repeat(32));
        let file_id = format!("0x{}", "8f".repeat(32));
        let orphan_cid = "bafkreiab234567234567234567234567234567234567234567234567a";
        let committed_cid = "bafkreiab234567234567234567234567234567234567234567234567b";

        let pending = RelayedTransactionRecord {
            tx_hash: tx_hash.clone(),
            operation_kind: "file.version_restore".to_owned(),
            operation_id: op_id.clone(),
            actor_member_id: actor.clone(),
            file_id: file_id.clone(),
            version_number: 3,
            content_cid: Some(committed_cid.to_owned()),
            envelope_set_cid: orphan_cid.to_owned(),
            chain_id: 1337,
            status: "pending".to_owned(),
            block_number: None,
            block_hash: None,
            gas_used: None,
        };
        store
            .record_relayed_transaction(&pending)
            .await
            .expect("insert pending tx");
        assert_eq!(
            store
                .get_relayed_transaction(&tx_hash)
                .await
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );

        store
            .update_relayed_transaction_status(
                &tx_hash,
                "confirmed",
                Some(901),
                Some(&format!("0x{}", "9a".repeat(32))),
                Some(111_000),
            )
            .await
            .expect("confirm tx");
        let confirmed = store
            .get_relayed_transaction(&tx_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(confirmed.status, "confirmed");
        assert_eq!(confirmed.block_number, Some(901));
        assert_eq!(confirmed.gas_used, Some(111_000));

        // Record two orphan candidates, mark one referenced, verify only the other is eligible.
        store
            .record_orphan_blob_candidate(
                orphan_cid,
                "envelope",
                &actor,
                Some(&file_id),
                Some(3),
                Some(&tx_hash),
                "contract_reverted",
            )
            .await
            .unwrap();
        store
            .record_orphan_blob_candidate(
                committed_cid,
                "content",
                &actor,
                Some(&file_id),
                Some(3),
                Some(&tx_hash),
                "staged_uncommitted",
            )
            .await
            .unwrap();
        store.mark_blob_referenced(committed_cid).await.unwrap();

        let eligible = store.list_eligible_orphan_candidates(0, 50).await.unwrap();
        assert!(eligible.iter().any(|c| c.cid == orphan_cid));
        assert!(!eligible.iter().any(|c| c.cid == committed_cid));

        store.mark_orphan_blob_unpinned(orphan_cid).await.unwrap();
        let after_unpin = store.list_eligible_orphan_candidates(0, 50).await.unwrap();
        assert!(!after_unpin.iter().any(|c| c.cid == orphan_cid));

        // Verify restore source version is persisted in the hash-chained audit record.
        store
            .record_write_attempt(
                "file.version_restore",
                Some(&actor),
                "restore-test-src",
                &file_id,
                3,
                Some(&op_id),
                1337,
                Some(901),
                "committed",
                None,
                Some(1),
            )
            .await
            .unwrap();
        let restore_events = store
            .query_member_audit_events(
                &actor,
                "restore-test-src",
                1337,
                901,
                Some("file.version_restore"),
                5,
            )
            .await
            .unwrap();
        assert!(!restore_events.is_empty());
        assert_eq!(restore_events[0].record["restored_from_version"], 1);

        // Clean up temporary test rows.
        sqlx::query("DELETE FROM gateway_relayed_transactions WHERE tx_hash = $1")
            .bind(&tx_hash)
            .execute(metadata.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM gateway_orphan_blobs WHERE cid IN ($1, $2)")
            .bind(orphan_cid)
            .bind(committed_cid)
            .execute(metadata.pool())
            .await
            .unwrap();
    }
}
