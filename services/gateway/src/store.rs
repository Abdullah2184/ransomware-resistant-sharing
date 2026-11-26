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

    async fn complete_login_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        challenge: &LoginChallenge,
        token_hash: &[u8; 32],
        session_expires_at: u64,
        source_id: &str,
        chain_id: u64,
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
                block_number: None,
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
    ) -> Result<(), sqlx::Error> {
        append_audit(
            transaction,
            AuditRecord {
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
            },
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
        )
        .await?;
        transaction.commit().await
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
    sqlx::query_scalar(
            "INSERT INTO gateway_rate_buckets (bucket_key, tokens, updated_at) \
             VALUES ($1, $2 - 1, clock_timestamp()) \
             ON CONFLICT (bucket_key) DO UPDATE SET \
                 tokens = LEAST( \
                     $2, \
                     gateway_rate_buckets.tokens + \
                         GREATEST(0, EXTRACT(EPOCH FROM (clock_timestamp() - gateway_rate_buckets.updated_at))::double precision * $3) \
                 ) - 1, \
                 updated_at = clock_timestamp() \
             RETURNING tokens >= 0",
        )
        .bind(key)
        .bind(capacity)
        .bind(refill_per_second)
        .fetch_one(&mut **transaction)
        .await
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    record: AuditRecord<'_>,
) -> Result<(), sqlx::Error> {
    let canonical =
        serde_json::to_string(&record).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
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
    .bind(record.resource_type)
    .bind(record.resource_id)
    .bind(record.resource_version.map(|version| version as i64))
    .bind(previous)
    .bind(&hash[..])
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub fn hash_session_token(token: &[u8; 32]) -> [u8; 32] {
    let digest = Keccak256::digest(token);
    let mut hash = [0; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn source_identifier(source: &str) -> String {
    let digest = Keccak256::digest(source.as_bytes());
    let mut output = String::with_capacity(66);
    output.push_str("0x");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2 + 2);
    output.push_str("0x");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_nonce(value: &str) -> Option<[u8; 32]> {
    let value = value.strip_prefix("0x")?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut nonce = [0; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(nonce)
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
    async fn challenge_session_rate_limit_and_audit_are_transactional() {
        let _guard = TEST_LOCK.lock().await;
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            eprintln!("Skipping gateway PostgreSQL test: DATABASE_URL is not set");
            return;
        };
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

        let audit_sequence: i64 = sqlx::query_scalar(
            "SELECT sequence FROM gateway_audit_events \
             WHERE record->>'operation_id' = $1 ORDER BY sequence DESC LIMIT 1",
        )
        .bind(&challenge.nonce)
        .fetch_one(&mut *transaction)
        .await
        .expect("find test audit entry");
        assert!(
            sqlx::query("UPDATE gateway_audit_events SET record = record WHERE sequence = $1")
                .bind(audit_sequence)
                .execute(&mut *transaction)
                .await
                .is_err(),
            "audit rows reject mutation"
        );
        transaction
            .rollback()
            .await
            .expect("rollback gateway test records");
    }
}
