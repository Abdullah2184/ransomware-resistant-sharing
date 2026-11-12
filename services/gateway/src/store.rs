use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha3::{Digest, Keccak256};
use sqlx::{PgPool, Postgres, Transaction};

use crate::auth::LoginChallenge;

const AUDIT_STREAM_LOCK: i64 = 0x5252_4653;

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

    pub async fn active_session_member(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT member_id FROM gateway_sessions \
             WHERE token_hash = $1 AND expires_at > $2",
        )
        .bind(token_hash.as_slice())
        .bind(unix_seconds()? as i64)
        .fetch_optional(&self.pool)
        .await
    }
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
