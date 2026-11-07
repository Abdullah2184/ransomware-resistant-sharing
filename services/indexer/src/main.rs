mod decoder;

use std::{collections::BTreeMap, env, error::Error, fmt, time::Duration};

use chain_adapter::{BesuClient, ChainError, ChainLog, FileHeadState, FinalizedBlock};
use domain::EvmAddress;
use metadata_store::PostgresStore;
use serde_json::Value;
use sqlx::{PgPool, Row};
use tokio::{signal, sync::Mutex, time};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BATCH_BLOCKS: u64 = 1_000;

#[derive(Clone, Debug)]
struct Config {
    expected_chain_id: u64,
    start_block: u64,
    batch_size: u64,
    reconciliation_interval: Duration,
    file_registry: EvmAddress,
    access_governance: EvmAddress,
}

impl Config {
    fn from_env() -> Result<Self, IndexerError> {
        let expected_chain_id = parse_env_u64("BESU_CHAIN_ID", "1337")?;
        let start_block = parse_env_u64("INDEXER_START_BLOCK", "0")?;
        let batch_size = parse_env_u64("INDEXER_BATCH_SIZE", "100")?;
        if batch_size == 0 || batch_size > MAX_BATCH_BLOCKS {
            return Err(IndexerError::InvalidConfiguration);
        }
        let confirmation_policy =
            env::var("INDEXER_CONFIRMATION_POLICY").unwrap_or_else(|_| "finalized".to_owned());
        if confirmation_policy != "finalized" {
            return Err(IndexerError::UnsupportedFinalityPolicy);
        }

        Ok(Self {
            expected_chain_id,
            start_block,
            batch_size,
            reconciliation_interval: Duration::from_secs(parse_env_u64(
                "INDEXER_RECONCILIATION_INTERVAL_SECONDS",
                "60",
            )?),
            file_registry: parse_address_env("CONTRACT_FILE_REGISTRY_ADDRESS")?,
            access_governance: parse_address_env("CONTRACT_ACCESS_GOVERNANCE_ADDRESS")?,
        })
    }

    fn contracts(&self) -> [EvmAddress; 2] {
        [self.file_registry, self.access_governance]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexerError {
    InvalidConfiguration,
    UnsupportedFinalityPolicy,
    ChainIdMismatch,
    ChainMismatch,
    InvalidRange,
    Chain(ChainError),
    Decode(decoder::DecodeError),
    Database,
}

impl fmt::Display for IndexerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("invalid indexer configuration"),
            Self::UnsupportedFinalityPolicy => {
                formatter.write_str("indexer requires the Besu finalized-block policy")
            }
            Self::ChainIdMismatch => formatter.write_str("configured chain ID does not match Besu"),
            Self::ChainMismatch => {
                formatter.write_str("indexed checkpoint does not match the finalized chain")
            }
            Self::InvalidRange => formatter.write_str("invalid finalized block range"),
            Self::Chain(error) => error.fmt(formatter),
            Self::Decode(error) => error.fmt(formatter),
            Self::Database => formatter.write_str("indexer database operation failed"),
        }
    }
}

impl Error for IndexerError {}

struct Indexer {
    config: Config,
    client: BesuClient,
    database: PostgresStore,
    last_reconciliation: Mutex<time::Instant>,
}

impl Indexer {
    async fn process_once(&self) -> Result<u64, IndexerError> {
        let actual_chain_id = self.client.chain_id().await.map_err(IndexerError::Chain)?;
        if actual_chain_id != self.config.expected_chain_id {
            return Err(IndexerError::ChainIdMismatch);
        }
        ensure_projection_chain(self.database.pool(), actual_chain_id).await?;

        let finalized = self
            .client
            .finalized_block()
            .await
            .map_err(IndexerError::Chain)?;
        let checkpoint = read_checkpoint(self.database.pool(), actual_chain_id).await?;

        let from_block = if let Some((checkpoint_number, checkpoint_hash)) = checkpoint {
            if checkpoint_number > finalized.number {
                return Err(IndexerError::ChainMismatch);
            }
            let canonical_hash = self
                .client
                .block_hash(checkpoint_number)
                .await
                .map_err(IndexerError::Chain)?;
            if canonical_hash != checkpoint_hash {
                return Err(IndexerError::ChainMismatch);
            }
            checkpoint_number
                .checked_add(1)
                .ok_or(IndexerError::InvalidRange)?
        } else {
            self.config.start_block
        };

        let mut processed = 0;
        let mut range_start = from_block;
        while range_start <= finalized.number {
            let range_end = range_start
                .saturating_add(self.config.batch_size - 1)
                .min(finalized.number);
            let mut logs = self
                .client
                .logs(range_start, range_end, &self.config.contracts())
                .await
                .map_err(IndexerError::Chain)?;
            logs.sort_by_key(|log| {
                (
                    log.block_number().unwrap_or_default(),
                    log.transaction_index().unwrap_or_default(),
                    log.log_index().unwrap_or_default(),
                )
            });
            let canonical_hashes = self
                .canonical_log_hashes(&logs, range_end, &finalized)
                .await?;

            apply_range(
                self.database.pool(),
                actual_chain_id,
                range_end,
                &canonical_hashes,
                &logs,
            )
            .await?;
            processed += range_end - range_start + 1;
            range_start = range_end.checked_add(1).ok_or(IndexerError::InvalidRange)?;
        }
        self.reconcile_if_due(&finalized).await?;
        Ok(processed)
    }

    async fn reconcile_if_due(&self, finalized: &FinalizedBlock) -> Result<(), IndexerError> {
        let mut last_reconciliation = self.last_reconciliation.lock().await;
        if last_reconciliation.elapsed() < self.config.reconciliation_interval {
            return Ok(());
        }

        let rows = sqlx::query(
            "SELECT file_id FROM files_projection WHERE file_status IS NOT NULL ORDER BY file_id",
        )
        .fetch_all(self.database.pool())
        .await
        .map_err(|_| IndexerError::Database)?;
        for row in rows {
            let file_id: String = row.try_get("file_id").map_err(|_| IndexerError::Database)?;
            let file_id = parse_bytes32(file_id.trim())?;
            let state = self
                .client
                .file_head(&self.config.file_registry, &file_id)
                .await
                .map_err(IndexerError::Chain)?;
            reconcile_head(self.database.pool(), &file_id, state, finalized.number).await?;
        }
        *last_reconciliation = time::Instant::now();
        Ok(())
    }

    async fn canonical_log_hashes(
        &self,
        logs: &[ChainLog],
        range_end: u64,
        finalized: &FinalizedBlock,
    ) -> Result<BTreeMap<u64, String>, IndexerError> {
        let mut hashes = BTreeMap::new();
        for log in logs {
            let number = log.block_number().map_err(IndexerError::Chain)?;
            if let Some(cached) = hashes.get(&number) {
                if cached != &log.block_hash.to_ascii_lowercase() {
                    return Err(IndexerError::ChainMismatch);
                }
                continue;
            }
            let canonical = self
                .client
                .block_hash(number)
                .await
                .map_err(IndexerError::Chain)?;
            if canonical != log.block_hash.to_ascii_lowercase() {
                return Err(IndexerError::ChainMismatch);
            }
            hashes.insert(number, canonical);
        }

        let end_hash = if range_end == finalized.number {
            finalized.hash.clone()
        } else {
            self.client
                .block_hash(range_end)
                .await
                .map_err(IndexerError::Chain)?
        };
        hashes.insert(range_end, end_hash);
        Ok(hashes)
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("indexer stopped: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), IndexerError> {
    let rebuild = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [argument] if argument == "--rebuild-projections" => true,
        [argument] if argument == "--help" || argument == "-h" => {
            println!("Usage: indexer [--rebuild-projections]");
            return Ok(());
        }
        _ => return Err(IndexerError::InvalidConfiguration),
    };
    let config = Config::from_env()?;
    let rpc_endpoint = env::var("BESU_RPC_URL").map_err(|_| IndexerError::InvalidConfiguration)?;
    let database_url = env::var("DATABASE_URL").map_err(|_| IndexerError::InvalidConfiguration)?;
    let client = BesuClient::new(&rpc_endpoint).map_err(IndexerError::Chain)?;
    let database = PostgresStore::connect(&database_url)
        .await
        .map_err(|_| IndexerError::Database)?;
    database
        .migrate()
        .await
        .map_err(|_| IndexerError::Database)?;

    let indexer = Indexer {
        config,
        client,
        database,
        last_reconciliation: Mutex::new(time::Instant::now() - Duration::from_secs(60)),
    };
    let chain_id = indexer
        .client
        .chain_id()
        .await
        .map_err(IndexerError::Chain)?;
    if chain_id != indexer.config.expected_chain_id {
        return Err(IndexerError::ChainIdMismatch);
    }
    ensure_projection_chain(indexer.database.pool(), chain_id).await?;
    if rebuild {
        rebuild_projections(indexer.database.pool(), chain_id).await?;
        eprintln!("rebuilt indexer projections from persisted finalized events");
    }
    let mut interval = time::interval(POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => return Ok(()),
            _ = interval.tick() => {
                match indexer.process_once().await {
                    Ok(_) => {}
                    Err(error @ (IndexerError::ChainMismatch | IndexerError::ChainIdMismatch | IndexerError::InvalidConfiguration | IndexerError::UnsupportedFinalityPolicy)) => return Err(error),
                    Err(error) => eprintln!("indexer polling failed: {error}"),
                }
            }
        }
    }
}

async fn reconcile_head(
    pool: &PgPool,
    file_id: &[u8; 32],
    state: Option<FileHeadState>,
    finalized_block: u64,
) -> Result<(), IndexerError> {
    let Some(state) = state else {
        return Err(IndexerError::ChainMismatch);
    };
    let finalized_block = i64::try_from(finalized_block).map_err(|_| IndexerError::InvalidRange)?;
    let file_id = format!("0x{}", encode_hex(file_id));
    sqlx::query(
        "UPDATE files_projection SET current_version = $2, current_head_manifest_hash = $3, \
         file_status = $4, updated_block_number = $5 WHERE file_id = $1 AND \
         (current_version IS DISTINCT FROM $2 OR current_head_manifest_hash IS DISTINCT FROM $3 \
          OR file_status IS DISTINCT FROM $4)",
    )
    .bind(file_id)
    .bind(i64::try_from(state.version_number).map_err(|_| IndexerError::InvalidRange)?)
    .bind(state.manifest_hash)
    .bind(i16::try_from(state.status).map_err(|_| IndexerError::InvalidRange)?)
    .bind(finalized_block)
    .execute(pool)
    .await
    .map_err(|_| IndexerError::Database)?;
    Ok(())
}

fn parse_bytes32(value: &str) -> Result<[u8; 32], IndexerError> {
    let digits = value.strip_prefix("0x").ok_or(IndexerError::InvalidRange)?;
    if digits.len() != 64 {
        return Err(IndexerError::InvalidRange);
    }
    let mut output = [0; 32];
    for (index, pair) in digits.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (parse_hex_nibble(pair[0]).ok_or(IndexerError::InvalidRange)? << 4)
            | parse_hex_nibble(pair[1]).ok_or(IndexerError::InvalidRange)?;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_env_u64(name: &str, default: &str) -> Result<u64, IndexerError> {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|_| IndexerError::InvalidConfiguration)
}

fn parse_address_env(name: &str) -> Result<EvmAddress, IndexerError> {
    let value = env::var(name).map_err(|_| IndexerError::InvalidConfiguration)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or(IndexerError::InvalidConfiguration)?;
    if digits.len() != 40 {
        return Err(IndexerError::InvalidConfiguration);
    }
    let mut bytes = [0; 20];
    for (index, pair) in digits.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = parse_hex_nibble(pair[0]).ok_or(IndexerError::InvalidConfiguration)?;
        let low = parse_hex_nibble(pair[1]).ok_or(IndexerError::InvalidConfiguration)?;
        bytes[index] = (high << 4) | low;
    }
    if bytes == [0; 20] {
        return Err(IndexerError::InvalidConfiguration);
    }
    Ok(EvmAddress::from_bytes(bytes))
}

fn parse_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

async fn read_checkpoint(
    pool: &PgPool,
    chain_id: u64,
) -> Result<Option<(u64, String)>, IndexerError> {
    let chain_id = i64::try_from(chain_id).map_err(|_| IndexerError::InvalidConfiguration)?;
    let row =
        sqlx::query("SELECT block_number, block_hash FROM indexer_checkpoints WHERE chain_id = $1")
            .bind(chain_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| IndexerError::Database)?;
    row.map(|row| {
        let number: i64 = row
            .try_get("block_number")
            .map_err(|_| IndexerError::Database)?;
        let hash: String = row
            .try_get("block_hash")
            .map_err(|_| IndexerError::Database)?;
        Ok((
            u64::try_from(number).map_err(|_| IndexerError::Database)?,
            hash.trim().to_owned(),
        ))
    })
    .transpose()
}

async fn ensure_projection_chain(pool: &PgPool, chain_id: u64) -> Result<(), IndexerError> {
    let chain_id = i64::try_from(chain_id).map_err(|_| IndexerError::InvalidConfiguration)?;
    let mut transaction = pool.begin().await.map_err(|_| IndexerError::Database)?;
    sqlx::query(
        "INSERT INTO indexer_projection_chain (singleton, chain_id) VALUES (TRUE, $1) \
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(chain_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| IndexerError::Database)?;
    let configured_chain: i64 =
        sqlx::query_scalar("SELECT chain_id FROM indexer_projection_chain WHERE singleton = TRUE")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
    if configured_chain != chain_id {
        return Err(IndexerError::ChainIdMismatch);
    }
    transaction
        .commit()
        .await
        .map_err(|_| IndexerError::Database)
}

async fn rebuild_projections(pool: &PgPool, chain_id: u64) -> Result<(), IndexerError> {
    const PAGE_SIZE: i64 = 1_000;

    let chain_id = i64::try_from(chain_id).map_err(|_| IndexerError::InvalidConfiguration)?;
    let mut transaction = pool.begin().await.map_err(|_| IndexerError::Database)?;
    for table in [
        "organizations_projection",
        "members_projection",
        "member_keys_projection",
        "files_projection",
        "folders_projection",
        "versions_projection",
        "access_projection",
        "envelope_sets_projection",
    ] {
        let statement = format!("DELETE FROM {table}");
        sqlx::query(&statement)
            .execute(&mut *transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
    }

    let (mut last_block, mut last_transaction, mut last_log) = (-1_i64, -1_i64, -1_i64);
    loop {
        let rows = sqlx::query(
            "SELECT block_number, transaction_index, log_index, event_name, event_data, transaction_hash \
             FROM indexed_contract_events WHERE chain_id = $1 \
             AND (block_number, transaction_index, log_index) > ($2, $3, $4) \
             ORDER BY block_number, transaction_index, log_index LIMIT $5",
        )
        .bind(chain_id)
        .bind(last_block)
        .bind(last_transaction)
        .bind(last_log)
        .bind(PAGE_SIZE)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| IndexerError::Database)?;
        if rows.is_empty() {
            break;
        }

        for row in rows {
            let block_number: i64 = row
                .try_get("block_number")
                .map_err(|_| IndexerError::Database)?;
            let transaction_index: i64 = row
                .try_get("transaction_index")
                .map_err(|_| IndexerError::Database)?;
            let log_index: i64 = row
                .try_get("log_index")
                .map_err(|_| IndexerError::Database)?;
            let event_name: String = row
                .try_get("event_name")
                .map_err(|_| IndexerError::Database)?;
            let fields: Value = row
                .try_get("event_data")
                .map_err(|_| IndexerError::Database)?;
            let transaction_hash: String = row
                .try_get("transaction_hash")
                .map_err(|_| IndexerError::Database)?;
            project_event(
                &mut transaction,
                &event_name,
                &fields,
                &transaction_hash,
                block_number,
            )
            .await?;
            (last_block, last_transaction, last_log) = (block_number, transaction_index, log_index);
        }
    }
    transaction
        .commit()
        .await
        .map_err(|_| IndexerError::Database)
}

async fn apply_range(
    pool: &PgPool,
    chain_id: u64,
    checkpoint_number: u64,
    canonical_hashes: &BTreeMap<u64, String>,
    logs: &[ChainLog],
) -> Result<(), IndexerError> {
    let chain_id = i64::try_from(chain_id).map_err(|_| IndexerError::InvalidConfiguration)?;
    let checkpoint_number =
        i64::try_from(checkpoint_number).map_err(|_| IndexerError::InvalidRange)?;
    let mut transaction = pool.begin().await.map_err(|_| IndexerError::Database)?;

    for log in logs {
        let decoded = decoder::decode(log).map_err(IndexerError::Decode)?;
        let block_number = i64::try_from(log.block_number().map_err(IndexerError::Chain)?)
            .map_err(|_| IndexerError::InvalidRange)?;
        let log_index = i64::try_from(log.log_index().map_err(IndexerError::Chain)?)
            .map_err(|_| IndexerError::InvalidRange)?;
        let transaction_index =
            i64::try_from(log.transaction_index().map_err(IndexerError::Chain)?)
                .map_err(|_| IndexerError::InvalidRange)?;
        let block_hash = canonical_hashes
            .get(&u64::try_from(block_number).map_err(|_| IndexerError::InvalidRange)?)
            .ok_or(IndexerError::ChainMismatch)?;
        let contract_address = log.address.to_ascii_lowercase();
        let transaction_hash = log.transaction_hash.to_ascii_lowercase();
        let topic0 = log
            .topics
            .first()
            .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidLog))?
            .to_ascii_lowercase();
        let topics = serde_json::to_value(&log.topics).map_err(|_| IndexerError::Database)?;

        let inserted = sqlx::query(
            "INSERT INTO indexed_contract_events \
             (chain_id, block_number, block_hash, transaction_hash, transaction_index, log_index, \
              contract_address, topic0, event_name, event_data, raw_topics, raw_data) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             ON CONFLICT (chain_id, transaction_hash, log_index) DO NOTHING",
        )
        .bind(chain_id)
        .bind(block_number)
        .bind(block_hash)
        .bind(&transaction_hash)
        .bind(transaction_index)
        .bind(log_index)
        .bind(&contract_address)
        .bind(&topic0)
        .bind(&decoded.name)
        .bind(&decoded.fields)
        .bind(&topics)
        .bind(log.data.to_ascii_lowercase())
        .execute(&mut *transaction)
        .await
        .map_err(|_| IndexerError::Database)?;

        if inserted.rows_affected() == 1 {
            project_event(
                &mut transaction,
                &decoded.name,
                &decoded.fields,
                &transaction_hash,
                block_number,
            )
            .await?;
        }
    }

    let block_hash = canonical_hashes
        .get(&(checkpoint_number as u64))
        .ok_or(IndexerError::ChainMismatch)?;
    sqlx::query(
        "INSERT INTO indexer_checkpoints (chain_id, block_number, block_hash) VALUES ($1,$2,$3) \
         ON CONFLICT (chain_id) DO UPDATE SET block_number = EXCLUDED.block_number, \
         block_hash = EXCLUDED.block_hash, updated_at = now() \
         WHERE indexer_checkpoints.block_number <= EXCLUDED.block_number",
    )
    .bind(chain_id)
    .bind(checkpoint_number)
    .bind(block_hash)
    .execute(&mut *transaction)
    .await
    .map_err(|_| IndexerError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| IndexerError::Database)?;
    Ok(())
}

async fn project_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_name: &str,
    fields: &Value,
    transaction_hash: &str,
    block_number: i64,
) -> Result<(), IndexerError> {
    match event_name {
        "OrganizationRegistered" | "OrganizationAuthorityChanged" => {
            sqlx::query(
                "INSERT INTO organizations_projection (organization_id, authority, updated_block_number) \
                 VALUES ($1,$2,$3) ON CONFLICT (organization_id) DO UPDATE SET \
                 authority = EXCLUDED.authority, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "organization_id")?)
            .bind(if event_name == "OrganizationRegistered" {
                field_string(fields, "authority")?
            } else {
                field_string(fields, "new_authority")?
            })
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "FileCreated" => {
            sqlx::query(
                "INSERT INTO files_projection \
                 (file_id, organization_id, creator_member_id, display_name, parent_folder_id, \
                  file_status, updated_block_number) VALUES ($1,$2,$3,$4,$5,1,$6) \
                 ON CONFLICT (file_id) DO UPDATE SET organization_id = EXCLUDED.organization_id, \
                  creator_member_id = EXCLUDED.creator_member_id, display_name = EXCLUDED.display_name, \
                  parent_folder_id = EXCLUDED.parent_folder_id, file_status = 1, \
                  updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_string(fields, "organization_id")?)
            .bind(field_string(fields, "creator_member_id")?)
            .bind(field_string(fields, "display_name")?)
            .bind(field_string(fields, "parent_folder_id")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "FileMetadataChanged" => {
            sqlx::query(
                "INSERT INTO files_projection (file_id, display_name, parent_folder_id, updated_block_number) \
                 VALUES ($1,$2,$3,$4) ON CONFLICT (file_id) DO UPDATE SET \
                 display_name = EXCLUDED.display_name, parent_folder_id = EXCLUDED.parent_folder_id, \
                 updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_string(fields, "display_name")?)
            .bind(field_string(fields, "parent_folder_id")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "FileStatusChanged" => {
            sqlx::query(
                "INSERT INTO files_projection (file_id, file_status, updated_block_number) VALUES ($1,$2,$3) \
                 ON CONFLICT (file_id) DO UPDATE SET file_status = EXCLUDED.file_status, \
                 updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_i16(fields, "new_status")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "VersionAppended" => {
            sqlx::query(
                "INSERT INTO versions_projection \
                 (file_id, version_number, manifest_hash, parent_manifest_hash, epoch_id, author_member_id, \
                  author_signing_address, content_cid, initial_envelope_set_cid, transaction_hash, block_number) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (file_id, version_number) DO NOTHING",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_i64(fields, "version_number")?)
            .bind(field_string(fields, "manifest_hash")?)
            .bind(field_string(fields, "parent_manifest_hash")?)
            .bind(field_string(fields, "epoch_id")?)
            .bind(field_string(fields, "author_member_id")?)
            .bind(field_string(fields, "author_signing_address")?)
            .bind(field_string(fields, "content_cid")?)
            .bind(field_string(fields, "initial_envelope_set_cid")?)
            .bind(transaction_hash)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "CurrentHeadAdvanced" => {
            sqlx::query(
                "INSERT INTO files_projection (file_id, current_version, current_head_manifest_hash, updated_block_number) \
                 VALUES ($1,$2,$3,$4) ON CONFLICT (file_id) DO UPDATE SET \
                 current_version = EXCLUDED.current_version, current_head_manifest_hash = EXCLUDED.current_head_manifest_hash, \
                 updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_i64(fields, "version_number")?)
            .bind(field_string(fields, "manifest_hash")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "FolderCreated" => {
            sqlx::query(
                "INSERT INTO folders_projection \
                 (folder_id, organization_id, parent_folder_id, display_name, updated_block_number) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (folder_id) DO UPDATE SET \
                 organization_id = EXCLUDED.organization_id, parent_folder_id = EXCLUDED.parent_folder_id, \
                 display_name = EXCLUDED.display_name, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "folder_id")?)
            .bind(field_string(fields, "organization_id")?)
            .bind(field_string(fields, "parent_folder_id")?)
            .bind(field_string(fields, "display_name")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "FolderRenamed" => {
            sqlx::query(
                "UPDATE folders_projection SET display_name = $2, updated_block_number = $3 WHERE folder_id = $1",
            )
            .bind(field_string(fields, "folder_id")?)
            .bind(field_string(fields, "display_name")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "MemberRegistered" => {
            sqlx::query(
                "INSERT INTO members_projection (member_id, organization_id, signing_address, member_status, updated_block_number) \
                 VALUES ($1,$2,$3,1,$4) ON CONFLICT (member_id) DO UPDATE SET \
                 organization_id = EXCLUDED.organization_id, signing_address = EXCLUDED.signing_address, \
                 member_status = EXCLUDED.member_status, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "member_id")?)
            .bind(field_string(fields, "organization_id")?)
            .bind(field_string(fields, "signing_address")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "MemberKeyRegistered" => {
            let member_id = field_string(fields, "member_id")?;
            let key_version = field_i32(fields, "key_version")?;
            let public_key = field_string(fields, "public_key")?;
            let encryption_key = fields
                .get("encryption_key")
                .and_then(Value::as_bool)
                .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))?;
            let key_kind = if encryption_key {
                "encryption"
            } else {
                "signing"
            };
            sqlx::query(
                "INSERT INTO member_keys_projection \
                 (member_id, key_version, key_kind, key_status, updated_block_number, public_key) \
                 VALUES ($1,$2,$3,1,$4,$5) ON CONFLICT (member_id, key_version, key_kind) \
                 DO UPDATE SET key_status = 1, updated_block_number = EXCLUDED.updated_block_number, \
                 public_key = EXCLUDED.public_key",
            )
            .bind(member_id)
            .bind(key_version)
            .bind(key_kind)
            .bind(block_number)
            .bind(public_key)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;

            if encryption_key {
                sqlx::query(
                    "UPDATE members_projection SET encryption_key_version = $2, \
                     encryption_public_key = $3, updated_block_number = $4 WHERE member_id = $1",
                )
                .bind(member_id)
                .bind(key_version)
                .bind(public_key)
                .bind(block_number)
                .execute(&mut **transaction)
                .await
                .map_err(|_| IndexerError::Database)?;
            } else {
                let signing_address = format!("0x{}", &public_key[26..]);
                sqlx::query(
                    "UPDATE members_projection SET signing_key_version = $2, signing_address = $3, \
                     updated_block_number = $4 WHERE member_id = $1",
                )
                .bind(member_id)
                .bind(key_version)
                .bind(signing_address)
                .bind(block_number)
                .execute(&mut **transaction)
                .await
                .map_err(|_| IndexerError::Database)?;
            }
        }
        "MemberStatusChanged" => {
            sqlx::query(
                "UPDATE members_projection SET member_status = $2, updated_block_number = $3 WHERE member_id = $1",
            )
            .bind(field_string(fields, "member_id")?)
            .bind(field_i16(fields, "new_status")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
            let member_status = field_i16(fields, "new_status")?;
            let key_status = match member_status {
                1 => 1,
                2 => 2,
                3 => 3,
                _ => return Err(IndexerError::Decode(decoder::DecodeError::InvalidAbiData)),
            };
            sqlx::query(
                "UPDATE member_keys_projection SET key_status = $2, updated_block_number = $3 \
                 WHERE member_id = $1 AND key_status IN (1, 2)",
            )
            .bind(field_string(fields, "member_id")?)
            .bind(key_status)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "MemberKeyStatusChanged" => {
            sqlx::query(
                "INSERT INTO member_keys_projection \
                 (member_id, key_version, key_kind, key_status, updated_block_number) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (member_id, key_version, key_kind) \
                 DO UPDATE SET key_status = EXCLUDED.key_status, \
                 updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "member_id")?)
            .bind(field_i32(fields, "key_version")?)
            .bind(
                if fields
                    .get("encryption_key")
                    .and_then(Value::as_bool)
                    .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))?
                {
                    "encryption"
                } else {
                    "signing"
                },
            )
            .bind(field_i16(fields, "new_status")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "MemberKeySuperseded" => {
            // Key status transitions and newly registered keys have dedicated events.
        }
        "ReadAccessGranted" | "ReadAccessRevoked" | "WriteAccessGranted" | "WriteAccessRevoked" => {
            let permission: i16 = if event_name.starts_with("Read") { 0 } else { 1 };
            let granted = event_name.ends_with("Granted");
            sqlx::query(
                "INSERT INTO access_projection \
                 (file_id, member_id, permission, granted, actor, proposal_id, updated_block_number) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (file_id, member_id, permission) \
                 DO UPDATE SET granted = EXCLUDED.granted, actor = EXCLUDED.actor, \
                 proposal_id = EXCLUDED.proposal_id, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_string(fields, "member_id")?)
            .bind(permission)
            .bind(granted)
            .bind(field_string(fields, "actor")?)
            .bind(field_string(fields, "proposal_id")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "EnvelopeSetInitialized" => {
            sqlx::query(
                "INSERT INTO envelope_sets_projection \
                 (file_id, version_number, epoch_id, envelope_set_cid, revision, updated_block_number) \
                 VALUES ($1,$2,$3,$4,0,$5) ON CONFLICT (file_id, version_number) DO UPDATE SET \
                 epoch_id = EXCLUDED.epoch_id, envelope_set_cid = EXCLUDED.envelope_set_cid, \
                 revision = 0, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_i64(fields, "version_number")?)
            .bind(field_string(fields, "epoch_id")?)
            .bind(field_string(fields, "envelope_set_cid")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        "EnvelopeSetUpdated" => {
            sqlx::query(
                "INSERT INTO envelope_sets_projection \
                 (file_id, version_number, epoch_id, envelope_set_cid, revision, updated_block_number) \
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (file_id, version_number) DO UPDATE SET \
                 epoch_id = EXCLUDED.epoch_id, envelope_set_cid = EXCLUDED.envelope_set_cid, \
                 revision = EXCLUDED.revision, updated_block_number = EXCLUDED.updated_block_number",
            )
            .bind(field_string(fields, "file_id")?)
            .bind(field_i64(fields, "version_number")?)
            .bind(field_string(fields, "epoch_id")?)
            .bind(field_string(fields, "new_cid")?)
            .bind(field_i32(fields, "revision")?)
            .bind(block_number)
            .execute(&mut **transaction)
            .await
            .map_err(|_| IndexerError::Database)?;
        }
        _ => {}
    }
    Ok(())
}

fn field_string<'a>(fields: &'a Value, name: &str) -> Result<&'a str, IndexerError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))
}

fn field_i64(fields: &Value, name: &str) -> Result<i64, IndexerError> {
    fields
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))
}

fn field_i16(fields: &Value, name: &str) -> Result<i16, IndexerError> {
    fields
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| i16::try_from(value).ok())
        .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))
}

fn field_i32(fields: &Value, name: &str) -> Result<i32, IndexerError> {
    fields
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(IndexerError::Decode(decoder::DecodeError::InvalidAbiData))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;
    use sqlx::{
        Executor,
        postgres::{PgConnectOptions, PgPoolOptions},
    };
    use std::{
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

    async fn isolated_pool() -> Option<(PgPool, PgPool, String)> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => {
                eprintln!("Skipping indexer PostgreSQL integration test: DATABASE_URL is not set");
                return None;
            }
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect to PostgreSQL for isolated indexer integration test");
        let schema = format!(
            "rrfs_indexer_test_{}_{}",
            std::process::id(),
            NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
        );
        let create_schema = format!("CREATE SCHEMA {schema}");
        admin
            .execute(create_schema.as_str())
            .await
            .expect("create isolated indexer test schema");
        let options = PgConnectOptions::from_str(&database_url)
            .expect("parse PostgreSQL connection options")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await
            .expect("connect to isolated indexer schema");
        sqlx::raw_sql(include_str!(
            "../../../crates/metadata_store/migrations/0001_indexer_projections.sql"
        ))
        .execute(&pool)
        .await
        .expect("create indexer projection tables");
        sqlx::raw_sql(include_str!(
            "../../../crates/metadata_store/migrations/0002_indexer_identity_projections.sql"
        ))
        .execute(&pool)
        .await
        .expect("create identity projection tables");
        Some((admin, pool, schema))
    }

    async fn drop_isolated_pool(admin: PgPool, pool: PgPool, schema: &str) {
        pool.close().await;
        let drop_schema = format!("DROP SCHEMA {schema} CASCADE");
        admin
            .execute(drop_schema.as_str())
            .await
            .expect("drop isolated indexer test schema");
        admin.close().await;
    }

    fn topic_word(value: &str) -> String {
        format!("0x{value}")
    }

    fn word(value: u64) -> String {
        format!("{value:064x}")
    }

    fn string_tail(value: &str) -> String {
        let mut tail = word(value.len() as u64);
        for byte in value.as_bytes() {
            tail.push_str(&format!("{byte:02x}"));
        }
        while !tail.len().is_multiple_of(64) {
            tail.push('0');
        }
        tail
    }

    fn log(
        signature: &str,
        indexed: &[String],
        data: &str,
        block_number: u64,
        log_index: u64,
    ) -> ChainLog {
        let topic = sha3::Keccak256::digest(signature.as_bytes());
        ChainLog {
            address: format!("0x{}", "11".repeat(20)),
            topics: std::iter::once(format!("0x{}", encode_hex(&topic)))
                .chain(indexed.iter().cloned())
                .collect(),
            data: data.to_owned(),
            block_number: format!("0x{block_number:x}"),
            block_hash: format!("0x{}", "22".repeat(32)),
            transaction_hash: format!(
                "0x{}{:02x}{:02x}",
                "33".repeat(30),
                block_number % 256,
                log_index % 256
            ),
            transaction_index: "0x0".to_owned(),
            log_index: format!("0x{log_index:x}"),
            removed: false,
        }
    }

    async fn event_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM indexed_contract_events")
            .fetch_one(pool)
            .await
            .expect("count indexed events")
    }

    #[tokio::test]
    async fn event_replay_is_idempotent_and_projection_rebuild_is_atomic() {
        let Some((admin, pool, schema)) = isolated_pool().await else {
            return;
        };
        let file_id = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let organization_id = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let creator_id = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let manifest_hash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let parent_hash = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let epoch_id = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let member_id = "0x7777777777777777777777777777777777777777777777777777777777777777";
        let content_cid = "bafy-content-reference";
        let envelope_cid = "bafy-envelope-reference";
        let name_tail = string_tail("quarterly-report");
        let mut created_data = word(64);
        created_data.push_str(&"66".repeat(32));
        created_data.push_str(&name_tail);
        let file_created = log(
            "FileCreated(bytes32,bytes32,bytes32,string,bytes32)",
            &[
                topic_word(&file_id[2..]),
                topic_word(&organization_id[2..]),
                topic_word(&creator_id[2..]),
            ],
            &format!("0x{created_data}"),
            10,
            0,
        );

        let content_tail = string_tail(content_cid);
        let envelope_tail = string_tail(envelope_cid);
        let content_offset = 192_u64;
        let envelope_offset = content_offset + u64::try_from(content_tail.len() / 2).unwrap();
        let mut version_data = format!(
            "{}{}{}{}{}{}",
            &parent_hash[2..],
            &epoch_id[2..],
            &member_id[2..],
            format!("{}{}", "00".repeat(12), "88".repeat(20)),
            word(content_offset),
            word(envelope_offset),
        );
        version_data.push_str(&content_tail);
        version_data.push_str(&envelope_tail);
        let version_appended = log(
            "VersionAppended(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,address,string,string)",
            &[
                topic_word(&file_id[2..]),
                topic_word(&word(1)),
                topic_word(&manifest_hash[2..]),
            ],
            &format!("0x{version_data}"),
            10,
            1,
        );
        let current_head = log(
            "CurrentHeadAdvanced(bytes32,uint64,bytes32)",
            &[topic_word(&file_id[2..])],
            &format!("0x{}{}", word(1), &manifest_hash[2..]),
            10,
            2,
        );
        let envelope_tail = string_tail(envelope_cid);
        let envelope_initialized = log(
            "EnvelopeSetInitialized(bytes32,uint64,bytes32,string)",
            &[
                topic_word(&file_id[2..]),
                topic_word(&word(1)),
                topic_word(&epoch_id[2..]),
            ],
            &format!("0x{}{}", word(32), envelope_tail),
            10,
            3,
        );
        let logs = vec![
            file_created,
            version_appended,
            current_head,
            envelope_initialized,
        ];
        let canonical_hashes = BTreeMap::from([(10, format!("0x{}", "22".repeat(32)))]);

        apply_range(&pool, 1337, 10, &canonical_hashes, &logs)
            .await
            .expect("index finalized events");
        apply_range(&pool, 1337, 10, &canonical_hashes, &logs)
            .await
            .expect("replay identical finalized events");
        assert_eq!(event_count(&pool).await, 4);
        let projected_head: (i64, String, String) = sqlx::query_as(
            "SELECT current_version, current_head_manifest_hash, display_name \
             FROM files_projection WHERE file_id = $1",
        )
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .expect("read file projection");
        assert_eq!(projected_head.0, 1);
        assert_eq!(projected_head.1.trim(), manifest_hash);
        assert_eq!(projected_head.2, "quarterly-report");

        sqlx::query("UPDATE files_projection SET display_name = 'corrupt' WHERE file_id = $1")
            .bind(file_id)
            .execute(&pool)
            .await
            .expect("simulate projection drift");
        rebuild_projections(&pool, 1337)
            .await
            .expect("rebuild projections from persisted events");
        let rebuilt_name: String =
            sqlx::query_scalar("SELECT display_name FROM files_projection WHERE file_id = $1")
                .bind(file_id)
                .fetch_one(&pool)
                .await
                .expect("read rebuilt file projection");
        assert_eq!(rebuilt_name, "quarterly-report");

        let projected_version: (String, String, String) = sqlx::query_as(
            "SELECT content_cid, initial_envelope_set_cid, author_signing_address \
             FROM versions_projection WHERE file_id = $1 AND version_number = 1",
        )
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .expect("read version projection");
        assert_eq!(projected_version.0, content_cid);
        assert_eq!(projected_version.1, envelope_cid);
        assert_eq!(
            projected_version.2.trim(),
            "0x8888888888888888888888888888888888888888"
        );
        assert_eq!(event_count(&pool).await, 4);

        drop_isolated_pool(admin, pool, &schema).await;
    }

    #[tokio::test]
    async fn failed_event_decode_rolls_back_events_and_checkpoint() {
        let Some((admin, pool, schema)) = isolated_pool().await else {
            return;
        };
        let organization = log(
            "OrganizationRegistered(bytes32,address)",
            &[
                topic_word(&"aa".repeat(32)),
                topic_word(&format!("{}{}", "00".repeat(12), "44".repeat(20))),
            ],
            "0x",
            4,
            0,
        );
        let malformed = log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            &[topic_word(&"bb".repeat(32)), topic_word(&word(1))],
            "0x01",
            4,
            1,
        );
        let hashes = BTreeMap::from([(4, format!("0x{}", "22".repeat(32)))]);
        assert!(
            apply_range(&pool, 1337, 4, &hashes, &[organization, malformed])
                .await
                .is_err()
        );
        assert_eq!(event_count(&pool).await, 0);
        let checkpoint = read_checkpoint(&pool, 1337).await.unwrap();
        assert_eq!(checkpoint, None);

        drop_isolated_pool(admin, pool, &schema).await;
    }

    #[tokio::test]
    async fn identity_and_key_projections_follow_registration_and_supersession_events() {
        let Some((admin, pool, schema)) = isolated_pool().await else {
            return;
        };
        let organization_id = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let member_id = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let organization = log(
            "OrganizationRegistered(bytes32,address)",
            &[
                topic_word(&organization_id[2..]),
                topic_word(&format!("{}{}", "00".repeat(12), "44".repeat(20))),
            ],
            "0x",
            20,
            0,
        );
        let member = log(
            "MemberRegistered(bytes32,bytes32,address)",
            &[
                topic_word(&member_id[2..]),
                topic_word(&organization_id[2..]),
            ],
            &format!("0x{}{}", "00".repeat(12), "44".repeat(20)),
            20,
            1,
        );
        let signing_key = log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            &[topic_word(&member_id[2..]), topic_word(&word(1))],
            &format!("0x{}{}", word(0), "00".repeat(12) + &"44".repeat(20)),
            20,
            2,
        );
        let encryption_key = log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            &[topic_word(&member_id[2..]), topic_word(&word(1))],
            &format!("0x{}{}", word(1), "55".repeat(32)),
            20,
            3,
        );
        let old_signing_status = log(
            "MemberKeyStatusChanged(bytes32,uint32,bool,uint8,uint8)",
            &[topic_word(&member_id[2..]), topic_word(&word(1))],
            &format!("0x{}{}{}", word(0), word(1), word(4)),
            21,
            0,
        );
        let old_encryption_status = log(
            "MemberKeyStatusChanged(bytes32,uint32,bool,uint8,uint8)",
            &[topic_word(&member_id[2..]), topic_word(&word(1))],
            &format!("0x{}{}{}", word(1), word(1), word(4)),
            21,
            1,
        );
        let signing_key_v2 = log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            &[topic_word(&member_id[2..]), topic_word(&word(2))],
            &format!("0x{}{}", word(0), "00".repeat(12) + &"66".repeat(20)),
            21,
            2,
        );
        let encryption_key_v2 = log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            &[topic_word(&member_id[2..]), topic_word(&word(2))],
            &format!("0x{}{}", word(1), "77".repeat(32)),
            21,
            3,
        );
        let logs = vec![
            organization,
            member,
            signing_key,
            encryption_key,
            old_signing_status,
            old_encryption_status,
            signing_key_v2,
            encryption_key_v2,
        ];
        let hashes = BTreeMap::from([
            (20, format!("0x{}", "22".repeat(32))),
            (21, format!("0x{}", "22".repeat(32))),
        ]);
        apply_range(&pool, 1337, 21, &hashes, &logs)
            .await
            .expect("index identity and key events");

        let member_projection: (String, i32, i32, String) = sqlx::query_as(
            "SELECT signing_address, signing_key_version, encryption_key_version, \
             encryption_public_key FROM members_projection WHERE member_id = $1",
        )
        .bind(member_id)
        .fetch_one(&pool)
        .await
        .expect("read member projection");
        assert_eq!(
            member_projection.0.trim(),
            "0x6666666666666666666666666666666666666666"
        );
        assert_eq!(member_projection.1, 2);
        assert_eq!(member_projection.2, 2);
        assert_eq!(member_projection.3.trim(), format!("0x{}", "77".repeat(32)));

        let key_statuses: Vec<(i32, String, i16)> = sqlx::query_as(
            "SELECT key_version, key_kind, key_status FROM member_keys_projection \
             WHERE member_id = $1 ORDER BY key_kind, key_version",
        )
        .bind(member_id)
        .fetch_all(&pool)
        .await
        .expect("read member key status history");
        assert_eq!(
            key_statuses,
            vec![
                (1, "encryption".to_owned(), 4),
                (2, "encryption".to_owned(), 1),
                (1, "signing".to_owned(), 4),
                (2, "signing".to_owned(), 1),
            ]
        );

        drop_isolated_pool(admin, pool, &schema).await;
    }
}
