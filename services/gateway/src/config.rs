use std::{env, net::SocketAddr};

use domain::EvmAddress;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    #[default]
    Development,
    Production,
}

impl RuntimeEnvironment {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" | "local" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            _ => Err("RRDS_ENV must be one of: development, production".to_owned()),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        match env::var("RRDS_ENV") {
            Ok(raw) if !raw.trim().is_empty() => Self::parse(&raw),
            Ok(_) | Err(env::VarError::NotPresent) => Ok(Self::Development),
            Err(env::VarError::NotUnicode(_)) => Err("RRDS_ENV is not valid Unicode".to_owned()),
        }
    }
}

pub struct GatewayConfig {
    pub environment: RuntimeEnvironment,
    pub database_url: String,
    pub besu_rpc_url: String,
    pub chain_id: u64,
    pub access_governance: EvmAddress,
    pub file_registry: EvmAddress,
    pub audience: String,
    pub bind: SocketAddr,
    pub challenge_ttl_seconds: u64,
    pub session_ttl_seconds: u64,
    pub rate_limit_capacity: u32,
    pub rate_limit_refill_per_second: f64,
    pub member_rate_limit_capacity: u32,
    pub member_rate_limit_refill_per_second: f64,
    pub org_rate_limit_capacity: u32,
    pub org_rate_limit_refill_per_second: f64,
    pub invalid_sig_limit_capacity: u32,
    pub invalid_sig_limit_refill_per_second: f64,
    pub max_concurrent_streams: usize,
    pub min_pin_replicas: usize,
    pub default_tx_gas_limit: u64,
    pub transaction_confirmation_timeout_seconds: u64,
    pub orphan_retention_seconds: u64,
    pub storage_health_interval_seconds: u64,
    pub max_blob_upload_bytes: usize,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, String> {
        let environment = RuntimeEnvironment::from_env()?;
        let database_url = required("DATABASE_URL")?;
        if environment == RuntimeEnvironment::Production && has_placeholder_secret(&database_url) {
            return Err(
                "DATABASE_URL contains a placeholder secret; configure production credentials"
                    .to_owned(),
            );
        }
        let besu_rpc_url = required("BESU_RPC_URL")?;
        if environment == RuntimeEnvironment::Production {
            validate_production_endpoint("BESU_RPC_URL", &besu_rpc_url)?;
        }
        let chain_id = parse_or_default("BESU_CHAIN_ID", 1337_u64)?;
        if chain_id == 0 {
            return Err("BESU_CHAIN_ID must be non-zero".to_owned());
        }
        let access_governance = parse_address(
            "CONTRACT_ACCESS_GOVERNANCE_ADDRESS",
            &required("CONTRACT_ACCESS_GOVERNANCE_ADDRESS")?,
        )?;
        let file_registry = parse_address(
            "CONTRACT_FILE_REGISTRY_ADDRESS",
            &required("CONTRACT_FILE_REGISTRY_ADDRESS")?,
        )?;
        let audience = required("GATEWAY_AUDIENCE")?;
        if audience.is_empty() || audience.len() > 512 || audience.chars().any(char::is_control) {
            return Err("GATEWAY_AUDIENCE must be at most 512 printable bytes".to_owned());
        }
        let bind = env::var("GATEWAY_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| "GATEWAY_BIND must be a socket address".to_owned())?;
        if !bind.ip().is_loopback() {
            return Err(
                "GATEWAY_BIND must use loopback; configure TLS termination before exposure"
                    .to_owned(),
            );
        }
        let challenge_ttl_seconds = parse_or_default("GATEWAY_CHALLENGE_TTL_SECONDS", 120_u64)?;
        if !(1..=300).contains(&challenge_ttl_seconds) {
            return Err("GATEWAY_CHALLENGE_TTL_SECONDS must be between 1 and 300".to_owned());
        }
        let session_ttl_seconds = parse_or_default("GATEWAY_SESSION_TTL_SECONDS", 900_u64)?;
        if !(1..=3600).contains(&session_ttl_seconds) {
            return Err("GATEWAY_SESSION_TTL_SECONDS must be between 1 and 3600".to_owned());
        }
        let rate_limit_capacity = parse_or_default("GATEWAY_RATE_LIMIT_CAPACITY", 30_u32)?;
        let rate_limit_refill_per_second =
            parse_or_default("GATEWAY_RATE_LIMIT_REFILL_PER_SECOND", 0.5_f64)?;
        if !(1..=10_000).contains(&rate_limit_capacity)
            || !rate_limit_refill_per_second.is_finite()
            || !(0.01..=1000.0).contains(&rate_limit_refill_per_second)
        {
            return Err(
                "gateway rate-limit configuration is outside its supported range".to_owned(),
            );
        }
        let member_rate_limit_capacity =
            parse_or_default("GATEWAY_MEMBER_RATE_LIMIT_CAPACITY", 60_u32)?;
        let member_rate_limit_refill_per_second =
            parse_or_default("GATEWAY_MEMBER_RATE_LIMIT_REFILL_PER_SECOND", 1.0_f64)?;
        if !(1..=10_000).contains(&member_rate_limit_capacity)
            || !member_rate_limit_refill_per_second.is_finite()
            || !(0.01..=1000.0).contains(&member_rate_limit_refill_per_second)
        {
            return Err(
                "gateway member rate-limit configuration is outside its supported range".to_owned(),
            );
        }
        let org_rate_limit_capacity = parse_or_default("GATEWAY_ORG_RATE_LIMIT_CAPACITY", 300_u32)?;
        let org_rate_limit_refill_per_second =
            parse_or_default("GATEWAY_ORG_RATE_LIMIT_REFILL_PER_SECOND", 5.0_f64)?;
        if !(1..=100_000).contains(&org_rate_limit_capacity)
            || !org_rate_limit_refill_per_second.is_finite()
            || !(0.01..=10_000.0).contains(&org_rate_limit_refill_per_second)
        {
            return Err(
                "gateway organization rate-limit configuration is outside its supported range"
                    .to_owned(),
            );
        }
        let invalid_sig_limit_capacity =
            parse_or_default("GATEWAY_INVALID_SIG_LIMIT_CAPACITY", 10_u32)?;
        let invalid_sig_limit_refill_per_second =
            parse_or_default("GATEWAY_INVALID_SIG_LIMIT_REFILL_PER_SECOND", 0.1_f64)?;
        if !(1..=1_000).contains(&invalid_sig_limit_capacity)
            || !invalid_sig_limit_refill_per_second.is_finite()
            || !(0.001..=100.0).contains(&invalid_sig_limit_refill_per_second)
        {
            return Err(
                "gateway invalid-signature rate-limit configuration is outside its supported range"
                    .to_owned(),
            );
        }
        let max_concurrent_streams = parse_or_default("GATEWAY_MAX_CONCURRENT_STREAMS", 32_usize)?;
        if !(1..=1024).contains(&max_concurrent_streams) {
            return Err("GATEWAY_MAX_CONCURRENT_STREAMS must be between 1 and 1024".to_owned());
        }

        let min_pin_replicas = parse_or_default("MIN_PIN_REPLICAS", 2_usize)?;
        if !(1..=64).contains(&min_pin_replicas) {
            return Err("MIN_PIN_REPLICAS must be between 1 and 64".to_owned());
        }
        let default_tx_gas_limit = parse_or_default("DEFAULT_TX_GAS_LIMIT", 2_000_000_u64)?;
        if !(100_000..=30_000_000).contains(&default_tx_gas_limit) {
            return Err("DEFAULT_TX_GAS_LIMIT must be between 100000 and 30000000".to_owned());
        }
        let transaction_confirmation_timeout_seconds =
            parse_or_default("TRANSACTION_CONFIRMATION_TIMEOUT", 30_u64)?;
        if !(1..=300).contains(&transaction_confirmation_timeout_seconds) {
            return Err(
                "TRANSACTION_CONFIRMATION_TIMEOUT must be between 1 and 300 seconds".to_owned(),
            );
        }
        let orphan_retention_seconds = parse_or_default("ORPHAN_RETENTION_SECONDS", 3600_u64)?;
        if !(60..=30 * 86_400).contains(&orphan_retention_seconds) {
            return Err("ORPHAN_RETENTION_SECONDS must be between 60 and 2592000".to_owned());
        }
        let storage_health_interval_seconds =
            parse_or_default("GATEWAY_STORAGE_HEALTH_INTERVAL_SECONDS", 30_u64)?;
        if !(5..=3600).contains(&storage_health_interval_seconds) {
            return Err(
                "GATEWAY_STORAGE_HEALTH_INTERVAL_SECONDS must be between 5 and 3600".to_owned(),
            );
        }
        let max_blob_upload_bytes =
            parse_or_default("GATEWAY_MAX_BLOB_UPLOAD_BYTES", 64 * 1024 * 1024_usize)?;
        if !(1024..=512 * 1024 * 1024).contains(&max_blob_upload_bytes) {
            return Err(
                "GATEWAY_MAX_BLOB_UPLOAD_BYTES must be between 1024 and 536870912".to_owned(),
            );
        }

        if environment == RuntimeEnvironment::Production {
            validate_production_storage_env()?;
        }

        Ok(Self {
            environment,
            database_url,
            besu_rpc_url,
            chain_id,
            access_governance,
            file_registry,
            audience,
            bind,
            challenge_ttl_seconds,
            session_ttl_seconds,
            rate_limit_capacity,
            rate_limit_refill_per_second,
            member_rate_limit_capacity,
            member_rate_limit_refill_per_second,
            org_rate_limit_capacity,
            org_rate_limit_refill_per_second,
            invalid_sig_limit_capacity,
            invalid_sig_limit_refill_per_second,
            max_concurrent_streams,
            min_pin_replicas,
            default_tx_gas_limit,
            transaction_confirmation_timeout_seconds,
            orphan_retention_seconds,
            storage_health_interval_seconds,
            max_blob_upload_bytes,
        })
    }
}

pub fn has_placeholder_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("replace-with-") || lower.contains("changeme") || lower.contains("placeholder")
}

pub fn validate_production_endpoint(name: &str, raw_url: &str) -> Result<(), String> {
    if raw_url.starts_with("https://")
        || raw_url.starts_with("http://127.0.0.1")
        || raw_url.starts_with("http://localhost")
        || raw_url.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err(format!(
        "{name} must use https:// or loopback in production mode"
    ))
}

fn validate_production_storage_env() -> Result<(), String> {
    if let Ok(urls) = env::var("IPFS_API_URLS") {
        for raw in urls.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            validate_production_endpoint("IPFS_API_URLS", raw)?;
        }
    }
    if let Ok(url) = env::var("IPFS_CLUSTER_API_URL")
        && !url.trim().is_empty()
    {
        validate_production_endpoint("IPFS_CLUSTER_API_URL", url.trim())?;
    }
    if let Ok(pass) = env::var("IPFS_CLUSTER_PASSWORD")
        && has_placeholder_secret(&pass)
    {
        return Err("IPFS_CLUSTER_PASSWORD contains a placeholder secret".to_owned());
    }
    Ok(())
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be configured"))
}

fn parse_or_default<T>(name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| format!("{name} has an invalid value")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid Unicode")),
    }
}

fn parse_address(name: &str, value: &str) -> Result<EvmAddress, String> {
    let bytes = value
        .strip_prefix("0x")
        .filter(|value| value.len() == 40)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{name} must be a 20-byte hex address"))?;
    let mut address = [0; 20];
    for (index, byte) in address.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&bytes[offset..offset + 2], 16)
            .map_err(|_| format!("{name} is invalid"))?;
    }
    if address == [0; 20] {
        return Err(format!("{name} must be non-zero"));
    }
    Ok(EvmAddress::from_bytes(address))
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeEnvironment, has_placeholder_secret, parse_address, validate_production_endpoint,
    };

    #[test]
    fn parse_address_reports_the_configured_variable_name() {
        let error = parse_address("CONTRACT_FILE_REGISTRY_ADDRESS", "not-an-address").unwrap_err();
        assert!(error.contains("CONTRACT_FILE_REGISTRY_ADDRESS"));
        let zero = format!("0x{}", "00".repeat(20));
        let zero_error = parse_address("CONTRACT_FILE_REGISTRY_ADDRESS", &zero).unwrap_err();
        assert!(zero_error.contains("CONTRACT_FILE_REGISTRY_ADDRESS"));
    }

    #[test]
    fn production_guards_reject_placeholder_secrets_and_plaintext_remote_urls() {
        assert_eq!(
            RuntimeEnvironment::parse("production").unwrap(),
            RuntimeEnvironment::Production
        );
        assert_eq!(
            RuntimeEnvironment::parse("development").unwrap(),
            RuntimeEnvironment::Development
        );
        assert!(RuntimeEnvironment::parse("staging-unknown").is_err());

        assert!(has_placeholder_secret(
            "postgres://rrfs_gateway:replace-with-a-generated-local-secret@127.0.0.1:5432/rrfs_dev"
        ));
        assert!(has_placeholder_secret("changeme-password"));
        assert!(!has_placeholder_secret(
            "postgres://rrfs_gateway:8f2e19c4b071a3e5@10.0.0.5:5432/rrfs_prod"
        ));

        assert!(validate_production_endpoint("BESU_RPC_URL", "https://besu.internal:8545").is_ok());
        assert!(validate_production_endpoint("BESU_RPC_URL", "http://127.0.0.1:8545").is_ok());
        assert!(validate_production_endpoint("IPFS_API_URLS", "http://10.0.0.9:5001").is_err());
    }
}
