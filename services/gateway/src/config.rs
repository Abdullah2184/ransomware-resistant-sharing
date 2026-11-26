use std::{env, net::SocketAddr};

use domain::EvmAddress;

pub struct GatewayConfig {
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
    pub invalid_sig_limit_capacity: u32,
    pub invalid_sig_limit_refill_per_second: f64,
    pub min_pin_replicas: usize,
    pub default_tx_gas_limit: u64,
    pub max_blob_upload_bytes: usize,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, String> {
        let database_url = required("DATABASE_URL")?;
        let besu_rpc_url = required("BESU_RPC_URL")?;
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

        let min_pin_replicas = parse_or_default("MIN_PIN_REPLICAS", 2_usize)?;
        if !(1..=64).contains(&min_pin_replicas) {
            return Err("MIN_PIN_REPLICAS must be between 1 and 64".to_owned());
        }
        let default_tx_gas_limit = parse_or_default("DEFAULT_TX_GAS_LIMIT", 2_000_000_u64)?;
        if !(100_000..=30_000_000).contains(&default_tx_gas_limit) {
            return Err("DEFAULT_TX_GAS_LIMIT must be between 100000 and 30000000".to_owned());
        }
        let max_blob_upload_bytes =
            parse_or_default("GATEWAY_MAX_BLOB_UPLOAD_BYTES", 64 * 1024 * 1024_usize)?;
        if !(1024..=512 * 1024 * 1024).contains(&max_blob_upload_bytes) {
            return Err(
                "GATEWAY_MAX_BLOB_UPLOAD_BYTES must be between 1024 and 536870912".to_owned(),
            );
        }

        Ok(Self {
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
            invalid_sig_limit_capacity,
            invalid_sig_limit_refill_per_second,
            min_pin_replicas,
            default_tx_gas_limit,
            max_blob_upload_bytes,
        })
    }
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
    use super::parse_address;

    #[test]
    fn parse_address_reports_the_configured_variable_name() {
        let error = parse_address("CONTRACT_FILE_REGISTRY_ADDRESS", "not-an-address").unwrap_err();
        assert!(error.contains("CONTRACT_FILE_REGISTRY_ADDRESS"));
        let zero = format!("0x{}", "00".repeat(20));
        let zero_error = parse_address("CONTRACT_FILE_REGISTRY_ADDRESS", &zero).unwrap_err();
        assert!(zero_error.contains("CONTRACT_FILE_REGISTRY_ADDRESS"));
    }
}
