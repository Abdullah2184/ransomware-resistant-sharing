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
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, String> {
        let database_url = required("DATABASE_URL")?;
        let besu_rpc_url = required("BESU_RPC_URL")?;
        let chain_id = parse_or_default("BESU_CHAIN_ID", 1337_u64)?;
        if chain_id == 0 {
            return Err("BESU_CHAIN_ID must be non-zero".to_owned());
        }
        let access_governance = parse_address(&required("CONTRACT_ACCESS_GOVERNANCE_ADDRESS")?)?;
        let file_registry = parse_address(&required("CONTRACT_FILE_REGISTRY_ADDRESS")?)?;
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

fn parse_address(value: &str) -> Result<EvmAddress, String> {
    let bytes = value
        .strip_prefix("0x")
        .filter(|value| value.len() == 40)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            "CONTRACT_ACCESS_GOVERNANCE_ADDRESS must be a 20-byte hex address".to_owned()
        })?;
    let mut address = [0; 20];
    for (index, byte) in address.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&bytes[offset..offset + 2], 16)
            .map_err(|_| "CONTRACT_ACCESS_GOVERNANCE_ADDRESS is invalid".to_owned())?;
    }
    if address == [0; 20] {
        return Err("CONTRACT_ACCESS_GOVERNANCE_ADDRESS must be non-zero".to_owned());
    }
    Ok(EvmAddress::from_bytes(address))
}
