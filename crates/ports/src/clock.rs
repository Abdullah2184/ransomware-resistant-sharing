use std::time::{SystemTime, UNIX_EPOCH};

use domain::DomainError;

/// Clock abstraction for deterministic deadline and challenge-expiry validation.
pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, DomainError>;
}

/// Wall-clock implementation backed by `SystemTime::now()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> Result<u64, DomainError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| DomainError::Internal)
    }
}
