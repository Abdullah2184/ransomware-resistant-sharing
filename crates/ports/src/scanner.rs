use std::fmt;

use domain::DomainError;

use crate::PortFuture;

/// Policy governing optional client-side pre-upload scanning (`TECHNICAL_SPECIFICATION.md` §14).
///
/// Defaults to [`ScannerMode::Disabled`] in the MVP. Scanning is always a
/// best-effort endpoint defense-in-depth signal and never a substitute for
/// immutability or version review (no `trustedVersion` flag exists on-chain).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScannerMode {
    #[default]
    Disabled,
    Warn,
    Enforce,
}

/// Raw outcome reported by a local pre-upload scanner implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanOutcome {
    Skipped,
    Clean,
    Suspicious { reason: String },
}

/// Actionable decision after applying [`ScannerMode`] to a [`ScanOutcome`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanVerdict {
    Allow,
    AllowWithWarning { reason: String },
    Block { reason: String },
}

impl fmt::Display for ScanVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => formatter.write_str("allowed"),
            Self::AllowWithWarning { reason } => {
                write!(formatter, "allowed with warning: {reason}")
            }
            Self::Block { reason } => write!(formatter, "blocked by pre-upload scanner: {reason}"),
        }
    }
}

/// Applies the configured [`ScannerMode`] to a [`ScanOutcome`].
pub fn evaluate_scan_outcome(mode: ScannerMode, outcome: ScanOutcome) -> ScanVerdict {
    match (mode, outcome) {
        (ScannerMode::Disabled, _) | (_, ScanOutcome::Skipped | ScanOutcome::Clean) => {
            ScanVerdict::Allow
        }
        (ScannerMode::Warn, ScanOutcome::Suspicious { reason }) => {
            ScanVerdict::AllowWithWarning { reason }
        }
        (ScannerMode::Enforce, ScanOutcome::Suspicious { reason }) => ScanVerdict::Block { reason },
    }
}

/// Client-side pre-upload plaintext scanning port.
///
/// Implementations run strictly on the user endpoint prior to client-side
/// encryption and never send plaintext to the gateway, indexer, or storage peers.
pub trait PreUploadScanner: Send + Sync {
    fn mode(&self) -> ScannerMode;

    fn scan_plaintext<'a>(
        &'a self,
        display_name: &'a str,
        plaintext: &'a [u8],
    ) -> PortFuture<'a, ScanOutcome>;

    fn evaluate<'a>(
        &'a self,
        display_name: &'a str,
        plaintext: &'a [u8],
    ) -> PortFuture<'a, ScanVerdict> {
        let mode = self.mode();
        Box::pin(async move {
            if mode == ScannerMode::Disabled {
                return Ok(ScanVerdict::Allow);
            }
            let outcome = self.scan_plaintext(display_name, plaintext).await?;
            Ok(evaluate_scan_outcome(mode, outcome))
        })
    }
}

/// Stable error alias for scanner port failures.
pub type ScannerError = DomainError;
