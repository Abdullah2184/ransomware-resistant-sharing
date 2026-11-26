//! Client-side pre-upload scanning adapters (`TECHNICAL_SPECIFICATION.md` §14).
//!
//! Scanning runs strictly on user endpoints prior to encryption and is
//! disabled by default in the MVP. Optional entropy or antivirus adapters can
//! be added later behind [`ports::PreUploadScanner`] without changing domain
//! or gateway code.

pub use ports::{PreUploadScanner, ScanOutcome, ScanVerdict, ScannerMode, evaluate_scan_outcome};

/// Default MVP scanner adapter: disabled by default and performs no inspection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DisabledScanner;

impl DisabledScanner {
    pub const fn new() -> Self {
        Self
    }
}

impl PreUploadScanner for DisabledScanner {
    fn mode(&self) -> ScannerMode {
        ScannerMode::Disabled
    }

    fn scan_plaintext<'a>(
        &'a self,
        _display_name: &'a str,
        _plaintext: &'a [u8],
    ) -> ports::PortFuture<'a, ScanOutcome> {
        Box::pin(async { Ok(ScanOutcome::Skipped) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubFlaggingScanner(ScannerMode);

    impl PreUploadScanner for StubFlaggingScanner {
        fn mode(&self) -> ScannerMode {
            self.0
        }

        fn scan_plaintext<'a>(
            &'a self,
            _display_name: &'a str,
            _plaintext: &'a [u8],
        ) -> ports::PortFuture<'a, ScanOutcome> {
            Box::pin(async {
                Ok(ScanOutcome::Suspicious {
                    reason: "stub_signal".to_owned(),
                })
            })
        }
    }

    #[tokio::test]
    async fn disabled_scanner_is_default_and_skips_inspection() {
        let scanner = DisabledScanner;
        assert_eq!(scanner.mode(), ScannerMode::Disabled);
        assert_eq!(
            scanner.scan_plaintext("report.pdf", b"data").await.unwrap(),
            ScanOutcome::Skipped
        );
        assert_eq!(
            scanner.evaluate("report.pdf", b"data").await.unwrap(),
            ScanVerdict::Allow
        );
    }

    #[tokio::test]
    async fn scanner_mode_policy_controls_warn_and_enforce_verdicts() {
        let disabled = StubFlaggingScanner(ScannerMode::Disabled);
        assert_eq!(
            disabled.evaluate("a.bin", b"x").await.unwrap(),
            ScanVerdict::Allow
        );

        let warn = StubFlaggingScanner(ScannerMode::Warn);
        assert_eq!(
            warn.evaluate("a.bin", b"x").await.unwrap(),
            ScanVerdict::AllowWithWarning {
                reason: "stub_signal".to_owned(),
            }
        );

        let enforce = StubFlaggingScanner(ScannerMode::Enforce);
        assert_eq!(
            enforce.evaluate("a.bin", b"x").await.unwrap(),
            ScanVerdict::Block {
                reason: "stub_signal".to_owned(),
            }
        );
    }
}
