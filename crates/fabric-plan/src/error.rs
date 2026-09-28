//! Plan validation and fingerprint errors.

use thiserror::Error;

/// Errors produced while validating or fingerprinting a fabric plan.
#[derive(Debug, Error)]
pub enum PlanError {
    /// A field failed validation. The message never contains secret material
    /// (plans cannot represent private keys by construction).
    #[error("invalid fabric plan: {0}")]
    Invalid(String),
    /// Fingerprint serialization failed.
    #[error("plan fingerprint serialization failed: {0}")]
    Fingerprint(String),
}
