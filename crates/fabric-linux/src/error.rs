//! Provider errors.
//!
//! Error messages never contain key material: the provider never places
//! private key bytes in argv, plans, ownership state, or error text.

use thiserror::Error;

/// Errors produced by the Linux fabric provider.
#[derive(Debug, Error)]
pub enum FabricError {
    /// The input plan or configuration is invalid.
    #[error("invalid fabric input: {0}")]
    Invalid(String),
    /// An external command failed. Includes the program and arguments for
    /// operator diagnosis (arguments never contain key material).
    #[error("command failed: {0}")]
    Command(String),
    /// A kernel object exists but does not match expected owned identity.
    /// The provider never adopts or deletes foreign state.
    #[error("foreign state rejected for {object}: expected {expected}, observed {observed}")]
    ForeignState {
        object: String,
        expected: String,
        observed: String,
    },
    /// Durable ownership or plan state is inconsistent with the request.
    #[error("ownership conflict: {0}")]
    Ownership(String),
    /// The requested operation is not implemented in this provider version.
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    /// Local filesystem I/O failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
