//! Errors for the evidence harness binary.
//!
//! Error text never contains private key material: the key travels by file
//! path or stdin only (contract §3.5), and failures reference commands and
//! paths, never key bytes.

use fabric_linux::FabricError;
use fabric_plan::PlanError;
use thiserror::Error;

/// Everything that can fail while collecting evidence on one host.
#[derive(Debug, Error)]
pub enum RunError {
    /// Invalid command line.
    #[error("usage error: {0}")]
    Usage(String),
    /// Local filesystem I/O.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The fabric provider refused or failed an operation.
    #[error("fabric provider: {0}")]
    Fabric(#[from] FabricError),
    /// Plan reading or validation failed.
    #[error("plan: {0}")]
    Plan(#[from] PlanError),
    /// JSON (de)serialization failed.
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// An external command failed.
    #[error("command failed: {0}")]
    Command(String),
    /// The leak check found fabric residue in this host's kernel.
    #[error("leak check found residue: {0}")]
    Leak(String),
}
