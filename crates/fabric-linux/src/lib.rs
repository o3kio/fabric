//! Linux provider for the Kubedo stretched-L2 edge fabric.
//!
//! This crate realizes [`fabric_plan::StretchedL2Plan`] on Linux hosts using
//! kernel primitives only: WireGuard (authenticated/encrypted host transport),
//! VXLAN with head-end replication and kernel MAC learning (per-network
//! stretched L2), network namespaces, veth pairs, and bounded nftables-free
//! host NAT rules for the underlay attachment.
//!
//! Design properties (normative: `contracts/fabric-provider-v1.md`):
//!
//! - **Journal before mutate**: the plan is persisted under the state root
//!   before any kernel object is created.
//! - **Idempotent**: re-applying an unchanged plan performs observations only.
//! - **Fail-closed on foreign state**: kernel objects that exist but do not
//!   match the expected identity are rejected, never adopted or deleted.
//! - **Key hygiene**: the WireGuard private key is stored once per host
//!   (0600, atomic create), referenced by path, never passed through argv,
//!   never serialized into plans, ownership state, or errors.
//!
//! The crate is synchronous and runtime-agnostic; hosts wrap calls in their
//! own async runtimes (for example via `spawn_blocking`).
//!
//! Provenance: clean Kubedo implementation written from the public Kubedo
//! decision documents (O3K ADR-0186/SPEC-0049, CHV ADR-021); no third-party
//! source was translated or copied.

pub mod config;
pub mod error;
pub mod keys;
pub mod naming;
pub mod ownership;
pub mod provider;
pub mod runner;

pub use config::FabricLinuxConfig;
pub use error::FabricError;
pub use keys::{derive_public_key, ensure_private_key};
pub use naming::Names;
pub use ownership::{FabricOwnership, NetworkOwnership, PeerRecord};
pub use provider::{ApplyReport, FabricReport, LinuxFabricProvider};
pub use runner::{CommandOutput, FabricCommand, RealCommandRunner, RecordingRunner};
