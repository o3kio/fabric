//! Shared conformance kit for the Kubedo stretched-L2 edge fabric.
//!
//! This crate is the anti-drift weapon between the fabric's consumers (O3K
//! `o3k-network`, CHV `chv-nwd`, and any future host): one suite that proves
//! the provider satisfies the fabric provider contract
//! (`contracts/fabric-provider-v1.md`).
//!
//! The suite runs against the reference in-memory fake kernel
//! ([`fabric_linux::RecordingRunner`]) and proves provider behavior
//! **modulo configuration** — it cannot exercise a consumer's plan
//! compilation, configuration choices (name prefix, ports), or integration
//! code; those are pinned by the design and change-control documents
//! (`docs/design.md`, `docs/change-control.md`). Consumers add this crate
//! as a dev-dependency at their pinned provider tag and run `run_suite()`
//! in their CI to re-verify that tag's behavior.
//!
//! The privileged multi-host evidence gate (three privileged host instances
//! — containers — on one physical kernel, real WireGuard handshakes,
//! cleartext underlay capture, zero-leak cleanup) is a separate harness in
//! this repository: `evidence/run-multinode.sh` (see `evidence/README.md`).
//!
//! Provenance: clean Kubedo implementation written from the public Kubedo
//! decision documents (O3K ADR-0186/SPEC-0049, CHV ADR-021).

pub mod suite;

pub use suite::{CaseResult, SuiteReport, run_suite};
