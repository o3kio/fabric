//! Shared conformance kit for the Kubedo stretched-L2 edge fabric.
//!
//! This crate is the anti-drift weapon between the fabric's consumers (O3K
//! `o3k-network`, CHV `chv-nwd`, and any future host): one executable suite
//! that proves a provider integration satisfies the fabric provider contract
//! (`contracts/fabric-provider-v1.md`).
//!
//! The portable suite runs against the reference in-memory fake kernel
//! ([`fabric_linux::RecordingRunner`]). The privileged multi-host gate
//! (three independent KVM/libvirt hosts, real WireGuard handshakes, cleartext
//! underlay capture, zero-leak cleanup) is planned as a separate harness in
//! this repository and is *not* created by this crate.
//!
//! Provenance: clean Kubedo implementation written from the public Kubedo
//! decision documents (O3K ADR-0186/SPEC-0049, CHV ADR-021).

pub mod suite;

pub use suite::{CaseResult, SuiteReport, run_suite};
