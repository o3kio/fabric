//! Portable plan types for the Kubedo stretched-L2 edge fabric.
//!
//! This crate defines the provider-facing input contract of the fabric: the
//! versioned, serde-serializable plan that a control plane (O3K `o3kd`, CHV
//! control plane, or any other host) compiles from its own canonical state and
//! hands to a fabric provider such as [`fabric_linux`]. It contains no I/O, no
//! kernel code, and no host-daemon assumptions.
//!
//! Semantics are normatively defined by:
//!
//! - O3K [ADR-0186](https://github.com/o3kio/o3k/blob/main/docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
//!   and [SPEC-0049](https://github.com/o3kio/o3k/blob/main/docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
//! - the [fabric provider contract](../../contracts/fabric-provider-v1.md) in
//!   this repository;
//! - CHV [ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)
//!   (aligned decision).
//!
//! Design summary: each tenant network is one literal L2 broadcast domain (a
//! stretched VLAN) across all enrolled hosts — per-network kernel VXLAN with
//! bounded head-end replication and kernel MAC learning, carried inside one
//! shared authenticated/encrypted WireGuard host fabric.
//!
//! Provenance: clean Kubedo implementation written from the public Kubedo
//! decision documents above; no third-party source was translated or copied.

pub mod binding;
pub mod error;
pub mod identity;
pub mod plan;
pub mod vni;

pub use binding::{BindingState, FabricVniBinding};
pub use error::PlanError;
pub use identity::{FabricHostIdentity, FabricPeer, PublicKey, UnderlayEndpoint};
pub use plan::StretchedL2Plan;
pub use vni::Vni;

/// VXLAN encapsulation overhead in bytes (outer UDP + VXLAN header).
pub const VXLAN_OVERHEAD_BYTES: u32 = 50;

/// WireGuard encapsulation overhead in bytes for IPv4 outer packets.
pub const WIREGUARD_OVERHEAD_BYTES_IPV4: u32 = 60;

/// WireGuard encapsulation overhead in bytes for IPv6 outer packets.
pub const WIREGUARD_OVERHEAD_BYTES_IPV6: u32 = 80;

/// Smallest tenant MTU the fabric will validate (minimal IPv4 MTU).
pub const MIN_TENANT_MTU: u32 = 576;

/// Largest MTU accepted on any layer.
pub const MAX_MTU: u32 = 65_535;

/// Derive the safe tenant MTU for a given fabric MTU.
///
/// `tenant = fabric - VXLAN_OVERHEAD`; the result is never below
/// [`MIN_TENANT_MTU`].
pub fn tenant_mtu_for(fabric_mtu: u32) -> u32 {
    fabric_mtu
        .saturating_sub(VXLAN_OVERHEAD_BYTES)
        .max(MIN_TENANT_MTU)
}
