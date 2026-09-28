//! Deterministic, bounded interface and namespace naming.
//!
//! Generated names use an FNV-1a 32-bit hash suffix (8 hex characters) of the
//! network identity. With a prefix of at most 4 characters every generated
//! link name fits IFNAMSIZ (15 bytes including the terminator).
//!
//! Names are *hints* for operators, never ownership proof; ownership is
//! recorded durably in the ownership journal and re-verified against observed
//! kernel state before every mutation.

use crate::error::FabricError;

/// FNV-1a 32-bit offset basis.
const FNV_OFFSET: u32 = 0x811c_9dc5;
/// FNV-1a 32-bit prime.
const FNV_PRIME: u32 = 0x0100_0193;

/// Compute the FNV-1a 32-bit hash of `input`.
pub fn fnv1a32(input: &str) -> u32 {
    let mut hash = FNV_OFFSET;
    for byte in input.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Deterministic name builder for one fabric installation.
#[derive(Clone, Debug)]
pub struct Names {
    prefix: String,
}

impl Names {
    /// Build names for a validated prefix (1..=4 ASCII chars).
    pub fn new(prefix: &str) -> Result<Self, FabricError> {
        if prefix.is_empty() || prefix.len() > 4 {
            return Err(FabricError::Invalid(
                "name prefix must be 1..=4 characters".to_string(),
            ));
        }
        Ok(Self {
            prefix: prefix.to_string(),
        })
    }

    /// The shared fabric network namespace.
    pub fn fabric_namespace(&self) -> String {
        format!("{}-fabric", self.prefix)
    }

    /// The host's single WireGuard interface.
    pub fn wireguard_interface(&self) -> String {
        format!("{}-wg", self.prefix)
    }

    /// The host-side underlay veth.
    pub fn host_underlay_veth(&self) -> String {
        format!("{}-u", self.prefix)
    }

    /// The fabric-side underlay veth.
    pub fn fabric_underlay_veth(&self) -> String {
        format!("{}-v", self.prefix)
    }

    /// The per-network VXLAN device.
    pub fn vxlan(&self, network_id: &str) -> String {
        self.hashed("x", network_id)
    }

    /// The per-network fabric-side bridge.
    pub fn fabric_bridge(&self, network_id: &str) -> String {
        self.hashed("b", network_id)
    }

    /// The per-network fabric-side attachment veth (bridge port).
    pub fn fabric_port_veth(&self, network_id: &str) -> String {
        self.hashed("p", network_id)
    }

    /// The per-network consumer-side attachment veth. The host (O3K realm
    /// bridge, CHV tenant bridge) enslaves this to its own tenant bridge.
    pub fn consumer_port_veth(&self, network_id: &str) -> String {
        self.hashed("c", network_id)
    }

    fn hashed(&self, kind: &str, network_id: &str) -> String {
        format!("{}-{}-{:08x}", self.prefix, kind, fnv1a32(network_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_fit_ifnamesiz() -> Result<(), FabricError> {
        let names = Names::new("o3k")?;
        for name in [
            names.vxlan("network-with-a-long-id"),
            names.fabric_bridge("network-with-a-long-id"),
            names.fabric_port_veth("network-with-a-long-id"),
            names.consumer_port_veth("network-with-a-long-id"),
            names.wireguard_interface(),
            names.host_underlay_veth(),
        ] {
            assert!(name.len() < 16, "{name} exceeds IFNAMSIZ");
        }
        Ok(())
    }

    #[test]
    fn names_are_deterministic() -> Result<(), FabricError> {
        let names = Names::new("chv")?;
        assert_eq!(names.vxlan("net-1"), names.vxlan("net-1"));
        assert_ne!(names.vxlan("net-1"), names.vxlan("net-2"));
        Ok(())
    }
}
