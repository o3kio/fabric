//! Provider configuration.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::error::FabricError;

/// Default WireGuard listen port (O3K convention: off the common 51820).
pub const DEFAULT_WIREGUARD_PORT: u16 = 65_001;

/// Standard VXLAN destination port.
pub const DEFAULT_VXLAN_PORT: u16 = 4789;

/// Legacy (v0.1.0/v0.1.1) underlay attachment link-local pair (host side /
/// fabric side). The NAT-free underlay no longer creates any of this
/// machinery; the addresses survive only as the exact specification
/// operands of the tolerant legacy cleanup (`iptables -t nat -D ...`).
pub const DEFAULT_UNDERLAY_HOST_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 253, 1);
/// Legacy fabric-side underlay veth address (the DNAT target of the
/// v0.1.0/v0.1.1 rule the cleanup deletes).
pub const DEFAULT_UNDERLAY_FABRIC_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 253, 2);
/// The legacy underlay attachment /30 (the MASQUERADE source operand of
/// the v0.1.0/v0.1.1 rule the cleanup deletes).
pub const UNDERLAY_PREFIX: &str = "169.254.253.0/30";
/// The legacy underlay subnet signature (the /30's common prefix). Any
/// nat-table rule referencing it is legacy underlay residue — the
/// post-cleanup residue verification fails closed on it, because
/// residue NAT state on the WireGuard transport is exactly the
/// silent-death mode of the v0.1.2 postmortem.
pub const UNDERLAY_SUBNET_TOKEN: &str = "169.254.253";

/// Configuration for the Linux fabric provider.
#[derive(Clone, Debug)]
pub struct FabricLinuxConfig {
    /// Durable state root (ownership, plans, WireGuard private key).
    root: PathBuf,
    /// Interface-name prefix (`o3k`, `chv`, ...). Bounded to 4 characters so
    /// every generated name fits IFNAMSIZ (15 bytes).
    name_prefix: String,
    /// WireGuard listen port.
    wireguard_port: u16,
    /// VXLAN destination port (inside the tunnel).
    vxlan_port: u16,
}

impl FabricLinuxConfig {
    /// A configuration with Kubedo defaults rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            name_prefix: "o3k".to_string(),
            wireguard_port: DEFAULT_WIREGUARD_PORT,
            vxlan_port: DEFAULT_VXLAN_PORT,
        }
    }

    /// Override the interface-name prefix (CHV uses `chv`).
    pub fn with_name_prefix(mut self, prefix: &str) -> Self {
        self.name_prefix = prefix.to_string();
        self
    }

    /// Override the WireGuard listen port. A port conflict must fail closed
    /// at runtime; there is no random fallback.
    pub fn with_wireguard_port(mut self, port: u16) -> Self {
        self.wireguard_port = port;
        self
    }

    /// Override the VXLAN destination port.
    pub fn with_vxlan_port(mut self, port: u16) -> Self {
        self.vxlan_port = port;
        self
    }

    /// The durable state root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The interface-name prefix.
    pub fn name_prefix(&self) -> &str {
        &self.name_prefix
    }

    /// The WireGuard listen port.
    pub fn wireguard_port(&self) -> u16 {
        self.wireguard_port
    }

    /// The VXLAN destination port.
    pub fn vxlan_port(&self) -> u16 {
        self.vxlan_port
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), FabricError> {
        if !self.root.is_absolute() {
            return Err(FabricError::Invalid(
                "state root must be an absolute path".to_string(),
            ));
        }
        let prefix = &self.name_prefix;
        if prefix.is_empty() || prefix.len() > 4 {
            return Err(FabricError::Invalid(
                "name prefix must be 1..=4 characters to keep names within IFNAMSIZ".to_string(),
            ));
        }
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(FabricError::Invalid(
                "name prefix must be ASCII alphanumeric or '-'".to_string(),
            ));
        }
        if self.wireguard_port == 0 || self.vxlan_port == 0 {
            return Err(FabricError::Invalid("ports must be nonzero".to_string()));
        }
        if self.wireguard_port == self.vxlan_port {
            return Err(FabricError::Invalid(
                "WireGuard and VXLAN ports must differ".to_string(),
            ));
        }
        Ok(())
    }

    /// The ownership journal path.
    pub fn ownership_path(&self) -> PathBuf {
        self.root.join("ownership.json")
    }

    /// The plan journal directory.
    pub fn plans_dir(&self) -> PathBuf {
        self.root.join("plans")
    }

    /// The plan journal file for one network.
    pub fn plan_path(&self, network_id: &str) -> PathBuf {
        self.plans_dir().join(format!("{network_id}.json"))
    }

    /// The WireGuard private key path.
    pub fn private_key_path(&self) -> PathBuf {
        self.root.join("wireguard-private.key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_root() {
        let config = FabricLinuxConfig::new("relative/path");
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_long_prefix() {
        let config = FabricLinuxConfig::new("/var/lib/fabric").with_name_prefix("toolong");
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_equal_ports() {
        let config = FabricLinuxConfig::new("/var/lib/fabric")
            .with_wireguard_port(4789)
            .with_vxlan_port(4789);
        assert!(config.validate().is_err());
    }
}
