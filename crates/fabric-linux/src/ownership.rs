//! Durable ownership journal.
//!
//! The journal records what the provider owns (per-network kernel object
//! names, flood lists, WireGuard peer sets) and the plan fingerprints they
//! were realized from. It is written atomically (temp file + rename) and is
//! the reconciliation input after crashes: durable desired state is compared
//! against observed kernel state, and foreign state fails closed.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::FabricError;

/// Ownership journal format version.
const STATE_VERSION: u32 = 1;

/// A WireGuard peer record owned by this host's fabric.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub host_id: String,
    pub public_key: String,
    pub underlay_endpoint: String,
    pub fabric_transport_ip: Ipv4Addr,
}

/// Per-network owned state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkOwnership {
    /// Fingerprint of the last applied plan.
    pub plan_fingerprint: String,
    /// The realized VNI (used to detect foreign VXLAN state).
    pub vni: u32,
    /// Owned kernel object names (vxlan, bridge, veths).
    pub vxlan_name: String,
    pub bridge_name: String,
    pub fabric_port_veth: String,
    pub consumer_port_veth: String,
    /// Current head-end replication destinations.
    pub flood_peers: Vec<Ipv4Addr>,
}

/// The whole ownership journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricOwnership {
    /// Journal format version.
    pub state_version: u32,
    /// True once the shared fabric (netns, WireGuard, underlay veths) has
    /// been configured on this host.
    pub fabric_configured: bool,
    /// WireGuard peers currently configured (union over live plans).
    pub peers: Vec<PeerRecord>,
    /// Per-network owned state, keyed by network id.
    pub networks: BTreeMap<String, NetworkOwnership>,
}

impl Default for FabricOwnership {
    fn default() -> Self {
        Self {
            state_version: STATE_VERSION,
            fabric_configured: false,
            peers: Vec::new(),
            networks: BTreeMap::new(),
        }
    }
}

impl FabricOwnership {
    /// Load the journal from `path`, or the default when absent.
    pub fn load_or_default(path: &Path) -> Result<Self, FabricError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)?;
        let loaded: Self = serde_json::from_str(&raw).map_err(|e| {
            FabricError::Ownership(format!("journal at {} is corrupt: {e}", path.display()))
        })?;
        if loaded.state_version != STATE_VERSION {
            return Err(FabricError::Ownership(format!(
                "journal at {} has unsupported version {}",
                path.display(),
                loaded.state_version
            )));
        }
        Ok(loaded)
    }

    /// Atomically save the journal to `path`.
    pub fn save(&self, path: &Path) -> Result<(), FabricError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_string_pretty(self)
            .map_err(|e| FabricError::Ownership(format!("journal serialization failed: {e}")))?;
        atomic_write(path, &encoded)?;
        Ok(())
    }
}

/// Atomic write with default file mode (temp file + rename).
pub(crate) fn atomic_write(path: &Path, contents: &str) -> Result<(), FabricError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_disk() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "fabric-own-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&root)?;
        let path = root.join("ownership.json");

        let ownership = FabricOwnership::default();
        ownership.save(&path)?;
        let loaded = FabricOwnership::load_or_default(&path)?;
        assert_eq!(loaded, ownership);
        assert!(!path.join("nonexistent").exists());

        let _unused = fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn missing_journal_is_default() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join("fabric-own-absent.json");
        let loaded = FabricOwnership::load_or_default(&path)?;
        assert_eq!(loaded, FabricOwnership::default());
        Ok(())
    }
}
