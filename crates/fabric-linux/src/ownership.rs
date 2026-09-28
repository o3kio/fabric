//! Durable ownership journal.
//!
//! The journal records what the provider owns (per-network kernel object
//! names, flood lists, WireGuard peer sets) and the plan fingerprints they
//! were realized from. It is written atomically (temp file + rename) and is
//! the reconciliation input after crashes: durable desired state is compared
//! against observed kernel state, and foreign state fails closed.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
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
    /// True once the shared fabric (netns, WireGuard) has been
    /// configured on this host.
    pub fabric_configured: bool,
    /// True while the fabric's WireGuard interface was created INSIDE
    /// the fabric namespace — the placement the v0.1.2 underlay
    /// redesign eliminated (a WireGuard interface's UDP socket binds
    /// in the namespace the interface was created in and never follows
    /// the interface; under the redesign the socket must live in the
    /// ROOT namespace, so the interface is created root-side and moved
    /// in). Only the unpushed round-3..5 code ever created the
    /// interface ns-side and set this flag; such journals (dev
    /// environments only) trigger the one-time full heal that deletes
    /// and re-creates the interface via the root-creation sequence.
    /// The flag is cleared once the replacement interface exists and
    /// is fully configured (key + listen port), so a heal interrupted
    /// anywhere simply re-runs. Journals written by v0.1.0/v0.1.1
    /// (field absent) and by the current code parse as `false` — the
    /// healthy value: their interfaces were already created in the
    /// root namespace and moved in. The field is additive, so READING
    /// is compatible in both directions (serde ignores the unknown
    /// field in old code, `serde(default)` fills the absent field in
    /// new code) — but round-trips through OLD code are not
    /// format-preserving: old code parsing a new journal silently
    /// strips the unknown flag on its next save.
    #[serde(default)]
    pub wireguard_born_in_fabric_ns: bool,
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
            wireguard_born_in_fabric_ns: false,
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

/// Crash-durable atomic write: temp file, fsync, rename, fsync parent.
///
/// The file is fsynced before the rename so the content is durable, and
/// the parent directory is fsynced after the rename so the rename itself
/// survives a power loss. A directory that cannot be fsynced surfaces as
/// an error (`File::open` + `sync_all` works for directories on Linux).
/// Used for both the ownership journal and the plan journal.
pub(crate) fn atomic_write(path: &Path, contents: &str) -> Result<(), FabricError> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
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
        // The temp file must not survive the atomic write.
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "no temp file may remain after save");

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

    #[test]
    fn legacy_journal_without_socket_placement_flag_parses()
    -> Result<(), Box<dyn std::error::Error>> {
        // A journal written before `wireguard_born_in_fabric_ns` existed
        // must keep parsing (as false — the healthy value under the
        // NAT-free underlay: v0.1.0/v0.1.1 created the wg root-side and
        // moved it in, so no heal is pending). The field is additive, so
        // READING is compatible in both directions — but not
        // round-tripping: old code reading a NEW journal parses it fine
        // and then strips the unknown flag on its next save. Never a
        // format break, though.
        let root = std::env::temp_dir().join(format!(
            "fabric-own-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&root)?;
        let path = root.join("ownership.json");
        fs::write(
            &path,
            "{\n  \"state_version\": 1,\n  \"fabric_configured\": true,\n  \
             \"peers\": [],\n  \"networks\": {}\n}\n",
        )?;
        let loaded = FabricOwnership::load_or_default(&path)?;
        assert!(loaded.fabric_configured);
        assert!(
            !loaded.wireguard_born_in_fabric_ns,
            "an old journal must parse as healthy (root-created wg placement, \
             no born-in-fabric-ns heal pending)"
        );
        // Round-trip rewrites the journal WITH the new field (serde's
        // default only affects deserialization), keeping the value.
        loaded.save(&path)?;
        let raw = fs::read_to_string(&path)?;
        assert!(
            raw.contains("wireguard_born_in_fabric_ns"),
            "a saved journal must carry the new field: {raw}"
        );
        let reloaded = FabricOwnership::load_or_default(&path)?;
        assert!(!reloaded.wireguard_born_in_fabric_ns);
        let _unused = fs::remove_dir_all(&root);
        Ok(())
    }
}
