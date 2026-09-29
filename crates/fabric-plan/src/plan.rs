//! The stretched-L2 fabric plan: the provider-facing input contract.
//!
//! A plan describes one (fabric domain, local host, network) triple: the
//! network's VNI binding, the local host's fabric transport address, the
//! tenant/fabric MTUs, and the bounded head-end replication peer set. The
//! control plane compiles it from canonical state; the provider realizes it
//! idempotently and fails closed on foreign state.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    MAX_MTU, MIN_TENANT_MTU, PlanError, VXLAN_OVERHEAD_BYTES, Vni,
    identity::{FabricPeer, PublicKey, UnderlayEndpoint, validate_identifier},
};

/// One network's stretched-L2 realization intent for one host.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StretchedL2Plan {
    /// Fabric domain this plan belongs to.
    pub fabric_domain_id: String,
    /// The local host executing this plan.
    pub local_host_id: String,
    /// The local host's fabric transport address (inside the WireGuard
    /// fabric). Provider/operator infrastructure addressing, never tenant.
    pub local_transport_ip: Ipv4Addr,
    /// The tenant network being realized.
    pub network_id: String,
    /// The network's current VNI binding.
    pub vni: Vni,
    /// Generation of the VNI binding this plan was compiled against.
    pub binding_generation: u64,
    /// MTU of the tenant L2 segment (applied to the VXLAN device and the
    /// consumer-facing attachment).
    pub tenant_mtu: u32,
    /// MTU of the encrypted fabric transport (WireGuard) layer.
    pub fabric_mtu: u32,
    /// Bounded head-end replication set: enrolled hosts that currently host
    /// at least one endpoint of this network. Derived only from accepted
    /// control-plane placement state.
    pub peers: Vec<FabricPeer>,
    /// Monotonic plan generation for fencing stale plans.
    pub plan_generation: u64,
}

impl StretchedL2Plan {
    /// Validate the plan against the fabric contract.
    pub fn validate(&self) -> Result<(), PlanError> {
        validate_identifier("fabric_domain_id", &self.fabric_domain_id)?;
        validate_identifier("local_host_id", &self.local_host_id)?;
        validate_identifier("network_id", &self.network_id)?;

        if self.local_transport_ip.is_unspecified() {
            return Err(PlanError::Invalid(
                "local transport IP must not be unspecified".to_string(),
            ));
        }

        if self.binding_generation == 0 {
            return Err(PlanError::Invalid(
                "binding_generation must be nonzero".to_string(),
            ));
        }
        if self.plan_generation == 0 {
            return Err(PlanError::Invalid(
                "plan_generation must be nonzero".to_string(),
            ));
        }

        if self.tenant_mtu < MIN_TENANT_MTU || self.tenant_mtu > MAX_MTU {
            return Err(PlanError::Invalid(format!(
                "tenant MTU {} outside {}..={MAX_MTU}",
                self.tenant_mtu, MIN_TENANT_MTU
            )));
        }
        if self.fabric_mtu > MAX_MTU {
            return Err(PlanError::Invalid(format!(
                "fabric MTU {} above {MAX_MTU}",
                self.fabric_mtu
            )));
        }
        if self.tenant_mtu + VXLAN_OVERHEAD_BYTES > self.fabric_mtu {
            return Err(PlanError::Invalid(format!(
                "tenant MTU {} + {VXLAN_OVERHEAD_BYTES} exceeds fabric MTU {}",
                self.tenant_mtu, self.fabric_mtu
            )));
        }

        let mut host_ids = BTreeSet::new();
        let mut transport_ips = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for peer in &self.peers {
            peer.validate()?;
            if peer.host_id == self.local_host_id {
                return Err(PlanError::Invalid(format!(
                    "peer list must not contain the local host {}",
                    self.local_host_id
                )));
            }
            if peer.fabric_transport_ip == self.local_transport_ip {
                return Err(PlanError::Invalid(
                    "peer list must not contain the local transport IP".to_string(),
                ));
            }
            if !host_ids.insert(peer.host_id.clone()) {
                return Err(PlanError::Invalid(
                    "peer list contains a duplicate host_id".to_string(),
                ));
            }
            if !transport_ips.insert(peer.fabric_transport_ip) {
                return Err(PlanError::Invalid(
                    "peer list contains a duplicate fabric transport IP".to_string(),
                ));
            }
            // Peers are keyed by public key during realization; a duplicate
            // would silently drop one peer from the WireGuard set.
            if !public_keys.insert(peer.public_key.clone()) {
                return Err(PlanError::Invalid(
                    "peer list contains a duplicate public key".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// The head-end replication destination set (peer transport IPs).
    pub fn flood_list(&self) -> BTreeSet<Ipv4Addr> {
        self.peers
            .iter()
            .map(|peer| peer.fabric_transport_ip)
            .collect()
    }

    /// A stable content fingerprint (SHA-256 over the canonical JSON
    /// serialization) for idempotent replay detection.
    pub fn fingerprint_sha256(&self) -> Result<String, PlanError> {
        let encoded =
            serde_json::to_string(self).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        let digest = Sha256::digest(encoded.as_bytes());
        Ok(hex(&digest))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Convenience test/validation helper exported for consumers building plans.
pub fn validate_endpoint(raw: &str) -> Result<UnderlayEndpoint, PlanError> {
    UnderlayEndpoint::parse(raw)
}

/// Convenience helper: build a [`PublicKey`] with validation.
pub fn validate_public_key(raw: &str) -> Result<PublicKey, PlanError> {
    PublicKey::new(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=";
    const KEY_B: &str = "K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kN=";

    fn peer_with_key(host: &str, ip: [u8; 4], key: &str) -> Result<FabricPeer, PlanError> {
        Ok(FabricPeer {
            host_id: host.to_string(),
            public_key: PublicKey::new(key)?,
            underlay_endpoint: UnderlayEndpoint::parse("198.51.100.1:65001")?,
            fabric_transport_ip: Ipv4Addr::from(ip),
        })
    }

    fn peer(host: &str, ip: [u8; 4]) -> Result<FabricPeer, PlanError> {
        peer_with_key(host, ip, KEY_A)
    }

    fn plan() -> Result<StretchedL2Plan, PlanError> {
        Ok(StretchedL2Plan {
            fabric_domain_id: "fab-1".to_string(),
            local_host_id: "host-01".to_string(),
            local_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            network_id: "net-a".to_string(),
            vni: Vni::new(100)?,
            binding_generation: 1,
            tenant_mtu: 1370,
            fabric_mtu: 1420,
            peers: vec![peer("host-02", [198, 18, 0, 2])?],
            plan_generation: 1,
        })
    }

    #[test]
    fn valid_plan_passes() -> Result<(), PlanError> {
        plan()?.validate()?;
        Ok(())
    }

    #[test]
    fn mtu_must_leave_room_for_vxlan() -> Result<(), PlanError> {
        let mut p = plan()?;
        p.tenant_mtu = p.fabric_mtu;
        assert!(p.validate().is_err());
        p.tenant_mtu = p.fabric_mtu - VXLAN_OVERHEAD_BYTES;
        p.validate()?;
        Ok(())
    }

    #[test]
    fn rejects_local_host_in_peer_list() -> Result<(), PlanError> {
        let mut p = plan()?;
        p.peers.push(peer("host-01", [198, 18, 0, 9])?);
        assert!(p.validate().is_err());
        Ok(())
    }

    #[test]
    fn rejects_duplicate_transport_ips() -> Result<(), PlanError> {
        let mut p = plan()?;
        // Distinct keys: only the transport IP is duplicated.
        p.peers
            .push(peer_with_key("host-03", [198, 18, 0, 2], KEY_B)?);
        assert!(p.validate().is_err());
        Ok(())
    }

    #[test]
    fn rejects_duplicate_public_keys() -> Result<(), PlanError> {
        let mut p = plan()?;
        // Distinct host and transport IP: only the public key is duplicated.
        // Realization keys peers by public key, so a duplicate would
        // silently drop a peer from the WireGuard set.
        p.peers.push(peer("host-03", [198, 18, 0, 3])?);
        assert!(p.validate().is_err());
        Ok(())
    }

    #[test]
    fn plan_json_with_unknown_field_is_rejected() -> Result<(), PlanError> {
        let p = plan()?;
        let mut value =
            serde_json::to_value(&p).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        value["surprise"] = serde_json::json!(true);
        let raw = value.to_string();
        // Sanity: the unmodified serialization still round-trips.
        let clean = serde_json::to_string(&p).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        let round: StretchedL2Plan =
            serde_json::from_str(&clean).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        assert!(round == p, "plan must round-trip through JSON");
        assert!(
            serde_json::from_str::<StretchedL2Plan>(&raw).is_err(),
            "plans with unknown fields must fail to deserialize"
        );
        Ok(())
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive() -> Result<(), PlanError> {
        let p1 = plan()?;
        let p2 = plan()?;
        assert_eq!(p1.fingerprint_sha256()?, p2.fingerprint_sha256()?);
        let mut p3 = p1.clone();
        p3.peers.clear();
        assert_ne!(p1.fingerprint_sha256()?, p3.fingerprint_sha256()?);
        Ok(())
    }

    #[test]
    fn flood_list_contains_peer_ips() -> Result<(), PlanError> {
        let p = plan()?;
        assert_eq!(
            p.flood_list(),
            BTreeSet::from([Ipv4Addr::new(198, 18, 0, 2)])
        );
        Ok(())
    }

    /// Review finding S1, plan level: a plan deserialized from JSON with a
    /// peer endpoint carrying an empty host or port 0 must fail
    /// `validate()` — previously only unknown *fields* were rejected at
    /// deserialization, endpoint *values* slipped through to the
    /// WireGuard command layer after the plan was journaled. Fails
    /// against pre-fix code.
    #[test]
    fn deserialized_plan_with_invalid_endpoint_values_fails_validation() -> Result<(), PlanError> {
        let raw = plan()?;
        let mut value =
            serde_json::to_value(&raw).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        value["peers"][0]["underlay_endpoint"] =
            serde_json::json!({"host": "198.51.100.1", "port": 0});
        let deserialized: StretchedL2Plan =
            serde_json::from_value(value).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        assert!(
            deserialized.validate().is_err(),
            "a deserialized plan with a port-0 endpoint must fail validation"
        );
        Ok(())
    }
}
