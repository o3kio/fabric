//! Host and peer identities for the shared WireGuard fabric.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::PlanError;

/// A WireGuard public key.
///
/// Public keys are safe to distribute through authenticated control-plane
/// state. The [`fmt::Debug`] implementation is intentionally terse so key
/// material never renders verbosely in logs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(String);

impl PublicKey {
    /// Wrap a base64-encoded WireGuard public key.
    pub fn new(key: impl Into<String>) -> Result<Self, PlanError> {
        let key = key.into();
        if key.trim().is_empty() {
            return Err(PlanError::Invalid(
                "public key must not be empty".to_string(),
            ));
        }
        if key.len() != 44 {
            return Err(PlanError::Invalid(format!(
                "public key must be 44 base64 characters, got {}",
                key.len()
            )));
        }
        Ok(Self(key))
    }

    /// The base64-encoded key material.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are not secret; rendering them aids operator debugging.
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.0)
    }
}

/// A `host:port` underlay endpoint advertised by an enrolled host.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderlayEndpoint {
    pub host: String,
    pub port: u16,
}

impl UnderlayEndpoint {
    /// Parse a `host:port` endpoint.
    pub fn parse(raw: &str) -> Result<Self, PlanError> {
        let (host, port) = raw
            .rsplit_once(':')
            .ok_or_else(|| PlanError::Invalid(format!("endpoint {raw:?} is not host:port")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| PlanError::Invalid(format!("endpoint {raw:?} has an invalid port")))?;
        let endpoint = Self {
            host: host.to_string(),
            port,
        };
        // Value rules live in `validate` (single source of truth) so the
        // serde deserialization path enforces exactly the same rules.
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validate the endpoint's values.
    ///
    /// `serde` deserialization does not run [`Self::parse`], so these value
    /// rules are re-checked wherever a deserialized endpoint enters a
    /// validated structure ([`FabricPeer::validate`],
    /// [`FabricHostIdentity::validate`]). Without this, a plan JSON with an
    /// empty host or port 0 passed `StretchedL2Plan::validate()` and only
    /// failed later at the WireGuard command layer, after the plan had
    /// been journaled (review finding S1).
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.host.is_empty() {
            return Err(PlanError::Invalid(
                "endpoint host must not be empty".to_string(),
            ));
        }
        if self
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(PlanError::Invalid(
                "endpoint host must not contain whitespace or control characters".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(PlanError::Invalid(
                "endpoint port must not be 0".to_string(),
            ));
        }
        Ok(())
    }
}

impl fmt::Display for UnderlayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl fmt::Debug for UnderlayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnderlayEndpoint({}:{})", self.host, self.port)
    }
}

/// The public fabric identity of one enrolled host.
///
/// This is provider/operator infrastructure identity, never tenant state. The
/// private key is deliberately not representable here: it stays host-local.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricHostIdentity {
    pub host_id: String,
    pub public_key: PublicKey,
    pub underlay_endpoint: UnderlayEndpoint,
    pub fabric_transport_ip: Ipv4Addr,
    pub fabric_generation: u64,
    pub underlay_mtu: u32,
    pub fabric_mtu: u32,
}

/// A remote peer participating in the fabric, as seen by one plan.
///
/// A plan's peer list is the bounded head-end replication set: exactly the
/// enrolled hosts that currently host at least one endpoint of the plan's
/// network, derived by the control plane from accepted placement state — never
/// from ARP, FDB observations, or traffic.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricPeer {
    pub host_id: String,
    pub public_key: PublicKey,
    pub underlay_endpoint: UnderlayEndpoint,
    pub fabric_transport_ip: Ipv4Addr,
}

impl FabricPeer {
    /// Validate this peer record.
    pub fn validate(&self) -> Result<(), PlanError> {
        validate_identifier("peer host_id", &self.host_id)?;
        // Endpoints can arrive deserialized (serde bypasses
        // `UnderlayEndpoint::parse`), so their value rules are re-checked
        // here — review finding S1.
        self.underlay_endpoint.validate()?;
        if self.fabric_transport_ip.is_unspecified() {
            return Err(PlanError::Invalid(
                "peer fabric transport IP must not be unspecified".to_string(),
            ));
        }
        Ok(())
    }
}

impl FabricHostIdentity {
    /// Validate this host identity.
    pub fn validate(&self) -> Result<(), PlanError> {
        validate_identifier("host_id", &self.host_id)?;
        // Same S1 rule as FabricPeer: deserialized endpoints are value-
        // validated here, not only at parse time.
        self.underlay_endpoint.validate()?;
        if self.fabric_transport_ip.is_unspecified() {
            return Err(PlanError::Invalid(
                "fabric transport IP must not be unspecified".to_string(),
            ));
        }
        if self.fabric_mtu < crate::MIN_TENANT_MTU + crate::VXLAN_OVERHEAD_BYTES {
            return Err(PlanError::Invalid(format!(
                "fabric MTU {} cannot carry the minimum tenant MTU",
                self.fabric_mtu
            )));
        }
        Ok(())
    }
}

/// Validate a plan-safe identifier: non-empty, bounded, filesystem-safe.
pub(crate) fn validate_identifier(field: &str, value: &str) -> Result<(), PlanError> {
    if value.is_empty() {
        return Err(PlanError::Invalid(format!("{field} must not be empty")));
    }
    if value.len() > 64 {
        return Err(PlanError::Invalid(format!(
            "{field} must be at most 64 characters"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(PlanError::Invalid(format!(
            "{field} must be ASCII alphanumeric, '-' or '_'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Result<PublicKey, PlanError> {
        PublicKey::new("K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=")
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        assert!(PublicKey::new("short").is_err());
        assert!(PublicKey::new("").is_err());
    }

    #[test]
    fn endpoint_parses_and_rejects() -> Result<(), PlanError> {
        let ep = UnderlayEndpoint::parse("203.0.113.7:65001")?;
        assert_eq!(ep.port, 65001);
        assert!(UnderlayEndpoint::parse("no-port").is_err());
        assert!(UnderlayEndpoint::parse("host:notaport").is_err());
        Ok(())
    }

    #[test]
    fn endpoint_rejects_empty_host_whitespace_and_port_zero() {
        assert!(UnderlayEndpoint::parse(":65001").is_err(), "empty host");
        assert!(
            UnderlayEndpoint::parse("bad host:65001").is_err(),
            "host with whitespace"
        );
        assert!(
            UnderlayEndpoint::parse("bad\nhost:65001").is_err(),
            "host with control characters"
        );
        assert!(UnderlayEndpoint::parse("host:0").is_err(), "port 0");
        assert!(UnderlayEndpoint::parse("203.0.113.7:1").is_ok());
    }

    /// Review finding S1: serde deserialization bypasses
    /// `UnderlayEndpoint::parse`, so a peer (or plan) built from JSON with
    /// an empty host, whitespace host, or port 0 must be caught by
    /// `FabricPeer::validate()` — previously it passed validation and only
    /// failed later at the WireGuard command layer, after the plan had
    /// been journaled. Every assertion below fails against pre-fix code.
    #[test]
    fn deserialized_endpoint_values_fail_peer_validation() -> Result<(), PlanError> {
        let base = serde_json::json!({
            "host_id": "host-02",
            "public_key": "K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=",
            "fabric_transport_ip": "198.18.0.2"
        });
        for (label, endpoint) in [
            ("empty host", serde_json::json!({"host": "", "port": 65001})),
            (
                "whitespace host",
                serde_json::json!({"host": "bad host", "port": 65001}),
            ),
            (
                "port 0",
                serde_json::json!({"host": "203.0.113.7", "port": 0}),
            ),
        ] {
            let mut value = base.clone();
            value["underlay_endpoint"] = endpoint;
            let peer: FabricPeer =
                serde_json::from_value(value).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
            assert!(
                peer.validate().is_err(),
                "{label}: a deserialized endpoint must fail validation, not the command layer"
            );
        }
        // Sanity: a well-formed deserialized endpoint still validates.
        let mut value = base;
        value["underlay_endpoint"] = serde_json::json!({"host": "203.0.113.7", "port": 65001});
        let peer: FabricPeer =
            serde_json::from_value(value).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        peer.validate()?;
        Ok(())
    }

    #[test]
    fn endpoint_json_with_unknown_field_is_rejected() -> Result<(), PlanError> {
        let ep = UnderlayEndpoint::parse("203.0.113.7:65001")?;
        let raw = format!(
            "{{\"host\":\"203.0.113.7\",\"port\":65001,\"surprise\":true,\"other\":{}}}",
            serde_json::to_string(&ep).map_err(|e| PlanError::Fingerprint(e.to_string()))?
        );
        assert!(
            serde_json::from_str::<UnderlayEndpoint>(&raw).is_err(),
            "endpoints with unknown fields must fail to deserialize"
        );
        Ok(())
    }

    #[test]
    fn peer_json_with_unknown_field_is_rejected() -> Result<(), PlanError> {
        let peer = FabricPeer {
            host_id: "host-02".to_string(),
            public_key: key()?,
            underlay_endpoint: UnderlayEndpoint::parse("203.0.113.7:65001")?,
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
        };
        let mut value =
            serde_json::to_value(&peer).map_err(|e| PlanError::Fingerprint(e.to_string()))?;
        value["surprise"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<FabricPeer>(value).is_err(),
            "peers with unknown fields must fail to deserialize"
        );
        Ok(())
    }

    #[test]
    fn identifiers_are_bounded() {
        assert!(validate_identifier("host_id", "host-01_x").is_ok());
        assert!(validate_identifier("host_id", "").is_err());
        assert!(validate_identifier("host_id", "bad/id").is_err());
        assert!(validate_identifier("host_id", &"x".repeat(65)).is_err());
    }

    #[test]
    fn host_identity_validates() -> Result<(), PlanError> {
        let id = FabricHostIdentity {
            host_id: "host-01".to_string(),
            public_key: key()?,
            underlay_endpoint: UnderlayEndpoint::parse("198.51.100.1:65001")?,
            fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            fabric_generation: 1,
            underlay_mtu: 1500,
            fabric_mtu: 1420,
        };
        id.validate()?;
        Ok(())
    }
}
