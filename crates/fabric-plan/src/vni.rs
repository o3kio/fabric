//! Validated 24-bit VXLAN VNI.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::PlanError;

/// Smallest valid VNI. VNIs are never tenant-supplied; they are allocated by
/// the control plane through a durable binding registry.
pub const MIN_VNI: u32 = 1;

/// Largest valid VNI (24-bit Geneve/VXLAN identifier space).
pub const MAX_VNI: u32 = 0x00ff_ffff;

/// A validated 24-bit VXLAN VNI.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Vni(u32);

impl Vni {
    /// Validate and wrap a raw VNI.
    pub fn new(raw: u32) -> Result<Self, PlanError> {
        if (MIN_VNI..=MAX_VNI).contains(&raw) {
            Ok(Self(raw))
        } else {
            Err(PlanError::Invalid(format!(
                "vni {raw} outside valid range {MIN_VNI}..={MAX_VNI}"
            )))
        }
    }

    /// The raw 24-bit value.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Vni {
    type Error = PlanError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        Self::new(raw)
    }
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        vni.0
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Vni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Vni({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_range_bounds() -> Result<(), PlanError> {
        assert_eq!(Vni::new(MIN_VNI)?.get(), MIN_VNI);
        assert_eq!(Vni::new(MAX_VNI)?.get(), MAX_VNI);
        assert!(Vni::new(0).is_err());
        assert!(Vni::new(MAX_VNI + 1).is_err());
        Ok(())
    }

    #[test]
    fn serde_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let vni = Vni::new(42)?;
        let encoded = serde_json::to_string(&vni)?;
        let decoded: Vni = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, vni);
        Ok(())
    }
}
