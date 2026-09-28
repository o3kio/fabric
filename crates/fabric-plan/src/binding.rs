//! Durable network-to-VNI binding records.
//!
//! The binding registry itself (allocation, collision prevention, reuse
//! fencing) is control-plane owned. This crate only defines the portable
//! record shape and its invariants so both control planes and providers agree
//! on what a binding means.

use serde::{Deserialize, Serialize};

use crate::{PlanError, Vni};

/// Lifecycle state of a binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    /// The binding is current and may be realized.
    Active,
    /// The binding is being withdrawn; owned tunnel state must be proven
    /// absent before the VNI may be reused.
    Withdrawn,
}

/// A durable mapping from one network in one fabric domain to a VNI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricVniBinding {
    pub fabric_domain_id: String,
    pub network_id: String,
    pub vni: Vni,
    pub binding_generation: u64,
    pub state: BindingState,
}

impl FabricVniBinding {
    /// Validate the binding record.
    pub fn validate(&self) -> Result<(), PlanError> {
        crate::identity::validate_identifier("fabric_domain_id", &self.fabric_domain_id)?;
        crate::identity::validate_identifier("network_id", &self.network_id)?;
        if self.binding_generation == 0 {
            return Err(PlanError::Invalid(
                "binding_generation must be nonzero".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_generations() -> Result<(), PlanError> {
        let binding = FabricVniBinding {
            fabric_domain_id: "fab-1".to_string(),
            network_id: "net-1".to_string(),
            vni: Vni::new(100)?,
            binding_generation: 1,
            state: BindingState::Active,
        };
        binding.validate()?;
        let mut bad = binding;
        bad.binding_generation = 0;
        assert!(bad.validate().is_err());
        Ok(())
    }
}
