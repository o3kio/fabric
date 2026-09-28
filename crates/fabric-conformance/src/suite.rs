//! The portable conformance suite.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fabric_linux::{FabricError, FabricLinuxConfig, LinuxFabricProvider, RecordingRunner};
use fabric_plan::{PublicKey, StretchedL2Plan, UnderlayEndpoint, Vni};

/// One named conformance case result.
#[derive(Clone, Debug)]
pub struct CaseResult {
    pub name: String,
    pub passed: bool,
    pub detail: Option<String>,
}

/// The whole suite report.
#[derive(Clone, Debug, Default)]
pub struct SuiteReport {
    pub results: Vec<CaseResult>,
}

impl SuiteReport {
    /// True when every case passed.
    pub fn passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }
}

static CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct CaseEnv {
    root: PathBuf,
    runner: RecordingRunner,
    config: FabricLinuxConfig,
}

impl CaseEnv {
    fn new(tag: &str) -> Result<Self, FabricError> {
        let id = CASE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("fabric-conf-{tag}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        let config = FabricLinuxConfig::new(&root);
        Ok(Self {
            root,
            runner: RecordingRunner::new(),
            config,
        })
    }

    fn provider(&mut self) -> Result<LinuxFabricProvider<RecordingRunner>, FabricError> {
        LinuxFabricProvider::open(self.config.clone(), std::mem::take(&mut self.runner))
    }

    fn take_runner_back(&mut self, provider: LinuxFabricProvider<RecordingRunner>) {
        self.runner = provider.into_runner();
    }

    fn cleanup(&self) {
        let _unused = std::fs::remove_dir_all(&self.root);
    }
}

/// Run the portable conformance suite against the reference fake kernel.
pub fn run_suite() -> SuiteReport {
    let mut results = Vec::new();
    for (name, case) in cases() {
        let result = match case() {
            Ok(()) => CaseResult {
                name,
                passed: true,
                detail: None,
            },
            Err(e) => CaseResult {
                name,
                passed: false,
                detail: Some(e.to_string()),
            },
        };
        results.push(result);
    }
    SuiteReport { results }
}

type Case = fn() -> Result<(), FabricError>;

fn cases() -> Vec<(String, Case)> {
    vec![
        (
            "plan_validation_rejects_oversize_tenant_mtu".to_string(),
            case_mtu_validation,
        ),
        (
            "apply_creates_expected_kernel_objects".to_string(),
            case_apply_creates,
        ),
        (
            "replay_of_unchanged_plan_is_idempotent".to_string(),
            case_replay_idempotent,
        ),
        (
            "flood_entries_scoped_to_plan_peers".to_string(),
            case_flood_scoping,
        ),
        (
            "peer_removal_after_network_removal".to_string(),
            case_peer_removal,
        ),
        (
            "foreign_vxlan_state_fails_closed".to_string(),
            case_foreign_state,
        ),
        (
            "teardown_removes_objects_and_keeps_key".to_string(),
            case_teardown,
        ),
        (
            "private_key_never_in_argv_or_journals".to_string(),
            case_key_hygiene,
        ),
        (
            "fabric_removal_requires_no_networks".to_string(),
            case_fabric_removal,
        ),
    ]
}

fn test_key() -> Result<PublicKey, fabric_plan::PlanError> {
    PublicKey::new("K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=")
}

fn plan_for(
    vni: u32,
    peers: &[(&str, [u8; 4])],
) -> Result<StretchedL2Plan, fabric_plan::PlanError> {
    let key = test_key()?;
    let endpoint = UnderlayEndpoint::parse("198.51.100.10:65001")?;
    let peers = peers
        .iter()
        .map(|(host, ip)| fabric_plan::FabricPeer {
            host_id: (*host).to_string(),
            public_key: key.clone(),
            underlay_endpoint: endpoint.clone(),
            fabric_transport_ip: Ipv4Addr::from(*ip),
        })
        .collect();
    Ok(StretchedL2Plan {
        fabric_domain_id: "fab-1".to_string(),
        local_host_id: "host-01".to_string(),
        local_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
        network_id: format!("net-{vni}"),
        vni: Vni::new(vni)?,
        binding_generation: 1,
        tenant_mtu: 1370,
        fabric_mtu: 1420,
        peers,
        plan_generation: 1,
    })
}

fn case_mtu_validation() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("mtu")?;
    let mut plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    plan.tenant_mtu = plan.fabric_mtu;
    let mut provider = env.provider()?;
    let err = provider.apply_plan(&plan);
    if err.is_ok() {
        env.cleanup();
        return Err(FabricError::Invalid(
            "oversize tenant MTU plan was accepted".to_string(),
        ));
    }
    env.take_runner_back(provider);
    env.cleanup();
    Ok(())
}

fn case_apply_creates() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("apply")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    let report = provider.apply_plan(&plan)?;
    let failed = !report.created_fabric || !report.created_network;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns_missing = !provider.runner().has_netns(&names.fabric_namespace());
    let vxlan_missing = !provider.runner().has_link(&names.vxlan(&plan.network_id));
    env.take_runner_back(provider);
    env.cleanup();
    if failed {
        return Err(FabricError::Invalid(
            "first apply must create the fabric and network objects".to_string(),
        ));
    }
    if ns_missing {
        return Err(FabricError::Invalid("fabric namespace missing".to_string()));
    }
    if vxlan_missing {
        return Err(FabricError::Invalid("vxlan device missing".to_string()));
    }
    Ok(())
}

fn case_replay_idempotent() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("replay")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;

    // Re-open from the same state root (simulates daemon restart) and replay.
    env.take_runner_back(provider);
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;

    // Peer reconfiguration is allowed (wg set is idempotent); object
    // creation must not repeat.
    let mutations = env.runner.mutating_calls();
    let created_again = mutations.iter().any(|call| {
        call.args.iter().any(|arg| arg == "add") && call.joined().contains("type vxlan")
    }) || mutations.iter().any(|call| {
        call.joined().contains("netns add") || call.joined().contains("type wireguard")
    });
    env.take_runner_back(provider);
    env.cleanup();
    if created_again {
        return Err(FabricError::Invalid(
            "replay recreated existing objects".to_string(),
        ));
    }
    Ok(())
}

fn case_flood_scoping() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("flood")?;
    let plan = plan_for(
        100,
        &[("host-02", [198, 18, 0, 2]), ("host-03", [198, 18, 0, 3])],
    )
    .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;

    let flood_entries: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .filter(|c| c.program == "ip" && c.joined().contains("bridge fdb replace"))
        .map(|c| c.joined())
        .collect();
    env.take_runner_back(provider);
    env.cleanup();
    if flood_entries.len() != 2 {
        return Err(FabricError::Invalid(format!(
            "expected 2 HER flood entries, saw {flood_entries:?}"
        )));
    }
    if !flood_entries
        .iter()
        .all(|c| c.contains("00:00:00:00:00:00"))
    {
        return Err(FabricError::Invalid(
            "HER entries must use the all-zeros BUM address".to_string(),
        ));
    }
    if !flood_entries.iter().any(|c| c.contains("dst 198.18.0.2"))
        || !flood_entries.iter().any(|c| c.contains("dst 198.18.0.3"))
    {
        return Err(FabricError::Invalid(
            "HER entries must target exactly the plan peers".to_string(),
        ));
    }
    Ok(())
}

fn case_peer_removal() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("peers")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let network_id = plan.network_id.clone();
    provider.remove_network(&network_id)?;

    let peer_removed = provider
        .runner()
        .calls()
        .iter()
        .any(|c| c.joined().contains("peer") && c.joined().contains("remove"));
    env.take_runner_back(provider);
    env.cleanup();
    if !peer_removed {
        return Err(FabricError::Invalid(
            "removing the last network must withdraw the WireGuard peer".to_string(),
        ));
    }
    Ok(())
}

fn case_foreign_state() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("foreign")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // A different plan (different VNI) targeting the same network id now
    // observes a VXLAN device with a foreign VNI: must fail closed.
    let mut foreign = plan_for(200, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    foreign.network_id = plan.network_id.clone();
    let mut provider = env.provider()?;
    let result = provider.apply_plan(&foreign);
    env.take_runner_back(provider);
    env.cleanup();
    match result {
        Err(FabricError::ForeignState { .. }) => Ok(()),
        Err(other) => Err(other),
        Ok(_) => Err(FabricError::Invalid(
            "foreign VXLAN state was adopted instead of rejected".to_string(),
        )),
    }
}

fn case_teardown() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("teardown")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let network_id = plan.network_id.clone();
    provider.remove_network(&network_id)?;

    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let key_exists = env.config.private_key_path().exists();
    let vxlan_gone = !provider.runner().has_link(&names.vxlan(&network_id));
    let ownership_empty = provider.ownership().networks.is_empty();
    env.take_runner_back(provider);
    env.cleanup();
    if !vxlan_gone {
        return Err(FabricError::Invalid("vxlan device leaked".to_string()));
    }
    if !ownership_empty {
        return Err(FabricError::Invalid("ownership entry leaked".to_string()));
    }
    if !key_exists {
        return Err(FabricError::Invalid(
            "WireGuard private key must survive network teardown".to_string(),
        ));
    }
    Ok(())
}

fn case_key_hygiene() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("keys")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // The fake genkey returns fixed material; assert it never appears in any
    // argv or persisted journal.
    let secret = "fabric-test-private-key-material";
    let leaked_in_argv = env
        .runner
        .calls()
        .iter()
        .any(|c| c.args.iter().any(|a| a.contains(secret)));
    let ownership_raw = std::fs::read_to_string(env.config.ownership_path())?;
    let plan_raw = std::fs::read_to_string(env.config.plan_path(&plan.network_id))?;
    env.cleanup();
    if leaked_in_argv {
        return Err(FabricError::Invalid(
            "private key material leaked into command argv".to_string(),
        ));
    }
    if ownership_raw.contains(secret) || plan_raw.contains(secret) {
        return Err(FabricError::Invalid(
            "private key material leaked into a persisted journal".to_string(),
        ));
    }
    Ok(())
}

fn case_fabric_removal() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("fabric-rm")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;

    // With a live network, fabric removal must be refused.
    if provider.remove_fabric_if_unused()? {
        env.take_runner_back(provider);
        env.cleanup();
        return Err(FabricError::Invalid(
            "fabric removal succeeded while a network is live".to_string(),
        ));
    }
    let network_id = plan.network_id.clone();
    provider.remove_network(&network_id)?;
    if !provider.remove_fabric_if_unused()? {
        env.take_runner_back(provider);
        env.cleanup();
        return Err(FabricError::Invalid(
            "fabric removal failed with no live networks".to_string(),
        ));
    }
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns_gone = !provider.runner().has_netns(&names.fabric_namespace());
    let key_kept = env.config.private_key_path().exists();
    env.take_runner_back(provider);
    env.cleanup();
    if !ns_gone {
        return Err(FabricError::Invalid("fabric namespace leaked".to_string()));
    }
    if !key_kept {
        return Err(FabricError::Invalid(
            "WireGuard private key must survive fabric teardown".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_suite_passes() {
        let report = run_suite();
        for case in &report.results {
            assert!(case.passed, "case {} failed: {:?}", case.name, case.detail);
        }
        assert!(report.passed());
    }
}
