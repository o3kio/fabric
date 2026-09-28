//! The portable conformance suite.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fabric_linux::{
    FabricCommand, FabricError, FabricLinuxConfig, LinuxFabricProvider, RecordingRunner,
};
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
            "wireguard_created_in_root_ns_and_moved_into_fabric_ns".to_string(),
            case_wireguard_created_in_root_and_moved,
        ),
        (
            "no_nat_rules_for_the_wireguard_transport".to_string(),
            case_no_nat_rules,
        ),
        (
            "legacy_underlay_rules_and_veth_removed_on_apply".to_string(),
            case_legacy_underlay_removed,
        ),
        (
            "born_in_fabric_ns_journal_heals_to_root_creation".to_string(),
            case_born_in_ns_journal_heals,
        ),
        (
            "runtime_socket_placement_heals_unflagged_ns_born_wg".to_string(),
            case_runtime_socket_placement_heals_unflagged_ns_born_wg,
        ),
        (
            "flood_list_has_no_duplicates_after_replays".to_string(),
            case_flood_no_duplicates_after_replays,
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
        (
            "wireguard_mtu_follows_max_fabric_mtu".to_string(),
            case_wireguard_mtu,
        ),
        (
            "teardown_after_restart_converges".to_string(),
            case_teardown_after_restart,
        ),
        (
            "reapply_heals_partial_state".to_string(),
            case_reapply_heals_partial_state,
        ),
        ("flood_list_shrinks".to_string(), case_flood_list_shrinks),
        (
            "foreign_state_rejects_prefix_vni".to_string(),
            case_foreign_state_rejects_prefix_vni,
        ),
        (
            "flood_duplicates_of_desired_dst_converge".to_string(),
            case_flood_duplicates_converge,
        ),
    ]
}

/// A deterministic, distinct, validly-shaped public key per host. Plans
/// reject duplicate public keys (peers are keyed by them), so multi-peer
/// cases must not share one key.
fn key_for(host: &str) -> Result<PublicKey, fabric_plan::PlanError> {
    let mut material = String::from("K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=");
    let seed = host.as_bytes().last().copied().unwrap_or(b'0');
    let letter = char::from(b'A' + (seed % 26));
    material.replace_range(42..=42, &letter.to_string());
    PublicKey::new(material)
}

fn plan_for(
    vni: u32,
    peers: &[(&str, [u8; 4])],
) -> Result<StretchedL2Plan, fabric_plan::PlanError> {
    let endpoint = UnderlayEndpoint::parse("198.51.100.10:65001")?;
    let mut built: Vec<fabric_plan::FabricPeer> = Vec::new();
    for (host, ip) in peers {
        built.push(fabric_plan::FabricPeer {
            host_id: (*host).to_string(),
            public_key: key_for(host)?,
            underlay_endpoint: endpoint.clone(),
            fabric_transport_ip: Ipv4Addr::from(*ip),
        });
    }
    Ok(StretchedL2Plan {
        fabric_domain_id: "fab-1".to_string(),
        local_host_id: "host-01".to_string(),
        local_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
        network_id: format!("net-{vni}"),
        vni: Vni::new(vni)?,
        binding_generation: 1,
        tenant_mtu: 1370,
        fabric_mtu: 1420,
        peers: built,
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
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let vxlan = names.vxlan(&plan.network_id);
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;

    // Re-open from the same state root (simulates daemon restart) and replay.
    env.take_runner_back(provider);
    let first_apply_mutations = env.runner.mutating_calls().len();
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // Peer reconfiguration is allowed (wg set is idempotent); object
    // creation must not repeat. Scoped to the REPLAY's mutations — the
    // first apply legitimately creates everything.
    let all_mutations = env.runner.mutating_calls();
    let replay_mutations = &all_mutations[first_apply_mutations..];
    let created_again = replay_mutations.iter().any(|call| {
        call.args.iter().any(|arg| arg == "add") && call.joined().contains("type vxlan")
    }) || replay_mutations.iter().any(|call| {
        call.joined().contains("netns add") || call.joined().contains("type wireguard")
    });
    // The fake kernel counts fdb instances: blind re-appending (the old
    // behavior) would leave duplicates after the replay.
    let flood_count = env
        .runner
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.2");
    env.cleanup();
    if created_again {
        return Err(FabricError::Invalid(
            "replay recreated existing objects".to_string(),
        ));
    }
    if flood_count != 1 {
        return Err(FabricError::Invalid(format!(
            "replay must not duplicate HER flood entries (saw {flood_count} instances)"
        )));
    }
    Ok(())
}

/// Regression case for the NAT-free underlay redesign: the WireGuard
/// interface MUST be created in the ROOT namespace and then moved into
/// the fabric namespace. A WireGuard interface's UDP socket binds in
/// the namespace the interface was CREATED in and never follows the
/// interface; under the NAT-free design that binding MUST live in the
/// root namespace, so outbound encrypted packets route via the host's
/// normal routing with dynamic source selection and inbound packets to
/// `<host-ip>:<port>` are delivered directly to the listener. Creating
/// the interface from inside the fabric namespace (the pre-fix
/// behavior) binds the socket there and strands the transport.
fn case_wireguard_created_in_root_and_moved() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("wg-root-create")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let wg = names.wireguard_interface();

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let joined: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .map(|call| call.joined())
        .collect();
    let created_in = provider.runner().link_created_in(&wg);
    let placed_in_ns = provider.runner().has_link_in(&wg, Some(&ns));
    env.take_runner_back(provider);
    env.cleanup();

    let root_add = format!("ip link add {wg} type wireguard");
    if !joined.iter().any(|line| line == &root_add) {
        return Err(FabricError::Invalid(format!(
            "the WireGuard interface must be created in the root namespace \
             (expected '{root_add}')"
        )));
    }
    let move_in = format!("ip link set {wg} netns {ns}");
    if !joined.iter().any(|line| line == &move_in) {
        return Err(FabricError::Invalid(format!(
            "the WireGuard interface must be moved into the fabric namespace \
             (expected '{move_in}')"
        )));
    }
    let ns_add = format!("ip netns exec {ns} ip link add {wg} type wireguard");
    if joined.iter().any(|line| line == &ns_add) {
        return Err(FabricError::Invalid(
            "the WireGuard interface must not be created inside the fabric namespace".to_string(),
        ));
    }
    if created_in != Some(None) {
        return Err(FabricError::Invalid(format!(
            "the wg socket must bind in the ROOT (creating) namespace, saw {created_in:?}"
        )));
    }
    if !placed_in_ns {
        return Err(FabricError::Invalid(
            "the wg link must live in the fabric namespace".to_string(),
        ));
    }
    Ok(())
}

/// The NAT-free underlay: the provider must not install ANY iptables
/// nat rule for the WireGuard transport. The v0.1.2 postmortem proved
/// two races any NAT state on the transport causes: (1) a DNAT rule
/// black-holes every NEW inbound flow when the socket lives in another
/// namespace, and (2) under simultaneous initiation the conntrack tuple
/// collision forces MASQUERADE to remap the source port, the peer roams
/// to the remapped port, and nothing steers return traffic back. The
/// only escape is for the transport to carry NO NAT state at all.
fn case_no_nat_rules() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("no-nat")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let appended: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .filter(|call| {
            call.program == "iptables" && call.args.iter().any(|arg| arg == "-A" || arg == "-I")
        })
        .map(|call| call.joined())
        .collect();
    let rules = provider.runner().iptables_rules();
    env.take_runner_back(provider);
    env.cleanup();
    if !appended.is_empty() {
        return Err(FabricError::Invalid(format!(
            "the provider must not append any iptables rule: {appended:?}"
        )));
    }
    if !rules.is_empty() {
        return Err(FabricError::Invalid(format!(
            "the kernel must hold no nat rules after apply: {rules:?}"
        )));
    }
    Ok(())
}

/// A host upgraded from v0.1.0/v0.1.1 (or the unpushed round-3..5
/// code) still carries the legacy underlay machinery: the DNAT +
/// MASQUERADE nat rules and the underlay veth pair. EVERY apply must
/// tolerantly delete them, with EXACTLY the rule specifications the old
/// code installed (`iptables -t nat -D` only matches spec-for-spec).
fn case_legacy_underlay_removed() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("legacy-clean")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let host_veth = names.host_underlay_veth();
    let fabric_veth = names.fabric_underlay_veth();
    let ns = names.fabric_namespace();

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // Seed the legacy machinery exactly as the old code left it: the
    // veth pair (fabric end moved into the namespace) and the two nat
    // rules, with the exact old specifications.
    let out = env.runner.run(
        "ip",
        &[
            "link",
            "add",
            host_veth.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            fabric_veth.as_str(),
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not seed the legacy veth pair: {}",
            out.stderr.trim()
        )));
    }
    let out = env
        .runner
        .run("ip", &["link", "set", fabric_veth.as_str(), "netns", &ns])?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not move the legacy fabric veth: {}",
            out.stderr.trim()
        )));
    }
    let masq: Vec<&str> = vec![
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        fabric_linux::config::UNDERLAY_PREFIX,
        "-j",
        "MASQUERADE",
    ];
    let dnat: Vec<&str> = vec![
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "!",
        "-i",
        host_veth.as_str(),
        "-p",
        "udp",
        "--dport",
        "65001",
        "-j",
        "DNAT",
        "--to-destination",
        "169.254.253.2",
    ];
    for rule in [&masq, &dnat] {
        let out = env.runner.run("iptables", rule)?;
        if !out.success {
            env.cleanup();
            return Err(FabricError::Command(format!(
                "could not seed the legacy nat rule: {}",
                out.stderr.trim()
            )));
        }
    }

    // A pure re-apply of the unchanged plan must remove it all.
    let before = env.runner.calls().len();
    let mut provider = env.provider()?;
    let report = provider.apply_plan(&plan)?;
    let slice: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .skip(before)
        .map(|call| call.joined())
        .collect();
    let rules_gone = provider.runner().iptables_rules().is_empty();
    let veth_gone = !provider.runner().has_link(host_veth.as_str())
        && !provider.runner().has_link(fabric_veth.as_str());
    env.take_runner_back(provider);
    env.cleanup();

    if report.created_fabric || report.created_network {
        return Err(FabricError::Invalid(
            "the cleanup re-apply must not re-create anything".to_string(),
        ));
    }
    let masq_del = format!(
        "iptables -t nat -D POSTROUTING -s {} -j MASQUERADE",
        fabric_linux::config::UNDERLAY_PREFIX
    );
    if !slice.iter().any(|line| line == &masq_del) {
        return Err(FabricError::Invalid(format!(
            "the MASQUERADE rule must be deleted with its exact spec: {masq_del}"
        )));
    }
    let dnat_del = format!(
        "iptables -t nat -D PREROUTING ! -i {host_veth} -p udp --dport 65001 \
         -j DNAT --to-destination 169.254.253.2"
    );
    if !slice.iter().any(|line| line == &dnat_del) {
        return Err(FabricError::Invalid(format!(
            "the DNAT rule must be deleted with its exact spec: {dnat_del}"
        )));
    }
    let veth_del = format!("ip link del {host_veth}");
    if !slice.iter().any(|line| line == &veth_del) {
        return Err(FabricError::Invalid(format!(
            "the underlay veth pair must be deleted via its root end: {veth_del}"
        )));
    }
    if !rules_gone {
        return Err(FabricError::Invalid(
            "no legacy nat rule may survive the apply".to_string(),
        ));
    }
    if !veth_gone {
        return Err(FabricError::Invalid(
            "neither end of the legacy underlay veth may survive".to_string(),
        ));
    }
    Ok(())
}

/// A deployment running the unpushed round-3..5 code presents the
/// one-time full-heal state: the wg link sits inside the fabric
/// namespace with its UDP socket bound THERE (a WireGuard socket binds
/// in its creating namespace for life), the journal's
/// `wireguard_born_in_fabric_ns` flag is set, and the legacy underlay
/// machinery is installed. Re-apply must heal to the root-creation
/// sequence: delete every recorded VXLAN before the ns-scoped wg, delete
/// the wg, clean up the legacy rules + veth, re-create the wg in the
/// ROOT namespace and move it in, force key/port, clear the flag — and
/// a further apply must be a pure no-op replay (modulo the unconditional
/// legacy cleanup deletions).
fn case_born_in_ns_journal_heals() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("born-heal")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let wg = names.wireguard_interface();
    let host_veth = names.host_underlay_veth();
    let fabric_veth = names.fabric_underlay_veth();
    let vxlan = names.vxlan(&plan.network_id);

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // Reproduce the round-3..5 residue: an ns-born wg, the heal-pending
    // flag, and the legacy underlay veth.
    let out = env
        .runner
        .run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not drop the moved wg for the case: {}",
            out.stderr.trim()
        )));
    }
    let out = env.runner.run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "link",
            "add",
            &wg,
            "type",
            "wireguard",
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not re-create the wg inside the namespace: {}",
            out.stderr.trim()
        )));
    }
    let mut ownership =
        fabric_linux::ownership::FabricOwnership::load_or_default(&env.config.ownership_path())?;
    ownership.wireguard_born_in_fabric_ns = true;
    ownership.save(&env.config.ownership_path())?;
    let out = env.runner.run(
        "ip",
        &[
            "link",
            "add",
            host_veth.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            fabric_veth.as_str(),
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not seed the legacy veth pair: {}",
            out.stderr.trim()
        )));
    }

    // Healing apply.
    let before = env.runner.calls().len();
    let mut provider = env.provider()?;
    let report = provider.apply_plan(&plan)?;
    let flag = provider.ownership().wireguard_born_in_fabric_ns;
    let heal_slice: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .skip(before)
        .map(|call| call.joined())
        .collect();
    let created_in = provider.runner().link_created_in(&wg);

    // Replay: a no-op modulo the unconditional legacy cleanup.
    let before_replay = provider.runner().calls().len();
    let replay_report = provider.apply_plan(&plan)?;
    let replay_slice: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .skip(before_replay)
        .map(|call| call.joined())
        .collect();
    let flood_after = provider
        .runner()
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.2");
    env.take_runner_back(provider);
    env.cleanup();

    if !report.created_fabric {
        return Err(FabricError::Invalid(
            "the heal must re-create the WireGuard interface".to_string(),
        ));
    }
    if flag {
        return Err(FabricError::Invalid(
            "a completed heal must clear the born-in-ns claim".to_string(),
        ));
    }
    let index_of = |needle: &str| heal_slice.iter().position(|line| line == needle);
    let (Some(vxlan_del_at), Some(wg_del_at)) = (
        index_of(&format!("ip netns exec {ns} ip link del {vxlan}")),
        index_of(&format!("ip netns exec {ns} ip link del {wg}")),
    ) else {
        return Err(FabricError::Invalid(
            "the heal must delete the recorded vxlan and the ns-scoped wg".to_string(),
        ));
    };
    if vxlan_del_at > wg_del_at {
        return Err(FabricError::Invalid(
            "the recorded vxlan must be deleted BEFORE the ns-scoped wg \
             (crash-window convergence)"
                .to_string(),
        ));
    }
    if !heal_slice
        .iter()
        .any(|line| line == &format!("ip link add {wg} type wireguard"))
    {
        return Err(FabricError::Invalid(
            "the heal must re-create the wg in the root namespace".to_string(),
        ));
    }
    if created_in != Some(None) {
        return Err(FabricError::Invalid(format!(
            "the healed wg socket must bind in the ROOT namespace, saw {created_in:?}"
        )));
    }
    if replay_report.created_fabric || replay_report.created_network {
        return Err(FabricError::Invalid(
            "post-heal replay must not re-create anything".to_string(),
        ));
    }
    if replay_slice.iter().any(|line| line.contains(" link add ")) {
        return Err(FabricError::Invalid(
            "post-heal replay must not create links".to_string(),
        ));
    }
    if replay_slice
        .iter()
        .any(|line| line == &format!("ip netns exec {ns} ip link del {wg}"))
    {
        return Err(FabricError::Invalid(
            "post-heal replay must not delete the wg".to_string(),
        ));
    }
    if replay_slice
        .iter()
        .any(|line| line == &format!("ip link del {wg}"))
    {
        return Err(FabricError::Invalid(
            "post-heal replay must not run the root-ns stray sweep".to_string(),
        ));
    }
    if !replay_slice
        .iter()
        .any(|line| line == &format!("ip link del {host_veth}"))
    {
        return Err(FabricError::Invalid(
            "the unconditional legacy veth cleanup must run on every replay".to_string(),
        ));
    }
    if flood_after != 1 {
        return Err(FabricError::Invalid(format!(
            "post-heal replays must not duplicate flood entries (saw {flood_after})"
        )));
    }
    Ok(())
}

/// MAJOR-1: the socket-placement check must be a RUNTIME observation,
/// not a journal inference. A deployment crashed between the ns-side wg
/// re-creation and the flag write (or a hand-repaired node) presents an
/// ns-born wg — its UDP socket bound in the fabric namespace — while
/// the journal's `wireguard_born_in_fabric_ns` flag reads FALSE and the
/// rest of the journal is ours. Re-apply must verify the placement from
/// the kernel (`ss -uln` in the fabric namespace) and heal to the
/// root-creation sequence. Pre-fix code trusted the journal flag alone
/// and passed green over the dead ns-bound socket.
fn case_runtime_socket_placement_heals_unflagged_ns_born_wg() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("runtime-heal")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let wg = names.wireguard_interface();

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // The crash residue: the wg is reborn INSIDE the namespace (socket
    // bound there) with a listen port configured from inside — the
    // observable listener — while the journal's born-in-ns flag stays
    // FALSE (the crash lost the flag write).
    let out = env
        .runner
        .run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not drop the moved wg for the case: {}",
            out.stderr.trim()
        )));
    }
    let out = env.runner.run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "link",
            "add",
            &wg,
            "type",
            "wireguard",
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not re-create the wg inside the namespace: {}",
            out.stderr.trim()
        )));
    }
    let port = env.config.wireguard_port().to_string();
    let out = env.runner.run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "wg",
            "set",
            &wg,
            "listen-port",
            port.as_str(),
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not configure the ns-born wg's listen port: {}",
            out.stderr.trim()
        )));
    }
    let flag_set = {
        let ownership = fabric_linux::ownership::FabricOwnership::load_or_default(
            &env.config.ownership_path(),
        )?;
        ownership.wireguard_born_in_fabric_ns
    };
    if flag_set {
        env.cleanup();
        return Err(FabricError::Invalid(
            "case seeding sanity: the born-in-ns flag must be FALSE here".to_string(),
        ));
    }

    // The healing apply, driven by the runtime observation.
    let before = env.runner.calls().len();
    let mut provider = env.provider()?;
    let report = provider.apply_plan(&plan)?;
    let flag = provider.ownership().wireguard_born_in_fabric_ns;
    let heal_slice: Vec<String> = provider
        .runner()
        .calls()
        .iter()
        .skip(before)
        .map(|call| call.joined())
        .collect();
    let created_in = provider.runner().link_created_in(&wg);
    env.take_runner_back(provider);
    env.cleanup();

    if !heal_slice
        .iter()
        .any(|line| line == &format!("ip netns exec {ns} ss -uln"))
    {
        return Err(FabricError::Invalid(
            "the apply must verify the socket placement from the kernel".to_string(),
        ));
    }
    if !report.created_fabric {
        return Err(FabricError::Invalid(
            "the runtime-verified heal must re-create the WireGuard interface".to_string(),
        ));
    }
    if flag {
        return Err(FabricError::Invalid(
            "a completed runtime-verified heal must clear the born-in-ns claim".to_string(),
        ));
    }
    if created_in != Some(None) {
        return Err(FabricError::Invalid(format!(
            "the healed wg socket must bind in the ROOT namespace, saw {created_in:?}"
        )));
    }
    Ok(())
}

/// The kernel does not guarantee `bridge fdb append` deduplication
/// (bridge(8); Launchpad #1531013 documented fleets accumulating
/// duplicate all-zeros flood entries), so the provider reconciles the
/// flood list against observed state instead of blindly re-appending.
/// After several applies, every desired destination must exist exactly
/// once — with a counting fake kernel, the old blind-append behavior
/// fails this case.
fn case_flood_no_duplicates_after_replays() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("fdb-dupes")?;
    let plan = plan_for(
        100,
        &[("host-02", [198, 18, 0, 2]), ("host-03", [198, 18, 0, 3])],
    )
    .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let vxlan = names.vxlan(&plan.network_id);

    let mut provider = env.provider()?;
    for _ in 0..3 {
        provider.apply_plan(&plan)?;
    }
    let count_2 = provider
        .runner()
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.2");
    let count_3 = provider
        .runner()
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.3");
    env.take_runner_back(provider);
    env.cleanup();

    if count_2 != 1 || count_3 != 1 {
        return Err(FabricError::Invalid(format!(
            "HER flood entries must exist exactly once after replays \
             (198.18.0.2: {count_2}, 198.18.0.3: {count_3})"
        )));
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
        .filter(|c| {
            c.program == "ip" && c.joined().contains("bridge fdb append")
                || c.program == "bridge" && c.joined().contains("fdb append")
        })
        .map(|c| c.joined())
        .collect();
    if !flood_entries.iter().any(|c| c.contains("dst 198.18.0.2"))
        || !flood_entries.iter().any(|c| c.contains("dst 198.18.0.3"))
    {
        return Err(FabricError::Invalid(
            "HER entries must target exactly the plan peers".to_string(),
        ));
    }
    // The kernel refuses `replace` on non-unicast entries; the fake kernel
    // enforces the same rule, so any regression to `replace` fails the
    // apply outright. Assert the verb explicitly as documentation.
    let replaced = provider
        .runner()
        .calls()
        .iter()
        .filter(|c| c.joined().contains("fdb replace"))
        .count();
    env.take_runner_back(provider);
    env.cleanup();
    if replaced != 0 {
        return Err(FabricError::Invalid(
            "HER flood entries must use append, not replace".to_string(),
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

fn case_wireguard_mtu() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("wg-mtu")?;
    // Default plan: tenant 1380 / fabric 1440 — VXLAN egress frames of up
    // to 1430 bytes exceed the kernel-default WireGuard MTU of 1420.
    let mut small = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    small.tenant_mtu = 1380;
    small.fabric_mtu = 1440;
    let mut provider = env.provider()?;
    provider.apply_plan(&small)?;

    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let wg = names.wireguard_interface();
    let expected_cmd = format!(
        "ip netns exec {} ip link set {wg} mtu 1440",
        names.fabric_namespace()
    );
    let command_seen = provider
        .runner()
        .calls()
        .iter()
        .any(|call| call.joined() == expected_cmd);
    let state_after_small = provider.runner().link_mtu(&wg);

    // A second, larger plan must raise the shared WireGuard MTU to the new
    // maximum across live plans.
    let mut larger = plan_for(200, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    larger.tenant_mtu = 1410;
    larger.fabric_mtu = 1460;
    provider.apply_plan(&larger)?;
    let state_after_large = provider.runner().link_mtu(&wg);
    env.take_runner_back(provider);
    env.cleanup();

    if !command_seen || state_after_small != Some(1440) {
        return Err(FabricError::Invalid(format!(
            "WireGuard MTU not set to fabric_mtu 1440 (command_seen={command_seen}, \
             fake-kernel mtu={state_after_small:?})"
        )));
    }
    if state_after_large != Some(1460) {
        return Err(FabricError::Invalid(format!(
            "WireGuard MTU must follow the maximum fabric_mtu across live plans, \
             expected 1460, saw {state_after_large:?}"
        )));
    }
    Ok(())
}

/// A teardown after a kernel restart (fresh kernel, surviving journals)
/// must succeed with zero residue, and a later apply must fully recreate.
fn case_teardown_after_restart() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("restart")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let network_id = plan.network_id.clone();

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // A rebooted kernel: fresh fake, SAME durable state root (ownership
    // and plan journals survive).
    env.runner = RecordingRunner::new();
    let mut provider = env.provider()?;
    provider.remove_network(&network_id)?;

    // Kernel-residue assertions against the fresh fake would be vacuous
    // (it never held the objects); the provider's own reports and the
    // journals are the meaningful evidence here.
    let ownership_empty = provider.ownership().networks.is_empty();
    let plan_gone = !env.config.plan_path(&network_id).exists();

    // A clean host must converge to Ok(true).
    let fabric_removed = provider.remove_fabric_if_unused()?;

    // Re-applying the same plan on the fresh kernel must fully recreate
    // and re-populate the HER flood list (reconciliation against the
    // observed — empty — forwarding state re-appends everything).
    let report = provider.apply_plan(&plan)?;
    let flood_healed = provider.runner().has_fdb_entry(
        &names.vxlan(&network_id),
        "00:00:00:00:00:00",
        "198.18.0.2",
    );
    env.take_runner_back(provider);
    env.cleanup();

    if !ownership_empty || !plan_gone {
        return Err(FabricError::Invalid(
            "teardown after restart left journal residue".to_string(),
        ));
    }
    if !fabric_removed {
        return Err(FabricError::Invalid(
            "fabric removal must converge on a clean host".to_string(),
        ));
    }
    if !report.created_network || !report.created_fabric {
        return Err(FabricError::Invalid(
            "re-apply after restart must recreate the fabric and network".to_string(),
        ));
    }
    if !flood_healed {
        return Err(FabricError::Invalid(
            "HER flood entries must be re-appended after kernel loss".to_string(),
        ));
    }
    Ok(())
}

/// A re-apply must heal partial state: a lost bridge is recreated and the
/// VXLAN re-enslaved (enslavement is an unconditional re-assert).
fn case_reapply_heals_partial_state() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("heal")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let bridge = names.fabric_bridge(&plan.network_id);
    let vxlan = names.vxlan(&plan.network_id);

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // Simulate a crash/partial state: only the fabric-side bridge is lost.
    let out = env
        .runner
        .run("ip", &["netns", "exec", &ns, "ip", "link", "del", &bridge])?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not delete the fabric bridge for the test: {}",
            out.stderr.trim()
        )));
    }

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let bridge_recreated = provider.runner().has_link(&bridge);
    let master_cmd = format!("ip netns exec {ns} ip link set {vxlan} master {bridge}");
    let master_asserts = provider
        .runner()
        .calls()
        .iter()
        .filter(|call| call.joined() == master_cmd)
        .count();
    env.take_runner_back(provider);
    env.cleanup();

    if !bridge_recreated {
        return Err(FabricError::Invalid(
            "re-apply must recreate a lost fabric bridge".to_string(),
        ));
    }
    if master_asserts < 2 {
        return Err(FabricError::Invalid(format!(
            "enslavement must be re-asserted on every apply (saw {master_asserts} of '{master_cmd}')"
        )));
    }
    Ok(())
}

/// Shrinking the peer set must delete the removed peer's flood entry from
/// the kernel while the kept one remains.
fn case_flood_list_shrinks() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("shrink")?;
    let two_peers = plan_for(
        100,
        &[("host-02", [198, 18, 0, 2]), ("host-03", [198, 18, 0, 3])],
    )
    .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let one_peer = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let vxlan = names.vxlan(&two_peers.network_id);

    let mut provider = env.provider()?;
    provider.apply_plan(&two_peers)?;
    provider.apply_plan(&one_peer)?;
    let kept = provider
        .runner()
        .has_fdb_entry(&vxlan, "00:00:00:00:00:00", "198.18.0.2");
    let removed = provider
        .runner()
        .has_fdb_entry(&vxlan, "00:00:00:00:00:00", "198.18.0.3");
    env.take_runner_back(provider);
    env.cleanup();

    if removed {
        return Err(FabricError::Invalid(
            "the removed peer's flood entry must be deleted from the kernel".to_string(),
        ));
    }
    if !kept {
        return Err(FabricError::Invalid(
            "the kept peer's flood entry must remain".to_string(),
        ));
    }
    Ok(())
}

/// A foreign VXLAN whose VNI merely extends the plan's VNI as a string
/// prefix (1000 vs 100) must be rejected — token-exact identity checks.
///
/// The foreign VXLAN is pre-created INSIDE the fabric namespace (the
/// namespace is added, then the ns-scoped `ip link add` runs), exactly
/// the shape a leftover from an older deployment or a rogue operator
/// would take on a real kernel — the fake's per-namespace name tables
/// make the ns-scoped `ip -d link show` inside the provider observe it.
fn case_foreign_state_rejects_prefix_vni() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("prefix-vni")?;
    let plan = plan_for(100, &[("host-02", [198, 18, 0, 2])])
        .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let vxlan = names.vxlan(&plan.network_id);

    // Pre-create the namespace, then a foreign VXLAN inside it at the
    // deterministic name: same dstport and local IP as the plan would
    // use, VNI 1000 (a strict prefix extension of the plan's 100 under
    // substring matching).
    let out = env.runner.run("ip", &["netns", "add", &ns])?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not create the fabric namespace for the test: {}",
            out.stderr.trim()
        )));
    }
    let out = env.runner.run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "link",
            "add",
            vxlan.as_str(),
            "type",
            "vxlan",
            "id",
            "1000",
            "dstport",
            "4789",
            "local",
            "198.18.0.1",
            "dev",
            names.wireguard_interface().as_str(),
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not pre-create the foreign vxlan for the test: {}",
            out.stderr.trim()
        )));
    }

    let mut provider = env.provider()?;
    let result = provider.apply_plan(&plan);
    env.take_runner_back(provider);
    env.cleanup();
    match result {
        Err(FabricError::ForeignState { .. }) => Ok(()),
        Err(other) => Err(other),
        Ok(_) => Err(FabricError::Invalid(
            "a foreign VXLAN with prefix-matching VNI was adopted instead of rejected".to_string(),
        )),
    }
}

/// Pre-existing duplicates of a still-desired destination (the
/// Launchpad #1531013 fleet state) must converge to exactly one entry:
/// reconciliation is instance-count aware — each `bridge fdb del`
/// removes exactly one instance — so the duplicated destination is
/// issued count−1 tolerant deletes. The fake kernel is seeded
/// mid-lifecycle (after a converged apply) to model a fleet that
/// accumulated the duplicate under older code.
fn case_flood_duplicates_converge() -> Result<(), FabricError> {
    let mut env = CaseEnv::new("fdb-dupe-seed")?;
    let plan = plan_for(
        100,
        &[("host-02", [198, 18, 0, 2]), ("host-03", [198, 18, 0, 3])],
    )
    .map_err(|e| FabricError::Invalid(e.to_string()))?;
    let names = fabric_linux::Names::new(env.config.name_prefix())?;
    let ns = names.fabric_namespace();
    let vxlan = names.vxlan(&plan.network_id);

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    env.take_runner_back(provider);

    // Seed the fake mid-lifecycle: one desired destination now has two
    // instances (duplicate append), the other one.
    let out = env.runner.run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "bridge",
            "fdb",
            "append",
            "00:00:00:00:00:00",
            "dev",
            vxlan.as_str(),
            "dst",
            "198.18.0.2",
        ],
    )?;
    if !out.success {
        env.cleanup();
        return Err(FabricError::Command(format!(
            "could not seed the duplicate flood entry: {}",
            out.stderr.trim()
        )));
    }

    let mut provider = env.provider()?;
    provider.apply_plan(&plan)?;
    let count_2 = provider
        .runner()
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.2");
    let count_3 = provider
        .runner()
        .fdb_entry_count(&vxlan, "00:00:00:00:00:00", "198.18.0.3");
    env.take_runner_back(provider);
    env.cleanup();

    if count_2 != 1 || count_3 != 1 {
        return Err(FabricError::Invalid(format!(
            "duplicate HER flood entries must converge to exactly one per \
             desired destination (198.18.0.2: {count_2}, 198.18.0.3: {count_3})"
        )));
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
