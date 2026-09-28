//! The consumer side of the tenant attachment.
//!
//! This simulates, for evidence collection, what a host's network daemon
//! (CHV's `chv-nwd` with its tenant bridge; O3K's realm bridge) does with
//! the provider's consumer veth: create a tenant bridge, attach a tenant
//! namespace via a veth pair, and enslave the provider-owned consumer veth
//! to that bridge. Everything here lives OUTSIDE the provider's ownership
//! (contract §3.9: the provider never bridges into site-local switches);
//! teardown of provider-owned objects stays with the provider.

use std::path::Path;

use fabric_linux::{CommandOutput, FabricCommand, FabricLinuxConfig, Names};
use fabric_plan::StretchedL2Plan;
use serde::Serialize;

use crate::error::RunError;

/// IFNAMSIZ is 16 bytes including the NUL terminator.
const IFNAMSIZ: usize = 16;

/// The interface name used for the tenant end inside the tenant netns.
const TENANT_IF: &str = "eth0";

/// Outcome of [`tenant_up`].
#[derive(Serialize)]
pub struct TenantUpReport {
    pub created_bridge: bool,
    pub created_netns: bool,
    pub created_veth: bool,
    pub bridge: String,
    pub tenant_ns: String,
    pub tenant_if: String,
    pub host_end: String,
    pub consumer_veth: String,
    pub bridge_mtu: u32,
}

/// Outcome of [`tenant_down`].
#[derive(Serialize)]
pub struct TenantDownReport {
    pub removed_netns: bool,
    pub removed_bridge: bool,
    pub removed_host_end: bool,
    /// The provider-owned consumer veth, deliberately NOT touched here
    /// (`remove_network` owns and removes it).
    pub consumer_veth_left_to_provider: String,
    pub network_id: String,
}

/// Create the tenant-side objects for one network on this host. Idempotent:
/// re-running reports `created_*: false` and re-asserts master/MTU/up state.
pub fn tenant_up<R: FabricCommand>(
    runner: &mut R,
    config: &FabricLinuxConfig,
    network_id: &str,
    bridge: &str,
    tenant_ns: &str,
    ip: &str,
) -> Result<TenantUpReport, RunError> {
    let names = Names::new(config.name_prefix())?;
    let consumer_veth = names.consumer_port_veth(network_id);
    // The veth pair is created in the container root ns (which already has
    // its own eth0) and the netns end is renamed to `eth0` after the move.
    let netns_end = format!("{tenant_ns}-{TENANT_IF}");
    let host_end = format!("{bridge}-p");
    for name in [&netns_end, &host_end] {
        if name.len() >= IFNAMSIZ {
            return Err(RunError::Usage(format!(
                "generated interface name {name:?} exceeds IFNAMSIZ; use shorter \
                 --bridge/--tenant-ns values"
            )));
        }
    }

    // The plan journal is the source of truth for the tenant MTU (the
    // provider already applied it to the consumer veth pair).
    let plan = read_plan(config, network_id)?;
    let bridge_mtu = plan.tenant_mtu;
    let mtu = bridge_mtu.to_string();

    // Tenant bridge (host-owned).
    let show = runner.run("ip", &["link", "show", bridge])?;
    let created_bridge = !show.success;
    if created_bridge {
        run_checked(runner, "ip", &["link", "add", bridge, "type", "bridge"])?;
    }
    run_checked(runner, "ip", &["link", "set", bridge, "up"])?;

    // Tenant netns.
    let created_netns = !has_netns(runner, tenant_ns)?;
    if created_netns {
        run_checked(runner, "ip", &["netns", "add", tenant_ns])?;
    }

    // Tenant veth pair. Deleting the netns later removes both ends.
    let eth0_show = ns_run(runner, tenant_ns, "ip", &["link", "show", TENANT_IF])?;
    let created_veth = !eth0_show.success;
    if created_veth {
        run_checked(
            runner,
            "ip",
            &[
                "link",
                "add",
                netns_end.as_str(),
                "type",
                "veth",
                "peer",
                "name",
                host_end.as_str(),
            ],
        )?;
        run_checked(
            runner,
            "ip",
            &["link", "set", netns_end.as_str(), "netns", tenant_ns],
        )?;
        ns_run_checked(
            runner,
            tenant_ns,
            "ip",
            &["link", "set", netns_end.as_str(), "name", TENANT_IF],
        )?;
        ns_run_checked(
            runner,
            tenant_ns,
            "ip",
            &["addr", "replace", ip, "dev", TENANT_IF],
        )?;
    }
    // MTU on the segment: both veth ends and the bridge carry tenant_mtu.
    run_checked(
        runner,
        "ip",
        &["link", "set", host_end.as_str(), "mtu", &mtu],
    )?;
    ns_run_checked(
        runner,
        tenant_ns,
        "ip",
        &["link", "set", TENANT_IF, "mtu", &mtu],
    )?;
    run_checked(
        runner,
        "ip",
        &["link", "set", host_end.as_str(), "master", bridge],
    )?;
    ns_run_checked(runner, tenant_ns, "ip", &["link", "set", TENANT_IF, "up"])?;
    run_checked(runner, "ip", &["link", "set", host_end.as_str(), "up"])?;

    // Enslave the provider-owned consumer veth to the tenant bridge and
    // make sure it is up (contract §3.9: the host does this under its own
    // policy). The provider owns the veth; we only attach it.
    let consumer_show = runner.run("ip", &["link", "show", consumer_veth.as_str()])?;
    if !consumer_show.success {
        return Err(RunError::Usage(format!(
            "consumer veth {consumer_veth} not found; run apply first"
        )));
    }
    run_checked(
        runner,
        "ip",
        &["link", "set", consumer_veth.as_str(), "master", bridge],
    )?;
    run_checked(
        runner,
        "ip",
        &["link", "set", consumer_veth.as_str(), "mtu", &mtu],
    )?;
    run_checked(runner, "ip", &["link", "set", consumer_veth.as_str(), "up"])?;
    run_checked(runner, "ip", &["link", "set", bridge, "mtu", &mtu])?;

    Ok(TenantUpReport {
        created_bridge,
        created_netns,
        created_veth,
        bridge: bridge.to_string(),
        tenant_ns: tenant_ns.to_string(),
        tenant_if: TENANT_IF.to_string(),
        host_end,
        consumer_veth,
        bridge_mtu,
    })
}

/// Remove the tenant-side objects. The provider-owned consumer veth is NOT
/// touched here: `remove_network` owns and removes it.
pub fn tenant_down<R: FabricCommand>(
    runner: &mut R,
    config: &FabricLinuxConfig,
    network_id: &str,
    bridge: &str,
    tenant_ns: &str,
) -> Result<TenantDownReport, RunError> {
    let names = Names::new(config.name_prefix())?;
    let consumer_veth = names.consumer_port_veth(network_id);
    // Deleting the netns destroys the tenant eth0 and, with it, its veth
    // peer (the host end).
    let removed_netns = has_netns(runner, tenant_ns)?;
    if removed_netns {
        run_checked(runner, "ip", &["netns", "del", tenant_ns])?;
    }
    // The host end only survives when the netns was already gone.
    let host_end = format!("{bridge}-p");
    let host_show = runner.run("ip", &["link", "show", host_end.as_str()])?;
    let removed_host_end = host_show.success;
    if host_show.success {
        run_checked(runner, "ip", &["link", "del", host_end.as_str()])?;
    }
    // The bridge detaches (never deletes) its enslaved ports; the
    // provider-owned consumer veth is removed by remove_network.
    let bridge_show = runner.run("ip", &["link", "show", bridge])?;
    let removed_bridge = bridge_show.success;
    if bridge_show.success {
        run_checked(runner, "ip", &["link", "del", bridge])?;
    }
    Ok(TenantDownReport {
        removed_netns,
        removed_bridge,
        removed_host_end,
        consumer_veth_left_to_provider: consumer_veth,
        network_id: network_id.to_string(),
    })
}

/// Read the journaled plan for one network (the tenant MTU source).
fn read_plan(config: &FabricLinuxConfig, network_id: &str) -> Result<StretchedL2Plan, RunError> {
    let path: &Path = &config.plan_path(network_id);
    let raw = std::fs::read_to_string(path).map_err(|e| {
        RunError::Usage(format!(
            "cannot read plan journal {} (apply first): {e}",
            path.display()
        ))
    })?;
    let plan: StretchedL2Plan = serde_json::from_str(&raw)
        .map_err(|e| RunError::Usage(format!("plan journal {} is corrupt: {e}", path.display())))?;
    Ok(plan)
}

fn has_netns<R: FabricCommand>(runner: &mut R, ns: &str) -> Result<bool, RunError> {
    let listing = runner.run("ip", &["netns", "list"])?;
    Ok(listing.success
        && listing
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(ns)))
}

fn run_checked<R: FabricCommand>(
    runner: &mut R,
    program: &str,
    args: &[&str],
) -> Result<(), RunError> {
    let output = runner.run(program, args)?;
    if output.success {
        Ok(())
    } else {
        Err(RunError::Command(format!(
            "{program} {} failed: {}",
            args.join(" "),
            output.stderr.trim()
        )))
    }
}

fn ns_run<R: FabricCommand>(
    runner: &mut R,
    ns: &str,
    program: &str,
    args: &[&str],
) -> Result<CommandOutput, RunError> {
    let mut full: Vec<&str> = vec!["netns", "exec", ns, program];
    full.extend_from_slice(args);
    Ok(runner.run("ip", &full)?)
}

fn ns_run_checked<R: FabricCommand>(
    runner: &mut R,
    ns: &str,
    program: &str,
    args: &[&str],
) -> Result<(), RunError> {
    let output = ns_run(runner, ns, program, args)?;
    if output.success {
        Ok(())
    } else {
        Err(RunError::Command(format!(
            "ip netns exec {ns} {program} {} failed: {}",
            args.join(" "),
            output.stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_linux::{LinuxFabricProvider, RecordingRunner};
    use fabric_plan::{FabricPeer, PublicKey, UnderlayEndpoint, Vni};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn test_plan() -> Result<StretchedL2Plan, fabric_plan::PlanError> {
        Ok(StretchedL2Plan {
            fabric_domain_id: "fabric-evidence".to_string(),
            local_host_id: "h1".to_string(),
            local_transport_ip: Ipv4Addr::new(100, 100, 0, 1),
            network_id: "evidence-net".to_string(),
            vni: Vni::new(4711)?,
            binding_generation: 1,
            tenant_mtu: 1380,
            fabric_mtu: 1440,
            peers: vec![FabricPeer {
                host_id: "h2".to_string(),
                public_key: PublicKey::new("K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=")?,
                underlay_endpoint: UnderlayEndpoint::parse("172.31.250.12:65001")?,
                fabric_transport_ip: Ipv4Addr::new(100, 100, 0, 2),
            }],
            plan_generation: 1,
        })
    }

    struct Env {
        root: PathBuf,
        config: FabricLinuxConfig,
        runner: RecordingRunner,
    }

    impl Env {
        fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let root = std::env::temp_dir().join(format!(
                "fabric-ev-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&root)?;
            let config = FabricLinuxConfig::new(&root).with_name_prefix("ev");
            Ok(Self {
                root,
                config,
                runner: RecordingRunner::new(),
            })
        }

        /// Apply the plan through a provider, then hand the runner back so
        /// tenant_up sees the provider-created consumer veth.
        fn apply(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let plan = test_plan().map_err(|e| RunError::Usage(e.to_string()))?;
            let mut provider =
                LinuxFabricProvider::open(self.config.clone(), std::mem::take(&mut self.runner))?;
            provider.apply_plan(&plan)?;
            self.runner = provider.into_runner();
            Ok(())
        }

        fn cleanup(&self) {
            let _unused = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn tenant_up_creates_and_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let mut env = Env::new("up")?;
        env.apply()?;

        let report = tenant_up(
            &mut env.runner,
            &env.config,
            "evidence-net",
            "brten",
            "tns",
            "10.42.0.11/24",
        )?;
        assert!(report.created_bridge);
        assert!(report.created_netns);
        assert!(report.created_veth);
        assert_eq!(report.tenant_if, "eth0");
        assert_eq!(report.host_end, "brten-p");
        assert_eq!(report.bridge_mtu, 1380);
        assert!(
            env.runner.has_link("brten"),
            "tenant bridge must exist in the (fake) kernel"
        );
        assert!(
            env.runner
                .calls()
                .iter()
                .any(|c| c.joined().contains(&format!(
                    "ip link set {} master brten",
                    report.consumer_veth
                ))),
            "the provider-owned consumer veth must be enslaved to the tenant bridge"
        );

        // Replay: nothing is created again.
        let replay = tenant_up(
            &mut env.runner,
            &env.config,
            "evidence-net",
            "brten",
            "tns",
            "10.42.0.11/24",
        )?;
        assert!(!replay.created_bridge);
        assert!(!replay.created_netns);
        assert!(!replay.created_veth);

        env.cleanup();
        Ok(())
    }

    #[test]
    fn tenant_up_requires_consumer_veth_from_apply() -> Result<(), Box<dyn std::error::Error>> {
        let mut env = Env::new("no-apply")?;
        let result = tenant_up(
            &mut env.runner,
            &env.config,
            "evidence-net",
            "brten",
            "tns",
            "10.42.0.11/24",
        );
        env.cleanup();
        assert!(result.is_err(), "tenant-up must fail without a prior apply");
        Ok(())
    }

    #[test]
    fn tenant_down_removes_only_tenant_objects() -> Result<(), Box<dyn std::error::Error>> {
        let mut env = Env::new("down")?;
        env.apply()?;
        let up = tenant_up(
            &mut env.runner,
            &env.config,
            "evidence-net",
            "brten",
            "tns",
            "10.42.0.11/24",
        )?;

        let down = tenant_down(&mut env.runner, &env.config, "evidence-net", "brten", "tns")?;
        assert!(down.removed_netns);
        assert!(down.removed_bridge);
        assert!(
            env.runner.has_link(&up.consumer_veth),
            "the provider-owned consumer veth must survive tenant-down"
        );
        assert!(
            !env.runner.has_link("brten"),
            "the tenant bridge must be gone"
        );
        // Idempotent replay reports nothing left to remove.
        let replay = tenant_down(&mut env.runner, &env.config, "evidence-net", "brten", "tns")?;
        assert!(!replay.removed_netns);
        assert!(!replay.removed_bridge);
        env.cleanup();
        Ok(())
    }

    #[test]
    fn tenant_up_rejects_oversize_generated_names() -> Result<(), Box<dyn std::error::Error>> {
        let mut env = Env::new("ifnamesiz")?;
        env.apply()?;
        let long_bridge = "bridgewaytoolong";
        let result = tenant_up(
            &mut env.runner,
            &env.config,
            "evidence-net",
            long_bridge,
            "tns",
            "10.42.0.11/24",
        );
        env.cleanup();
        assert!(result.is_err(), "host end name must stay within IFNAMSIZ");
        Ok(())
    }
}
