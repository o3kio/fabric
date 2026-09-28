//! Zero-leak teardown verification.
//!
//! Checks this host's KERNEL state only: no fabric netns, no prefixed
//! links, no NAT rules referencing the underlay prefix, no routes via the
//! host underlay veth. The private key file and journal directories under
//! the state root REMAIN by design (contract §3.5: keys survive teardown)
//! and are intentionally not residue.

use fabric_linux::{FabricCommand, Names};
use serde::Serialize;

use crate::error::RunError;

/// The provider's link-local underlay attachment prefix (see
/// `fabric_linux::config::UNDERLAY_PREFIX`).
const UNDERLAY_PREFIX: &str = "169.254.253.0/30";
/// The fabric-side DNAT target inside the underlay /30.
const UNDERLAY_FABRIC_IP: &str = "169.254.253.2";

/// Leak-check outcome. `residue` entries are human-readable descriptions.
#[derive(Serialize)]
pub struct LeakReport {
    pub clean: bool,
    pub residue: Vec<String>,
}

/// Verify zero fabric objects remain in this host's kernel.
pub fn leak_check<R: FabricCommand>(runner: &mut R, prefix: &str) -> Result<LeakReport, RunError> {
    let names = Names::new(prefix)?;
    let mut residue = Vec::new();

    // Fabric netns.
    let listing = runner.run("ip", &["netns", "list"])?;
    if listing.success
        && listing
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(names.fabric_namespace().as_str()))
    {
        residue.push(format!("netns {} still exists", names.fabric_namespace()));
    }

    // Any link whose name starts with `<prefix>-`.
    let links = runner.run("ip", &["-o", "link"])?;
    let marker = format!("{prefix}-");
    for name in parse_link_names(&links.stdout) {
        if name.starts_with(&marker) {
            residue.push(format!("link {name} still exists"));
        }
    }

    // NAT rules referencing the underlay prefix or its DNAT target.
    let nat = runner.run("iptables", &["-t", "nat", "-S"])?;
    for rule in nat_residue(&nat.stdout) {
        residue.push(format!("nat rule: {rule}"));
    }

    // Routes still pointing through the host underlay veth.
    let routes = runner.run("ip", &["route", "show"])?;
    for route in route_residue(&routes.stdout, &names.host_underlay_veth()) {
        residue.push(format!("route: {route}"));
    }

    Ok(LeakReport {
        clean: residue.is_empty(),
        residue,
    })
}

/// Extract interface names from `ip -o link` output.
///
/// Line shape: `"<idx>: <name>[@<peer-ifidx>]: <flags> ..."`.
pub fn parse_link_names(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|field| {
            let field = field.strip_suffix(':').unwrap_or(field);
            field.split('@').next().unwrap_or(field).to_string()
        })
        .collect()
}

/// Return the `iptables -t nat -S` rule lines that reference the fabric
/// underlay prefix (`-s 169.254.253.0/30 ... MASQUERADE`) or its DNAT
/// target (`... --to-destination 169.254.253.2`). Token-exact matching so
/// neighboring addresses (e.g. 169.254.253.254) do not false-positive.
pub fn nat_residue(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .any(|token| token == UNDERLAY_PREFIX || token == UNDERLAY_FABRIC_IP)
        })
        .map(str::to_string)
        .collect()
}

/// Return the `ip route show` lines that route via `dev <dev>`.
pub fn route_residue(output: &str, dev: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            tokens
                .windows(2)
                .any(|pair| pair[0] == "dev" && pair[1] == dev)
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_linux::{FabricLinuxConfig, LinuxFabricProvider, RecordingRunner};
    use fabric_plan::{FabricPeer, PublicKey, UnderlayEndpoint, Vni};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    const SAMPLE_LINKS: &str = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT group default qlen 1000
2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default
4: ev-wg@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 state UP mode DEFAULT group default
7: brten: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1380 state UP mode DEFAULT group default
";

    const SAMPLE_NAT: &str = "\
-P PREROUTING ACCEPT
-A POSTROUTING -s 172.31.250.0/24 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 169.254.253.0/30 -j MASQUERADE
-A PREROUTING ! -i ev-u -p udp --dport 65001 -j DNAT --to-destination 169.254.253.2
";

    const SAMPLE_ROUTES: &str = "\
default via 172.31.250.1 dev eth0
172.31.250.0/24 dev eth0 proto kernel scope link src 172.31.250.2
169.254.253.0/30 dev ev-u proto kernel scope link src 169.254.253.1
";

    #[test]
    fn parses_link_names_with_veth_and_suffixes() {
        let names = parse_link_names(SAMPLE_LINKS);
        assert_eq!(
            names,
            vec![
                "lo".to_string(),
                "eth0".to_string(),
                "ev-wg".to_string(),
                "brten".to_string()
            ]
        );
    }

    #[test]
    fn nat_residue_matches_underlay_rules_only() {
        let rules = nat_residue(SAMPLE_NAT);
        assert_eq!(rules.len(), 2, "both fabric rules must be flagged");
        let rules = nat_residue(
            "-A POSTROUTING -s 169.254.253.254 -j MASQUERADE\n-A POSTROUTING -j RETURN\n",
        );
        assert!(
            rules.is_empty(),
            "neighboring underlay addresses must not false-positive"
        );
    }

    #[test]
    fn route_residue_matches_only_the_underlay_veth() {
        let routes = route_residue(SAMPLE_ROUTES, "ev-u");
        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains("169.254.253.0/30 dev ev-u"));
        assert!(route_residue(SAMPLE_ROUTES, "eth0").len() == 2);
        assert!(route_residue(SAMPLE_ROUTES, "lo").is_empty());
    }

    #[test]
    fn leak_check_clean_after_full_provider_teardown() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("clean")?;
        let config = FabricLinuxConfig::new(&root).with_name_prefix("ev");
        let plan = evidence_plan()?;
        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let network_id = plan.network_id.clone();
        provider.remove_network(&network_id)?;
        assert!(provider.remove_fabric_if_unused()?);
        let mut runner = provider.into_runner();

        let report = leak_check(&mut runner, "ev")?;
        std::fs::remove_dir_all(&root)?;
        assert!(report.clean, "residue: {:?}", report.residue);
        Ok(())
    }

    #[test]
    fn leak_check_flags_leftover_fabric() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("dirty")?;
        let config = FabricLinuxConfig::new(&root).with_name_prefix("ev");
        let plan = evidence_plan()?;
        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let mut runner = provider.into_runner();

        let report = leak_check(&mut runner, "ev")?;
        std::fs::remove_dir_all(&root)?;
        assert!(!report.clean, "a live fabric must not pass the leak check");
        assert!(
            report
                .residue
                .iter()
                .any(|r| r.contains("netns ev-fabric still exists")),
            "residue must name the leftover fabric netns: {:?}",
            report.residue
        );
        Ok(())
    }

    fn evidence_plan() -> Result<fabric_plan::StretchedL2Plan, fabric_plan::PlanError> {
        Ok(fabric_plan::StretchedL2Plan {
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

    fn temp_root(tag: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "fabric-ev-leak-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
