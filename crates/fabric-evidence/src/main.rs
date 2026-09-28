//! `fabric-evidence` — the per-host half of the privileged multi-host
//! evidence harness for the Kubedo stretched-L2 edge fabric (roadmap issue
//! #2, Phase 3; CHV ADR-021 / O3K ADR-0186).
//!
//! The binary runs INSIDE one host (a privileged container in the reference
//! orchestration, `evidence/run-multinode.sh`) and operates on that host's
//! kernel through the real provider (`LinuxFabricProvider` with
//! [`RealCommandRunner`]) plus a small set of tenant-side operations that
//! simulate what a consumer host daemon does with the provider's consumer
//! veth. Every subcommand prints machine-readable JSON on stdout; errors go
//! to stderr; the exit code is 0 or 1.
//!
//! Key hygiene is inherited from the provider: private key material only
//! ever travels by file path or stdin and never appears in output.

mod cli;
mod error;
mod leak;
mod probe;
mod tenant;

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use fabric_linux::{FabricLinuxConfig, LinuxFabricProvider, RealCommandRunner};
use fabric_plan::StretchedL2Plan;
use serde_json::json;

use cli::Command;
use error::RunError;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fabric-evidence: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), RunError> {
    match cli::parse(args)? {
        Command::Identity { root, prefix } => cmd_identity(&root, &prefix),
        Command::Apply { root, prefix, plan } => cmd_apply(&root, &prefix, &plan),
        Command::TenantUp {
            root,
            prefix,
            network_id,
            bridge,
            tenant_ns,
            ip,
        } => cmd_tenant_up(&root, &prefix, &network_id, &bridge, &tenant_ns, &ip),
        Command::TenantDown {
            root,
            prefix,
            network_id,
            bridge,
            tenant_ns,
        } => cmd_tenant_down(&root, &prefix, &network_id, &bridge, &tenant_ns),
        Command::Probe {
            tenant_ns,
            target,
            size,
            count,
            deadline,
        } => cmd_probe(&tenant_ns, &target, size, count, deadline),
        Command::Neighbors { tenant_ns } => cmd_neighbors(&tenant_ns),
        Command::Teardown {
            root,
            prefix,
            network_id,
        } => cmd_teardown(&root, &prefix, &network_id),
        Command::FabricDown { root, prefix } => cmd_fabric_down(&root, &prefix),
        Command::LeakCheck { root, prefix } => cmd_leak_check(&root, &prefix),
    }
}

/// `identity`: ensure/derive the host keypair with the provider's config
/// paths. Prints the PUBLIC key only.
fn cmd_identity(root: &Path, prefix: &str) -> Result<(), RunError> {
    let config = provider_config(root, prefix)?;
    let mut runner = RealCommandRunner;
    let key_path = fabric_linux::ensure_private_key(&config.private_key_path(), &mut runner)?;
    // The private key is read host-locally and piped to `wg pubkey` via
    // stdin; it is never printed, logged, or placed in argv.
    let private = fs::read_to_string(&key_path)?;
    let public = fabric_linux::derive_public_key(&mut runner, private.trim())?;
    println!("{}", json!({ "public_key": public.as_str() }));
    Ok(())
}

/// `apply`: read the plan JSON and run it through the real provider.
fn cmd_apply(root: &Path, prefix: &str, plan_path: &Path) -> Result<(), RunError> {
    let plan = read_plan(plan_path)?;
    let config = provider_config(root, prefix)?;
    let mut provider = LinuxFabricProvider::open(config, RealCommandRunner)?;
    let report = provider.apply_plan(&plan)?;
    println!(
        "{}",
        json!({
            "created_fabric": report.created_fabric,
            "created_network": report.created_network,
        })
    );
    Ok(())
}

fn cmd_tenant_up(
    root: &Path,
    prefix: &str,
    network_id: &str,
    bridge: &str,
    tenant_ns: &str,
    ip: &str,
) -> Result<(), RunError> {
    let config = provider_config(root, prefix)?;
    let mut runner = RealCommandRunner;
    let report = tenant::tenant_up(&mut runner, &config, network_id, bridge, tenant_ns, ip)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn cmd_tenant_down(
    root: &Path,
    prefix: &str,
    network_id: &str,
    bridge: &str,
    tenant_ns: &str,
) -> Result<(), RunError> {
    let config = provider_config(root, prefix)?;
    let mut runner = RealCommandRunner;
    let report = tenant::tenant_down(&mut runner, &config, network_id, bridge, tenant_ns)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn cmd_probe(
    tenant_ns: &str,
    target: &str,
    size: Option<u32>,
    count: u32,
    deadline: u32,
) -> Result<(), RunError> {
    let mut runner = RealCommandRunner;
    let report = probe::run_probe(&mut runner, tenant_ns, target, size, count, deadline)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn cmd_neighbors(tenant_ns: &str) -> Result<(), RunError> {
    let mut runner = RealCommandRunner;
    let report = probe::run_neighbors(&mut runner, tenant_ns)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn cmd_teardown(root: &Path, prefix: &str, network_id: &str) -> Result<(), RunError> {
    let config = provider_config(root, prefix)?;
    let mut provider = LinuxFabricProvider::open(config, RealCommandRunner)?;
    provider.remove_network(network_id)?;
    println!("{}", json!({ "removed": true, "network_id": network_id }));
    Ok(())
}

fn cmd_fabric_down(root: &Path, prefix: &str) -> Result<(), RunError> {
    let config = provider_config(root, prefix)?;
    let mut provider = LinuxFabricProvider::open(config, RealCommandRunner)?;
    let removed = provider.remove_fabric_if_unused()?;
    println!("{}", json!({ "removed": removed }));
    Ok(())
}

/// `leak-check`: print the JSON report first, then fail (exit 1) when
/// residue was found, so orchestrators get both the machine-readable
/// result and a nonzero exit code.
fn cmd_leak_check(root: &Path, prefix: &str) -> Result<(), RunError> {
    // The state root is accepted for CLI uniformity but intentionally
    // unused: the check covers kernel state only, and the key/journal
    // files under the root survive teardown by design.
    let _unused_root = root;
    let mut runner = RealCommandRunner;
    let report = leak::leak_check(&mut runner, prefix)?;
    println!("{}", serde_json::to_string(&report)?);
    if !report.clean {
        return Err(RunError::Leak(report.residue.join("; ")));
    }
    Ok(())
}

fn provider_config(root: &Path, prefix: &str) -> Result<FabricLinuxConfig, RunError> {
    let config = FabricLinuxConfig::new(root).with_name_prefix(prefix);
    config.validate()?;
    Ok(config)
}

/// Read and validate a plan JSON file.
fn read_plan(path: &Path) -> Result<StretchedL2Plan, RunError> {
    let raw = fs::read_to_string(path)?;
    let plan: StretchedL2Plan = serde_json::from_str(&raw)
        .map_err(|e| RunError::Usage(format!("plan {} is not valid JSON: {e}", path.display())))?;
    plan.validate()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_file(tag: &str, contents: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "fabric-ev-main-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("plan.json");
        std::fs::write(&path, contents)?;
        Ok(path)
    }

    const PLAN_JSON: &str = r#"{
  "fabric_domain_id": "fabric-evidence",
  "local_host_id": "h1",
  "local_transport_ip": "100.100.0.1",
  "network_id": "evidence-net",
  "vni": 4711,
  "binding_generation": 1,
  "tenant_mtu": 1380,
  "fabric_mtu": 1440,
  "peers": [
    {
      "host_id": "h2",
      "public_key": "K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=",
      "underlay_endpoint": { "host": "172.31.250.12", "port": 65001 },
      "fabric_transport_ip": "100.100.0.2"
    }
  ],
  "plan_generation": 1
}"#;

    #[test]
    fn reads_and_validates_a_plan_json() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_file("plan", PLAN_JSON)?;
        let plan = read_plan(&path)?;
        assert_eq!(plan.network_id, "evidence-net");
        assert_eq!(plan.vni.get(), 4711);
        assert_eq!(plan.tenant_mtu, 1380);
        assert_eq!(plan.fabric_mtu, 1440);
        let _unused = std::fs::remove_dir_all(path.parent().ok_or("no parent")?);
        Ok(())
    }

    #[test]
    fn rejects_invalid_plan_json() -> Result<(), Box<dyn std::error::Error>> {
        let path = temp_file("bad", "{ not json")?;
        assert!(read_plan(&path).is_err());

        // Structurally valid JSON that violates the MTU layering invariant.
        let broken = PLAN_JSON.replace("\"tenant_mtu\": 1380", "\"tenant_mtu\": 1500");
        let path = temp_file("mtu", &broken)?;
        assert!(read_plan(&path).is_err());
        Ok(())
    }
}
