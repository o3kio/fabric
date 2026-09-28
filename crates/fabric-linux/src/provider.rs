//! The Linux fabric provider: idempotent realization of stretched-L2 plans.
//!
//! Realization order (see `contracts/fabric-provider-v1.md`):
//! validate plan -> journal plan -> ensure fabric (netns/WireGuard/underlay)
//! -> configure peers (union over live plans) -> re-assert the WireGuard MTU
//! (maximum fabric_mtu across live plans) -> ensure network (VXLAN +
//! learning bridge + attachment veth + bounded HER flood list) -> save
//! ownership. Teardown runs in reverse dependency order and preserves the
//! WireGuard private key.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use fabric_plan::StretchedL2Plan;

use crate::config::{
    DEFAULT_UNDERLAY_FABRIC_IP, DEFAULT_UNDERLAY_HOST_IP, FabricLinuxConfig, UNDERLAY_PREFIX,
};
use crate::error::FabricError;
use crate::keys;
use crate::naming::Names;
use crate::ownership::{FabricOwnership, NetworkOwnership, PeerRecord};
use crate::runner::{CommandOutput, FabricCommand};

/// The all-zeros (BUM) FDB address used for head-end replication entries.
pub const FLOOD_MAC: &str = "00:00:00:00:00:00";

/// Outcome flags from [`LinuxFabricProvider::apply_plan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ApplyReport {
    /// True when the shared fabric objects were created by this call.
    pub created_fabric: bool,
    /// True when this network's objects were created by this call.
    pub created_network: bool,
}

/// Outcome flags from [`LinuxFabricProvider::ensure_fabric`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FabricReport {
    pub created_netns: bool,
    pub created_wireguard: bool,
    pub created_underlay: bool,
}

/// The provider.
pub struct LinuxFabricProvider<R: FabricCommand> {
    config: FabricLinuxConfig,
    runner: R,
    ownership: FabricOwnership,
}

impl<R: FabricCommand> LinuxFabricProvider<R> {
    /// Open the provider, loading (or initializing) the ownership journal.
    pub fn open(config: FabricLinuxConfig, runner: R) -> Result<Self, FabricError> {
        config.validate()?;
        fs::create_dir_all(config.root())?;
        let ownership = FabricOwnership::load_or_default(&config.ownership_path())?;
        Ok(Self {
            config,
            runner,
            ownership,
        })
    }

    /// Apply one plan idempotently.
    pub fn apply_plan(&mut self, plan: &StretchedL2Plan) -> Result<ApplyReport, FabricError> {
        plan.validate()
            .map_err(|e| FabricError::Invalid(e.to_string()))?;
        let fingerprint = plan
            .fingerprint_sha256()
            .map_err(|e| FabricError::Invalid(e.to_string()))?;

        // Journal before mutate.
        self.persist_plan(plan)?;

        let fabric_report = self.ensure_fabric(plan)?;
        self.configure_peers()?;
        // Re-assert the WireGuard MTU on every apply: the kernel default
        // (1420) is below what validated plans may push through the VXLAN
        // devices (tenant_mtu + 50 bytes of VXLAN overhead).
        self.enforce_wireguard_mtu()?;
        let created_network = self.ensure_network(plan, &fingerprint)?;

        self.ownership.save(&self.config.ownership_path())?;
        Ok(ApplyReport {
            created_fabric: fabric_report.created_netns
                || fabric_report.created_wireguard
                || fabric_report.created_underlay,
            created_network,
        })
    }

    /// Remove one network's fabric state (reverse dependency order).
    ///
    /// The WireGuard private key and the shared fabric survive.
    pub fn remove_network(&mut self, network_id: &str) -> Result<(), FabricError> {
        let entry = self
            .ownership
            .networks
            .get(network_id)
            .cloned()
            .ok_or_else(|| {
                FabricError::Ownership(format!("network {network_id} is not owned by this host"))
            })?;
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();

        // Flood entries first.
        for ip in &entry.flood_peers {
            self.ns_fdb(&ns, "del", &entry.vxlan_name, ip)?;
        }
        // Attachment veth pair (deleting one end removes both).
        self.run_checked("ip", &["link", "del", &entry.consumer_port_veth])?;
        // VXLAN, then bridge.
        self.ns_run_checked(&ns, "ip", &["link", "del", &entry.vxlan_name])?;
        self.ns_run_checked(&ns, "ip", &["link", "del", &entry.bridge_name])?;

        // Drop the plan journal and ownership entry.
        let plan_path = self.config.plan_path(network_id);
        if plan_path.exists() {
            fs::remove_file(&plan_path)?;
        }
        self.ownership.networks.remove(network_id);

        // Reconcile peers against the remaining live plans.
        self.configure_peers()?;
        self.ownership.save(&self.config.ownership_path())?;
        Ok(())
    }

    /// Remove the shared fabric when no networks remain.
    ///
    /// Returns true when the fabric was removed. The private key file is
    /// intentionally preserved so planned peer public keys stay valid.
    pub fn remove_fabric_if_unused(&mut self) -> Result<bool, FabricError> {
        if !self.ownership.networks.is_empty() {
            return Ok(false);
        }
        if let Ok(entries) = fs::read_dir(self.config.plans_dir()) {
            let has_plans = entries
                .filter_map(Result::ok)
                .any(|e| e.path().extension().is_some_and(|x| x == "json"));
            if has_plans {
                return Ok(false);
            }
        }

        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let host_veth = names.host_underlay_veth();

        self.ns_run_checked(&ns, "ip", &["link", "del", &wg])?;
        self.run_checked("ip", &["link", "del", &host_veth])?;
        self.iptables_delete_underlay_rules(&host_veth)?;
        self.run_checked("ip", &["netns", "del", &ns])?;

        self.ownership.fabric_configured = false;
        self.ownership.peers.clear();
        self.ownership.save(&self.config.ownership_path())?;
        Ok(true)
    }

    /// Read-only access to the current ownership journal.
    pub fn ownership(&self) -> &FabricOwnership {
        &self.ownership
    }

    /// Read-only access to the command runner (for test kits inspecting the
    /// recorded call journal or fake-kernel state).
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Consume the provider and return the command runner (for test kits
    /// that need to inspect the recorded call journal).
    pub fn into_runner(self) -> R {
        self.runner
    }

    // ---- shared fabric -------------------------------------------------

    fn ensure_fabric(&mut self, plan: &StretchedL2Plan) -> Result<FabricReport, FabricError> {
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        // Namespace.
        let listing = self.run("ip", &["netns", "list"])?;
        let has_ns = listing.success
            && listing
                .stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(ns.as_str()));
        let created_netns = !has_ns;
        if !has_ns {
            self.run_checked("ip", &["netns", "add", &ns])?;
        }

        // WireGuard interface.
        let wg_show = self.ns_run(&ns, "ip", &["link", "show", &wg])?;
        let created_wireguard = !wg_show.success;
        if created_wireguard {
            self.run_checked("ip", &["link", "add", &wg, "type", "wireguard"])?;
            self.run_checked("ip", &["link", "set", &wg, "netns", &ns])?;
        }

        // Key, port, address, link-up: on creation, or the first apply after
        // a crash that lost the configured flag while the link survived.
        if created_wireguard || !self.ownership.fabric_configured {
            let key_path =
                keys::ensure_private_key(&self.config.private_key_path(), &mut self.runner)?;
            let key_arg = path_arg(&key_path)?;
            self.ns_run_checked(&ns, "wg", &["set", &wg, "private-key", key_arg.as_str()])?;
            let port = self.config.wireguard_port().to_string();
            self.ns_run_checked(&ns, "wg", &["set", &wg, "listen-port", port.as_str()])?;
            let local_addr = format!("{}/32", plan.local_transport_ip);
            self.ns_run_checked(
                &ns,
                "ip",
                &["addr", "replace", local_addr.as_str(), "dev", &wg],
            )?;
            self.ns_run_checked(&ns, "ip", &["link", "set", &wg, "up"])?;
            self.ownership.fabric_configured = true;
        }

        // Underlay attachment veth pair.
        let host_veth = names.host_underlay_veth();
        let fabric_veth = names.fabric_underlay_veth();
        let host_show = self.run("ip", &["link", "show", host_veth.as_str()])?;
        let created_underlay = !host_show.success;
        if created_underlay {
            self.run_checked(
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
            self.run_checked("ip", &["link", "set", fabric_veth.as_str(), "netns", &ns])?;
            let host_addr = format!("{}/30", DEFAULT_UNDERLAY_HOST_IP);
            self.run_checked(
                "ip",
                &["addr", "add", host_addr.as_str(), "dev", host_veth.as_str()],
            )?;
            self.run_checked("ip", &["link", "set", host_veth.as_str(), "up"])?;
            let fabric_addr = format!("{}/30", DEFAULT_UNDERLAY_FABRIC_IP);
            self.ns_run_checked(
                &ns,
                "ip",
                &[
                    "addr",
                    "add",
                    fabric_addr.as_str(),
                    "dev",
                    fabric_veth.as_str(),
                ],
            )?;
            self.ns_run_checked(&ns, "ip", &["link", "set", fabric_veth.as_str(), "up"])?;
            let gateway = DEFAULT_UNDERLAY_HOST_IP.to_string();
            self.ns_run_checked(
                &ns,
                "ip",
                &["route", "replace", "default", "via", gateway.as_str()],
            )?;
            self.iptables_add_underlay_rules(&host_veth)?;
            // Fabric forwarding and asymmetric-route tolerance.
            self.ns_run_checked(&ns, "sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
            let host_rp = format!("net.ipv4.conf.{}.rp_filter=0", host_veth);
            self.run_checked("sysctl", &["-w", host_rp.as_str()])?;
            let fabric_rp = format!("net.ipv4.conf.{}.rp_filter=0", fabric_veth);
            self.ns_run_checked(&ns, "sysctl", &["-w", fabric_rp.as_str()])?;
        }

        Ok(FabricReport {
            created_netns,
            created_wireguard,
            created_underlay,
        })
    }

    fn iptables_add_underlay_rules(&mut self, host_veth: &str) -> Result<(), FabricError> {
        let wg_port = self.config.wireguard_port().to_string();
        let fabric_ip = DEFAULT_UNDERLAY_FABRIC_IP.to_string();
        self.run_checked(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                UNDERLAY_PREFIX,
                "-j",
                "MASQUERADE",
            ],
        )?;
        self.run_checked(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "!",
                "-i",
                host_veth,
                "-p",
                "udp",
                "--dport",
                wg_port.as_str(),
                "-j",
                "DNAT",
                "--to-destination",
                fabric_ip.as_str(),
            ],
        )
    }

    fn iptables_delete_underlay_rules(&mut self, host_veth: &str) -> Result<(), FabricError> {
        let wg_port = self.config.wireguard_port().to_string();
        let fabric_ip = DEFAULT_UNDERLAY_FABRIC_IP.to_string();
        self.run_checked(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                UNDERLAY_PREFIX,
                "-j",
                "MASQUERADE",
            ],
        )?;
        self.run_checked(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "!",
                "-i",
                host_veth,
                "-p",
                "udp",
                "--dport",
                wg_port.as_str(),
                "-j",
                "DNAT",
                "--to-destination",
                fabric_ip.as_str(),
            ],
        )
    }

    // ---- peers ----------------------------------------------------------

    /// Configure the WireGuard peer set as the union over all live plans.
    fn configure_peers(&mut self) -> Result<(), FabricError> {
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        let mut desired: BTreeMap<String, PeerRecord> = BTreeMap::new();
        for plan in self.live_plans()? {
            for peer in &plan.peers {
                desired.insert(
                    peer.public_key.as_str().to_string(),
                    PeerRecord {
                        host_id: peer.host_id.clone(),
                        public_key: peer.public_key.as_str().to_string(),
                        underlay_endpoint: peer.underlay_endpoint.to_string(),
                        fabric_transport_ip: peer.fabric_transport_ip,
                    },
                );
            }
        }

        let current: BTreeMap<String, PeerRecord> = self
            .ownership
            .peers
            .iter()
            .map(|p| (p.public_key.clone(), p.clone()))
            .collect();

        // Remove stale peers first (by public key).
        for (public_key, record) in current.iter() {
            if !desired.contains_key(public_key) {
                self.ns_run_checked(&ns, "wg", &["set", &wg, "peer", public_key, "remove"])?;
                let route = format!("{}/32", record.fabric_transport_ip);
                self.ns_run_checked(&ns, "ip", &["route", "del", route.as_str()])?;
            }
        }
        // Add or refresh desired peers. AllowedIPs carry only the peer's
        // fabric transport /32 — never tenant prefixes.
        for (public_key, record) in desired.iter() {
            let allowed = format!("{}/32", record.fabric_transport_ip);
            self.ns_run_checked(
                &ns,
                "wg",
                &[
                    "set",
                    &wg,
                    "peer",
                    public_key,
                    "endpoint",
                    record.underlay_endpoint.as_str(),
                    "allowed-ips",
                    allowed.as_str(),
                ],
            )?;
            self.ns_run_checked(
                &ns,
                "ip",
                &["route", "replace", allowed.as_str(), "dev", &wg],
            )?;
        }

        self.ownership.peers = desired.into_values().collect();
        Ok(())
    }

    /// Re-assert the WireGuard interface MTU as the maximum `fabric_mtu`
    /// across all live plans.
    ///
    /// `ip link add <if> type wireguard` comes up with the kernel-default
    /// MTU of 1420. VXLAN egress frames can be up to `tenant_mtu + 50`
    /// bytes and plan validation only guarantees `tenant_mtu + 50 <=
    /// fabric_mtu`, so the WireGuard MTU must cover the largest live plan
    /// or large tenant packets fail with EMSGSIZE (or fragment on the
    /// underlay). This runs on every apply: the plan journal is persisted
    /// before `ensure_fabric`, so `live_plans()` already includes the plan
    /// being applied. Re-setting an identical MTU is a benign re-assert,
    /// exactly like `ip addr replace`.
    ///
    /// `remove_network` deliberately does NOT recompute the MTU: a
    /// conservatively larger WireGuard MTU is always safe (it only admits
    /// frames that no live plan emits), while shrinking on teardown would
    /// add a failure mode for zero benefit. The next apply re-converges to
    /// the true maximum over the remaining live plans.
    fn enforce_wireguard_mtu(&mut self) -> Result<(), FabricError> {
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let Some(max_mtu) = self.live_plans()?.iter().map(|plan| plan.fabric_mtu).max() else {
            return Ok(());
        };
        let mtu = max_mtu.to_string();
        self.ns_run_checked(&ns, "ip", &["link", "set", &wg, "mtu", mtu.as_str()])
    }

    // ---- per-network ----------------------------------------------------

    fn ensure_network(
        &mut self,
        plan: &StretchedL2Plan,
        fingerprint: &str,
    ) -> Result<bool, FabricError> {
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let vxlan = names.vxlan(&plan.network_id);
        let bridge = names.fabric_bridge(&plan.network_id);
        let port_veth = names.fabric_port_veth(&plan.network_id);
        let consumer_veth = names.consumer_port_veth(&plan.network_id);

        // VXLAN device: one per network, learning enabled (no `nolearning`).
        let vxlan_show = self.ns_run(&ns, "ip", &["-d", "link", "show", vxlan.as_str()])?;
        let mut created = false;
        if vxlan_show.success {
            verify_vxlan_identity(&vxlan, plan, &vxlan_show.stdout)?;
        } else {
            let vni = plan.vni.get().to_string();
            let dstport = self.config.vxlan_port().to_string();
            let local = plan.local_transport_ip.to_string();
            self.ns_run_checked(
                &ns,
                "ip",
                &[
                    "link",
                    "add",
                    vxlan.as_str(),
                    "type",
                    "vxlan",
                    "id",
                    vni.as_str(),
                    "dstport",
                    dstport.as_str(),
                    "local",
                    local.as_str(),
                    "dev",
                    &wg,
                ],
            )?;
            let mtu = plan.tenant_mtu.to_string();
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "set", vxlan.as_str(), "mtu", mtu.as_str()],
            )?;
            self.ns_run_checked(&ns, "ip", &["link", "set", vxlan.as_str(), "up"])?;
            created = true;
        }

        // Fabric-side bridge.
        let bridge_show = self.ns_run(&ns, "ip", &["link", "show", bridge.as_str()])?;
        let created_bridge = !bridge_show.success;
        if created_bridge {
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "add", bridge.as_str(), "type", "bridge"],
            )?;
            self.ns_run_checked(&ns, "ip", &["link", "set", bridge.as_str(), "up"])?;
            created = true;
        }
        if created {
            // Enslave the VXLAN to the learning bridge.
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "set", vxlan.as_str(), "master", bridge.as_str()],
            )?;
        }

        // Consumer attachment veth pair.
        let consumer_show = self.run("ip", &["link", "show", consumer_veth.as_str()])?;
        let created_veth = !consumer_show.success;
        if created_veth {
            self.run_checked(
                "ip",
                &[
                    "link",
                    "add",
                    consumer_veth.as_str(),
                    "type",
                    "veth",
                    "peer",
                    "name",
                    port_veth.as_str(),
                ],
            )?;
            self.run_checked("ip", &["link", "set", port_veth.as_str(), "netns", &ns])?;
            let mtu = plan.tenant_mtu.to_string();
            self.run_checked(
                "ip",
                &["link", "set", consumer_veth.as_str(), "mtu", mtu.as_str()],
            )?;
            self.run_checked("ip", &["link", "set", consumer_veth.as_str(), "up"])?;
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "set", port_veth.as_str(), "master", bridge.as_str()],
            )?;
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "set", port_veth.as_str(), "mtu", mtu.as_str()],
            )?;
            self.ns_run_checked(&ns, "ip", &["link", "set", port_veth.as_str(), "up"])?;
            created = true;
        }

        // Bounded head-end replication flood list (diffed for idempotency).
        // Flood entries share the all-zeros (non-unicast) MAC, so adds MUST
        // use `append` — the kernel rejects `replace` on non-unicast entries,
        // and replace semantics would in any case clobber the other remotes.
        let desired: BTreeSet<Ipv4Addr> = plan.flood_list();
        let current: BTreeSet<Ipv4Addr> = self
            .ownership
            .networks
            .get(&plan.network_id)
            .map(|entry| entry.flood_peers.iter().copied().collect())
            .unwrap_or_default();
        for ip in desired.difference(&current) {
            self.ns_fdb(&ns, "append", &vxlan, ip)?;
        }
        for ip in current.difference(&desired) {
            self.ns_fdb(&ns, "del", &vxlan, ip)?;
        }

        self.ownership.networks.insert(
            plan.network_id.clone(),
            NetworkOwnership {
                plan_fingerprint: fingerprint.to_string(),
                vni: plan.vni.get(),
                vxlan_name: vxlan,
                bridge_name: bridge,
                fabric_port_veth: port_veth,
                consumer_port_veth: consumer_veth,
                flood_peers: desired.into_iter().collect(),
            },
        );
        Ok(created)
    }

    // ---- helpers ----------------------------------------------------------

    fn live_plans(&self) -> Result<Vec<StretchedL2Plan>, FabricError> {
        let mut plans = Vec::new();
        let entries = match fs::read_dir(self.config.plans_dir()) {
            Ok(entries) => entries,
            Err(_) => return Ok(plans),
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            match serde_json::from_str::<StretchedL2Plan>(&raw) {
                Ok(plan) => plans.push(plan),
                Err(e) => {
                    return Err(FabricError::Ownership(format!(
                        "plan journal {} is corrupt: {e}",
                        path.display()
                    )));
                }
            }
        }
        Ok(plans)
    }

    fn persist_plan(&self, plan: &StretchedL2Plan) -> Result<(), FabricError> {
        let path = self.config.plan_path(&plan.network_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_string_pretty(plan)
            .map_err(|e| FabricError::Invalid(format!("plan serialization failed: {e}")))?;
        crate::ownership::atomic_write(&path, &encoded)
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, FabricError> {
        self.runner.run(program, args)
    }

    fn run_checked(&mut self, program: &str, args: &[&str]) -> Result<(), FabricError> {
        let output = self.runner.run(program, args)?;
        if output.success {
            Ok(())
        } else {
            Err(FabricError::Command(format!(
                "{program} {} failed: {}",
                args.join(" "),
                output.stderr.trim()
            )))
        }
    }

    fn ns_run(
        &mut self,
        ns: &str,
        program: &str,
        args: &[&str],
    ) -> Result<CommandOutput, FabricError> {
        let mut full: Vec<&str> = vec!["netns", "exec", ns, program];
        full.extend_from_slice(args);
        self.runner.run("ip", &full)
    }

    fn ns_run_checked(
        &mut self,
        ns: &str,
        program: &str,
        args: &[&str],
    ) -> Result<(), FabricError> {
        let output = self.ns_run(ns, program, args)?;
        if output.success {
            Ok(())
        } else {
            Err(FabricError::Command(format!(
                "ip netns exec {ns} {program} {} failed: {}",
                args.join(" "),
                output.stderr.trim()
            )))
        }
    }

    fn ns_fdb(
        &mut self,
        ns: &str,
        op: &str,
        vxlan: &str,
        ip: &Ipv4Addr,
    ) -> Result<(), FabricError> {
        let dst = ip.to_string();
        self.ns_run_checked(
            ns,
            "bridge",
            &["fdb", op, FLOOD_MAC, "dev", vxlan, "dst", dst.as_str()],
        )
    }
}

fn config_names(config: &FabricLinuxConfig) -> Result<Names, FabricError> {
    Names::new(config.name_prefix())
}

fn path_arg(path: &Path) -> Result<String, FabricError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| FabricError::Invalid("private key path is not valid UTF-8".to_string()))
}

/// Verify an observed VXLAN device matches the plan identity; fail closed on
/// foreign state.
fn verify_vxlan_identity(
    name: &str,
    plan: &StretchedL2Plan,
    observed: &str,
) -> Result<(), FabricError> {
    let expected_vni = format!("id {}", plan.vni.get());
    if !observed.contains(&expected_vni) {
        return Err(FabricError::ForeignState {
            object: name.to_string(),
            expected: format!("vxlan {expected_vni}"),
            observed: observed.trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;
    use fabric_plan::{FabricPeer, PlanError, PublicKey, UnderlayEndpoint, Vni};
    use std::path::PathBuf;

    fn test_plan(
        network_id: &str,
        vni: u32,
        tenant_mtu: u32,
        fabric_mtu: u32,
    ) -> Result<StretchedL2Plan, PlanError> {
        Ok(StretchedL2Plan {
            fabric_domain_id: "fab-1".to_string(),
            local_host_id: "host-01".to_string(),
            local_transport_ip: Ipv4Addr::new(198, 18, 0, 1),
            network_id: network_id.to_string(),
            vni: Vni::new(vni)?,
            binding_generation: 1,
            tenant_mtu,
            fabric_mtu,
            peers: vec![FabricPeer {
                host_id: "host-02".to_string(),
                public_key: PublicKey::new("K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=")?,
                underlay_endpoint: UnderlayEndpoint::parse("198.51.100.10:65001")?,
                fabric_transport_ip: Ipv4Addr::new(198, 18, 0, 2),
            }],
            plan_generation: 1,
        })
    }

    fn test_root(tag: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "fabric-provider-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn plan_error(e: PlanError) -> FabricError {
        FabricError::Invalid(e.to_string())
    }

    #[test]
    fn apply_sets_wireguard_mtu_to_plan_fabric_mtu() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-mtu")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let expected_cmd = format!(
            "ip netns exec {} ip link set {} mtu 1440",
            names.fabric_namespace(),
            names.wireguard_interface()
        );
        let command_seen = provider
            .runner()
            .calls()
            .iter()
            .any(|call| call.joined() == expected_cmd);
        let state_mtu = provider.runner().link_mtu(&names.wireguard_interface());
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            command_seen,
            "apply must set the WireGuard MTU via: {expected_cmd}"
        );
        assert_eq!(state_mtu, Some(1440));
        Ok(())
    }

    #[test]
    fn wireguard_mtu_follows_maximum_fabric_mtu_across_live_plans()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-mtu-max")?;
        let config = FabricLinuxConfig::new(&root);
        let small = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let large = test_plan("net-b", 200, 1410, 1460).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&small)?;
        assert_eq!(
            provider.runner().link_mtu(&names.wireguard_interface()),
            Some(1440)
        );
        // Applying a second plan with a larger fabric_mtu raises the shared
        // WireGuard MTU to the new maximum.
        provider.apply_plan(&large)?;
        let raised = provider.runner().link_mtu(&names.wireguard_interface());
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert_eq!(raised, Some(1460));
        Ok(())
    }

    #[test]
    fn wireguard_mtu_does_not_shrink_on_network_removal() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("wg-mtu-keep")?;
        let config = FabricLinuxConfig::new(&root);
        let small = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let large = test_plan("net-b", 200, 1410, 1460).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&small)?;
        provider.apply_plan(&large)?;
        provider.remove_network("net-b")?;
        // remove_network deliberately keeps the (conservatively larger)
        // WireGuard MTU; the next apply re-converges to the true maximum.
        let kept = provider.runner().link_mtu(&names.wireguard_interface());
        provider.apply_plan(&small)?;
        let converged = provider.runner().link_mtu(&names.wireguard_interface());
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert_eq!(kept, Some(1460));
        assert_eq!(converged, Some(1440));
        Ok(())
    }

    #[test]
    fn wireguard_mtu_is_reasserted_on_idempotent_replay() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("wg-mtu-replay")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        provider.apply_plan(&plan)?;
        let mtu_sets = provider
            .runner()
            .calls()
            .iter()
            .filter(|call| {
                let wg = names.wireguard_interface();
                call.joined()
                    .contains(&format!("ip link set {wg} mtu 1440"))
            })
            .count();
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert_eq!(
            mtu_sets, 2,
            "every apply re-asserts the WireGuard MTU (benign, like addr replace)"
        );
        Ok(())
    }
}
