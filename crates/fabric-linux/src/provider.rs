//! The Linux fabric provider: idempotent realization of stretched-L2 plans.
//!
//! Realization order (see `contracts/fabric-provider-v1.md`):
//! validate plan -> journal plan -> ensure fabric (netns/WireGuard/underlay)
//! -> configure peers (union over live plans) -> re-assert the WireGuard MTU
//! (maximum fabric_mtu across live plans) -> ensure network (VXLAN +
//! learning bridge + attachment veth + bounded HER flood list) -> save
//! ownership. Teardown runs in reverse dependency order and preserves the
//! WireGuard private key.
//!
//! Reconciliation is re-assertive, not create-only: enslavement, link
//! state, MTUs, and the local transport address are re-asserted on every
//! apply (all through idempotent `replace`/`set` verbs), and every desired
//! HER flood entry is re-appended on every apply, so a crash between two
//! mutations — or a kernel that lost state — heals on the next apply.
//! Teardown is idempotent in the same sense: deleting an object that is
//! already absent is success, and the journals always converge to the
//! desired end state.

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
    /// The WireGuard private key and the shared fabric survive. Teardown is
    /// idempotent: objects that are already absent (a rebooted kernel, a
    /// partially completed earlier teardown) count as removed, and the
    /// plan journal plus ownership entry are dropped unconditionally so
    /// the journals converge to the desired end state. Unexpected errors
    /// still fail closed.
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

        // When the fabric namespace itself is gone (e.g. the kernel was
        // rebooted while the journals survived), every ns-scoped object is
        // gone with it; only the host-scoped deletion remains to run.
        if self.has_fabric_netns(&ns)? {
            // Flood entries first (absent entries are tolerated).
            for ip in &entry.flood_peers {
                self.ns_fdb_del(&ns, &entry.vxlan_name, ip)?;
            }
            // VXLAN, then bridge.
            self.ns_run_tolerant(&ns, "ip", &["link", "del", &entry.vxlan_name])?;
            self.ns_run_tolerant(&ns, "ip", &["link", "del", &entry.bridge_name])?;
        }
        // Attachment veth pair (deleting one end removes both).
        self.run_tolerant("ip", &["link", "del", &entry.consumer_port_veth])?;

        // Drop the plan journal and ownership entry — always, so that a
        // teardown interrupted anywhere still converges on retry.
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
    /// Like [`Self::remove_network`], this converges idempotently: absent
    /// objects count as removed, so a host whose kernel never saw the
    /// fabric (or lost it across a reboot) still reports `Ok(true)`.
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

        // The ns-scoped deletions are skipped when the namespace is
        // already gone; the remaining deletions tolerate absent objects.
        if self.has_fabric_netns(&ns)? {
            self.ns_run_tolerant(&ns, "ip", &["link", "del", &wg])?;
        }
        self.run_tolerant("ip", &["link", "del", host_veth.as_str()])?;
        self.iptables_delete_underlay_rules(&host_veth)?;
        if self.has_fabric_netns(&ns)? {
            self.run_tolerant("ip", &["netns", "del", &ns])?;
        }

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
        let has_ns = self.has_fabric_netns(&ns)?;
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

        // Key and listen port: on creation, or the first apply after a
        // crash that lost the configured flag while the link survived.
        // (Re-asserting these would be harmless but is not needed.)
        if created_wireguard || !self.ownership.fabric_configured {
            let key_path =
                keys::ensure_private_key(&self.config.private_key_path(), &mut self.runner)?;
            let key_arg = path_arg(&key_path)?;
            self.ns_run_checked(&ns, "wg", &["set", &wg, "private-key", key_arg.as_str()])?;
            let port = self.config.wireguard_port().to_string();
            self.ns_run_checked(&ns, "wg", &["set", &wg, "listen-port", port.as_str()])?;
            self.ownership.fabric_configured = true;
        }
        // The local transport address is a mutable plan field: re-assert
        // it on every apply (`ip addr replace` is idempotent) so a plan
        // that changes it — or a crash between creation and addressing —
        // converges.
        let local_addr = format!("{}/32", plan.local_transport_ip);
        self.ns_run_checked(
            &ns,
            "ip",
            &["addr", "replace", local_addr.as_str(), "dev", &wg],
        )?;
        self.ns_run_checked(&ns, "ip", &["link", "set", &wg, "up"])?;

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
        }
        // Addressing, link state, and the default route are re-asserted on
        // every apply (all idempotent verbs): a crash between the pair
        // creation and any of these steps must not leave a permanently
        // half-plumbed underlay that re-apply reports as healthy.
        let host_addr = format!("{}/30", DEFAULT_UNDERLAY_HOST_IP);
        self.run_checked(
            "ip",
            &[
                "addr",
                "replace",
                host_addr.as_str(),
                "dev",
                host_veth.as_str(),
            ],
        )?;
        self.run_checked("ip", &["link", "set", host_veth.as_str(), "up"])?;
        let fabric_addr = format!("{}/30", DEFAULT_UNDERLAY_FABRIC_IP);
        self.ns_run_checked(
            &ns,
            "ip",
            &[
                "addr",
                "replace",
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
        if created_underlay {
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
        // Tolerant: absent rules ("Bad rule ...") mean the desired end
        // state is already reached (e.g. a rebooted kernel).
        self.run_tolerant(
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
        self.run_tolerant(
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
    ///
    /// When the fabric namespace is absent the kernel holds no peer state;
    /// the kernel commands are skipped and the journal records the desired
    /// set (the next apply realizes it after recreating the namespace).
    fn configure_peers(&mut self) -> Result<(), FabricError> {
        let names = config_names(&self.config)?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let ns_present = self.has_fabric_netns(&ns)?;

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

        if ns_present {
            // Remove stale peers first (by public key).
            for (public_key, record) in current.iter() {
                if !desired.contains_key(public_key) {
                    self.ns_run_checked(&ns, "wg", &["set", &wg, "peer", public_key, "remove"])?;
                    // The route may already be gone (partial teardown).
                    let route = format!("{}/32", record.fabric_transport_ip);
                    self.ns_run_tolerant(&ns, "ip", &["route", "del", route.as_str()])?;
                }
            }
            // Add or refresh desired peers. AllowedIPs carry only the peer's
            // fabric transport /32 — never tenant prefixes.
            for (public_key, record) in desired.iter() {
                // A kept peer that moved to a new transport IP leaves a
                // stale /32 route behind; withdraw it before the replace
                // for the new address (it may already be gone).
                if let Some(previous) = current.get(public_key)
                    && previous.fabric_transport_ip != record.fabric_transport_ip
                {
                    let stale = format!("{}/32", previous.fabric_transport_ip);
                    self.ns_run_tolerant(&ns, "ip", &["route", "del", stale.as_str()])?;
                }
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
        let mut created = false;

        // VXLAN device: one per network, learning enabled (no `nolearning`).
        let vxlan_show = self.ns_run(&ns, "ip", &["-d", "link", "show", vxlan.as_str()])?;
        if vxlan_show.success {
            verify_vxlan_identity(&vxlan, plan, self.config.vxlan_port(), &vxlan_show.stdout)?;
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
            created = true;
        }

        // Fabric-side bridge.
        let bridge_show = self.ns_run(&ns, "ip", &["link", "show", bridge.as_str()])?;
        if !bridge_show.success {
            self.ns_run_checked(
                &ns,
                "ip",
                &["link", "add", bridge.as_str(), "type", "bridge"],
            )?;
            created = true;
        }

        // Enslavement, MTU, and link state are UNCONDITIONAL re-asserts on
        // every apply: a crash between object creation and any of these
        // steps must not leave a half-plumbed network that re-apply
        // reports as healthy. All verbs are idempotent.
        self.ns_run_checked(&ns, "ip", &["link", "set", bridge.as_str(), "up"])?;
        let mtu = plan.tenant_mtu.to_string();
        self.ns_run_checked(
            &ns,
            "ip",
            &["link", "set", vxlan.as_str(), "mtu", mtu.as_str()],
        )?;
        self.ns_run_checked(
            &ns,
            "ip",
            &["link", "set", vxlan.as_str(), "master", bridge.as_str()],
        )?;
        self.ns_run_checked(&ns, "ip", &["link", "set", vxlan.as_str(), "up"])?;

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
            created = true;
        }
        // Re-asserted on every apply (see above).
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

        // Bounded head-end replication flood list.
        //
        // Every desired entry is APPENDED on every apply: `append` is
        // idempotent per (dev, mac, dst), and diffing against the journal
        // would leave a recreated (post-reboot) VXLAN without flood
        // entries — a green apply with dead BUM flooding. Entries in the
        // journal but no longer desired are deleted (tolerantly: they may
        // already be gone). Flood entries share the all-zeros
        // (non-unicast) MAC, so adds MUST use `append` — the kernel
        // rejects `replace` on non-unicast entries, and replace semantics
        // would in any case clobber the other remotes.
        let desired: BTreeSet<Ipv4Addr> = plan.flood_list();
        let current: BTreeSet<Ipv4Addr> = self
            .ownership
            .networks
            .get(&plan.network_id)
            .map(|entry| entry.flood_peers.iter().copied().collect())
            .unwrap_or_default();
        for ip in &desired {
            self.ns_fdb_append(&ns, &vxlan, ip)?;
        }
        for ip in current.difference(&desired) {
            self.ns_fdb_del(&ns, &vxlan, ip)?;
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

    /// True when the fabric network namespace currently exists.
    ///
    /// Fails closed when the listing itself fails (the provider cannot
    /// know what is safe to delete).
    fn has_fabric_netns(&mut self, ns: &str) -> Result<bool, FabricError> {
        let listing = self.run("ip", &["netns", "list"])?;
        if !listing.success {
            return Err(FabricError::Command(format!(
                "ip netns list failed: {}",
                listing.stderr.trim()
            )));
        }
        Ok(listing
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(ns)))
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

    /// Run a deletion and treat "object already absent" as success.
    ///
    /// Used only on teardown paths, where the desired end state of the
    /// command is already reached when the object is gone. Any other
    /// failure is a hard error (fail closed).
    fn run_tolerant(&mut self, program: &str, args: &[&str]) -> Result<(), FabricError> {
        let output = self.runner.run(program, args)?;
        if output.success || object_already_absent(&output.stderr) {
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

    /// Namespaced deletion with absence tolerance (see [`Self::run_tolerant`]).
    fn ns_run_tolerant(
        &mut self,
        ns: &str,
        program: &str,
        args: &[&str],
    ) -> Result<(), FabricError> {
        let output = self.ns_run(ns, program, args)?;
        if output.success || object_already_absent(&output.stderr) {
            Ok(())
        } else {
            Err(FabricError::Command(format!(
                "ip netns exec {ns} {program} {} failed: {}",
                args.join(" "),
                output.stderr.trim()
            )))
        }
    }

    /// Append one HER flood entry (`append` is idempotent per
    /// (dev, mac, dst); the kernel rejects `replace` here).
    fn ns_fdb_append(&mut self, ns: &str, vxlan: &str, ip: &Ipv4Addr) -> Result<(), FabricError> {
        let dst = ip.to_string();
        self.ns_run_checked(
            ns,
            "bridge",
            &[
                "fdb",
                "append",
                FLOOD_MAC,
                "dev",
                vxlan,
                "dst",
                dst.as_str(),
            ],
        )
    }

    /// Delete one HER flood entry, tolerating an already-absent entry.
    fn ns_fdb_del(&mut self, ns: &str, vxlan: &str, ip: &Ipv4Addr) -> Result<(), FabricError> {
        let dst = ip.to_string();
        self.ns_run_tolerant(
            ns,
            "bridge",
            &["fdb", "del", FLOOD_MAC, "dev", vxlan, "dst", dst.as_str()],
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
///
/// The `ip -d link show` output is token-parsed: the tokens following
/// `id`, `dstport`, and `local` must match the plan's VNI, the configured
/// VXLAN port, and the plan's local transport IP exactly. Substring
/// matching would let VNI 100 accept a foreign VNI 1000.
fn verify_vxlan_identity(
    name: &str,
    plan: &StretchedL2Plan,
    vxlan_port: u16,
    observed: &str,
) -> Result<(), FabricError> {
    let tokens: Vec<&str> = observed.split_whitespace().collect();
    let token_after = |flag: &str| -> Option<&str> {
        tokens
            .iter()
            .position(|t| *t == flag)
            .and_then(|i| tokens.get(i + 1).copied())
    };
    let mismatch = |field: &str, expected_value: &str| FabricError::ForeignState {
        object: name.to_string(),
        expected: format!("{field} {expected_value}"),
        observed: observed.trim().to_string(),
    };
    let observed_vni =
        token_after("id").ok_or_else(|| mismatch("vxlan id", &plan.vni.get().to_string()))?;
    if observed_vni != plan.vni.get().to_string() {
        return Err(mismatch("vxlan id", &plan.vni.get().to_string()));
    }
    let observed_dstport =
        token_after("dstport").ok_or_else(|| mismatch("vxlan dstport", &vxlan_port.to_string()))?;
    if observed_dstport != vxlan_port.to_string() {
        return Err(mismatch("vxlan dstport", &vxlan_port.to_string()));
    }
    let observed_local = token_after("local")
        .ok_or_else(|| mismatch("vxlan local", &plan.local_transport_ip.to_string()))?;
    if observed_local != plan.local_transport_ip.to_string() {
        return Err(mismatch(
            "vxlan local",
            &plan.local_transport_ip.to_string(),
        ));
    }
    Ok(())
}

/// stderr fragments indicating that the object a deletion targets is
/// already absent — the desired end state of the command is reached.
///
/// Kept in the provider (not the fake kernel) on purpose: the fake fails
/// like the real `ip`/`iptables`, and only the provider decides that an
/// absent object means success during teardown.
fn object_already_absent(stderr: &str) -> bool {
    const ABSENT_PATTERNS: &[&str] = &[
        // `ip link del` on a missing device (iproute2 wording varies).
        "Cannot find device",
        "does not exist",
        // `bridge fdb del` / `ip route del` of a missing entry.
        "No such file or directory",
        // `ip netns exec` into a namespace lost between check and delete.
        "Cannot open network namespace",
        // `iptables -D` of a rule that is not present.
        "Bad rule",
    ];
    ABSENT_PATTERNS
        .iter()
        .any(|pattern| stderr.contains(pattern))
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

    // ---- C1: exact (token-level) VXLAN identity verification ------------

    /// Realistic `ip -d link show` output for a VXLAN device.
    fn vxlan_show(vni: u32, dstport: u16, local: &str) -> String {
        format!(
            "9: o3k-x-1a2b3c4d: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP \n    \
             vxlan id {vni} local {local} dstport {dstport} learning\n"
        )
    }

    fn identity_result(vni: u32, observed: &str) -> Result<(), FabricError> {
        let plan = test_plan("net-a", vni, 1380, 1440).map_err(plan_error)?;
        verify_vxlan_identity("o3k-x-1a2b3c4d", &plan, 4789, observed)
    }

    #[test]
    fn vxlan_identity_rejects_prefix_vni() -> Result<(), FabricError> {
        // VNI 100 must not match an observed 1000 (substring trap).
        let observed = vxlan_show(1000, 4789, "198.18.0.1");
        match identity_result(100, &observed) {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(FabricError::Invalid(format!(
                "prefix VNI must be rejected, got {other:?}"
            ))),
        }
    }

    #[test]
    fn vxlan_identity_accepts_exact_vni() -> Result<(), FabricError> {
        let observed = vxlan_show(200, 4789, "198.18.0.1");
        identity_result(200, &observed)
    }

    #[test]
    fn vxlan_identity_rejects_wrong_dstport() -> Result<(), FabricError> {
        let observed = vxlan_show(100, 8472, "198.18.0.1");
        match identity_result(100, &observed) {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(FabricError::Invalid(format!(
                "foreign dstport must be rejected, got {other:?}"
            ))),
        }
    }

    #[test]
    fn vxlan_identity_rejects_wrong_local_ip() -> Result<(), FabricError> {
        let observed = vxlan_show(100, 4789, "198.18.0.7");
        match identity_result(100, &observed) {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(FabricError::Invalid(format!(
                "foreign local transport IP must be rejected, got {other:?}"
            ))),
        }
    }

    #[test]
    fn vxlan_identity_rejects_missing_identity_tokens() -> Result<(), FabricError> {
        // A VXLAN without a `local` (anycast) must not pass verification.
        let observed = "9: o3k-x-1a2b3c4d: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP \n    \
             vxlan id 100 dstport 4789 learning\n";
        match identity_result(100, observed) {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(FabricError::Invalid(format!(
                "missing local token must be rejected, got {other:?}"
            ))),
        }
    }

    // ---- M1: idempotent teardown across a lost kernel -------------------

    #[test]
    fn teardown_converges_when_kernel_lost_all_state() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("teardown-lost")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let network_id = plan.network_id.clone();
        let names = Names::new(config.name_prefix())?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let _runner = provider.into_runner();

        // Rebooted kernel: fresh fake, same state root.
        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.remove_network(&network_id)?;
        assert!(provider.ownership().networks.is_empty());
        assert!(!config.plan_path(&network_id).exists());
        assert!(provider.remove_fabric_if_unused()?);
        assert!(!provider.runner().has_netns(&names.fabric_namespace()));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        Ok(())
    }

    // ---- M2: unconditional HER flood append ------------------------------

    #[test]
    fn flood_entries_are_reappended_after_kernel_loss() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("flood-reassert")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let network_id = plan.network_id.clone();
        let names = Names::new(config.name_prefix())?;
        let vxlan = names.vxlan(&network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert!(
            provider
                .runner()
                .has_fdb_entry(vxlan.as_str(), FLOOD_MAC, "198.18.0.2")
        );
        let mut runner = provider.into_runner();

        // The kernel loses the fdb (e.g. the VXLAN was recreated) while
        // the journal still lists the flood peers.
        let out = runner.run(
            "bridge",
            &[
                "fdb",
                "del",
                FLOOD_MAC,
                "dev",
                vxlan.as_str(),
                "dst",
                "198.18.0.2",
            ],
        )?;
        assert!(
            out.success,
            "could not drop the flood entry: {}",
            out.stderr
        );
        assert!(!runner.has_fdb_entry(vxlan.as_str(), FLOOD_MAC, "198.18.0.2"));

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let healed = provider
            .runner()
            .has_fdb_entry(vxlan.as_str(), FLOOD_MAC, "198.18.0.2");
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            healed,
            "re-apply must re-append HER flood entries the kernel lost"
        );
        Ok(())
    }

    // ---- M3/M4: re-asserted enslavement, MTUs, transport address ---------

    #[test]
    fn enslavement_and_link_up_are_reasserted_on_every_apply()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("reassert")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let vxlan = names.vxlan(&plan.network_id);
        let bridge = names.fabric_bridge(&plan.network_id);
        let port_veth = names.fabric_port_veth(&plan.network_id);
        let consumer_veth = names.consumer_port_veth(&plan.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        provider.apply_plan(&plan)?;
        let count = |needle: &str| {
            provider
                .runner()
                .calls()
                .iter()
                .filter(|call| call.joined().contains(needle))
                .count()
        };
        let vxlan_master = count(&format!("ip link set {vxlan} master {bridge}"));
        let port_master = count(&format!("ip link set {port_veth} master {bridge}"));
        let port_up = count(&format!("ip link set {port_veth} up"));
        let consumer_up = count(&format!("ip link set {consumer_veth} up"));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        // Two applies: every re-assert must have run twice.
        assert_eq!(vxlan_master, 2, "vxlan enslavement must be re-asserted");
        assert_eq!(port_master, 2, "port veth enslavement must be re-asserted");
        assert_eq!(
            port_up, 2,
            "fabric-side port veth must be set up on every apply"
        );
        assert_eq!(
            consumer_up, 2,
            "consumer veth must be set up on every apply"
        );
        Ok(())
    }

    #[test]
    fn mtu_changes_are_applied_to_existing_objects() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("mtu-move")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-a", 100, 1400, 1460).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let network_id = plan_a.network_id.clone();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        let vxlan_mtu = provider.runner().link_mtu(&names.vxlan(&network_id));
        let consumer_mtu = provider
            .runner()
            .link_mtu(&names.consumer_port_veth(&network_id));
        let port_mtu = provider
            .runner()
            .link_mtu(&names.fabric_port_veth(&network_id));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert_eq!(vxlan_mtu, Some(1400), "vxlan MTU must follow the plan");
        assert_eq!(
            consumer_mtu,
            Some(1400),
            "consumer veth MTU must follow the plan"
        );
        assert_eq!(
            port_mtu,
            Some(1400),
            "fabric-side port veth MTU must follow the plan"
        );
        Ok(())
    }

    #[test]
    fn local_transport_addr_is_reasserted_via_addr_replace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("local-reassert")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert!(provider.runner().has_addr(&wg, "198.18.0.1/32"));
        let mut runner = provider.into_runner();

        // The kernel loses the transport address (e.g. the WireGuard link
        // was recreated after a crash) while the journals survive.
        let out = runner.run(
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                "ip",
                "addr",
                "del",
                "198.18.0.1/32",
                "dev",
                &wg,
            ],
        )?;
        assert!(
            out.success,
            "could not drop the transport addr: {}",
            out.stderr
        );
        assert!(!runner.has_addr(&wg, "198.18.0.1/32"));

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let healed = provider.runner().has_addr(&wg, "198.18.0.1/32");
        let replace_cmd = format!("ip addr replace 198.18.0.1/32 dev {wg}");
        let command_seen = provider
            .runner()
            .calls()
            .iter()
            .any(|call| call.joined().contains(&replace_cmd));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            command_seen,
            "the transport address must be re-asserted via addr replace"
        );
        assert!(healed, "re-apply must restore the transport address");
        Ok(())
    }

    #[test]
    fn changing_local_transport_ip_fails_closed_on_existing_vxlan()
    -> Result<(), Box<dyn std::error::Error>> {
        // A plan that moves the local transport IP conflicts with the
        // identity (local address) of the VXLAN the provider already
        // owns: foreign state, never adopted (the WireGuard /32 is
        // re-asserted via addr replace; the VXLAN is not touched).
        let root = test_root("local-move")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let mut plan_b = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        plan_b.local_transport_ip = Ipv4Addr::new(198, 18, 0, 9);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        let result = provider.apply_plan(&plan_b);
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        match result {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(Box::new(FabricError::Invalid(format!(
                "a moved local transport IP must fail closed on the existing \
                 vxlan, got {other:?}"
            )))),
        }
    }

    // ---- m8: stale /32 route when a kept peer moves ----------------------

    #[test]
    fn peer_transport_move_deletes_the_stale_route() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("peer-move")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let mut plan_b = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        plan_b.peers[0].fabric_transport_ip = Ipv4Addr::new(198, 18, 0, 9);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        assert!(provider.runner().has_route("198.18.0.2/32"));
        provider.apply_plan(&plan_b)?;
        let new_route = provider.runner().has_route("198.18.0.9/32");
        let old_route = provider.runner().has_route("198.18.0.2/32");
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(new_route, "the peer's new transport /32 must be routed");
        assert!(
            !old_route,
            "the peer's stale transport /32 must be withdrawn"
        );
        Ok(())
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
