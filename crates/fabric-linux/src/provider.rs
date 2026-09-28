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
//! apply (all through idempotent `replace`/`set` verbs), and the HER
//! flood list is reconciled against the OBSERVED forwarding state
//! (append-missing / delete-unwanted / deduplicate — the kernel does
//! not guarantee `bridge fdb append` deduplication, and each
//! `bridge fdb del` removes exactly one instance), so a crash between
//! two mutations
//! — or a kernel that lost state — heals on the next apply. Teardown is
//! idempotent in the same sense: deleting an object that is already
//! absent is success, and the journals always converge to the desired
//! end state.

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
    ///
    /// Naming caveat: the shared-fabric object names (WireGuard link,
    /// host underlay veth, iptables rules) are re-rendered from the
    /// CURRENT configuration, not from the journal — so a `name_prefix`
    /// (or port) change between create and teardown leaves the
    /// old-prefix shared objects behind. Network-scoped objects are
    /// immune: they are deleted by their journal-recorded names.
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
        // The WireGuard link is gone with the namespace; the born-in-ns
        // claim must not outlive it (a later re-apply re-establishes it).
        self.ownership.wireguard_born_in_fabric_ns = false;
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
        //
        // INVARIANT (contract §3.10): the interface MUST be created from
        // INSIDE the fabric namespace. A WireGuard interface's UDP socket
        // binds in the namespace the interface was CREATED in, and that
        // binding is immutable for the interface's lifetime — moving the
        // link into another namespace (or toggling it down/up inside the
        // new namespace) never moves the socket. Empirically verified on
        // kernel 6.8: `ip link add w type wireguard` in the root ns
        // followed by `ip link set w netns <ns>` leaves the listening
        // socket in the ROOT ns. The underlay DNAT rule then rewrites
        // every NEW inbound UDP flow to the fabric-side underlay address
        // — into the fabric namespace, where nothing listens — so those
        // flows are silently black-holed (the kernel answers with a
        // conntrack-reverse-NAT'd ICMP port-unreachable and the wg never
        // sees the packet). Pairs survive only while a peer's outbound
        // conntrack reply-tuple shields the flow from the NAT table,
        // which makes the failure intermittent and timing-dependent.
        let wg_show = self.ns_run(&ns, "ip", &["link", "show", &wg])?;
        let wg_in_ns = wg_show.success;
        let mut created_wireguard = false;
        if !wg_in_ns {
            // No WireGuard interface inside the fabric namespace. A stray
            // link with our deterministic name may sit in the ROOT
            // namespace (the legacy create-then-move sequence, crashed
            // between add and move): it can never carry a usable socket
            // placement for us, so it is swept tolerantly — absence is
            // the normal case — before the interface is created inside
            // the namespace.
            //
            // The sweep is gated on OWNERSHIP EVIDENCE (contract §3.10):
            // journal-before-mutate means every object the old code ever
            // created was preceded by an ownership-journal write, so a
            // genuine legacy add-then-crash-before-move stray implies a
            // journal that shows we own(ed) fabric state. ONE EXCEPTION:
            // the released v0.1.0/v0.1.1 code saved the ownership journal
            // only at the END of apply, so a crash on the very FIRST
            // apply in the add→move window leaves a stray with an empty
            // journal — that state wedges fail-closed here and on the
            // collision check below (manual cleanup is the remedy; it is
            // no worse than the released baseline, which also wedged).
            // On a fresh host (no journal) a root-ns link with our
            // deterministic name is FOREIGN state and must not be
            // deleted here — the both-namespaces collision check in the
            // healthy path below fails closed on it instead once the
            // ns-scoped interface exists.
            if self.owns_fabric_state() {
                self.run_tolerant("ip", &["link", "del", &wg])?;
            }
            // Crash-window recovery for a LEGACY journal (born-in-ns
            // flag not yet set) whose WireGuard was lost entirely —
            // including the crash window of a heal that deleted the wg
            // BEFORE the recorded VXLANs. Every recorded VXLAN binds
            // `dev <wg>`, and that underlay reference died with the old
            // interface, so the recorded VXLANs are stale even though
            // identity verification cannot see the binding (contract
            // §3.3): they are deleted tolerantly, by journal-recorded
            // name, before the replacement wg exists. This apply's
            // network re-creates its VXLAN below; other networks heal
            // on their next apply.
            if !self.ownership.wireguard_born_in_fabric_ns && !self.ownership.networks.is_empty() {
                self.delete_recorded_vxlans(&ns)?;
            }
            self.ns_run_checked(&ns, "ip", &["link", "add", &wg, "type", "wireguard"])?;
            created_wireguard = true;
        } else if !self.ownership.wireguard_born_in_fabric_ns {
            // LEGACY HEAL (one-time upgrade; contract §3.10): the wg link
            // lives in the fabric namespace, but the journal predates the
            // born-in-fabric-ns invariant — the interface was created in
            // the root namespace and moved in, so its UDP socket is bound
            // in the ROOT namespace and the creating-netns binding cannot
            // be repaired in place. The only fix is delete + re-create
            // from inside the namespace. Every per-network VXLAN device
            // recorded in the ownership journal is deleted as well: the
            // VXLANs bind `dev <wg>`, and that underlay reference breaks
            // when the wg is deleted. This is a one-time WireGuard
            // session drop + re-handshake on upgrade. All deletions are
            // tolerant, so a heal interrupted anywhere simply re-runs:
            // the flag is only set once the replacement link exists AND
            // is fully configured below.
            //
            // ORDER (contract §3.10): the recorded VXLANs are deleted
            // BEFORE the ns-scoped wg. A heal interrupted between the
            // two then finds the wg absent with the flag still unset,
            // and the wg-absent branch above recreates the wg AND (for
            // a legacy journal) sweeps any recorded VXLANs the crash
            // left behind — every interruption slice converges. The
            // reverse order (wg first) would orphan the VXLANs forever:
            // the wg-absent recovery would set the flag and never
            // delete them, while identity verification keeps passing
            // them green on a dead `dev` binding.
            //
            // The root-namespace sweep runs first (tolerantly): a
            // legacy-crash stray may coexist with the ns-scoped link, and
            // a stray that survives the heal would wedge the next apply
            // at the both-namespaces fail-closed check.
            self.run_tolerant("ip", &["link", "del", &wg])?;
            self.delete_recorded_vxlans(&ns)?;
            self.ns_run_tolerant(&ns, "ip", &["link", "del", &wg])?;
            self.ns_run_checked(&ns, "ip", &["link", "add", &wg, "type", "wireguard"])?;
            created_wireguard = true;
        } else {
            // Healthy path. Fail closed when a link with our
            // deterministic name ALSO exists in the root namespace:
            // that is foreign state (two interfaces, one name) —
            // never adopted, never deleted here.
            let root_show = self.run("ip", &["link", "show", &wg])?;
            if root_show.success {
                return Err(FabricError::ForeignState {
                    object: wg.clone(),
                    expected: "the WireGuard link to exist only inside the fabric namespace"
                        .to_string(),
                    observed: format!(
                        "a link with the same name also exists in the root namespace: {}",
                        root_show.stdout.trim()
                    ),
                });
            }
        }

        // Key and listen port: on creation, the legacy heal (the fresh
        // link has no key), or the first apply after a crash that lost
        // the configured flag while the link survived. (Re-asserting
        // these would be harmless but is not needed.)
        if created_wireguard || !self.ownership.fabric_configured {
            let key_path =
                keys::ensure_private_key(&self.config.private_key_path(), &mut self.runner)?;
            let key_arg = path_arg(&key_path)?;
            self.ns_run_checked(&ns, "wg", &["set", &wg, "private-key", key_arg.as_str()])?;
            let port = self.config.wireguard_port().to_string();
            self.ns_run_checked(&ns, "wg", &["set", &wg, "listen-port", port.as_str()])?;
            self.ownership.fabric_configured = true;
        }
        if created_wireguard {
            // The interface inside the fabric namespace was born there
            // and is now fully configured (key + listen port): record
            // the invariant in the journal so later applies take the
            // healthy path. Persisted immediately — after the mutation,
            // before the rest of the apply — so a crash anywhere later
            // still converges: with the flag unset the next apply simply
            // re-runs the (idempotent) creation/heal.
            self.ownership.wireguard_born_in_fabric_ns = true;
            self.ownership.save(&self.config.ownership_path())?;
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
        // Reconciled against the OBSERVED forwarding state, not against
        // the journal and not by blind re-append: bridge(8) documents
        // that `append` "adds a new fdb entry with an already known
        // LLADDR ... added multiple times", and field reports
        // (Launchpad #1531013) show fleets accumulating duplicate
        // all-zeros flood entries — the kernel does NOT guarantee
        // per-(dev, mac, dst) deduplication, so unconditionally
        // re-appending on every apply grows the table without bound on
        // kernels that do not dedup. Desired destinations absent from
        // `bridge fdb show dev <vxlan>` are appended (with `append`,
        // never `replace` — the kernel rejects `replace` on non-unicast
        // MACs, and replace semantics would clobber the other remotes).
        //
        // Reconciliation is INSTANCE-COUNT aware: the show prints one
        // line per entry instance, and each `bridge fdb del` removes
        // exactly ONE instance (one RTM_DELNEIGH), so a destination
        // observed N times is issued N−1 tolerant deletes when it is
        // still desired and N when it is not. Collapsing the observed
        // table into a set would make N>1 accumulated duplicates of a
        // still-desired destination — the exact fleet state this
        // reconciliation exists to fix — indistinguishable from 1, and
        // the duplicates would persist forever. A kernel that lost the
        // fdb (a recreated VXLAN, a reboot) converges because the
        // observed table is empty and every desired entry is
        // re-appended — the journal is never consulted, so
        // reconciliation also catches entries the journal does not know
        // about.
        let desired: BTreeSet<Ipv4Addr> = plan.flood_list();
        let observed = self.ns_fdb_show_flood(&ns, &vxlan)?;
        for ip in &desired {
            if !observed.contains_key(ip) {
                self.ns_fdb_append(&ns, &vxlan, ip)?;
            }
        }
        for (ip, count) in &observed {
            // Converge to exactly one instance when the destination is
            // desired, zero when it is not: `keep` is the number of
            // instances that must remain.
            let keep = usize::from(desired.contains(ip));
            for _ in keep..*count {
                self.ns_fdb_del(&ns, &vxlan, ip)?;
            }
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

    /// True when the ownership journal shows this host owns (or owned)
    /// shared fabric state — the evidence that gates root-namespace
    /// stray sweeps (see the WireGuard section of [`Self::ensure_fabric`]).
    fn owns_fabric_state(&self) -> bool {
        self.ownership.fabric_configured || !self.ownership.networks.is_empty()
    }

    /// Tolerantly delete every per-network VXLAN recorded in the
    /// ownership journal, by journal-recorded name (ownership fencing:
    /// deterministic names are hints, the journal is proof).
    ///
    /// Used by the legacy heal and its crash-window recovery: a VXLAN
    /// binds its underlay to `dev <wg>` at creation, and that reference
    /// dies with the wg — identity verification cannot see the binding
    /// (contract §3.3), so a VXLAN that outlived its wg cannot be
    /// repaired in place, only deleted and re-created by the next apply
    /// of its network.
    fn delete_recorded_vxlans(&mut self, ns: &str) -> Result<(), FabricError> {
        let recorded: Vec<String> = self
            .ownership
            .networks
            .values()
            .map(|entry| entry.vxlan_name.clone())
            .collect();
        for vxlan in &recorded {
            self.ns_run_tolerant(ns, "ip", &["link", "del", vxlan])?;
        }
        Ok(())
    }

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
    /// Used on the teardown paths AND on the creation/heal sweeps (the
    /// root-ns stray sweep, the legacy heal's VXLAN/wg deletions, and
    /// the duplicate flood-entry deletes), where an absent object
    /// equally means the desired end state is already reached. Any
    /// other failure is a hard error (fail closed).
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

    /// The observed all-zeros (BUM) flood destinations on `vxlan`, read
    /// from `bridge fdb show dev <vxlan>`, WITH the number of entry
    /// instances observed per destination.
    ///
    /// This is the reconciliation input for the HER flood list: the
    /// kernel's forwarding table is the source of truth, not the journal.
    /// The per-destination instance COUNT is kept (not collapsed into a
    /// set) because the kernel does not guarantee `append` deduplication
    /// and each `bridge fdb del` removes exactly one instance — the
    /// reconciliation needs N to converge N accumulated duplicates.
    /// Fails closed when the show itself fails (the provider cannot know
    /// what to append or delete).
    fn ns_fdb_show_flood(
        &mut self,
        ns: &str,
        vxlan: &str,
    ) -> Result<BTreeMap<Ipv4Addr, usize>, FabricError> {
        let output = self.ns_run(ns, "bridge", &["fdb", "show", "dev", vxlan])?;
        if !output.success {
            return Err(FabricError::Command(format!(
                "ip netns exec {ns} bridge fdb show dev {vxlan} failed: {}",
                output.stderr.trim()
            )));
        }
        // iproute2 line shape (one line per entry instance):
        // `<mac> dev <dev> dst <ip> [self permanent]`. Lines that do not
        // match are ignored (e.g. local entries without a dst).
        let mut observed: BTreeMap<Ipv4Addr, usize> = BTreeMap::new();
        for line in output.stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let token_after = |flag: &str| -> Option<&str> {
                tokens
                    .iter()
                    .position(|t| *t == flag)
                    .and_then(|i| tokens.get(i + 1).copied())
            };
            if tokens.first() != Some(&FLOOD_MAC) {
                continue;
            }
            if token_after("dev") != Some(vxlan) {
                continue;
            }
            if let Some(dst) = token_after("dst").and_then(|dst| dst.parse::<Ipv4Addr>().ok()) {
                *observed.entry(dst).or_insert(0) += 1;
            }
        }
        Ok(observed)
    }

    /// Append one HER flood entry. `append` (never `replace` — the
    /// kernel rejects replace on non-unicast MACs); the caller reconciles
    /// against observed state so a destination is only appended when it
    /// is absent, because the kernel does not guarantee append
    /// deduplication.
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

    /// Delete ONE instance of one HER flood entry — each `bridge fdb del`
    /// (one RTM_DELNEIGH) removes exactly one instance, so the
    /// count-aware reconciliation issues one call per instance that must
    /// go — tolerating an already-absent entry.
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
/// The `ip -d link show` output is token-parsed. The search is anchored
/// to the `vxlan` paragraph — the detail block that begins with the
/// literal `vxlan` token — because `ip -d link show` output for other
/// link kinds carries its own tokens (a bridge detail line starts with
/// `id <bridge-id>`); tokens in the link header before the paragraph are
/// never consulted. Within the paragraph, the tokens following `id`,
/// `dstport`, and `local` must match the plan's VNI, the configured
/// VXLAN port, and the plan's local transport IP exactly (the iproute2
/// format assumption: `vxlan id <vni> [local <ip>] ... dstport <p>`).
/// Substring matching would let VNI 100 accept a foreign VNI 1000.
fn verify_vxlan_identity(
    name: &str,
    plan: &StretchedL2Plan,
    vxlan_port: u16,
    observed: &str,
) -> Result<(), FabricError> {
    let tokens: Vec<&str> = observed.split_whitespace().collect();
    // Anchor to the vxlan detail paragraph: everything before the
    // literal `vxlan` token is link-header noise.
    let paragraph = match tokens.iter().position(|t| *t == "vxlan") {
        Some(pos) => &tokens[pos..],
        None => {
            return Err(FabricError::ForeignState {
                object: name.to_string(),
                expected: "a vxlan detail paragraph in `ip -d link show`".to_string(),
                observed: observed.trim().to_string(),
            });
        }
    };
    let token_after = |flag: &str| -> Option<&str> {
        paragraph
            .iter()
            .position(|t| *t == flag)
            .and_then(|i| paragraph.get(i + 1).copied())
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
/// Every pattern is a REAL kernel/iproute2 wording, verified on kernel
/// 6.8 / iproute2 6.1:
///
/// - `ip link del` / `ip link set` / `ip addr` on a missing device:
///   `Cannot find device "x"`; `ip link show` says
///   `Device "x" does not exist.` instead (both kept — iproute2
///   wording varies by verb and version).
/// - `ip route del` of a missing route: `RTNETLINK answers: No such
///   process` (NOT the fdb's "No such file or directory" — this exact
///   mismatch once made teardown hard-fail on real kernels in the
///   reboot/lost-ns scenarios the tolerance was written for). An
///   entirely empty routing table yields `FIB table does not exist`,
///   which equally means the route is gone.
/// - `bridge fdb del` of a missing entry:
///   `RTNETLINK answers: No such file or directory`.
/// - `ip netns del` of a missing namespace:
///   `Cannot remove namespace file "...": No such file or directory`.
/// - `ip netns exec` into a namespace lost between check and delete:
///   `Cannot open network namespace`.
/// - `iptables -D` of a rule that is not present: `Bad rule`.
///
/// Kept in the provider (not the fake kernel) on purpose: the fake fails
/// like the real `ip`/`iptables`, and only the provider decides that an
/// absent object means success during teardown.
fn object_already_absent(stderr: &str) -> bool {
    const ABSENT_PATTERNS: &[&str] = &[
        // `ip link del|set` / `ip addr` on a missing device, and
        // `bridge fdb ... dev` on a missing device.
        "Cannot find device",
        // `ip link show` of a missing device (iproute2 wording varies).
        "does not exist",
        // `bridge fdb del` of a missing entry, and `ip netns del` of a
        // missing namespace (via the shared "No such file or directory"
        // suffix).
        "No such file or directory",
        // `ip route del` of a missing route (real kernels; see above).
        "No such process",
        // `ip route del` against an entirely empty routing table.
        "FIB table does not exist",
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

    /// Rewrite the ownership journal in the legacy format (field absent)
    /// — exactly the state a pre-fix deployment presents.
    fn strip_born_flag(config: &FabricLinuxConfig) -> Result<(), FabricError> {
        let journal = config.ownership_path();
        let raw = fs::read_to_string(&journal)?;
        let mut value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| FabricError::Ownership(e.to_string()))?;
        let removed = value
            .as_object_mut()
            .ok_or_else(|| FabricError::Invalid("journal is not an object".to_string()))?
            .remove("wireguard_born_in_fabric_ns");
        if removed.is_none() {
            return Err(FabricError::Invalid(
                "the applied journal must carry the born-in-ns flag".to_string(),
            ));
        }
        fs::write(
            &journal,
            serde_json::to_string_pretty(&value)
                .map_err(|e| FabricError::Ownership(e.to_string()))?,
        )?;
        Ok(())
    }

    /// A fabric peer with a public key deterministically derived from the
    /// host id (plans reject duplicate public keys, so multi-peer tests
    /// must not share one key).
    fn peer_for(host: &str, ip: [u8; 4]) -> Result<FabricPeer, PlanError> {
        let mut material = "K7XbF9cV2mQpT3nZ8sL4dW6yH1jR5uA0eG9iO2pS7kM=".to_string();
        let seed = host.as_bytes().last().copied().unwrap_or(b'0');
        let letter = char::from(b'A' + (seed % 26));
        material.replace_range(42..=42, &letter.to_string());
        Ok(FabricPeer {
            host_id: host.to_string(),
            public_key: PublicKey::new(material)?,
            underlay_endpoint: UnderlayEndpoint::parse("198.51.100.10:65001")?,
            fabric_transport_ip: Ipv4Addr::from(ip),
        })
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

    // ---- CRITICAL: WireGuard socket binds in the creating namespace ----

    /// Regression test for the socket-placement bug: the WireGuard
    /// interface MUST be created from inside the fabric namespace
    /// (`ip netns exec <ns> ip link add ...`), never created in the root
    /// namespace and moved in — the UDP socket binds in the creating
    /// namespace and never follows the interface, so a root-ns creation
    /// leaves the listener outside the fabric underlay where the DNAT
    /// rule black-holes every NEW inbound flow.
    #[test]
    fn wireguard_is_created_inside_the_fabric_namespace() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("wg-in-ns")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let joined: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .map(|call| call.joined())
            .collect();
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        let ns_add = format!("ip netns exec {ns} ip link add {wg} type wireguard");
        assert!(
            joined.iter().any(|line| line == &ns_add),
            "the WireGuard interface must be created inside the fabric namespace: {ns_add}"
        );
        let root_add = format!("ip link add {wg} type wireguard");
        assert!(
            !joined.iter().any(|line| line == &root_add),
            "the WireGuard interface must NOT be created in the root namespace"
        );
        let root_move = format!("ip link set {wg} netns {ns}");
        assert!(
            !joined.iter().any(|line| line == &root_move),
            "the WireGuard interface must NOT be moved into the fabric namespace \
             (the socket never follows)"
        );
        Ok(())
    }

    /// A deployment running the pre-fix code has the wg link inside the
    /// fabric namespace with its UDP socket bound in the ROOT namespace
    /// (creating_netns is immutable), journaled without the
    /// born-in-fabric-ns flag. Re-apply must heal: delete the wg and
    /// every recorded VXLAN (they bind `dev <wg>`), re-create the wg
    /// inside the namespace, force key/port configuration, and record
    /// the flag — then a further apply is a pure no-op replay.
    #[test]
    fn legacy_wireguard_socket_placement_is_healed() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-heal")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-b", 200, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let vxlan_a = names.vxlan(&plan_a.network_id);
        let vxlan_b = names.vxlan(&plan_b.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        assert!(provider.ownership().wireguard_born_in_fabric_ns);
        let runner = provider.into_runner();

        // Rewrite the ownership journal in the legacy format (field
        // absent): exactly the state a pre-fix deployment presents.
        strip_born_flag(&config)?;

        // Healing apply of net-a.
        let before_heal = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let heal_report = provider.apply_plan(&plan_a)?;
        let healed_flag = provider.ownership().wireguard_born_in_fabric_ns;
        let heal_slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before_heal)
            .map(|call| call.joined())
            .collect();
        let vxlan_b_gone = !provider.runner().has_link(&vxlan_b);
        let flood_a = provider
            .runner()
            .fdb_entry_count(&vxlan_a, FLOOD_MAC, "198.18.0.2");

        assert!(
            heal_report.created_fabric,
            "the heal re-creates the WireGuard interface"
        );
        assert!(healed_flag, "the journal must record the heal");
        // The wg is deleted (namespace-scoped, plus the root-ns stray
        // sweep) and re-created INSIDE the namespace.
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {wg}")),
            "the heal must delete the legacy wg inside the namespace"
        );
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "the heal must sweep a possible root-ns stray first"
        );
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the heal must re-create the wg inside the namespace"
        );
        // Every recorded VXLAN is deleted (they bind dev <wg>); the
        // applied network's VXLAN is re-created in the same apply.
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {vxlan_a}")),
            "the heal must delete the applied network's vxlan"
        );
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {vxlan_b}")),
            "the heal must delete every recorded vxlan, not just the applied one"
        );
        // MAJOR-1: the recorded VXLANs must be deleted BEFORE the
        // ns-scoped wg. With the reverse (pre-fix) order, a crash
        // between the wg delete and the VXLAN deletes orphans the VXLANs
        // forever: the wg-absent recovery sets the flag and never
        // deletes them, while identity verification keeps passing them
        // green on a dead `dev <wg>` binding.
        let index_of = |needle: &str| heal_slice.iter().position(|line| line == needle);
        let (Some(wg_del_at), Some(vxlan_a_at), Some(vxlan_b_at)) = (
            index_of(&format!("ip netns exec {ns} ip link del {wg}")),
            index_of(&format!("ip netns exec {ns} ip link del {vxlan_a}")),
            index_of(&format!("ip netns exec {ns} ip link del {vxlan_b}")),
        ) else {
            return Err(Box::new(FabricError::Invalid(
                "heal ordering assertions could not find the deletion calls".to_string(),
            )));
        };
        assert!(
            vxlan_a_at < wg_del_at && vxlan_b_at < wg_del_at,
            "the recorded vxlans must be deleted before the ns-scoped wg \
             (crash-window convergence, contract §3.10)"
        );
        assert!(
            heal_slice.iter().any(|line| line.contains(&format!(
                "ip netns exec {ns} ip link add {vxlan_a} type vxlan"
            ))),
            "the applied network's vxlan must be re-created in the same apply"
        );
        assert!(
            vxlan_b_gone,
            "the other network's vxlan heals on its own next apply, not this one"
        );
        // The fresh link has no key: key and listen port are forced.
        assert!(
            heal_slice.iter().any(
                |line| line.starts_with(&format!("ip netns exec {ns} wg set {wg} private-key"))
            ),
            "the heal must re-configure the private key"
        );
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} wg set {wg} listen-port 65001")),
            "the heal must re-configure the listen port"
        );
        assert_eq!(
            flood_a, 1,
            "the re-created vxlan's flood list must be rebuilt exactly once"
        );

        // The other network converges on its next apply.
        let before_b = provider.runner().calls().len();
        provider.apply_plan(&plan_b)?;
        let b_slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before_b)
            .map(|call| call.joined())
            .collect();
        let vxlan_b_back = provider.runner().has_link(&vxlan_b);
        let flood_b = provider
            .runner()
            .fdb_entry_count(&vxlan_b, FLOOD_MAC, "198.18.0.2");
        assert!(
            b_slice.iter().any(|line| line.contains(&format!(
                "ip netns exec {ns} ip link add {vxlan_b} type vxlan"
            ))),
            "net-b's next apply must re-create its vxlan"
        );
        assert!(vxlan_b_back);
        assert_eq!(
            flood_b, 1,
            "net-b's flood list must be rebuilt exactly once"
        );

        // After the heal, an unchanged-plan apply is a pure no-op replay:
        // no object creation, no deletion, no duplicate flood entries.
        let before_replay = provider.runner().calls().len();
        let replay_report = provider.apply_plan(&plan_a)?;
        let replay_slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before_replay)
            .map(|call| call.joined())
            .collect();
        let flood_a_after = provider
            .runner()
            .fdb_entry_count(&vxlan_a, FLOOD_MAC, "198.18.0.2");
        let flag_after = provider.ownership().wireguard_born_in_fabric_ns;
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            !replay_report.created_fabric && !replay_report.created_network,
            "post-heal replay must not re-create anything"
        );
        assert!(
            !replay_slice.iter().any(|line| line.contains(" link add ")),
            "post-heal replay must not create links: {replay_slice:?}"
        );
        assert!(
            !replay_slice.iter().any(|line| line.contains(" link del ")),
            "post-heal replay must not delete links: {replay_slice:?}"
        );
        assert_eq!(
            flood_a_after, 1,
            "post-heal replays must not duplicate flood entries"
        );
        assert!(flag_after);
        Ok(())
    }

    /// The legacy create-then-move sequence crashed between add and move:
    /// a stray WireGuard link with our deterministic name sits in the
    /// ROOT namespace and the fabric namespace has none. Apply must
    /// clear the stray and create the interface inside the namespace.
    #[test]
    fn stray_root_namespace_wireguard_is_swept_on_create() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("wg-stray")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        // Pre-seed the crash residue: a root-ns WireGuard link.
        let mut runner = RecordingRunner::new();
        let out = runner.run("ip", &["link", "add", &wg, "type", "wireguard"])?;
        assert!(out.success, "could not pre-seed the stray: {}", out.stderr);
        let preseed_len = runner.calls().len();

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let joined: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(preseed_len)
            .map(|call| call.joined())
            .collect();
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        // The stray was swept (tolerant root-ns deletion)...
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "the root-ns stray must be swept before creation"
        );
        // ...and the interface was created inside the namespace, never
        // in the root namespace.
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must be created inside the fabric namespace"
        );
        assert!(
            !joined
                .iter()
                .any(|line| line == &format!("ip link add {wg} type wireguard")),
            "the wg must NOT be created in the root namespace"
        );
        assert!(flag, "the creation must be journaled");
        Ok(())
    }

    /// A WireGuard link with our deterministic name existing in the root
    /// namespace while the journal claims a healthy fabric (the link is
    /// also visible from the fabric namespace — on a real kernel that
    /// means one link per namespace) is foreign state: fail closed,
    /// never adopt and never delete.
    #[test]
    fn root_and_fabric_namespace_wireguard_collision_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-collision")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert!(provider.ownership().wireguard_born_in_fabric_ns);
        let mut runner = provider.into_runner();

        // Foreign state: the wg link exists in the ROOT namespace (here:
        // the namespace-placed link was replaced by a root-placed one —
        // on a real kernel this is the both-namespaces collision).
        let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
        assert!(
            out.success,
            "could not drop the wg for the test: {}",
            out.stderr
        );
        let out = runner.run("ip", &["link", "add", &wg, "type", "wireguard"])?;
        assert!(
            out.success,
            "could not pre-seed the root-ns wg: {}",
            out.stderr
        );

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let result = provider.apply_plan(&plan);
        // MINOR-1: the foreign root-ns link must SURVIVE the failed
        // apply — the healthy path never deletes, it only fails closed.
        let foreign_survived = provider.runner().has_link(&wg);
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            foreign_survived,
            "a foreign root-ns wg must never be deleted by a failed apply"
        );
        match result {
            Err(FabricError::ForeignState { .. }) => Ok(()),
            other => Err(Box::new(FabricError::Invalid(format!(
                "a root-ns wg alongside the fabric-ns wg must fail closed, got {other:?}"
            )))),
        }
    }

    /// Real `ip route del` of a nonexistent route fails with
    /// "RTNETLINK answers: No such process" (kernel 6.8, verified) — not
    /// the fdb's "No such file or directory". The tolerant withdrawal of
    /// a stale peer route must swallow that exact wording, or teardown
    /// wedges on real kernels in the reboot/lost-state scenarios it was
    /// written for.
    #[test]
    fn stale_route_deletion_tolerates_already_missing_route()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("route-missing")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let mut plan_b = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        plan_b.peers[0].fabric_transport_ip = Ipv4Addr::new(198, 18, 0, 9);
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        assert!(provider.runner().has_route("198.18.0.2/32"));
        let mut runner = provider.into_runner();

        // The kernel lost the route (reboot / partial teardown) while
        // the journals survive: configure_peers' stale-route withdrawal
        // now deletes an already-absent route.
        let out = runner.run(
            "ip",
            &["netns", "exec", &ns, "ip", "route", "del", "198.18.0.2/32"],
        )?;
        assert!(
            out.success,
            "could not drop the route for the test: {}",
            out.stderr
        );
        assert!(!runner.has_route("198.18.0.2/32"));

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let healed = provider.apply_plan(&plan_b);
        let new_route = match &healed {
            Ok(_) => provider.runner().has_route("198.18.0.9/32"),
            Err(_) => false,
        };
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        healed?;
        assert!(
            new_route,
            "the peer's new transport /32 must be routed despite the \
             pre-missing stale route"
        );
        Ok(())
    }

    /// The HER flood list reconciles against the OBSERVED forwarding
    /// state, so entries the journal does not know about (injected here,
    /// e.g. by an operator or an old buggy apply) are deleted too, and
    /// desired entries present exactly once are left alone — no blind
    /// re-append, no duplicates.
    #[test]
    fn flood_list_reconciles_against_observed_state() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("flood-observed")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let vxlan = names.vxlan(&plan.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert_eq!(
            provider
                .runner()
                .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.2"),
            1
        );
        let mut runner = provider.into_runner();

        // Inject a flood destination that is neither desired nor
        // journaled.
        let out = runner.run(
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                "bridge",
                "fdb",
                "append",
                FLOOD_MAC,
                "dev",
                vxlan.as_str(),
                "dst",
                "198.18.0.99",
            ],
        )?;
        assert!(
            out.success,
            "could not inject the foreign flood entry: {}",
            out.stderr
        );
        assert!(
            runner.has_fdb_entry(&vxlan, FLOOD_MAC, "198.18.0.99"),
            "injection sanity"
        );

        let before = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let foreign_gone = !provider
            .runner()
            .has_fdb_entry(&vxlan, FLOOD_MAC, "198.18.0.99");
        let desired_kept = provider
            .runner()
            .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.2");
        let appends_on_replay = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .filter(|call| call.joined().contains("fdb append"))
            .count();
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            foreign_gone,
            "an observed-but-undesired flood entry must be deleted even \
             though the journal does not know it"
        );
        assert_eq!(
            desired_kept, 1,
            "an already-present desired entry must not be re-appended"
        );
        assert_eq!(
            appends_on_replay, 0,
            "a fully-converged flood list must produce zero appends"
        );
        Ok(())
    }

    // ---- MAJOR-1: interrupted-heal crash windows -------------------------

    /// MAJOR-1 slice (a): a heal interrupted AFTER the recorded-VXLAN
    /// deletes but BEFORE the wg delete (pre-seeded: wg present, legacy
    /// journal, VXLANs absent) converges on the next apply — the heal
    /// re-enters and finishes, the applied network's VXLAN is
    /// re-created, and the born-in-ns flag is set. The other network's
    /// VXLAN heals on its own next apply.
    #[test]
    fn interrupted_heal_after_vxlan_deletes_converges() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("heal-crashtest-a")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-b", 200, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let vxlan_a = names.vxlan(&plan_a.network_id);
        let vxlan_b = names.vxlan(&plan_b.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        assert!(provider.ownership().wireguard_born_in_fabric_ns);
        let mut runner = provider.into_runner();

        // Legacy journal (flag stripped) + crash residue: the heal's
        // VXLAN deletes ran, the wg delete did not.
        strip_born_flag(&config)?;
        for vxlan in [&vxlan_a, &vxlan_b] {
            let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", vxlan])?;
            assert!(
                out.success,
                "could not pre-delete {vxlan} for the test: {}",
                out.stderr
            );
        }

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let report = provider.apply_plan(&plan_a)?;
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        let vxlan_a_back = provider.runner().has_link(&vxlan_a);
        let vxlan_b_still_gone = !provider.runner().has_link(&vxlan_b);
        let flood_a = provider
            .runner()
            .fdb_entry_count(&vxlan_a, FLOOD_MAC, "198.18.0.2");

        // The other network converges on its next apply.
        provider.apply_plan(&plan_b)?;
        let vxlan_b_back = provider.runner().has_link(&vxlan_b);
        let flood_b = provider
            .runner()
            .fdb_entry_count(&vxlan_b, FLOOD_MAC, "198.18.0.2");
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            report.created_fabric,
            "the interrupted heal must finish: the wg is re-created"
        );
        assert!(flag, "the heal must record the born-in-ns flag");
        assert!(
            vxlan_a_back,
            "the applied network's vxlan must be re-created in the same apply"
        );
        assert!(
            vxlan_b_still_gone,
            "the other network's vxlan heals on its own next apply, not this one"
        );
        assert_eq!(
            flood_a, 1,
            "the re-created vxlan's flood list must be rebuilt exactly once"
        );
        assert!(vxlan_b_back, "net-b's next apply must re-create its vxlan");
        assert_eq!(
            flood_b, 1,
            "net-b's flood list must be rebuilt exactly once"
        );
        Ok(())
    }

    /// MAJOR-1 slice (b): the crash window of the OLD heal order — the
    /// wg was deleted, the recorded VXLANs were not (pre-seeded: wg
    /// absent, legacy journal, VXLANs present, journal records both
    /// networks). The next apply takes the wg-absent branch: it must
    /// delete the stale VXLANs (their `dev <wg>` binding died with the
    /// old interface and identity verification cannot see that),
    /// re-create the wg inside the namespace plus this network's VXLAN,
    /// and set the flag. A second apply must be a pure no-op replay.
    #[test]
    fn interrupted_heal_after_wg_delete_converges() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("heal-crashtest-b")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-b", 200, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let vxlan_a = names.vxlan(&plan_a.network_id);
        let vxlan_b = names.vxlan(&plan_b.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        assert!(provider.ownership().wireguard_born_in_fabric_ns);
        let mut runner = provider.into_runner();

        // Legacy journal (flag stripped) + the OLD order's crash
        // residue: the wg is gone, the recorded VXLANs survived it.
        strip_born_flag(&config)?;
        let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
        assert!(
            out.success,
            "could not pre-delete the wg for the test: {}",
            out.stderr
        );

        let before = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let report = provider.apply_plan(&plan_a)?;
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        let slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .map(|call| call.joined())
            .collect();
        let vxlan_a_back = provider.runner().has_link(&vxlan_a);
        let vxlan_b_gone = !provider.runner().has_link(&vxlan_b);
        let flood_a = provider
            .runner()
            .fdb_entry_count(&vxlan_a, FLOOD_MAC, "198.18.0.2");

        // The second apply must be a pure no-op replay.
        let before_replay = provider.runner().calls().len();
        let replay_report = provider.apply_plan(&plan_a)?;
        let replay_slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before_replay)
            .map(|call| call.joined())
            .collect();
        let flood_a_after = provider
            .runner()
            .fdb_entry_count(&vxlan_a, FLOOD_MAC, "198.18.0.2");
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            report.created_fabric,
            "the wg-absent recovery must re-create the WireGuard interface"
        );
        assert!(flag, "the recovery must record the born-in-ns flag");
        // The stale, binding-dead VXLANs are swept by journal-recorded
        // name BEFORE the replacement wg exists...
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {vxlan_a}")),
            "the stale recorded vxlan of the applied network must be deleted"
        );
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {vxlan_b}")),
            "every stale recorded vxlan must be deleted, not just the applied one"
        );
        // ...the wg is re-created inside the namespace...
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must be re-created inside the fabric namespace"
        );
        // ...and this network's VXLAN is re-created on the NEW wg.
        assert!(
            slice.iter().any(|line| line.contains(&format!(
                "ip netns exec {ns} ip link add {vxlan_a} type vxlan"
            ))),
            "the applied network's vxlan must be re-created on the new wg"
        );
        assert!(vxlan_a_back, "the applied network's vxlan must exist again");
        assert!(
            vxlan_b_gone,
            "the other network's stale vxlan must be gone (it heals on its \
             own next apply, it must not be adopted with a dead binding)"
        );
        assert_eq!(
            flood_a, 1,
            "the re-created vxlan's flood list must be rebuilt exactly once"
        );
        assert!(
            !replay_report.created_fabric && !replay_report.created_network,
            "the second apply must not re-create anything"
        );
        assert!(
            !replay_slice.iter().any(|line| line.contains(" link add ")),
            "the second apply must not create links: {replay_slice:?}"
        );
        assert!(
            !replay_slice.iter().any(|line| line.contains(" link del ")),
            "the second apply must not delete links: {replay_slice:?}"
        );
        assert_eq!(
            flood_a_after, 1,
            "the second apply must not duplicate flood entries"
        );
        Ok(())
    }

    // ---- MINOR-1: root-ns stray sweep gating -----------------------------

    /// On a fresh host (empty journal) the root-ns stray sweep must NOT
    /// run: a root-ns link with our deterministic name is FOREIGN state
    /// there, and journal-before-mutate means a genuine legacy
    /// add-then-crash stray always implies a journal that shows we
    /// own(ed) fabric state. In the fake kernel the sweep is a tolerated
    /// no-op when no link exists, so the gate is observable through the
    /// recorded call journal: the pre-fix code issued the root-ns
    /// deletion on EVERY fresh apply.
    #[test]
    fn root_stray_sweep_is_skipped_on_a_fresh_host() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("stray-gate-fresh")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let joined: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .map(|call| call.joined())
            .collect();
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            !joined
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "a fresh host (empty journal) must not run the root-ns stray sweep: \
             a colliding root link would be foreign state"
        );
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must still be created inside the fabric namespace"
        );
        assert!(flag, "the creation must be journaled");
        Ok(())
    }

    /// The other side of the gate: when the journal shows we own(ed)
    /// fabric state, a lost ns-scoped wg re-apply DOES run the root-ns
    /// stray sweep (a legacy add-then-crash stray is ours to clean) and
    /// re-creates the wg inside the namespace — while the recorded
    /// VXLANs are NOT deleted, because the born-in-ns flag is set (no
    /// heal pending; the belt-and-braces VXLAN sweep is scoped to
    /// legacy journals).
    #[test]
    fn root_stray_sweep_runs_with_ownership_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("stray-gate-owned")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let vxlan = names.vxlan(&plan.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert!(provider.ownership().wireguard_born_in_fabric_ns);
        let mut runner = provider.into_runner();

        // The ns-scoped wg is lost (kernel crash / operator) while the
        // journal survives: the next apply takes the wg-absent branch.
        let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
        assert!(
            out.success,
            "could not pre-delete the wg for the test: {}",
            out.stderr
        );

        let before = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let report = provider.apply_plan(&plan)?;
        let slice: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .map(|call| call.joined())
            .collect();
        let vxlan_kept = provider.runner().has_link(&vxlan);
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "with ownership evidence in the journal, the root-ns stray \
             sweep must run before the wg is re-created"
        );
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must be re-created inside the fabric namespace"
        );
        assert!(
            report.created_fabric && !report.created_network,
            "only the wg is re-created; the network state is untouched"
        );
        assert!(
            vxlan_kept,
            "with the born-in-ns flag set, a lost wg must NOT delete the \
             recorded vxlans (no heal pending)"
        );
        assert!(flag);
        Ok(())
    }

    // ---- MAJOR-2: duplicate convergence ----------------------------------

    /// Pre-existing duplicates of still-desired destinations — the
    /// Launchpad #1531013 fleet state — converge to exactly one entry:
    /// reconciliation counts instances per destination and issues
    /// count−1 tolerant `bridge fdb del` operations (each removes
    /// exactly one instance), while the healthy destination is left
    /// alone. Collapsing the observed table to a set (the pre-fix
    /// behavior) makes the duplicate indistinguishable from 1 and it
    /// persists forever.
    #[test]
    fn flood_duplicates_of_desired_destinations_converge() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("flood-dupe-conv")?;
        let config = FabricLinuxConfig::new(&root);
        let mut plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        plan.peers.push(peer_for("host-03", [198, 18, 0, 3])?);
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let vxlan = names.vxlan(&plan.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        assert_eq!(
            provider
                .runner()
                .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.2"),
            1
        );
        assert_eq!(
            provider
                .runner()
                .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.3"),
            1
        );
        let mut runner = provider.into_runner();

        // Pre-seed the fleet state: one desired destination has
        // accumulated a duplicate (count 2), the other is healthy.
        let out = runner.run(
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                "bridge",
                "fdb",
                "append",
                FLOOD_MAC,
                "dev",
                vxlan.as_str(),
                "dst",
                "198.18.0.2",
            ],
        )?;
        assert!(
            out.success,
            "could not seed the duplicate flood entry: {}",
            out.stderr
        );
        assert_eq!(
            runner.fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.2"),
            2,
            "seeding sanity: the duplicate must be observable"
        );

        let before = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let count_2 = provider
            .runner()
            .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.2");
        let count_3 = provider
            .runner()
            .fdb_entry_count(&vxlan, FLOOD_MAC, "198.18.0.3");
        let dels_of_duplicate = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .filter(|call| {
                call.joined().contains("fdb del") && call.joined().contains("dst 198.18.0.2")
            })
            .count();
        let appends_on_heal = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .filter(|call| call.joined().contains("fdb append"))
            .count();
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert_eq!(
            count_2, 1,
            "a duplicated desired destination must converge to exactly one entry"
        );
        assert_eq!(
            count_3, 1,
            "the healthy destination must stay at exactly one entry"
        );
        assert_eq!(
            dels_of_duplicate, 1,
            "exactly count-1 tolerant deletes must be issued for the \
             duplicated destination (one instance per del)"
        );
        assert_eq!(
            appends_on_heal, 0,
            "present desired destinations must not be re-appended"
        );
        Ok(())
    }
}
