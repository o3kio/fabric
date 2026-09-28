//! The Linux fabric provider: idempotent realization of stretched-L2 plans.
//!
//! Realization order (see `contracts/fabric-provider-v1.md`):
//! validate plan -> journal plan -> ensure fabric (netns/WireGuard) ->
//! configure peers (union over live plans) -> re-assert the WireGuard MTU
//! (maximum fabric_mtu across live plans) -> ensure network (VXLAN +
//! learning bridge + attachment veth + bounded HER flood list) -> save
//! ownership. Teardown runs in reverse dependency order and preserves the
//! WireGuard private key.
//!
//! Underlay design (contract §3.10, the v0.1.2 redesign): the WireGuard
//! interface is created in the ROOT namespace and moved into the fabric
//! namespace, so its UDP transport socket — which binds in the CREATING
//! namespace and never follows the interface — lives in the root
//! namespace. Outbound encrypted packets route via the host's normal
//! routing with dynamic source selection, and inbound packets to
//! `<host-ip>:<port>` are delivered directly to the listener. NO NAT
//! rules exist for the transport: a MASQUERADE-remapped source port
//! under simultaneous initiation makes the peer roam to a port nothing
//! steers back, and a DNAT rule black-holes NEW inbound flows when the
//! socket is elsewhere (the two races proven in the v0.1.2 postmortem).
//! The v0.1.0/v0.1.1 underlay machinery (veth pair, 169.254.253.0/30,
//! DNAT + MASQUERADE rules) is therefore deleted tolerantly on every
//! apply.
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

use crate::config::{DEFAULT_UNDERLAY_FABRIC_IP, FabricLinuxConfig, UNDERLAY_PREFIX};
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
            created_fabric: fabric_report.created_netns || fabric_report.created_wireguard,
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
    /// legacy underlay veth, legacy iptables rules) are re-rendered from
    /// the CURRENT configuration, not from the journal — so a `name_prefix`
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

        // The ns-scoped deletions are skipped when the namespace is
        // already gone; the remaining deletions tolerate absent objects.
        if self.has_fabric_netns(&ns)? {
            self.ns_run_tolerant(&ns, "ip", &["link", "del", &wg])?;
        }
        // The legacy underlay machinery (v0.1.0/v0.1.1, and the unpushed
        // round-3..5 code) — tolerated when already absent.
        self.cleanup_legacy_underlay(&names)?;
        if self.has_fabric_netns(&ns)? {
            self.run_tolerant("ip", &["netns", "del", &ns])?;
        }

        self.ownership.fabric_configured = false;
        // The WireGuard link is gone with the namespace; any pending
        // born-in-fabric-ns heal claim must not outlive it (a later
        // re-apply creates the replacement root-side anyway).
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
        // INVARIANT (contract §3.10, the v0.1.2 underlay redesign): the
        // interface MUST be created in the ROOT namespace and then moved
        // into the fabric namespace (`ip link add <wg> type wireguard`;
        // `ip link set <wg> netns <fabric-ns>`). A WireGuard interface's
        // UDP socket binds in the namespace the interface was CREATED in
        // and that binding is immutable for the interface's lifetime —
        // which under this design is exactly what we want:
        //
        // - Outbound: the root-ns socket routes via the host's normal
        //   routing with dynamic source selection. No NAT rule exists,
        //   so nothing can rewrite the flow — the peer always sees
        //   `<host-underlay-ip>:<port>`, stable.
        // - Inbound: `<peer>:<port> → <host-ip>:<port>` is delivered
        //   directly to the root-ns listener.
        //
        // NO NAT rules may exist for the transport (see §3.10 for the
        // two-race postmortem): a MASQUERADE-remapped source port under
        // simultaneous initiation makes the peer roam to a port nothing
        // steers back, and a DNAT rule black-holes every NEW inbound
        // flow when the socket is elsewhere.
        let wg_show = self.ns_run(&ns, "ip", &["link", "show", &wg])?;
        let wg_in_ns = wg_show.success;
        let mut created_wireguard = false;
        if wg_in_ns && !self.ownership.wireguard_born_in_fabric_ns {
            // Healthy path: the wg lives in the fabric namespace and the
            // journal carries no pending born-in-fabric-ns heal. Fail
            // closed when a link with our deterministic name ALSO exists
            // in the root namespace: that is foreign state (two
            // interfaces, one name) — never adopted, never deleted here.
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
            // v0.1.0/v0.1.1 journals (the flag field is absent, so it
            // deserializes as false) already carry a root-created +
            // moved wg — the placement this design mandates — so the wg
            // is NOT recreated; only the unconditional legacy-underlay
            // cleanup below runs.
            self.cleanup_legacy_underlay(&names)?;
        } else {
            if wg_in_ns {
                // FULL HEAL (one-time; contract §3.10). The journal
                // carries `wireguard_born_in_fabric_ns == true` — written
                // only by the unpushed round-3..5 code, so this state
                // exists in dev environments only. That code created the
                // wg from INSIDE the fabric namespace, so its UDP socket
                // is bound there — the placement this design eliminates.
                // The creating-netns binding cannot be repaired in
                // place; the only fix is delete + re-create via the
                // root-creation sequence.
                //
                // The root-namespace stray sweep runs first
                // (tolerantly): a legacy-crash stray may coexist with
                // the ns-scoped link, and a stray that survived would
                // wedge the recreation below at `ip link add` (name in
                // use).
                self.run_tolerant("ip", &["link", "del", &wg])?;
                // ORDER (the round-5 crash-window-safe ordering,
                // contract §3.10): every per-network VXLAN recorded in
                // the ownership journal is deleted BEFORE the ns-scoped
                // wg. A heal interrupted between the two then finds the
                // wg absent with the flag still set, and the wg-absent
                // branch below re-enters the same deletions — every
                // interruption slice converges. The reverse order (wg
                // first) would orphan the VXLANs forever: the wg-absent
                // recovery would clear the flag and never delete them,
                // while identity verification keeps passing them green
                // on a dead `dev <wg>` binding. Each network fully
                // heals on its own next apply (this apply's network
                // below).
                self.delete_recorded_vxlans(&ns)?;
                self.ns_run_tolerant(&ns, "ip", &["link", "del", &wg])?;
            } else {
                // No WireGuard interface inside the fabric namespace.
                // A stray link with our deterministic name may sit in
                // the ROOT namespace — the crash window of THIS design's
                // own create-then-move sequence (crashed between
                // `ip link add` and `ip link set netns`), or the same
                // window in the released v0.1.0/v0.1.1 code. It can
                // never serve the fabric from there, so it is swept
                // tolerantly — absence is the normal case — before the
                // interface is created root-side.
                //
                // The sweep is gated on OWNERSHIP EVIDENCE (contract
                // §3.10): journal-before-mutate means every object the
                // old code ever created was preceded by an
                // ownership-journal write, so a genuine crash stray
                // implies a journal that shows we own(ed) fabric state.
                // ONE EXCEPTION: the released v0.1.0/v0.1.1 code saved
                // the ownership journal only at the END of apply, so a
                // crash on the very FIRST apply in the add→move window
                // leaves a stray with an empty journal — that state
                // wedges fail-closed here and on the collision check
                // above (manual cleanup is the remedy; it is no worse
                // than the released baseline, which also wedged). On a
                // fresh host (no journal) a root-ns link with our
                // deterministic name is FOREIGN state and must not be
                // deleted here — the `ip link add` below fails closed on
                // it instead.
                if self.owns_fabric_state() {
                    self.run_tolerant("ip", &["link", "del", &wg])?;
                }
                // Crash-window recovery for a PENDING heal (flag still
                // set) whose WireGuard was lost entirely — including the
                // crash window of a heal that deleted the wg (the
                // branch above). Every recorded VXLAN binds
                // `dev <wg>`, and that underlay reference died with the
                // old interface, so the recorded VXLANs are stale even
                // though identity verification cannot see the binding
                // (contract §3.3): they are deleted tolerantly, by
                // journal-recorded name, before the replacement wg
                // exists. This apply's network re-creates its VXLAN
                // below; other networks heal on their next apply.
                if self.ownership.wireguard_born_in_fabric_ns && !self.ownership.networks.is_empty()
                {
                    self.delete_recorded_vxlans(&ns)?;
                }
            }
            // Legacy underlay machinery (rules first, then the veth
            // pair) — AFTER the wg deletion in the heal path, BEFORE the
            // recreation, and UNCONDITIONAL: every apply on every path
            // that reaches here tolerantly deletes the v0.1.0/v0.1.1
            // DNAT + MASQUERADE nat rules and the underlay veth pair
            // (absence is the normal case on this design's hosts).
            self.cleanup_legacy_underlay(&names)?;
            // Create in the ROOT namespace, then move into the fabric
            // namespace (the invariant above).
            self.run_checked("ip", &["link", "add", &wg, "type", "wireguard"])?;
            self.run_checked("ip", &["link", "set", &wg, "netns", &ns])?;
            created_wireguard = true;
        }

        // Key and listen port: on creation, the full heal (the fresh
        // link has no key), or the first apply after a crash that lost
        // the configured flag while the link survived. (Re-asserting
        // these would be harmless but is not needed.) The commands run
        // from inside the fabric namespace — `wg set` configures the
        // interface wherever it lives and never moves the UDP socket,
        // which stays bound in the creating (root) namespace.
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
            // The interface was created in the ROOT namespace, moved
            // into the fabric namespace, and is now fully configured
            // (key + listen port): clear any born-in-fabric-ns heal
            // claim so later applies take the healthy path. Persisted
            // immediately — after the mutation, before the rest of the
            // apply — so a crash anywhere later still converges: with
            // the claim still set the next apply simply re-runs the
            // (idempotent) creation/heal.
            self.ownership.wireguard_born_in_fabric_ns = false;
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

        Ok(FabricReport {
            created_netns,
            created_wireguard,
        })
    }

    /// Tolerantly delete the v0.1.0/v0.1.1 underlay machinery: the exact
    /// DNAT and MASQUERADE nat rules and the underlay veth pair (its
    /// root end; deleting it removes the pair and the fabric-ns routes
    /// via it).
    ///
    /// UNCONDITIONAL on every apply and idempotent: absence is this
    /// design's normal case (the rules and the veth are never created
    /// anymore), so every deletion here is tolerant — an absent rule
    /// (`iptables: Bad rule ...`) or device (`Cannot find device ...`)
    /// means the desired end state is already reached. Any other
    /// failure is a hard error (fail closed). The rule specifications
    /// are EXACTLY the ones the v0.1.0/v0.1.1 code installed (verified
    /// spec-for-spec against `git show v0.1.1:crates/fabric-linux/src/
    /// provider.rs`), because `iptables -t nat -D` only hits a rule
    /// whose specification matches token for token.
    fn cleanup_legacy_underlay(&mut self, names: &Names) -> Result<(), FabricError> {
        let host_veth = names.host_underlay_veth();
        self.iptables_delete_underlay_rules(&host_veth)?;
        // Deleting the root end removes the whole pair on a real kernel.
        self.run_tolerant("ip", &["link", "del", host_veth.as_str()])
    }

    fn iptables_delete_underlay_rules(&mut self, host_veth: &str) -> Result<(), FabricError> {
        let wg_port = self.config.wireguard_port().to_string();
        let fabric_ip = DEFAULT_UNDERLAY_FABRIC_IP.to_string();
        // Tolerant: absent rules ("Bad rule ...") mean the desired end
        // state is already reached (the normal case on this design's
        // hosts).
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
    /// — exactly the state a v0.1.0/v0.1.1 deployment presents (their
    /// code created the wg root-side and moved it in, so the placement
    /// is already the one this design mandates).
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

    /// Force the ownership journal's `wireguard_born_in_fabric_ns` field
    /// to `value` — `true` reproduces exactly the state the unpushed
    /// round-3..5 code left behind (its wg was created inside the
    /// fabric namespace, socket and all), the one-time full-heal
    /// trigger under the NAT-free underlay.
    fn force_born_flag(config: &FabricLinuxConfig, value: bool) -> Result<(), FabricError> {
        let journal = config.ownership_path();
        let raw = fs::read_to_string(&journal)?;
        let mut parsed: FabricOwnership =
            serde_json::from_str(&raw).map_err(|e| FabricError::Ownership(e.to_string()))?;
        parsed.wireguard_born_in_fabric_ns = value;
        parsed.save(&journal)?;
        Ok(())
    }

    /// Seed the fake kernel with the exact legacy underlay machinery the
    /// v0.1.0/v0.1.1 (and unpushed round-3..5) code installed: the
    /// underlay veth pair with the fabric end moved into the namespace,
    /// and the two nat rules — with EXACTLY the specifications that code
    /// used, because `iptables -t nat -D` only hits spec-for-spec
    /// matches.
    fn seed_legacy_underlay(
        runner: &mut RecordingRunner,
        config: &FabricLinuxConfig,
        names: &Names,
    ) -> Result<(), FabricError> {
        let ns = names.fabric_namespace();
        let host_veth = names.host_underlay_veth();
        let fabric_veth = names.fabric_underlay_veth();
        let out = runner.run(
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
            return Err(FabricError::Command(format!(
                "could not seed the legacy veth pair: {}",
                out.stderr.trim()
            )));
        }
        let out = runner.run("ip", &["link", "set", fabric_veth.as_str(), "netns", &ns])?;
        if !out.success {
            return Err(FabricError::Command(format!(
                "could not move the legacy fabric veth: {}",
                out.stderr.trim()
            )));
        }
        let wg_port = config.wireguard_port().to_string();
        let fabric_ip = DEFAULT_UNDERLAY_FABRIC_IP.to_string();
        let rules: Vec<Vec<&str>> = vec![
            vec![
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                UNDERLAY_PREFIX,
                "-j",
                "MASQUERADE",
            ],
            vec![
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
                wg_port.as_str(),
                "-j",
                "DNAT",
                "--to-destination",
                fabric_ip.as_str(),
            ],
        ];
        for rule in &rules {
            let out = runner.run("iptables", rule)?;
            if !out.success {
                return Err(FabricError::Command(format!(
                    "could not seed the legacy nat rule: {}",
                    out.stderr.trim()
                )));
            }
        }
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
        let ns = names.fabric_namespace();
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
            "ip",
            &[
                "netns",
                "exec",
                &ns,
                "bridge",
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

    /// Regression test for the NAT-free underlay redesign: the WireGuard
    /// interface MUST be created in the ROOT namespace and then moved
    /// into the fabric namespace (`ip link add <wg> type wireguard`;
    /// `ip link set <wg> netns <fabric-ns>`) — never created from inside
    /// the fabric namespace. A WireGuard interface's UDP socket binds in
    /// the namespace the interface was CREATED in and never follows the
    /// interface; under this design the socket MUST live in the root
    /// namespace so that (a) outbound WG packets route via the host's
    /// normal routing with dynamic source selection and (b) inbound
    /// packets to <host-ip>:<port> are delivered directly to the
    /// listener. Creating the wg inside the fabric namespace (the
    /// pre-fix behavior) binds the socket there and, with no NAT rules
    /// in play, strands the transport.
    #[test]
    fn wireguard_is_created_in_the_root_namespace_and_moved_in()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-root-create")?;
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
        let created_in_root = provider.runner().link_created_in(&wg);
        let placed_in_ns = provider.runner().has_link_in(&wg, Some(&ns));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        // Created in the ROOT namespace, moved into the fabric namespace.
        let root_add = format!("ip link add {wg} type wireguard");
        assert!(
            joined.iter().any(|line| line == &root_add),
            "the WireGuard interface must be created in the root namespace: {root_add}"
        );
        let move_in = format!("ip link set {wg} netns {ns}");
        assert!(
            joined.iter().any(|line| line == &move_in),
            "the WireGuard interface must be moved into the fabric namespace: {move_in}"
        );
        // ...and never created from inside the fabric namespace.
        let ns_add = format!("ip netns exec {ns} ip link add {wg} type wireguard");
        assert!(
            !joined.iter().any(|line| line == &ns_add),
            "the WireGuard interface must NOT be created inside the fabric namespace \
             (the socket binds in the creating namespace)"
        );
        // Fake-kernel state agrees: the socket's creating namespace is
        // the root namespace, the link's placement is the fabric ns.
        assert_eq!(
            created_in_root,
            Some(None),
            "the wg must have been CREATED in the root namespace (socket placement)"
        );
        assert!(placed_in_ns, "the wg link must live in the fabric ns");
        Ok(())
    }

    /// Regression test for the NAT-free underlay: the provider must NOT
    /// install ANY iptables nat rule for the WireGuard transport. The
    /// v0.1.2 postmortem proved two races that any NAT state on the
    /// transport causes: (1) a DNAT rule black-holes every NEW inbound
    /// flow when the socket lives in another namespace, and (2) under
    /// simultaneous initiation the conntrack tuple collision forces
    /// MASQUERADE to remap the source port (observed 65001 → 37414),
    /// the peer roams to the remapped port, and nothing steers return
    /// traffic back — the pair never recovers. The only escape is for
    /// the outbound direction to carry NO NAT state at all.
    #[test]
    fn no_nat_rules_are_installed_for_the_transport() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("no-nat")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        // The only iptables commands the provider may issue are the
        // legacy TOLERANT DELETIONS (-D); an append (-A/-I) of any nat
        // rule is the regression.
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
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            appended.is_empty(),
            "the provider must not append any iptables rule: {appended:?}"
        );
        assert!(
            rules.is_empty(),
            "the fake kernel must hold no nat rules after apply: {rules:?}"
        );
        Ok(())
    }

    /// A host upgraded from v0.1.0/v0.1.1 (or the unpushed round-3..5
    /// code) still carries the legacy underlay machinery: the DNAT +
    /// MASQUERADE nat rules and the underlay veth pair. EVERY apply —
    /// including a pure re-apply of an unchanged plan on an otherwise
    /// healthy fabric — must tolerantly delete them, with EXACTLY the
    /// rule specifications the old code installed (`iptables -t nat -D`
    /// only matches spec-for-spec). Absence (a fresh host, a second
    /// apply) is a tolerated no-op.
    #[test]
    fn legacy_underlay_rules_and_veth_are_removed_on_every_apply()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("legacy-cleanup")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let host_veth = names.host_underlay_veth();
        let fabric_veth = names.fabric_underlay_veth();

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        // Seed the legacy machinery exactly as the old code left it.
        {
            let mut runner = provider.into_runner();
            seed_legacy_underlay(&mut runner, &config, &names)?;
            let seeded_rules = runner.iptables_rules();
            let seeded_veth = runner.has_link(host_veth.as_str());
            assert_eq!(
                seeded_rules.len(),
                2,
                "seeding sanity: both legacy nat rules must be present"
            );
            assert!(seeded_veth, "seeding sanity: the legacy veth must exist");
            provider = LinuxFabricProvider::open(config.clone(), runner)?;
        }

        // A pure re-apply (unchanged plan, healthy fabric) must still
        // remove the legacy machinery.
        let before = provider.runner().calls().len();
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
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            !report.created_fabric && !report.created_network,
            "the cleanup re-apply must not re-create anything"
        );
        // The EXACT v0.1.1 rule specifications, deleted spec-for-spec.
        let masq_del = format!("iptables -t nat -D POSTROUTING -s {UNDERLAY_PREFIX} -j MASQUERADE");
        assert!(
            slice.iter().any(|line| line == &masq_del),
            "the MASQUERADE rule must be deleted with its exact spec: {masq_del}"
        );
        let dnat_del = format!(
            "iptables -t nat -D PREROUTING ! -i {host_veth} -p udp --dport 65001 \
             -j DNAT --to-destination {}",
            DEFAULT_UNDERLAY_FABRIC_IP
        );
        assert!(
            slice.iter().any(|line| line == &dnat_del),
            "the DNAT rule must be deleted with its exact spec: {dnat_del}"
        );
        // The veth pair goes via its root end.
        let veth_del = format!("ip link del {host_veth}");
        assert!(
            slice.iter().any(|line| line == &veth_del),
            "the underlay veth pair must be deleted via its root end: {veth_del}"
        );
        assert!(rules_gone, "no legacy nat rule may survive the apply");
        assert!(veth_gone, "neither end of the underlay veth may survive");
        Ok(())
    }

    /// A v0.1.0/v0.1.1 journal (the born flag field is absent) already
    /// carries a root-created + moved WireGuard — exactly the placement
    /// this design mandates — so the wg must NOT be recreated: no
    /// deletion, no creation, no key/port forcing. Only the
    /// unconditional legacy rule/veth cleanup runs. (The pre-fix code
    /// treated this journal as needing a heal into the fabric
    /// namespace and deleted + recreated the wg.)
    #[test]
    fn legacy_journal_does_not_recreate_the_root_created_wireguard()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("legacy-keep")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let vxlan = names.vxlan(&plan.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let runner = provider.into_runner();

        // Rewrite the ownership journal in the legacy format (field
        // absent): exactly the state a v0.1.0/v0.1.1 deployment presents.
        strip_born_flag(&config)?;

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
        let wg_kept = provider.runner().has_link_in(&wg, Some(&ns));
        let vxlan_kept = provider.runner().has_link(&vxlan);
        let flag = provider.ownership().wireguard_born_in_fabric_ns;
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            !report.created_fabric,
            "a legacy journal must not re-create the (already root-created) wg"
        );
        assert!(
            !slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {wg}")),
            "the wg must not be deleted"
        );
        assert!(
            !slice
                .iter()
                .any(|line| line.contains(&format!("link add {wg}"))),
            "the wg must not be recreated: {slice:?}"
        );
        assert!(
            !slice.iter().any(
                |line| line.starts_with(&format!("ip netns exec {ns} wg set {wg} private-key"))
            ),
            "key/port must not be forced on a wg that already carries them"
        );
        assert!(
            !slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} wg set {wg} listen-port 65001")),
            "the listen port must not be forced on a configured wg"
        );
        assert!(wg_kept, "the wg must survive untouched");
        assert!(vxlan_kept, "the recorded vxlan must survive (no heal)");
        assert!(!flag, "no born-in-ns claim may appear");
        // The unconditional legacy cleanup still ran.
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip link del {}", names.host_underlay_veth())),
            "the legacy veth cleanup must still run"
        );
        Ok(())
    }

    /// Swap the fabric-ns WireGuard for one CREATED inside the namespace
    /// — reproducing the link the unpushed round-3..5 code left behind,
    /// whose UDP socket is bound in the fabric namespace (a WireGuard
    /// socket binds in its creating namespace for life and never
    /// follows the interface). Used by the born-in-ns heal scenarios.
    fn reborn_wg_in_ns(runner: &mut RecordingRunner, names: &Names) -> Result<(), FabricError> {
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
        if !out.success {
            return Err(FabricError::Command(format!(
                "could not drop the moved wg for the test: {}",
                out.stderr.trim()
            )));
        }
        let out = runner.run(
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
            return Err(FabricError::Command(format!(
                "could not re-create the wg inside the namespace: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    /// A deployment running the unpushed round-3..5 code presents the
    /// one-time full-heal state: the wg link sits inside the fabric
    /// namespace with its UDP socket bound THERE (creating_netns is
    /// immutable), the journal carries `wireguard_born_in_fabric_ns ==
    /// true`, and the legacy underlay machinery (DNAT + MASQUERADE
    /// rules, underlay veth) is still installed. Re-apply must heal:
    /// sweep a possible root-ns stray, delete every recorded VXLAN
    /// BEFORE the ns-scoped wg (crash-window ordering), delete the
    /// ns-scoped wg, clean up the legacy rules + veth, re-create the wg
    /// in the ROOT namespace and move it in, force key/port, and clear
    /// the flag. The other network's VXLAN heals on its own next apply,
    /// and a further apply is a pure no-op replay (modulo the
    /// unconditional legacy cleanup).
    #[test]
    fn born_in_fabric_ns_journal_is_healed_to_root_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-heal")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-b", 200, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let host_veth = names.host_underlay_veth();
        let vxlan_a = names.vxlan(&plan_a.network_id);
        let vxlan_b = names.vxlan(&plan_b.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        assert!(
            !provider.ownership().wireguard_born_in_fabric_ns,
            "sanity: the new code journals no heal claim"
        );
        let mut runner = provider.into_runner();

        // Reproduce the round-3..5 residue: an ns-born wg (socket bound
        // in the fabric namespace), the heal-pending flag, and the
        // legacy underlay machinery.
        reborn_wg_in_ns(&mut runner, &names)?;
        force_born_flag(&config, true)?;
        seed_legacy_underlay(&mut runner, &config, &names)?;
        assert_eq!(runner.link_created_in(&wg), Some(Some(ns.clone())));

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
        assert!(
            !healed_flag,
            "a completed heal must clear the born-in-ns claim"
        );
        // ORDER (crash-window convergence, contract §3.10): the
        // root-ns stray sweep runs first (a stray would wedge the
        // recreation at `ip link add`)...
        let index_of = |needle: &str| heal_slice.iter().position(|line| line == needle);
        let (Some(root_sweep_at), Some(wg_del_at), Some(vxlan_a_at), Some(vxlan_b_at)) = (
            index_of(&format!("ip link del {wg}")),
            index_of(&format!("ip netns exec {ns} ip link del {wg}")),
            index_of(&format!("ip netns exec {ns} ip link del {vxlan_a}")),
            index_of(&format!("ip netns exec {ns} ip link del {vxlan_b}")),
        ) else {
            return Err(Box::new(FabricError::Invalid(
                "heal ordering assertions could not find the deletion calls".to_string(),
            )));
        };
        assert!(
            root_sweep_at < vxlan_a_at && root_sweep_at < vxlan_b_at,
            "the root-ns stray sweep must run before the recorded-vxlan deletes"
        );
        // ...then every recorded VXLAN is deleted BEFORE the ns-scoped
        // wg. With the reverse order, a crash between the wg delete and
        // the VXLAN deletes orphans the VXLANs forever: the wg-absent
        // recovery would clear the flag and never delete them, while
        // identity verification keeps passing them green on a dead
        // `dev <wg>` binding.
        assert!(
            vxlan_a_at < wg_del_at && vxlan_b_at < wg_del_at,
            "the recorded vxlans must be deleted before the ns-scoped wg"
        );
        // ...and the wg is re-created in the ROOT namespace and moved
        // in, never from inside the fabric namespace.
        let (Some(root_add_at), Some(move_at)) = (
            index_of(&format!("ip link add {wg} type wireguard")),
            index_of(&format!("ip link set {wg} netns {ns}")),
        ) else {
            return Err(Box::new(FabricError::Invalid(
                "the heal must re-create the wg root-side and move it in".to_string(),
            )));
        };
        assert!(
            wg_del_at < root_add_at,
            "the ns wg dies before the recreation"
        );
        assert!(root_add_at < move_at, "the root add precedes the move");
        assert!(
            !heal_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the heal must NOT re-create the wg inside the fabric namespace"
        );
        // The legacy machinery goes in the same apply, with the EXACT
        // v0.1.1 rule specifications.
        let masq_del = format!("iptables -t nat -D POSTROUTING -s {UNDERLAY_PREFIX} -j MASQUERADE");
        assert!(
            heal_slice.iter().any(|line| line == &masq_del),
            "the heal must delete the legacy MASQUERADE rule: {masq_del}"
        );
        let dnat_del = format!(
            "iptables -t nat -D PREROUTING ! -i {host_veth} -p udp --dport 65001 \
             -j DNAT --to-destination {}",
            DEFAULT_UNDERLAY_FABRIC_IP
        );
        assert!(
            heal_slice.iter().any(|line| line == &dnat_del),
            "the heal must delete the legacy DNAT rule: {dnat_del}"
        );
        assert!(
            heal_slice
                .iter()
                .any(|line| line == &format!("ip link del {host_veth}")),
            "the heal must delete the legacy underlay veth pair"
        );
        assert!(
            provider.runner().iptables_rules().is_empty(),
            "no legacy nat rule may survive the heal"
        );
        // The fresh link has no key: key and listen port are forced
        // (from inside the namespace — `wg set` never moves the socket).
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
        // The applied network's VXLAN is re-created in the same apply;
        // the other network's heals on its own next apply.
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
        assert_eq!(
            flood_a, 1,
            "the re-created vxlan's flood list must be rebuilt exactly once"
        );
        // The replacement wg is root-born: its socket binds root-side.
        assert_eq!(
            provider.runner().link_created_in(&wg),
            Some(None),
            "the healed wg must have been CREATED in the root namespace"
        );
        assert!(provider.runner().has_link_in(&wg, Some(&ns)));

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

        // After the heal, an unchanged-plan apply is a pure no-op
        // replay — modulo the UNCONDITIONAL legacy cleanup, whose
        // tolerant deletions (`iptables -t nat -D ...`, `ip link del
        // <host-veth>`) run on every apply by design.
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
            !replay_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {wg}")),
            "post-heal replay must not delete the wg"
        );
        assert!(
            !replay_slice
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "post-heal replay must not run the root-ns stray sweep"
        );
        assert!(
            !replay_slice.iter().any(
                |line| line.starts_with(&format!("ip netns exec {ns} wg set {wg} private-key"))
            ),
            "post-heal replay must not force the private key"
        );
        assert!(
            !replay_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} wg set {wg} listen-port 65001")),
            "post-heal replay must not force the listen port"
        );
        // The unconditional legacy cleanup DID run (tolerated no-ops).
        assert!(
            replay_slice
                .iter()
                .any(|line| line == &format!("ip link del {host_veth}")),
            "the unconditional legacy veth cleanup runs on every replay"
        );
        assert_eq!(
            flood_a_after, 1,
            "post-heal replays must not duplicate flood entries"
        );
        assert!(!flag_after);
        Ok(())
    }

    /// The crash window of THIS design's own create-then-move sequence
    /// (crashed between `ip link add` and `ip link set netns` — the
    /// same window the released v0.1.0/v0.1.1 code had): a stray
    /// WireGuard link with our deterministic name sits in the ROOT
    /// namespace while the fabric namespace has none. With ownership
    /// evidence in the journal (journal-before-mutate means a genuine
    /// crash stray implies it), apply must sweep the stray tolerantly
    /// and then run the root-create + move sequence.
    #[test]
    fn stray_root_namespace_wireguard_is_swept_on_create() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("wg-stray")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();

        // Establish ownership first (the journal evidence that gates the
        // sweep), then leave the crash residue behind.
        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan)?;
        let mut runner = provider.into_runner();
        let out = runner.run("ip", &["netns", "exec", &ns, "ip", "link", "del", &wg])?;
        assert!(
            out.success,
            "could not drop the ns wg for the test: {}",
            out.stderr
        );
        let out = runner.run("ip", &["link", "add", &wg, "type", "wireguard"])?;
        assert!(out.success, "could not pre-seed the stray: {}", out.stderr);

        let before = runner.calls().len();
        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        provider.apply_plan(&plan)?;
        let joined: Vec<String> = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
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
        // ...and the replacement is created in the ROOT namespace and
        // moved in, never from inside the fabric namespace.
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip link add {wg} type wireguard")),
            "the wg must be created in the root namespace"
        );
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip link set {wg} netns {ns}")),
            "the wg must be moved into the fabric namespace"
        );
        assert!(
            !joined
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must NOT be created inside the fabric namespace"
        );
        assert!(!flag, "the creation must leave no heal claim behind");
        Ok(())
    }

    /// The other side of the ownership gate: on a FRESH host (empty
    /// journal) a root-ns link with our deterministic name is FOREIGN
    /// state — the sweep must not delete it, and the root-side
    /// `ip link add` fails closed on the name collision instead. The
    /// foreign link survives untouched (manual cleanup is the remedy;
    /// see the WireGuard section of `ensure_fabric` for why this is no
    /// worse than the released baseline).
    #[test]
    fn fresh_host_root_stray_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("wg-stray-fresh")?;
        let config = FabricLinuxConfig::new(&root);
        let plan = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let wg = names.wireguard_interface();

        // Fresh host, no journal — plus a foreign root-ns link with our
        // deterministic name.
        let mut runner = RecordingRunner::new();
        let out = runner.run("ip", &["link", "add", &wg, "type", "wireguard"])?;
        assert!(out.success, "could not pre-seed the stray: {}", out.stderr);
        let before = runner.calls().len();

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let result = provider.apply_plan(&plan);
        let sweep_issued = provider
            .runner()
            .calls()
            .iter()
            .skip(before)
            .any(|call| call.joined() == format!("ip link del {wg}"));
        let foreign_survived = provider.runner().has_link_in(&wg, None);
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "a fresh-host root-ns stray must fail the apply closed"
        );
        assert!(
            !sweep_issued,
            "a fresh host (empty journal) must not run the root-ns stray \
             sweep: the colliding link would be foreign state"
        );
        assert!(
            foreign_survived,
            "the foreign root-ns link must survive the failed apply untouched"
        );
        Ok(())
    }

    /// A WireGuard link with our deterministic name existing in BOTH the
    /// root namespace and the fabric namespace (real kernels keep
    /// per-namespace name tables, so both coexist) while the journal
    /// claims a healthy fabric is foreign state: fail closed, never
    /// adopt and never delete.
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
        let mut runner = provider.into_runner();

        // Foreign state: a SECOND link with our deterministic name in
        // the ROOT namespace, alongside the healthy fabric-ns wg (the
        // per-namespace name tables allow both to exist).
        let out = runner.run("ip", &["link", "add", &wg, "type", "wireguard"])?;
        assert!(
            out.success,
            "could not pre-seed the root-ns wg: {}",
            out.stderr
        );

        let mut provider = LinuxFabricProvider::open(config.clone(), runner)?;
        let result = provider.apply_plan(&plan);
        // The foreign root-ns link AND the healthy ns-scoped link must
        // SURVIVE the failed apply — the healthy path never deletes, it
        // only fails closed.
        let foreign_survived = provider.runner().has_link_in(&wg, None);
        let ns_wg_survived = provider.runner().has_link_in(&wg, Some(&ns));
        drop(provider);

        let _unused = fs::remove_dir_all(&root);
        assert!(
            foreign_survived,
            "a foreign root-ns wg must never be deleted by a failed apply"
        );
        assert!(
            ns_wg_survived,
            "the healthy fabric-ns wg must never be deleted by a failed apply"
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
    /// deletes but BEFORE the wg delete (pre-seeded: ns-born wg present,
    /// heal-pending flag set, VXLANs absent) converges on the next
    /// apply — the heal re-enters and finishes (the VXLAN deletions are
    /// tolerant no-ops), the applied network's VXLAN is re-created, and
    /// the born-in-ns claim is cleared. The other network's VXLAN heals
    /// on its own next apply.
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
        let mut runner = provider.into_runner();

        // Round-3..5 state (ns-born wg + heal-pending flag) plus the
        // crash residue: the heal's VXLAN deletes ran, the wg delete
        // did not.
        reborn_wg_in_ns(&mut runner, &names)?;
        force_born_flag(&config, true)?;
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
        assert!(!flag, "a completed heal must clear the born-in-ns claim");
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

    /// MAJOR-1 slice (b): the crash window DURING the heal — the ns wg
    /// was deleted, the recorded VXLANs were not (pre-seeded: wg
    /// absent, heal-pending flag set, VXLANs present, journal records
    /// both networks). The next apply takes the wg-absent branch: it
    /// must delete the stale VXLANs (their `dev <wg>` binding died with
    /// the old interface and identity verification cannot see that),
    /// re-create the wg in the ROOT namespace, move it in, plus this
    /// network's VXLAN, and clear the flag. A second apply must be a
    /// pure no-op replay (modulo the unconditional legacy cleanup).
    #[test]
    fn interrupted_heal_after_wg_delete_converges() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("heal-crashtest-b")?;
        let config = FabricLinuxConfig::new(&root);
        let plan_a = test_plan("net-a", 100, 1380, 1440).map_err(plan_error)?;
        let plan_b = test_plan("net-b", 200, 1380, 1440).map_err(plan_error)?;
        let names = Names::new(config.name_prefix())?;
        let ns = names.fabric_namespace();
        let wg = names.wireguard_interface();
        let host_veth = names.host_underlay_veth();
        let vxlan_a = names.vxlan(&plan_a.network_id);
        let vxlan_b = names.vxlan(&plan_b.network_id);

        let mut provider = LinuxFabricProvider::open(config.clone(), RecordingRunner::new())?;
        provider.apply_plan(&plan_a)?;
        provider.apply_plan(&plan_b)?;
        let mut runner = provider.into_runner();

        // Round-3..5 state (heal-pending flag) plus the crash residue:
        // the wg is gone, the recorded VXLANs survived it.
        force_born_flag(&config, true)?;
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

        // The second apply must be a pure no-op replay (modulo the
        // unconditional legacy cleanup).
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
        assert!(!flag, "the recovery must clear the born-in-ns claim");
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
        // ...the wg is re-created in the ROOT namespace and moved in...
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip link add {wg} type wireguard")),
            "the wg must be re-created in the root namespace"
        );
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip link set {wg} netns {ns}")),
            "the wg must be moved into the fabric namespace"
        );
        assert!(
            !slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must NOT be re-created inside the fabric namespace"
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
            !replay_slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link del {wg}")),
            "the second apply must not delete the wg"
        );
        assert!(
            !replay_slice
                .iter()
                .any(|line| line == &format!("ip link del {wg}")),
            "the second apply must not run the root-ns stray sweep"
        );
        // The unconditional legacy cleanup DID run (tolerated no-ops).
        assert!(
            replay_slice
                .iter()
                .any(|line| line == &format!("ip link del {host_veth}")),
            "the unconditional legacy veth cleanup runs on every replay"
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
    /// there, and journal-before-mutate means a genuine crash stray
    /// always implies a journal that shows we own(ed) fabric state. In
    /// the fake kernel the sweep is a tolerated no-op when no link
    /// exists, so the gate is observable through the recorded call
    /// journal. The wg itself is created in the ROOT namespace and
    /// moved into the fabric namespace (the design-F invariant), and no
    /// heal claim is journaled.
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
                .any(|line| line == &format!("ip link add {wg} type wireguard")),
            "the wg must be created in the root namespace"
        );
        assert!(
            joined
                .iter()
                .any(|line| line == &format!("ip link set {wg} netns {ns}")),
            "the wg must be moved into the fabric namespace"
        );
        assert!(!flag, "the creation must leave no heal claim behind");
        Ok(())
    }

    /// The other side of the gate: when the journal shows we own(ed)
    /// fabric state, a lost ns-scoped wg re-apply DOES run the root-ns
    /// stray sweep (a crash stray is ours to clean) and re-creates the
    /// wg via the root-create + move sequence — while the recorded
    /// VXLANs are NOT deleted, because the born-in-ns flag is clear (no
    /// heal pending; the belt-and-braces VXLAN sweep is scoped to
    /// pending heals).
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
                .any(|line| line == &format!("ip link add {wg} type wireguard")),
            "the wg must be re-created in the root namespace"
        );
        assert!(
            slice
                .iter()
                .any(|line| line == &format!("ip link set {wg} netns {ns}")),
            "the wg must be moved into the fabric namespace"
        );
        assert!(
            !slice
                .iter()
                .any(|line| line == &format!("ip netns exec {ns} ip link add {wg} type wireguard")),
            "the wg must NOT be re-created inside the fabric namespace"
        );
        assert!(
            report.created_fabric && !report.created_network,
            "only the wg is re-created; the network state is untouched"
        );
        assert!(
            vxlan_kept,
            "with no heal pending (flag clear), a lost wg must NOT delete \
             the recorded vxlans"
        );
        assert!(!flag);
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
