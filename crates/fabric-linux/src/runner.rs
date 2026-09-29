//! Command execution seam.
//!
//! All kernel manipulation goes through [`FabricCommand`], which makes the
//! provider fully testable: [`RecordingRunner`] implements a small in-memory
//! fake kernel plus a call journal used by the conformance suite to prove
//! command sequences, idempotency, and key hygiene.

use std::collections::BTreeMap;
use std::process::Command;

use crate::error::FabricError;

/// The result of one external command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    /// A successful empty result.
    pub fn ok() -> Self {
        Self {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

/// One recorded command invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandCall {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
}

impl CommandCall {
    /// The joined command line for matching (never contains key material:
    /// private keys travel by file path or stdin, never argv).
    pub fn joined(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            line.push_str(arg);
        }
        line
    }
}

/// The execution seam for all provider commands.
pub trait FabricCommand {
    /// Run a command, capturing output. A nonzero exit is reported through
    /// [`CommandOutput::success`], not through `Err` (which is reserved for
    /// spawn failures).
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, FabricError>;

    /// Run a command with stdin. Used for `wg pubkey`; private key material
    /// is only ever passed here or referenced by file path.
    fn run_with_stdin(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: &str,
    ) -> Result<CommandOutput, FabricError>;
}

/// Real subprocess execution.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealCommandRunner;

impl RealCommandRunner {
    fn spawn(
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Result<CommandOutput, FabricError> {
        let mut command = Command::new(program);
        command.args(args);
        if stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        }
        let output = if stdin.is_some() {
            let mut child = command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| FabricError::Command(format!("spawn {program}: {e}")))?;
            {
                use std::io::Write;
                if let Some(handle) = child.stdin.as_mut() {
                    let _unused = handle.write_all(stdin.unwrap_or("").as_bytes());
                }
            }
            child
                .wait_with_output()
                .map_err(|e| FabricError::Command(format!("wait {program}: {e}")))?
        } else {
            command
                .output()
                .map_err(|e| FabricError::Command(format!("run {program}: {e}")))?
        };
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

impl FabricCommand for RealCommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, FabricError> {
        Self::spawn(program, args, None)
    }

    fn run_with_stdin(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: &str,
    ) -> Result<CommandOutput, FabricError> {
        Self::spawn(program, args, Some(stdin))
    }
}

/// A recorded link in the fake kernel.
///
/// Links are keyed by `(name, netns)` — a real kernel's interface name
/// tables are per-network-namespace, so the same name CAN exist in the
/// root namespace and inside a namespace simultaneously (the
/// both-namespaces WireGuard collision the provider must fail closed
/// on). The key's namespace is set at creation (`ip netns exec NS ip
/// link add ...` places the link in NS; a bare `ip link add` places it
/// in the root namespace) and updated by `ip link set <link> netns
/// <ns>`. `creating_netns` records the birth namespace separately: a
/// WireGuard interface's UDP socket binds in the namespace the link
/// was CREATED in and never follows a later move — the placement the
/// underlay design depends on (contract §3.10).
#[derive(Clone, Debug, Default)]
struct FakeLink {
    kind: String,
    vni: Option<u32>,
    dstport: Option<u16>,
    local: Option<String>,
    mtu: Option<u32>,
    /// The other end of a veth pair, if any. Deleting either end of a
    /// pair removes both, wherever the peer currently lives (real
    /// kernel semantics).
    peer: Option<String>,
    /// The namespace this link was CREATED in (`None` = root). Never
    /// changes after creation — like a WireGuard socket binding.
    creating_netns: Option<String>,
    /// The WireGuard listen port configured on this link (via
    /// `wg set <if> listen-port <p>`). A real WireGuard socket binds
    /// in the link's CREATING namespace the moment a listen port (or
    /// an endpoint) is configured; the fake models the listener from
    /// `creating_netns` + this field, which is what `ss -uln` answers
    /// per namespace.
    listen_port: Option<u16>,
    addrs: std::collections::BTreeSet<String>,
}

/// An in-memory fake kernel plus call journal.
///
/// It models just enough of `ip`/`wg`/`bridge`/`iptables`/`sysctl` for the
/// provider's observation and mutation paths: namespaces, per-namespace
/// link placement, VXLAN identity, iptables nat rules (with the real
/// `Bad rule` wording on a non-matching `-D`), and success/failure
/// injection.
pub struct RecordingRunner {
    calls: Vec<CommandCall>,
    netns: std::collections::BTreeSet<String>,
    /// Links keyed by `(name, netns)` — per-namespace name tables, like
    /// the real kernel.
    links: BTreeMap<(String, Option<String>), FakeLink>,
    /// FOREIGN UDP listeners, keyed by `(namespace, port)` (`None` =
    /// root namespace) — processes unrelated to the fabric that happen
    /// to bind a port in a namespace, INDEPENDENT of any wg link.
    /// Seeded explicitly (see [`Self::add_foreign_udp_listener`]) so a
    /// test can place a listener on the configured WireGuard port in
    /// either namespace and exercise the provider's three-way
    /// socket-placement discriminator in its unattributable case: a
    /// foreign listener coexisting with our own (wherever ours is
    /// bound). `ss -uln` answers from this set as well as from the
    /// wg-link socket-placement model.
    foreign_udp_listeners: std::collections::BTreeSet<(Option<String>, u16)>,
    /// Routing-table entries (destination strings; the fake kernel models
    /// one global table, which is sufficient because the provider only
    /// manages routes inside the fabric namespace).
    routes: std::collections::BTreeSet<String>,
    /// iptables rules keyed by `<table>|<chain>|<spec>` with an instance
    /// count: `-A` appends one instance (the real iptables permits
    /// duplicate rules), `-D` removes exactly one matching instance and
    /// fails with the real `Bad rule` wording when none exists.
    iptables: BTreeMap<String, usize>,
    /// Forwarding-table entries: (device, mac, dst) triples with an
    /// instance count. Flood entries share the all-zeros MAC with one
    /// row per remote. `append` increments the count — the kernel does
    /// NOT guarantee per-(dev, mac, dst) deduplication (bridge(8):
    /// append "adds a new fdb entry with an already known LLADDR ...
    /// added multiple times"; Launchpad #1531013 documented fleets
    /// accumulating duplicate all-zeros flood entries) — so duplicate
    /// appends are visible to tests. `del` removes exactly ONE instance
    /// per call (one RTM_DELNEIGH), like the real kernel.
    fdb: BTreeMap<(String, String, String), usize>,
    failures: Vec<String>,
    /// Failures matched against the FULL joined command line (equality,
    /// not substring). Needed where a target command line is a strict
    /// SUBSTRING of another: the root-namespace `ss -uln` leg of the
    /// socket-placement discriminator is a suffix of the fabric-ns leg
    /// `ip netns exec <ns> ss -uln`, so a substring injection can only
    /// ever hit the fabric leg first. An exact-line injection pins the
    /// root leg alone.
    exact_failures: Vec<String>,
}

impl RecordingRunner {
    /// A fresh fake kernel with no objects.
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            netns: std::collections::BTreeSet::new(),
            links: BTreeMap::new(),
            foreign_udp_listeners: std::collections::BTreeSet::new(),
            routes: std::collections::BTreeSet::new(),
            iptables: BTreeMap::new(),
            fdb: BTreeMap::new(),
            failures: Vec::new(),
            exact_failures: Vec::new(),
        }
    }

    /// All recorded calls, in order.
    pub fn calls(&self) -> &[CommandCall] {
        &self.calls
    }

    /// Mutating calls only (observations excluded), for idempotency checks.
    pub fn mutating_calls(&self) -> Vec<CommandCall> {
        self.calls
            .iter()
            .filter(|call| !is_observation(&call.program, &call.args))
            .cloned()
            .collect()
    }

    /// Inject a failure for any command whose joined line contains `pattern`.
    pub fn fail_on(&mut self, pattern: impl Into<String>) {
        self.failures.push(pattern.into());
    }

    /// Inject a failure for any command whose joined line EQUALS `line`
    /// — see `exact_failures` for why substring matching is not enough
    /// when the target line is a substring of another (the bare
    /// root-ns `ss -uln` vs `ip netns exec <ns> ss -uln`).
    pub fn fail_on_exact(&mut self, line: impl Into<String>) {
        self.exact_failures.push(line.into());
    }

    /// Seed a FOREIGN UDP listener on `port` in `netns` (`None` = the
    /// root namespace): a process unrelated to the fabric — not a wg
    /// link — that happens to bind that port there. Independent of any
    /// link state, so the provider's three-way socket-placement
    /// discriminator can be exercised in its unattributable case (a
    /// foreign listener in one namespace coexisting with our own socket
    /// in the other). Observable through `ss -uln` in the seeding
    /// namespace only.
    pub fn add_foreign_udp_listener(&mut self, netns: Option<&str>, port: u16) {
        self.foreign_udp_listeners
            .insert((netns.map(str::to_string), port));
    }

    /// True when the fake kernel currently holds a link named `name` in
    /// ANY namespace.
    pub fn has_link(&self, name: &str) -> bool {
        self.links.keys().any(|(n, _)| n == name)
    }

    /// True when the fake kernel holds a link named `name` in exactly the
    /// namespace `netns` (`None` = root namespace). Real kernels keep
    /// per-namespace name tables, so the same name may exist in several
    /// namespaces at once.
    pub fn has_link_in(&self, name: &str, netns: Option<&str>) -> bool {
        self.links
            .contains_key(&(name.to_string(), netns.map(str::to_string)))
    }

    /// The namespace a link named `name` was CREATED in (`Some(None)` =
    /// root namespace), when such a link exists in any namespace. A
    /// WireGuard interface's UDP socket binds in its creating namespace
    /// for life and never follows `ip link set netns` — this is the
    /// observable socket placement the underlay design depends on.
    pub fn link_created_in(&self, name: &str) -> Option<Option<String>> {
        self.links
            .iter()
            .find(|((n, _), _)| n == name)
            .map(|(_, link)| link.creating_netns.clone())
    }

    /// The iptables rules the fake kernel currently holds, as joined
    /// `"<table> <chain> <spec>"` strings (e.g.
    /// `"nat POSTROUTING -s 169.254.253.0/30 -j MASQUERADE"`), one entry
    /// per rule instance. Empty on hosts where the provider installed no
    /// NAT rules — the regression signal for the NAT-free underlay.
    pub fn iptables_rules(&self) -> Vec<String> {
        let mut rules = Vec::new();
        for (key, count) in &self.iptables {
            let parts: Vec<&str> = key.splitn(3, '|').collect();
            if parts.len() == 3 {
                for _ in 0..*count {
                    rules.push(format!("{} {} {}", parts[0], parts[1], parts[2]));
                }
            }
        }
        rules
    }

    /// True when the fake kernel holds a route with destination `dest`
    /// (e.g. `198.18.0.2/32` or `default`).
    pub fn has_route(&self, dest: &str) -> bool {
        self.routes.contains(dest)
    }

    /// True when a link named `dev` (in any namespace) currently carries
    /// the address `addr` (e.g. `198.18.0.1/32`).
    pub fn has_addr(&self, dev: &str, addr: &str) -> bool {
        self.links
            .iter()
            .any(|((name, _), link)| name == dev && link.addrs.contains(addr))
    }

    /// The fake kernel's current MTU for a link named `name` (in any
    /// namespace), when the link exists and an MTU was set on it (links
    /// start at the generic default of 1500).
    pub fn link_mtu(&self, name: &str) -> Option<u32> {
        self.links
            .iter()
            .find(|((n, _), _)| n == name)
            .and_then(|(_, link)| link.mtu)
    }

    /// True when the fake kernel currently holds a namespace named `ns`.
    pub fn has_netns(&self, ns: &str) -> bool {
        self.netns.contains(ns)
    }

    /// True when the fake kernel holds the forwarding-table entry
    /// `(dev, mac, dst)` (one or more instances).
    pub fn has_fdb_entry(&self, dev: &str, mac: &str, dst: &str) -> bool {
        self.fdb_entry_count(dev, mac, dst) > 0
    }

    /// The number of instances of the forwarding-table entry
    /// `(dev, mac, dst)` the fake kernel currently holds. A count above
    /// one means duplicate `append`s accumulated — exactly what the
    /// real kernel may do (it does not guarantee append dedup).
    pub fn fdb_entry_count(&self, dev: &str, mac: &str, dst: &str) -> usize {
        self.fdb
            .get(&(dev.to_string(), mac.to_string(), dst.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Interpret `bridge` arguments starting at `rest` (after any
    /// `netns exec NS` prefix already stripped); `ns` is the namespace
    /// the command executes in, which decides which link table the
    /// device lookup consults.
    ///
    /// Models the kernel's forwarding-table rules closely enough to catch
    /// verb-level mistakes a real kernel rejects: `replace` is refused for
    /// non-unicast entries (the kernel error that motivated the provider's
    /// use of `append` for HER flood lists), `append` ACCUMULATES (the
    /// kernel does not guarantee per-(dev, mac, dst) deduplication —
    /// bridge(8) documents that entries "added multiple times" pile up,
    /// and field reports show duplicate all-zeros flood entries), `add` of
    /// an existing entry fails, and `del` removes exactly ONE instance
    /// per call (decrement-or-remove, one RTM_DELNEIGH — a destination
    /// that accumulated N duplicates needs N deletes to disappear
    /// entirely). `fdb show [dev <dev>]` prints one line per instance,
    /// like the real `bridge fdb show`.
    fn bridge(&mut self, ns: Option<&str>, rest: &[&str]) -> CommandOutput {
        if rest.first() != Some(&"fdb") {
            return CommandOutput::ok();
        }
        let op = rest.get(1).copied().unwrap_or("");
        if op == "show" {
            // `bridge fdb show [dev <dev>]`: without a dev filter, every
            // entry; with one, only that device's entries (the real
            // command filters the same way).
            let dev_filter = arg_after(rest, "dev").map(str::to_string);
            let mut stdout = String::new();
            for ((dev, mac, dst), count) in &self.fdb {
                if dev_filter
                    .as_deref()
                    .is_some_and(|filter| filter != dev.as_str())
                {
                    continue;
                }
                for _ in 0..*count {
                    stdout.push_str(&format!("{mac} dev {dev} dst {dst} self permanent\n"));
                }
            }
            return CommandOutput {
                success: true,
                stdout,
                stderr: String::new(),
            };
        }
        // fdb <op> <mac> dev <dev> [dst <ip>]
        let mac = rest.get(2).copied().unwrap_or("");
        let dev = arg_after(rest, "dev").unwrap_or("");
        let dst = arg_after(rest, "dst").unwrap_or("");
        if dev.is_empty() {
            return command_error("bridge: insufficient arguments");
        }
        let dev_key = (dev.to_string(), ns.map(str::to_string));
        if !self.links.contains_key(&dev_key) {
            return command_error(&format!("Cannot find device \"{dev}\""));
        }
        if self
            .links
            .get(&dev_key)
            .is_some_and(|link| link.kind != "vxlan")
        {
            return command_error("Operation not supported: fdb with dst requires a vxlan device");
        }
        if !is_unicast_mac(mac) && op == "replace" {
            return command_error("Cannot replace non-unicast fdb entries.");
        }
        let entry = (dev.to_string(), mac.to_string(), dst.to_string());
        match op {
            "append" => {
                // The kernel does not dedup: each append adds an instance.
                *self.fdb.entry(entry).or_insert(0) += 1;
                CommandOutput::ok()
            }
            "add" => match self.fdb.entry(entry) {
                std::collections::btree_map::Entry::Occupied(_) => {
                    command_error("RTNETLINK answers: File exists")
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(1);
                    CommandOutput::ok()
                }
            },
            "del" => {
                // One RTM_DELNEIGH removes exactly ONE instance: a
                // destination that accumulated N duplicate entries needs
                // N deletes to disappear entirely (the real kernel
                // behaves the same way).
                match self.fdb.get_mut(&entry) {
                    Some(count) if *count > 1 => {
                        *count -= 1;
                        CommandOutput::ok()
                    }
                    Some(_) => {
                        self.fdb.remove(&entry);
                        CommandOutput::ok()
                    }
                    None => command_error("RTNETLINK answers: No such file or directory"),
                }
            }
            "replace" => {
                let mac_owned = mac.to_string();
                self.fdb
                    .retain(|(d, m, _), _| !(d == dev && *m == mac_owned));
                self.fdb.insert(entry, 1);
                CommandOutput::ok()
            }
            _ => command_error("bridge: unknown fdb operation"),
        }
    }

    fn record(&mut self, program: &str, args: &[&str], stdin: Option<&str>) {
        self.calls.push(CommandCall {
            program: program.to_string(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            stdin: stdin.map(str::to_string),
        });
    }

    fn should_fail(&self, program: &str, args: &[&str]) -> bool {
        let joined = format!("{program} {}", args.join(" "));
        self.failures.iter().any(|p| joined.contains(p)) || self.exact_failures.contains(&joined)
    }

    /// Interpret `ip` arguments starting at `rest`. `ns` is the network
    /// namespace the command executes in (`Some(..)` for
    /// `ip netns exec NS ip ...`, `None` for a root-namespace call); it
    /// decides which per-namespace link table created links are placed
    /// into and which links a namespace-scoped command observes or
    /// mutates — like the real kernel, where a link named `x` in the
    /// root namespace and one named `x` inside a namespace are two
    /// different interfaces.
    fn ip(&mut self, ns: Option<&str>, rest: &[&str]) -> CommandOutput {
        // Normalize: drop a leading `-d` detail flag, remembering it.
        let detail = rest.first() == Some(&"-d");
        let rest = if detail { &rest[1..] } else { rest };
        // The per-namespace table key every lookup below uses.
        let key_of = |name: &str| (name.to_string(), ns.map(str::to_string));
        // link add NAME type KIND [vxlan opts]
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"add") {
            let name = rest[2];
            let mut link = FakeLink {
                kind: "generic".to_string(),
                // A link is born in the namespace the add runs in; its
                // WireGuard socket (if any) binds there for life.
                creating_netns: ns.map(str::to_string),
                ..FakeLink::default()
            };
            let mut peer_name: Option<&str> = None;
            let mut i = 3;
            while i < rest.len() {
                match rest[i] {
                    "type" => {
                        if let Some(kind) = rest.get(i + 1) {
                            link.kind = (*kind).to_string();
                        }
                        i += 2;
                    }
                    "id" => {
                        if let Some(vni) = rest.get(i + 1) {
                            link.vni = parse_u32(vni);
                        }
                        i += 2;
                    }
                    "dstport" => {
                        if let Some(port) = rest.get(i + 1) {
                            link.dstport = port.parse::<u16>().ok();
                        }
                        i += 2;
                    }
                    "local" => {
                        if let Some(local) = rest.get(i + 1) {
                            link.local = Some((*local).to_string());
                        }
                        i += 2;
                    }
                    "peer" => {
                        // `peer name <name>`: a veth pair creates both ends.
                        if let (Some(&"name"), Some(peer)) = (rest.get(i + 1), rest.get(i + 2)) {
                            peer_name = Some(peer);
                            i += 3;
                        } else {
                            i += 1;
                        }
                    }
                    _ => i += 1,
                }
            }
            // The kernel refuses to create an existing name — per
            // namespace.
            if self.links.contains_key(&key_of(name)) {
                return command_error("RTNETLINK answers: File exists");
            }
            if let Some(peer) = peer_name {
                if self.links.contains_key(&key_of(peer)) {
                    return command_error("RTNETLINK answers: File exists");
                }
                let peer_link = FakeLink {
                    peer: Some(name.to_string()),
                    creating_netns: ns.map(str::to_string),
                    ..FakeLink::default()
                };
                self.links.insert(key_of(peer), peer_link);
                link.peer = Some(peer.to_string());
            }
            self.links.insert(key_of(name), link);
            return CommandOutput::ok();
        }
        // link del NAME. Deleting a device drops its forwarding entries;
        // deleting one end of a veth pair removes BOTH ends, wherever the
        // peer currently lives (real kernel semantics — deleting the
        // root-ns underlay veth also removes the fabric-ns peer and the
        // routes via them). Deleting a missing device fails like the real
        // `ip` ("Cannot find device") — providers must tolerate that
        // explicitly.
        if rest.first() == Some(&"link") && matches!(rest.get(1), Some(&"del") | Some(&"delete")) {
            if let Some(name) = rest.get(2) {
                let Some((_, link)) = self.links.remove_entry(&key_of(name)) else {
                    return cannot_find_device(name);
                };
                self.drop_link_state(name);
                if let Some(peer) = link.peer {
                    // The peer may have been moved to another namespace;
                    // find it by name anywhere.
                    let peer_key = self.links.keys().find(|(n, _)| n == &peer).cloned();
                    if let Some(peer_key) = peer_key {
                        self.links.remove(&peer_key);
                        self.drop_link_state(&peer);
                    }
                }
            }
            return CommandOutput::ok();
        }
        // addr add|replace|del ADDR dev DEV
        if rest.first() == Some(&"addr") {
            let op = rest.get(1).copied().unwrap_or("");
            let addr = rest.get(2).copied().unwrap_or("");
            let dev = arg_after(rest, "dev").unwrap_or("");
            let Some(link) = self.links.get_mut(&key_of(dev)) else {
                return cannot_find_device(dev);
            };
            return match op {
                "add" => {
                    if link.addrs.contains(addr) {
                        command_error("RTNETLINK answers: File exists")
                    } else {
                        link.addrs.insert(addr.to_string());
                        CommandOutput::ok()
                    }
                }
                "replace" => {
                    // Same-address re-assert is the idempotent path. The
                    // fake models one primary address per host part: a
                    // replaced address displaces an existing one with the
                    // same host part (the provider's /32 transport moves
                    // exactly once per plan change).
                    let host_part = addr.split('/').next().unwrap_or(addr);
                    link.addrs.retain(|existing| {
                        existing.split('/').next().unwrap_or(existing) != host_part
                    });
                    link.addrs.insert(addr.to_string());
                    CommandOutput::ok()
                }
                "del" => {
                    if link.addrs.remove(addr) {
                        CommandOutput::ok()
                    } else {
                        command_error("RTNETLINK answers: No such file or directory")
                    }
                }
                _ => CommandOutput::ok(),
            };
        }
        // route replace <dest...> | route del <dest...>
        if rest.first() == Some(&"route") {
            let op = rest.get(1).copied().unwrap_or("");
            let dest = rest.get(2).copied().unwrap_or("");
            return match op {
                "replace" => {
                    self.routes.insert(dest.to_string());
                    CommandOutput::ok()
                }
                "del" => {
                    // The real `ip` fails with "No such process" when the
                    // route is absent (and "FIB table does not exist" on
                    // an entirely empty table) — both verified on kernel
                    // 6.8. The provider's tolerant deletions must match
                    // those strings, never the fdb wording.
                    if self.routes.remove(dest) {
                        CommandOutput::ok()
                    } else {
                        command_error("RTNETLINK answers: No such process")
                    }
                }
                _ => CommandOutput::ok(),
            };
        }
        // link set NAME mtu N | link set NAME name NEW | link set NAME netns NS
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"set") {
            if let (Some(name), Some(op)) = (rest.get(2), rest.get(3)) {
                match *op {
                    "mtu" => {
                        let value = rest.get(4).copied().and_then(parse_u32);
                        return match (self.links.get_mut(&key_of(name)), value) {
                            (Some(link), Some(mtu)) => {
                                link.mtu = Some(mtu);
                                CommandOutput::ok()
                            }
                            (Some(_), None) => {
                                command_error(&format!("invalid MTU value for \"{name}\""))
                            }
                            (None, _) => cannot_find_device(name),
                        };
                    }
                    "name" => {
                        if let Some(new_name) = rest.get(4)
                            && let Some((_, link)) = self.links.remove_entry(&key_of(name))
                        {
                            self.links.insert(key_of(new_name), link);
                            return CommandOutput::ok();
                        }
                        return cannot_find_device(name);
                    }
                    "netns" => {
                        // `ip link set NAME netns NS` moves the link into
                        // NS (the placement — never the WireGuard socket,
                        // which stays bound in the creating namespace).
                        let Some(target) = rest.get(4) else {
                            return cannot_find_device(name);
                        };
                        let Some((_, link)) = self.links.remove_entry(&key_of(name)) else {
                            return cannot_find_device(name);
                        };
                        self.links
                            .insert((name.to_string(), Some((*target).to_string())), link);
                        return CommandOutput::ok();
                    }
                    // up/down/master/addr: accepted, not modeled.
                    _ => {}
                }
            }
            return CommandOutput::ok();
        }
        // link show [-d] NAME — observes only the command's own
        // namespace's name table, like the real kernel.
        if rest.first() == Some(&"link")
            && rest.get(1) == Some(&"show")
            && let Some(name) = rest.get(2)
        {
            if let Some(link) = self.links.get(&key_of(name)) {
                let mut stdout = format!(
                    "{}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu {} state UP\n",
                    name,
                    link.mtu.unwrap_or(1500)
                );
                if detail {
                    match link.kind.as_str() {
                        "vxlan" => {
                            let vni = link.vni.unwrap_or(0);
                            let dstport = link.dstport.unwrap_or(0);
                            // Shape mirrors the real `ip -d link show`:
                            // `vxlan id <vni> [local <ip>] ... dstport <p>`.
                            match link.local.as_ref() {
                                Some(local) => stdout.push_str(&format!(
                                    "    vxlan id {vni} local {local} dstport {dstport} learning\n"
                                )),
                                None => stdout.push_str(&format!(
                                    "    vxlan id {vni} dstport {dstport} learning\n"
                                )),
                            }
                        }
                        "wireguard" => stdout.push_str("    wireguard\n"),
                        _ => stdout.push_str("    link/ether\n"),
                    }
                }
                return CommandOutput {
                    success: true,
                    stdout,
                    stderr: String::new(),
                };
            }
            return missing_device(name);
        }
        CommandOutput::ok()
    }

    /// Drop the forwarding-table entries of a deleted device.
    fn drop_link_state(&mut self, name: &str) {
        self.fdb.retain(|(dev, _, _), _| dev != name);
    }

    /// Interpret `iptables` arguments: `[-t TABLE] OP CHAIN SPEC...`.
    ///
    /// `-A`/`-I` append one rule instance (the real iptables permits
    /// identical duplicate rules); `-D` removes exactly ONE matching
    /// instance and fails with the real wording when no rule matches —
    /// `iptables: Bad rule (does a matching rule exist in that chain?)` —
    /// which the provider's tolerant deletions must match. `-S`/`-L`
    /// dump one `-A CHAIN SPEC` line per instance.
    fn iptables(&mut self, args: &[&str]) -> CommandOutput {
        let mut rest = args;
        let mut table = "filter".to_string();
        if rest.first() == Some(&"-t") {
            if let Some(t) = rest.get(1) {
                table = (*t).to_string();
            }
            rest = &rest[2..];
        }
        let Some(op) = rest.first().copied() else {
            return CommandOutput::ok();
        };
        if op == "-S" || op == "-L" {
            let prefix = format!("{table}|");
            let mut stdout = String::new();
            for (key, count) in &self.iptables {
                if !key.starts_with(&prefix) {
                    continue;
                }
                let parts: Vec<&str> = key.splitn(3, '|').collect();
                if parts.len() == 3 {
                    for _ in 0..*count {
                        stdout.push_str(&format!("-A {} {}\n", parts[1], parts[2]));
                    }
                }
            }
            return CommandOutput {
                success: true,
                stdout,
                stderr: String::new(),
            };
        }
        let chain = rest.get(1).copied().unwrap_or("");
        let spec = rest[2..].join(" ");
        let key = format!("{table}|{chain}|{spec}");
        match op {
            "-A" | "-I" => {
                *self.iptables.entry(key).or_insert(0) += 1;
                CommandOutput::ok()
            }
            "-D" => match self.iptables.get_mut(&key) {
                Some(count) if *count > 1 => {
                    *count -= 1;
                    CommandOutput::ok()
                }
                Some(_) => {
                    self.iptables.remove(&key);
                    CommandOutput::ok()
                }
                None => {
                    command_error("iptables: Bad rule (does a matching rule exist in that chain?).")
                }
            },
            _ => CommandOutput::ok(),
        }
    }

    /// Interpret `wg` arguments executed inside namespace `ns` (the
    /// `ip netns exec NS wg ...` shape the provider uses):
    /// `wg set <if> [private-key <path>] [listen-port <port>]
    /// [peer ...]`.
    ///
    /// `listen-port` is recorded on the link — a real WireGuard socket
    /// binds in the link's CREATING namespace as soon as the port is
    /// configured, and the fake's `ss -uln` answers from exactly that
    /// model, so a provider that misplaces the socket placement is
    /// observable. `wg set` on a missing device fails with the real
    /// wording. Private keys travel by file path (never argv) and are
    /// not modeled beyond success.
    fn wg(&mut self, ns: Option<&str>, rest: &[&str]) -> CommandOutput {
        if rest.first() != Some(&"set") {
            return CommandOutput::ok();
        }
        let Some(name) = rest.get(1) else {
            return command_error("wg: insufficient arguments");
        };
        let key = ((*name).to_string(), ns.map(str::to_string));
        let Some(link) = self.links.get_mut(&key) else {
            return command_error(&format!(
                "Unable to modify interface: {name}: No such device"
            ));
        };
        if let Some(i) = rest.iter().position(|t| *t == "listen-port")
            && let Some(port) = rest.get(i + 1)
        {
            link.listen_port = port.parse::<u16>().ok();
        }
        CommandOutput::ok()
    }

    /// `ss -uln` (listening UDP sockets, numeric) executed in namespace
    /// `ns` (`None` = root): one line per WireGuard listener whose
    /// socket is bound in that namespace, plus one per FOREIGN listener
    /// seeded there (see [`Self::add_foreign_udp_listener`]).
    ///
    /// Answered from the socket-placement model: a WireGuard socket
    /// binds in the namespace the link was CREATED in (`creating_netns`)
    /// and never follows a later `ip link set netns` — so the dump of
    /// the fabric namespace lists exactly the interfaces born INSIDE it
    /// (the ns-bound placement the provider's runtime verification
    /// detects), never a root-created link that was moved in. Line
    /// shapes mirror the real ss(8) `State Recv-Q Send-Q Local
    /// Address:Port Peer Address:Port` columns, with both the wildcard
    /// IPv4 and bracketed IPv6 local-address forms a dual-stack bind
    /// prints.
    fn ss(&self, ns: Option<&str>, rest: &[&str]) -> CommandOutput {
        // Collect the combined short flags (`-uln`, `-u -l -n`, `-lun`,
        // ...): a substring check would miss `-l` inside `-uln`.
        let mut flags = String::new();
        for arg in rest {
            if arg.starts_with('-') && !arg.starts_with("--") {
                flags.push_str(&arg[1..]);
            }
        }
        let has = |flag: char| flags.contains(flag);
        if !(has('u') && has('l') && has('n')) {
            return CommandOutput::ok();
        }
        let mut stdout =
            String::from("State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n");
        for link in self.links.values() {
            if link.kind != "wireguard" {
                continue;
            }
            if link.creating_netns.as_deref() != ns {
                continue;
            }
            let Some(port) = link.listen_port else {
                continue;
            };
            stdout.push_str(&format!("UNCONN 0      0      0.0.0.0:{port} 0.0.0.0:*\n"));
            stdout.push_str(&format!("UNCONN 0      0      [::]:{port} [::]:*\n"));
        }
        for (netns, port) in &self.foreign_udp_listeners {
            if netns.as_deref() != ns {
                continue;
            }
            stdout.push_str(&format!("UNCONN 0      0      0.0.0.0:{port} 0.0.0.0:*\n"));
            stdout.push_str(&format!("UNCONN 0      0      [::]:{port} [::]:*\n"));
        }
        CommandOutput {
            success: true,
            stdout,
            stderr: String::new(),
        }
    }
}

fn parse_u32(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok()
}

/// The argument that follows `flag` in `args`, if present.
fn arg_after<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == flag)
        .and_then(|i| args.get(i + 1).copied())
}

/// True for a unicast MAC: not all-zeros, not broadcast, and without the
/// multicast bit set in the first octet.
fn is_unicast_mac(mac: &str) -> bool {
    let Some(first) = mac.split(':').next() else {
        return false;
    };
    let Ok(first) = u8::from_str_radix(first, 16) else {
        return false;
    };
    if first & 0x01 != 0 {
        return false;
    }
    !mac.split(':').all(|octet| octet == "00")
}

/// A failed command with a stderr message, like the real `ip`.
fn command_error(message: &str) -> CommandOutput {
    CommandOutput {
        success: false,
        stdout: String::new(),
        stderr: message.to_string(),
    }
}

/// The `ip` "device does not exist" failure of `link show` (real
/// wording, verified on kernel 6.8 / iproute2 6.1).
fn missing_device(name: &str) -> CommandOutput {
    command_error(&format!("Device \"{name}\" does not exist."))
}

/// The `ip` "Cannot find device" failure of mutations (`link del`,
/// `link set`, `addr ...`) on a missing device (real wording, verified
/// on kernel 6.8 / iproute2 6.1).
fn cannot_find_device(name: &str) -> CommandOutput {
    command_error(&format!("Cannot find device \"{name}\""))
}

/// Deterministic base64 public key for the fake kernel: a function of
/// the private-key material's LENGTH modulo 64 — so all realistic
/// 44-character materials deliberately collide on one fake key (the
/// fake models `wg pubkey` succeeding, not its one-way function) — and
/// always valid under `fabric_plan::PublicKey::new` (43 alphabet
/// characters plus one trailing '=' pad).
fn fake_public_key(private_material: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let seed = private_material.len();
    let mut key = String::with_capacity(44);
    for i in 0..43 {
        let index = (seed + i * 7 + 11) % ALPHABET.len();
        key.push(ALPHABET[index] as char);
    }
    key.push('=');
    key
}

fn is_observation(program: &str, args: &[String]) -> bool {
    // A bare `ss ...` invocation (the root-namespace leg of the
    // socket-placement discriminator) is always an observation — the
    // provider only ever runs `ss` to look, never to mutate.
    if program == "ss" {
        return true;
    }
    // `ip [netns exec NS] (ip) ([-d]) link show ...` and `ip netns list`
    let mut rest: &[String] = args;
    if rest.first().map(String::as_str) == Some("netns")
        && rest.get(1).map(String::as_str) == Some("exec")
    {
        rest = &rest[3..];
    }
    // After stripping, a namespaced call begins with the inner program
    // (`ip`); a host-level call begins with ip arguments directly.
    let mut ip_args: &[String] = if rest.first().map(String::as_str) == Some("ip") {
        &rest[1..]
    } else {
        rest
    };
    if ip_args.first().map(String::as_str) == Some("-d") {
        ip_args = &ip_args[1..];
    }
    if ip_args.first().map(String::as_str) == Some("netns")
        && ip_args.get(1).map(String::as_str) == Some("list")
    {
        return true;
    }
    if ip_args.first().map(String::as_str) == Some("link")
        && ip_args.get(1).map(String::as_str) == Some("show")
    {
        return true;
    }
    // `bridge fdb show ...` (namespaced: `ip netns exec NS bridge fdb show`;
    // bare: program `bridge`, args starting `fdb show`)
    if (ip_args.first().map(String::as_str) == Some("bridge")
        && ip_args.get(1).map(String::as_str) == Some("fdb")
        && ip_args.get(2).map(String::as_str) == Some("show"))
        || (ip_args.first().map(String::as_str) == Some("fdb")
            && ip_args.get(1).map(String::as_str) == Some("show"))
    {
        return true;
    }
    // `ss -uln` (namespaced: `ip netns exec NS ss -uln`; bare: program
    // `ss`) — the runtime socket-placement observation.
    if ip_args.first().map(String::as_str) == Some("ss") {
        return true;
    }
    // `iptables -S` / `-L` dumps (any table) — the nat-residue
    // observation. A standalone `-S`/`-L` token never appears inside a
    // rule specification the provider issues.
    if ip_args.iter().any(|arg| arg == "-S" || arg == "-L") {
        return true;
    }
    false
}

impl Default for RecordingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricCommand for RecordingRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CommandOutput, FabricError> {
        self.record(program, args, None);
        if self.should_fail(program, args) {
            return Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "injected failure".to_string(),
            });
        }
        match program {
            "ip" => {
                // Strip `netns exec NS` prefix. A missing namespace fails
                // like the real `ip netns exec`; otherwise the namespace
                // is the scope the inner command runs in.
                if args.first() == Some(&"netns") && args.get(1) == Some(&"exec") {
                    if let Some(ns) = args.get(2).filter(|ns| !self.netns.contains(**ns)) {
                        return Ok(command_error(&format!(
                            "Cannot open network namespace \"{ns}\""
                        )));
                    }
                    match args.get(3) {
                        Some(&"ip") => return Ok(self.ip(args.get(2).copied(), &args[4..])),
                        Some(&"bridge") => return Ok(self.bridge(args.get(2).copied(), &args[4..])),
                        Some(&"wg") => return Ok(self.wg(args.get(2).copied(), &args[4..])),
                        Some(&"ss") => return Ok(self.ss(args.get(2).copied(), &args[4..])),
                        _ => return Ok(CommandOutput::ok()),
                    }
                }
                if args.first() == Some(&"netns") && args.get(1) == Some(&"list") {
                    let stdout = self
                        .netns
                        .iter()
                        .map(|ns| format!("{ns} (id: 0)"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    return Ok(CommandOutput {
                        success: true,
                        stdout,
                        stderr: String::new(),
                    });
                }
                if args.first() == Some(&"netns") && args.get(1) == Some(&"add") {
                    if let Some(ns) = args.get(2) {
                        self.netns.insert((*ns).to_string());
                    }
                    return Ok(CommandOutput::ok());
                }
                if args.first() == Some(&"netns") && args.get(1) == Some(&"del") {
                    if let Some(ns) = args.get(2) {
                        if !self.netns.contains(*ns) {
                            // Real wording (iproute2, verified on 6.8):
                            // removing a namespace that does not exist
                            // fails on the missing namespace file.
                            return Ok(command_error(&format!(
                                "Cannot remove namespace file \"/run/netns/{ns}\": \
                                 No such file or directory"
                            )));
                        }
                        // Deleting a namespace destroys the links placed
                        // in it, like the real kernel.
                        let ns_name = (*ns).to_string();
                        self.netns.remove(*ns);
                        self.links
                            .retain(|(_, netns), _| netns.as_deref() != Some(ns_name.as_str()));
                    }
                    return Ok(CommandOutput::ok());
                }
                Ok(self.ip(None, args))
            }
            "wg" => {
                if args.first() == Some(&"genkey") {
                    return Ok(CommandOutput {
                        success: true,
                        stdout: "fabric-test-private-key-material\n".to_string(),
                        stderr: String::new(),
                    });
                }
                Ok(CommandOutput::ok())
            }
            "bridge" => Ok(self.bridge(None, args)),
            "iptables" => Ok(self.iptables(args)),
            "ss" => Ok(self.ss(None, args)),
            _ => Ok(CommandOutput::ok()),
        }
    }

    fn run_with_stdin(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: &str,
    ) -> Result<CommandOutput, FabricError> {
        self.record(program, args, Some(stdin));
        if program == "wg" && args.first() == Some(&"pubkey") {
            return Ok(CommandOutput {
                // Deterministic 44-character base64 public key — 43
                // alphabet characters plus one trailing '=' pad, the
                // exact shape a real `wg pubkey` emits for 32 key bytes —
                // so key-shape validation in the plan layer is exercised
                // faithfully (review loop F-3).
                success: true,
                stdout: format!("{}\n", fake_public_key(stdin.trim())),
                stderr: String::new(),
            });
        }
        Ok(CommandOutput::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert a command result into an output, turning transport errors
    /// into failed outputs (unwrap/expect/panic are denied by the lints).
    fn ok_or_err_out(res: Result<CommandOutput, FabricError>) -> CommandOutput {
        match res {
            Ok(out) => out,
            Err(e) => CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: format!("command error: {e}"),
            },
        }
    }

    fn vxlan(runner: &mut RecordingRunner) {
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "link", "add", "vx0", "type", "vxlan", "id", "4711", "dstport", "4789",
            ],
        ));
        assert!(out.success, "vxlan creation failed: {}", out.stderr);
    }

    fn fdb(runner: &mut RecordingRunner, op: &str, dst: &str) -> CommandOutput {
        ok_or_err_out(runner.run(
            "bridge",
            &["fdb", op, "00:00:00:00:00:00", "dev", "vx0", "dst", dst],
        ))
    }

    #[test]
    fn fdb_replace_on_non_unicast_is_rejected_like_the_kernel() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        let out = fdb(&mut runner, "replace", "198.18.0.2");
        assert!(!out.success, "kernel rejects replace on non-unicast MACs");
        assert!(
            out.stderr
                .contains("Cannot replace non-unicast fdb entries")
        );
        assert!(!runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.2"));
    }

    #[test]
    fn fdb_append_accumulates_and_del_removes_one_instance_per_call() {
        // The kernel does NOT guarantee append deduplication (bridge(8);
        // Launchpad #1531013): each append adds an instance. Each
        // `bridge fdb del` (one RTM_DELNEIGH) removes exactly ONE
        // instance — a destination that accumulated N duplicates needs N
        // deletes to disappear entirely. Duplicate counts are observable
        // through `fdb_entry_count` and in `fdb show` output.
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        assert_eq!(
            runner.fdb_entry_count("vx0", "00:00:00:00:00:00", "198.18.0.2"),
            2,
            "duplicate appends must be visible"
        );
        assert!(fdb(&mut runner, "append", "198.18.0.3").success);
        assert!(runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.3"));
        // `fdb show` prints one line per instance.
        let show = ok_or_err_out(runner.run("bridge", &["fdb", "show"]));
        assert!(show.success);
        assert_eq!(
            show.stdout
                .lines()
                .filter(|l| l.contains("dst 198.18.0.2"))
                .count(),
            2,
            "duplicated entries show as duplicated lines"
        );
        // One del removes ONE instance: the duplicate shrinks to 1...
        assert!(fdb(&mut runner, "del", "198.18.0.2").success);
        assert_eq!(
            runner.fdb_entry_count("vx0", "00:00:00:00:00:00", "198.18.0.2"),
            1,
            "del removes exactly one instance"
        );
        assert!(runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.2"));
        // ...and the last del removes the entry outright.
        assert!(fdb(&mut runner, "del", "198.18.0.2").success);
        assert_eq!(
            runner.fdb_entry_count("vx0", "00:00:00:00:00:00", "198.18.0.2"),
            0,
            "the final del removes the last instance"
        );
        let out = fdb(&mut runner, "del", "198.18.0.2");
        assert!(!out.success, "deleting a missing entry must fail");
        assert!(
            out.stderr.contains("No such file or directory"),
            "real fdb del wording: {}",
            out.stderr
        );
    }

    #[test]
    fn fdb_show_filters_by_device() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "link", "add", "vx1", "type", "vxlan", "id", "4712", "dstport", "4789",
            ],
        ));
        assert!(out.success, "second vxlan creation failed: {}", out.stderr);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        let out = ok_or_err_out(runner.run(
            "bridge",
            &[
                "fdb",
                "append",
                "00:00:00:00:00:00",
                "dev",
                "vx1",
                "dst",
                "198.18.0.9",
            ],
        ));
        assert!(out.success, "append to vx1 failed: {}", out.stderr);
        let out = ok_or_err_out(runner.run("bridge", &["fdb", "show", "dev", "vx1"]));
        assert!(out.success);
        assert!(
            !out.stdout.contains("198.18.0.2"),
            "the dev filter must hide other devices' entries: {}",
            out.stdout
        );
        assert!(out.stdout.contains("198.18.0.9"));
    }

    #[test]
    fn fdb_add_existing_fails_but_append_does_not() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        assert!(fdb(&mut runner, "add", "198.18.0.2").success);
        let out = fdb(&mut runner, "add", "198.18.0.2");
        assert!(!out.success);
        assert!(out.stderr.contains("File exists"));
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
    }

    #[test]
    fn fdb_requires_an_existing_vxlan_device() {
        let mut runner = RecordingRunner::new();
        let out = fdb(&mut runner, "append", "198.18.0.2");
        assert!(!out.success);
        assert!(out.stderr.contains("Cannot find device"));
        // A non-vxlan device refuses remote entries.
        let out = ok_or_err_out(runner.run("ip", &["link", "add", "eth9", "type", "dummy"]));
        assert!(out.success, "dummy link creation failed: {}", out.stderr);
        let out = ok_or_err_out(runner.run(
            "bridge",
            &[
                "fdb",
                "append",
                "00:00:00:00:00:00",
                "dev",
                "eth9",
                "dst",
                "198.18.0.2",
            ],
        ));
        assert!(!out.success);
    }

    #[test]
    fn link_deletion_drops_its_fdb_entries() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        let out = ok_or_err_out(runner.run("ip", &["link", "del", "vx0"]));
        assert!(out.success, "link deletion failed: {}", out.stderr);
        assert!(!runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.2"));
    }

    #[test]
    fn deleting_a_missing_link_fails_like_the_kernel() {
        let mut runner = RecordingRunner::new();
        let out = ok_or_err_out(runner.run("ip", &["link", "del", "gone0"]));
        assert!(
            !out.success,
            "the real kernel fails to delete a missing link"
        );
        assert!(
            out.stderr.contains("Cannot find device"),
            "stderr must name the missing device like the real ip: {}",
            out.stderr
        );
    }

    #[test]
    fn netns_scoped_link_add_places_the_link_in_the_namespace() {
        let mut runner = RecordingRunner::new();
        let out = ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"]));
        assert!(out.success, "netns add failed: {}", out.stderr);
        // A link created from inside a namespace is placed there.
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "ip",
                "link",
                "add",
                "wgx",
                "type",
                "wireguard",
            ],
        ));
        assert!(out.success, "ns-scoped link add failed: {}", out.stderr);
        // A namespace-scoped show observes it...
        let out =
            ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ip", "link", "show", "wgx"]));
        assert!(out.success, "ns-scoped show must see the link");
        // ...but the ROOT namespace does not (real kernel semantics).
        let out = ok_or_err_out(runner.run("ip", &["link", "show", "wgx"]));
        assert!(
            !out.success,
            "a root-ns show must not see a namespace-placed link"
        );
        assert!(out.stderr.contains("does not exist"));

        // `ip link set <link> netns <ns>` moves the placement...
        let out = ok_or_err_out(runner.run("ip", &["link", "add", "wgroot", "type", "wireguard"]));
        assert!(out.success, "root link add failed: {}", out.stderr);
        let out = ok_or_err_out(runner.run("ip", &["link", "show", "wgroot"]));
        assert!(out.success, "a root-created link is visible in the root ns");
        let out = ok_or_err_out(runner.run("ip", &["link", "set", "wgroot", "netns", "nsx"]));
        assert!(out.success, "netns move failed: {}", out.stderr);
        let out = ok_or_err_out(runner.run("ip", &["link", "show", "wgroot"]));
        assert!(
            !out.success,
            "a moved link is no longer visible in the root ns"
        );

        // ...and deleting the namespace destroys its links.
        let out = ok_or_err_out(runner.run("ip", &["netns", "del", "nsx"]));
        assert!(out.success, "netns del failed: {}", out.stderr);
        assert!(!runner.has_link("wgx"), "ns links die with the netns");
        assert!(!runner.has_link("wgroot"));
    }

    /// Real kernels keep per-namespace name tables: the same name can
    /// exist in the root namespace and inside a namespace at the same
    /// time. The fake models this — it is the state the provider's
    /// both-namespaces WireGuard collision check fails closed on.
    #[test]
    fn the_same_link_name_can_exist_in_two_namespaces() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        // Root-created link...
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "add", "wg0", "type", "wireguard"])).success
        );
        // ...plus a DIFFERENT link with the same name inside the ns: both
        // coexist (the add does not fail with "File exists").
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "ip",
                "link",
                "add",
                "wg0",
                "type",
                "wireguard",
            ],
        ));
        assert!(out.success, "per-ns name tables must allow the same name");
        assert!(runner.has_link_in("wg0", None));
        assert!(runner.has_link_in("wg0", Some("nsx")));
        // Each namespace's show sees only its own link...
        assert!(ok_or_err_out(runner.run("ip", &["link", "show", "wg0"])).success);
        assert!(
            ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ip", "link", "show", "wg0"]))
                .success
        );
        // ...and a root-ns deletion does not touch the ns-scoped one.
        assert!(ok_or_err_out(runner.run("ip", &["link", "del", "wg0"])).success);
        assert!(
            !runner.has_link_in("wg0", None),
            "the root-ns link must be gone"
        );
        assert!(
            runner.has_link_in("wg0", Some("nsx")),
            "the ns-scoped link must survive a root-ns deletion"
        );
    }

    /// The creating namespace of a link is recorded separately from its
    /// current placement: a WireGuard interface's UDP socket binds in
    /// the creating namespace for life and never follows
    /// `ip link set netns` — the placement the underlay design
    /// depends on.
    #[test]
    fn link_creation_namespace_is_recorded_separately_from_placement() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        // Root-created, then moved: the socket stays root-side.
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "add", "wgroot", "type", "wireguard"]))
                .success
        );
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "set", "wgroot", "netns", "nsx"])).success
        );
        assert_eq!(runner.link_created_in("wgroot"), Some(None));
        assert!(runner.has_link_in("wgroot", Some("nsx")));
        // Created INSIDE the namespace: the socket binds ns-side.
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "ip",
                "link",
                "add",
                "wgns",
                "type",
                "wireguard",
            ],
        ));
        assert!(out.success, "ns-scoped add failed: {}", out.stderr);
        assert_eq!(
            runner.link_created_in("wgns"),
            Some(Some("nsx".to_string()))
        );
        assert_eq!(runner.link_created_in("missing"), None);
    }

    /// `wg set <if> listen-port <p>` is recorded on the link, and the
    /// listener is observable per namespace from the socket-placement
    /// model (`creating_netns`): `ss -uln` inside the CREATING
    /// namespace lists the port, `ss -uln` in a namespace the link was
    /// merely moved into does not. This is the observable the
    /// provider's runtime socket-placement verification depends on.
    #[test]
    fn wg_listen_port_is_answered_by_ss_per_creating_namespace() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        // Root-created, configured, moved in: the socket stays
        // root-side, so the fabric-ns dump must stay empty. (The wg is
        // configured from inside the namespace AFTER the move — the
        // provider's own order; `wg set` addresses the interface in
        // the namespace it executes in.)
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "add", "wgroot", "type", "wireguard"]))
                .success
        );
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "set", "wgroot", "netns", "nsx"])).success
        );
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "wg",
                "set",
                "wgroot",
                "listen-port",
                "65001",
            ],
        ));
        assert!(out.success, "wg set listen-port failed: {}", out.stderr);
        let ns_ss = ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ss", "-uln"]));
        assert!(ns_ss.success);
        assert!(
            !ns_ss.stdout.contains("65001"),
            "a root-created wg moved into the ns must NOT listen there: {}",
            ns_ss.stdout
        );
        let root_ss = ok_or_err_out(runner.run("ss", &["-uln"]));
        assert!(root_ss.success);
        assert!(
            root_ss.stdout.contains(":65001"),
            "the root-ns dump must list the root-bound listener: {}",
            root_ss.stdout
        );

        // Created INSIDE the namespace and configured there: the socket
        // binds ns-side — the ns dump lists it, the root dump does not.
        assert!(
            ok_or_err_out(runner.run(
                "ip",
                &[
                    "netns",
                    "exec",
                    "nsx",
                    "ip",
                    "link",
                    "add",
                    "wgns",
                    "type",
                    "wireguard",
                ],
            ))
            .success
        );
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "wg",
                "set",
                "wgns",
                "listen-port",
                "65002",
            ],
        ));
        assert!(out.success, "wg set listen-port failed: {}", out.stderr);
        let ns_ss = ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ss", "-uln"]));
        assert!(
            ns_ss.stdout.contains(":65002"),
            "an ns-born wg must listen in its creating namespace: {}",
            ns_ss.stdout
        );
        let root_ss = ok_or_err_out(runner.run("ss", &["-uln"]));
        assert!(
            !root_ss.stdout.contains(":65002"),
            "an ns-born wg must NOT listen in the root ns: {}",
            root_ss.stdout
        );

        // An unconfigured (port-less) wg listens nowhere: the ns dump
        // still holds exactly the one ns-bound listener (two address
        // forms) plus the header.
        assert!(
            ok_or_err_out(runner.run(
                "ip",
                &[
                    "netns",
                    "exec",
                    "nsx",
                    "ip",
                    "link",
                    "add",
                    "wgbare",
                    "type",
                    "wireguard",
                ],
            ))
            .success
        );
        let ns_ss = ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ss", "-uln"]));
        assert_eq!(
            ns_ss.stdout.lines().count(),
            3, // header + the one ns-bound listener x 2 address forms
            "only configured wireguard listeners appear: {}",
            ns_ss.stdout
        );
    }

    /// FOREIGN UDP listeners (round-7) are observable per namespace,
    /// independent of any wg link: a listener seeded in one namespace
    /// appears in that namespace's `ss -uln` dump only, never in
    /// another's and never tied to link state. This is the seeding
    /// primitive for the provider's three-way socket-placement
    /// discriminator tests.
    #[test]
    fn foreign_udp_listeners_appear_only_in_their_seeded_namespace() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        // A foreign listener on 65001 INSIDE the namespace — no wg link
        // involved at all.
        runner.add_foreign_udp_listener(Some("nsx"), 65001);
        // ...and one on 65002 in the root namespace.
        runner.add_foreign_udp_listener(None, 65002);

        let ns_ss = ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ss", "-uln"]));
        assert!(ns_ss.success);
        assert!(
            ns_ss.stdout.contains(":65001"),
            "the foreign ns listener must be observable in its namespace: {}",
            ns_ss.stdout
        );
        assert!(
            !ns_ss.stdout.contains(":65002"),
            "a foreign root listener must NOT leak into the ns dump: {}",
            ns_ss.stdout
        );
        let root_ss = ok_or_err_out(runner.run("ss", &["-uln"]));
        assert!(root_ss.success);
        assert!(
            root_ss.stdout.contains(":65002"),
            "the foreign root listener must be observable in the root ns: {}",
            root_ss.stdout
        );
        assert!(
            !root_ss.stdout.contains(":65001"),
            "a foreign ns listener must NOT leak into the root dump: {}",
            root_ss.stdout
        );

        // The combined unattributable case is representable: our own
        // root-created, moved-in wg (socket root-side) PLUS a foreign
        // listener on the same port inside the namespace — both dumps
        // show the port.
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "add", "wgroot", "type", "wireguard"]))
                .success
        );
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "set", "wgroot", "netns", "nsx"])).success
        );
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "wg",
                "set",
                "wgroot",
                "listen-port",
                "65001",
            ],
        ));
        assert!(out.success, "wg set listen-port failed: {}", out.stderr);
        runner.add_foreign_udp_listener(None, 65001);
        let root_ss = ok_or_err_out(runner.run("ss", &["-uln"]));
        assert!(
            root_ss.stdout.contains(":65001"),
            "our own root-bound socket must be observable: {}",
            root_ss.stdout
        );
        let ns_ss = ok_or_err_out(runner.run("ip", &["netns", "exec", "nsx", "ss", "-uln"]));
        assert!(
            ns_ss.stdout.contains(":65001"),
            "the foreign ns listener coexists observably: {}",
            ns_ss.stdout
        );
    }

    /// `wg set` on a missing device fails with the real wording — a
    /// provider that configures a wg it never created (or lost to a
    /// namespace change between check and set) must fail closed, not
    /// pass vacuously.
    #[test]
    fn wg_set_on_a_missing_device_fails_like_the_real_wg() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "netns",
                "exec",
                "nsx",
                "wg",
                "set",
                "missing0",
                "listen-port",
                "65001",
            ],
        ));
        assert!(!out.success, "wg set on a missing device must fail");
        assert!(
            out.stderr.contains("No such device"),
            "real wg wording: {}",
            out.stderr
        );
    }

    /// Deleting one end of a veth pair removes BOTH ends, wherever the
    /// peer currently lives — the real kernel semantics the legacy
    /// underlay cleanup relies on (deleting the root-ns underlay veth
    /// also removes the fabric-ns peer).
    #[test]
    fn deleting_one_end_of_a_veth_pair_removes_both() {
        let mut runner = RecordingRunner::new();
        assert!(ok_or_err_out(runner.run("ip", &["netns", "add", "nsx"])).success);
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "link", "add", "ev-u", "type", "veth", "peer", "name", "ev-v",
            ],
        ));
        assert!(out.success, "veth pair creation failed: {}", out.stderr);
        // The fabric end moves into the namespace (the v0.1.0/v0.1.1
        // underlay shape).
        assert!(ok_or_err_out(runner.run("ip", &["link", "set", "ev-v", "netns", "nsx"])).success);
        assert!(runner.has_link_in("ev-u", None));
        assert!(runner.has_link_in("ev-v", Some("nsx")));
        // Deleting the ROOT end removes the moved peer too.
        assert!(ok_or_err_out(runner.run("ip", &["link", "del", "ev-u"])).success);
        assert!(!runner.has_link("ev-u"));
        assert!(
            !runner.has_link("ev-v"),
            "deleting one veth end must remove the pair"
        );
        // Deleting a now-missing end fails like the real ip.
        let out = ok_or_err_out(runner.run("ip", &["link", "del", "ev-u"]));
        assert!(!out.success);
        assert!(out.stderr.contains("Cannot find device"));
    }

    /// iptables nat rules: `-A` appends (duplicates accumulate, like the
    /// real iptables), `-D` removes exactly one matching instance, and a
    /// `-D` with no matching rule fails with the REAL wording the
    /// provider's tolerant deletions must match.
    #[test]
    fn iptables_append_delete_and_bad_rule_wording() {
        let mut runner = RecordingRunner::new();
        let masq = [
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "169.254.253.0/30",
            "-j",
            "MASQUERADE",
        ];
        assert!(ok_or_err_out(runner.run("iptables", &masq)).success);
        assert!(ok_or_err_out(runner.run("iptables", &masq)).success);
        assert_eq!(runner.iptables_rules().len(), 2, "duplicates accumulate");
        // The dump lists one line per instance.
        let out = ok_or_err_out(runner.run("iptables", &["-t", "nat", "-S"]));
        assert!(out.success);
        assert_eq!(
            out.stdout
                .lines()
                .filter(|l| l.contains("MASQUERADE"))
                .count(),
            2
        );
        // A spec-for-spec -D removes ONE instance; a mismatched spec
        // (different port) is a different rule entirely.
        let del = [
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            "169.254.253.0/30",
            "-j",
            "MASQUERADE",
        ];
        assert!(ok_or_err_out(runner.run("iptables", &del)).success);
        assert_eq!(runner.iptables_rules().len(), 1);
        let wrong = [
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            "169.254.253.0/30",
            "-j",
            "ACCEPT",
        ];
        let out = ok_or_err_out(runner.run("iptables", &wrong));
        assert!(!out.success, "a non-matching spec must fail");
        // ...with the REAL iptables wording (kernel-faithful fake).
        assert!(
            out.stderr
                .contains("Bad rule (does a matching rule exist in that chain?)"),
            "real iptables -D wording: {}",
            out.stderr
        );
        // The last matching instance deletes cleanly; then Bad rule.
        assert!(ok_or_err_out(runner.run("iptables", &del)).success);
        let out = ok_or_err_out(runner.run("iptables", &del));
        assert!(!out.success, "deleting a missing rule must fail");
        assert!(out.stderr.contains("Bad rule"));
        assert!(runner.iptables_rules().is_empty());
    }

    #[test]
    fn deleting_a_missing_netns_fails_like_the_kernel() {
        let mut runner = RecordingRunner::new();
        let out = ok_or_err_out(runner.run("ip", &["netns", "del", "gone-ns"]));
        assert!(!out.success, "the real ip fails to remove a missing netns");
        assert!(
            out.stderr.contains("No such file or directory"),
            "stderr must name the missing namespace file: {}",
            out.stderr
        );
    }

    #[test]
    fn creating_an_existing_link_fails_like_the_kernel() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        let out = ok_or_err_out(runner.run(
            "ip",
            &[
                "link", "add", "vx0", "type", "vxlan", "id", "4711", "dstport", "4789",
            ],
        ));
        assert!(!out.success, "the real kernel refuses duplicate names");
        assert!(out.stderr.contains("File exists"));
        // The existing peer name of a veth pair is equally refused.
        let out = ok_or_err_out(runner.run(
            "ip",
            &["link", "add", "new0", "type", "veth", "peer", "name", "vx0"],
        ));
        assert!(!out.success, "duplicate veth peer names must be refused");
        assert!(out.stderr.contains("File exists"));
    }

    #[test]
    fn netns_exec_into_a_missing_namespace_fails() {
        let mut runner = RecordingRunner::new();
        let out = ok_or_err_out(runner.run("ip", &["netns", "exec", "nope", "ip", "link"]));
        assert!(
            !out.success,
            "the real kernel cannot exec into a missing netns"
        );
        assert!(
            out.stderr.contains("Cannot open network namespace"),
            "stderr must name the failure: {}",
            out.stderr
        );
    }

    #[test]
    fn addr_and_route_semantics() {
        let mut runner = RecordingRunner::new();
        assert!(
            ok_or_err_out(runner.run("ip", &["link", "add", "wg0", "type", "wireguard"])).success
        );
        assert!(
            ok_or_err_out(runner.run("ip", &["addr", "replace", "198.18.0.1/32", "dev", "wg0"]))
                .success
        );
        assert!(runner.has_addr("wg0", "198.18.0.1/32"));
        // Replace of the same address is the idempotent re-assert path.
        assert!(
            ok_or_err_out(runner.run("ip", &["addr", "replace", "198.18.0.1/32", "dev", "wg0"]))
                .success
        );
        assert!(runner.has_addr("wg0", "198.18.0.1/32"));
        // `add` of an existing address fails; `del` of a missing one too.
        assert!(
            !ok_or_err_out(runner.run("ip", &["addr", "add", "198.18.0.1/32", "dev", "wg0"]))
                .success
        );
        assert!(
            ok_or_err_out(runner.run("ip", &["addr", "del", "198.18.0.1/32", "dev", "wg0"]))
                .success
        );
        assert!(
            !ok_or_err_out(runner.run("ip", &["addr", "del", "198.18.0.1/32", "dev", "wg0"]))
                .success
        );

        assert!(
            ok_or_err_out(runner.run("ip", &["route", "replace", "198.18.0.2/32", "dev", "wg0"]))
                .success
        );
        assert!(runner.has_route("198.18.0.2/32"));
        assert!(ok_or_err_out(runner.run("ip", &["route", "del", "198.18.0.2/32"])).success);
        assert!(!runner.has_route("198.18.0.2/32"));
        let out = ok_or_err_out(runner.run("ip", &["route", "del", "198.18.0.2/32"]));
        assert!(!out.success, "deleting a missing route must fail");
        assert!(
            out.stderr.contains("No such process"),
            "real route-del wording (not the fdb wording): {}",
            out.stderr
        );
    }
}
