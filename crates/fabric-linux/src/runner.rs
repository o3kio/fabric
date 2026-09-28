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
#[derive(Clone, Debug, Default)]
struct FakeLink {
    kind: String,
    vni: Option<u32>,
    dstport: Option<u16>,
    local: Option<String>,
    mtu: Option<u32>,
    addrs: std::collections::BTreeSet<String>,
}

/// An in-memory fake kernel plus call journal.
///
/// It models just enough of `ip`/`wg`/`bridge`/`iptables`/`sysctl` for the
/// provider's observation and mutation paths: namespaces, link existence,
/// VXLAN identity, and success/failure injection.
pub struct RecordingRunner {
    calls: Vec<CommandCall>,
    netns: std::collections::BTreeSet<String>,
    links: BTreeMap<String, FakeLink>,
    /// Routing-table entries (destination strings; the fake kernel models
    /// one global table, which is sufficient because the provider only
    /// manages routes inside the fabric namespace).
    routes: std::collections::BTreeSet<String>,
    /// Forwarding-table entries: (device, mac, dst) triples. Flood entries
    /// share the all-zeros MAC with one row per remote.
    fdb: std::collections::BTreeSet<(String, String, String)>,
    failures: Vec<String>,
}

impl RecordingRunner {
    /// A fresh fake kernel with no objects.
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            netns: std::collections::BTreeSet::new(),
            links: BTreeMap::new(),
            routes: std::collections::BTreeSet::new(),
            fdb: std::collections::BTreeSet::new(),
            failures: Vec::new(),
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
            .filter(|call| !is_observation(&call.args))
            .cloned()
            .collect()
    }

    /// Inject a failure for any command whose joined line contains `pattern`.
    pub fn fail_on(&mut self, pattern: impl Into<String>) {
        self.failures.push(pattern.into());
    }

    /// True when the fake kernel currently holds a link named `name`.
    pub fn has_link(&self, name: &str) -> bool {
        self.links.contains_key(name)
    }

    /// True when the fake kernel holds a route with destination `dest`
    /// (e.g. `198.18.0.2/32` or `default`).
    pub fn has_route(&self, dest: &str) -> bool {
        self.routes.contains(dest)
    }

    /// True when link `dev` currently carries the address `addr`
    /// (e.g. `198.18.0.1/32`).
    pub fn has_addr(&self, dev: &str, addr: &str) -> bool {
        self.links
            .get(dev)
            .is_some_and(|link| link.addrs.contains(addr))
    }

    /// The fake kernel's current MTU for a link, when the link exists and
    /// an MTU was set on it (links start at the generic default of 1500).
    pub fn link_mtu(&self, name: &str) -> Option<u32> {
        self.links.get(name).and_then(|link| link.mtu)
    }

    /// True when the fake kernel currently holds a namespace named `ns`.
    pub fn has_netns(&self, ns: &str) -> bool {
        self.netns.contains(ns)
    }

    /// True when the fake kernel holds the forwarding-table entry
    /// `(dev, mac, dst)`.
    pub fn has_fdb_entry(&self, dev: &str, mac: &str, dst: &str) -> bool {
        self.fdb
            .contains(&(dev.to_string(), mac.to_string(), dst.to_string()))
    }

    /// Interpret `bridge` arguments starting at `rest` (after any
    /// `netns exec NS` prefix already stripped).
    ///
    /// Models the kernel's forwarding-table rules closely enough to catch
    /// verb-level mistakes a real kernel rejects: `replace` is refused for
    /// non-unicast entries (the kernel error that motivated the provider's
    /// use of `append` for HER flood lists), `append` is idempotent per
    /// (dev, mac, dst), and `del` of a missing entry fails.
    fn bridge(&mut self, rest: &[&str]) -> CommandOutput {
        if rest.first() != Some(&"fdb") {
            return CommandOutput::ok();
        }
        let op = rest.get(1).copied().unwrap_or("");
        if op == "show" {
            let stdout = self
                .fdb
                .iter()
                .map(|(dev, mac, dst)| format!("{mac} dev {dev} dst {dst} self permanent"))
                .collect::<Vec<_>>()
                .join("\n");
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
        let Some(link) = self.links.get(dev) else {
            return command_error("Cannot find device");
        };
        if link.kind != "vxlan" {
            return command_error("Operation not supported: fdb with dst requires a vxlan device");
        }
        if !is_unicast_mac(mac) && op == "replace" {
            return command_error("Cannot replace non-unicast fdb entries.");
        }
        let entry = (dev.to_string(), mac.to_string(), dst.to_string());
        match op {
            "append" => {
                self.fdb.insert(entry);
                CommandOutput::ok()
            }
            "add" => {
                if self.fdb.contains(&entry) {
                    command_error("RTNETLINK answers: File exists")
                } else {
                    self.fdb.insert(entry);
                    CommandOutput::ok()
                }
            }
            "del" => {
                if self.fdb.remove(&entry) {
                    CommandOutput::ok()
                } else {
                    command_error("RTNETLINK answers: No such file or directory")
                }
            }
            "replace" => {
                let mac_owned = mac.to_string();
                self.fdb.retain(|(d, m, _)| !(d == dev && *m == mac_owned));
                self.fdb.insert(entry);
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
        self.failures.iter().any(|p| joined.contains(p))
    }

    /// Interpret `ip` arguments starting at `rest` (after any
    /// `netns exec NS` prefix already stripped).
    fn ip(&mut self, rest: &[&str]) -> CommandOutput {
        // Normalize: drop a leading `-d` detail flag, remembering it.
        let detail = rest.first() == Some(&"-d");
        let rest = if detail { &rest[1..] } else { rest };
        // link add NAME type KIND [vxlan opts]
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"add") {
            let name = rest[2];
            let mut link = FakeLink {
                kind: "generic".to_string(),
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
            // The kernel refuses to create an existing name.
            if self.links.contains_key(name) {
                return command_error("RTNETLINK answers: File exists");
            }
            if let Some(peer) = peer_name {
                if self.links.contains_key(peer) {
                    return command_error("RTNETLINK answers: File exists");
                }
                self.links.insert(peer.to_string(), FakeLink::default());
            }
            self.links.insert(name.to_string(), link);
            return CommandOutput::ok();
        }
        // link del NAME (deleting a device drops its forwarding entries,
        // as the kernel does). Deleting a missing device fails like the
        // real `ip` — providers must tolerate that explicitly.
        if rest.first() == Some(&"link") && matches!(rest.get(1), Some(&"del") | Some(&"delete")) {
            if let Some(name) = rest.get(2) {
                if !self.links.contains_key(*name) {
                    return missing_device(name);
                }
                self.links.remove(*name);
                self.fdb.retain(|(dev, _, _)| dev != name);
            }
            return CommandOutput::ok();
        }
        // addr add|replace|del ADDR dev DEV
        if rest.first() == Some(&"addr") {
            let op = rest.get(1).copied().unwrap_or("");
            let addr = rest.get(2).copied().unwrap_or("");
            let dev = arg_after(rest, "dev").unwrap_or("");
            let Some(link) = self.links.get_mut(dev) else {
                return missing_device(dev);
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
                    if self.routes.remove(dest) {
                        CommandOutput::ok()
                    } else {
                        command_error("RTNETLINK answers: No such file or directory")
                    }
                }
                _ => CommandOutput::ok(),
            };
        }
        // link set NAME mtu N | link set NAME name NEW
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"set") {
            if let (Some(name), Some(op)) = (rest.get(2), rest.get(3)) {
                match *op {
                    "mtu" => {
                        let value = rest.get(4).copied().and_then(parse_u32);
                        return match (self.links.get_mut(*name), value) {
                            (Some(link), Some(mtu)) => {
                                link.mtu = Some(mtu);
                                CommandOutput::ok()
                            }
                            (Some(_), None) => {
                                command_error(&format!("invalid MTU value for \"{name}\""))
                            }
                            (None, _) => missing_device(name),
                        };
                    }
                    "name" => {
                        if let (Some(new_name), Some(link)) =
                            (rest.get(4), self.links.remove(*name))
                        {
                            self.links.insert((*new_name).to_string(), link);
                            return CommandOutput::ok();
                        }
                        return missing_device(name);
                    }
                    // up/down/netns/master/addr: accepted, not modeled.
                    _ => {}
                }
            }
            return CommandOutput::ok();
        }
        // link show [-d] NAME
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"show") {
            if let (Some(name), Some(link)) =
                (rest.get(2), rest.get(2).and_then(|n| self.links.get(*n)))
            {
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
            if let Some(name) = rest.get(2) {
                return missing_device(name);
            }
        }
        CommandOutput::ok()
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

/// The `ip` "device does not exist" failure.
fn missing_device(name: &str) -> CommandOutput {
    command_error(&format!("Device \"{name}\" does not exist."))
}

fn is_observation(args: &[String]) -> bool {
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
                // like the real `ip netns exec`.
                if args.first() == Some(&"netns") && args.get(1) == Some(&"exec") {
                    if let Some(ns) = args.get(2).filter(|ns| !self.netns.contains(**ns)) {
                        return Ok(command_error(&format!(
                            "Cannot open network namespace \"{ns}\""
                        )));
                    }
                    match args.get(3) {
                        Some(&"ip") => return Ok(self.ip(&args[4..])),
                        Some(&"bridge") => return Ok(self.bridge(&args[4..])),
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
                        self.netns.remove(*ns);
                    }
                    return Ok(CommandOutput::ok());
                }
                Ok(self.ip(args))
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
            "bridge" => Ok(self.bridge(args)),
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
                // Deterministic 44-character base64-shaped public key.
                success: true,
                stdout: format!("pubkey-{:035}-x\n", stdin.trim().len()),
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
    fn fdb_append_is_idempotent_and_del_removes() {
        let mut runner = RecordingRunner::new();
        vxlan(&mut runner);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        assert!(fdb(&mut runner, "append", "198.18.0.2").success);
        assert!(runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.2"));
        assert!(fdb(&mut runner, "append", "198.18.0.3").success);
        assert!(runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.3"));
        assert!(fdb(&mut runner, "del", "198.18.0.2").success);
        assert!(!runner.has_fdb_entry("vx0", "00:00:00:00:00:00", "198.18.0.2"));
        let out = fdb(&mut runner, "del", "198.18.0.2");
        assert!(!out.success, "deleting a missing entry must fail");
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
            out.stderr.contains("does not exist"),
            "stderr must name the missing device: {}",
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
        assert!(out.stderr.contains("No such file or directory"));
    }
}
