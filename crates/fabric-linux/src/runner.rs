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
    failures: Vec<String>,
}

impl RecordingRunner {
    /// A fresh fake kernel with no objects.
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            netns: std::collections::BTreeSet::new(),
            links: BTreeMap::new(),
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

    /// True when the fake kernel currently holds a namespace named `ns`.
    pub fn has_netns(&self, ns: &str) -> bool {
        self.netns.contains(ns)
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
                    _ => i += 1,
                }
            }
            self.links.insert(name.to_string(), link);
            return CommandOutput::ok();
        }
        // link del NAME
        if rest.first() == Some(&"link") && matches!(rest.get(1), Some(&"del") | Some(&"delete")) {
            if let Some(name) = rest.get(2) {
                self.links.remove(*name);
            }
            return CommandOutput::ok();
        }
        // link show [-d] NAME
        if rest.first() == Some(&"link") && rest.get(1) == Some(&"show") {
            if let (Some(name), Some(link)) =
                (rest.get(2), rest.get(2).and_then(|n| self.links.get(*n)))
            {
                let mut stdout = format!(
                    "{}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
                    name
                );
                if detail {
                    match link.kind.as_str() {
                        "vxlan" => {
                            let vni = link.vni.unwrap_or(0);
                            let dstport = link.dstport.unwrap_or(0);
                            stdout.push_str(&format!(
                                "    vxlan id {vni} dstport {dstport} learning\n"
                            ));
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
                return CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: format!("Device \"{name}\" does not exist."),
                };
            }
        }
        CommandOutput::ok()
    }
}

fn parse_u32(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok()
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
                // Strip `netns exec NS` prefix.
                if args.first() == Some(&"netns") && args.get(1) == Some(&"exec") {
                    match args.get(3) {
                        Some(&"ip") => return Ok(self.ip(&args[4..])),
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
