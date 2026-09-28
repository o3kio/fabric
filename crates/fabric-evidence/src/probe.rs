//! Tenant-namespace reachability probes: real `ping` and real `ip neigh`
//! from inside the tenant netns. These are the datapath evidence primitives;
//! nothing here is simulated.

use fabric_linux::{CommandOutput, FabricCommand};
use serde::Serialize;

use crate::error::RunError;

/// Default ping count when `--count` is absent.
pub const DEFAULT_COUNT: u32 = 4;
/// Default ping deadline in seconds when `--deadline` is absent.
pub const DEFAULT_DEADLINE: u32 = 10;
/// How many characters of ping stdout to keep in the JSON report.
const STDOUT_TAIL_CHARS: usize = 1200;

/// Result of one probe (`ok` is true iff ping exited 0).
#[derive(Serialize)]
pub struct ProbeReport {
    pub ok: bool,
    pub stdout_tail: String,
}

/// Result of one neighbor-table dump.
#[derive(Serialize)]
pub struct NeighborsReport {
    pub entries: String,
}

/// Build the `ip netns exec <ns> ping ...` argument vector.
///
/// Factored out so tests can pin the exact command shape (the evidence
/// claims depend on it: real ping, inside the tenant netns).
pub fn ping_args(
    tenant_ns: &str,
    target: &str,
    size: Option<u32>,
    count: u32,
    deadline: u32,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "netns".to_string(),
        "exec".to_string(),
        tenant_ns.to_string(),
        "ping".to_string(),
        "-c".to_string(),
        count.to_string(),
        "-w".to_string(),
        deadline.to_string(),
    ];
    if let Some(size) = size {
        args.push("-s".to_string());
        args.push(size.to_string());
    }
    args.push(target.to_string());
    args
}

/// Run one real ping from inside the tenant netns. A failed ping is a
/// *result* (`ok: false`), not an error.
pub fn run_probe<R: FabricCommand>(
    runner: &mut R,
    tenant_ns: &str,
    target: &str,
    size: Option<u32>,
    count: u32,
    deadline: u32,
) -> Result<ProbeReport, RunError> {
    let args = ping_args(tenant_ns, target, size, count, deadline);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output: CommandOutput = runner.run("ip", &refs)?;
    Ok(ProbeReport {
        ok: output.success,
        stdout_tail: tail(&output.stdout),
    })
}

/// Dump the tenant netns neighbor table (proves real MAC learning: entries
/// must be REACHABLE with the peers' real MACs).
pub fn run_neighbors<R: FabricCommand>(
    runner: &mut R,
    tenant_ns: &str,
) -> Result<NeighborsReport, RunError> {
    let output = runner.run("ip", &["netns", "exec", tenant_ns, "ip", "neigh"])?;
    if !output.success {
        return Err(RunError::Command(format!(
            "ip netns exec {tenant_ns} ip neigh failed: {}",
            output.stderr.trim()
        )));
    }
    Ok(NeighborsReport {
        entries: output.stdout,
    })
}

/// Keep the last [`STDOUT_TAIL_CHARS`] characters of a command's stdout
/// (multi-line safe), trimmed of trailing whitespace.
pub fn tail(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let kept: String = if chars.len() <= STDOUT_TAIL_CHARS {
        text.to_string()
    } else {
        chars[chars.len() - STDOUT_TAIL_CHARS..].iter().collect()
    };
    kept.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_args_shape_without_size() {
        let args = ping_args("tns", "10.42.0.12", None, 4, 10);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(
            refs,
            vec![
                "netns",
                "exec",
                "tns",
                "ping",
                "-c",
                "4",
                "-w",
                "10",
                "10.42.0.12"
            ]
        );
    }

    #[test]
    fn ping_args_shape_with_size() {
        let args = ping_args("tns", "10.42.0.12", Some(1300), 3, 20);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(
            refs,
            vec![
                "netns",
                "exec",
                "tns",
                "ping",
                "-c",
                "3",
                "-w",
                "20",
                "-s",
                "1300",
                "10.42.0.12"
            ]
        );
    }

    #[test]
    fn tail_keeps_the_end() {
        let long = "a\n".repeat(2000);
        let kept = tail(&long);
        assert!(kept.chars().count() <= STDOUT_TAIL_CHARS);
        assert!(kept.ends_with('a'));
        assert_eq!(tail("short\n"), "short");
    }
}
