//! Hand-rolled subcommand parsing.
//!
//! The workspace has no argument-parser dependency and the evidence CLI is
//! intentionally tiny, so this is a plain `--flag value` parser over
//! `std::env::args`. Every subcommand prints machine-readable JSON on
//! stdout and human-readable errors on stderr; the process exits 0/1.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::RunError;

/// The full usage text (also the body of usage errors).
pub const USAGE: &str = "\
fabric-evidence — privileged per-host evidence collector for the Kubedo
stretched-L2 fabric (roadmap issue #2, Phase 3; CHV ADR-021).

Runs INSIDE one privileged host/container and operates on that host's
kernel. JSON on stdout; errors on stderr; exit code 0/1.

usage:
  fabric-evidence identity    --root DIR --prefix P
  fabric-evidence apply       --root DIR --prefix P --plan FILE
  fabric-evidence tenant-up   --root DIR --prefix P --network-id ID \
--bridge NAME --tenant-ns NAME --ip CIDR
  fabric-evidence tenant-down --root DIR --prefix P --network-id ID \
--bridge NAME --tenant-ns NAME
  fabric-evidence probe       --tenant-ns NAME --target IP \
[--size N] [--count N] [--deadline SECS]
  fabric-evidence neighbors   --tenant-ns NAME
  fabric-evidence teardown    --root DIR --prefix P --network-id ID
  fabric-evidence fabric-down --root DIR --prefix P
  fabric-evidence leak-check  --root DIR --prefix P";

/// One parsed invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Ensure/derive the host keypair; print `{"public_key": "..."}`.
    Identity { root: PathBuf, prefix: String },
    /// Apply one plan through the provider; print the created flags.
    Apply {
        root: PathBuf,
        prefix: String,
        plan: PathBuf,
    },
    /// Simulate the consumer side (tenant bridge + tenant netns + veths).
    TenantUp {
        root: PathBuf,
        prefix: String,
        network_id: String,
        bridge: String,
        tenant_ns: String,
        ip: String,
    },
    /// Reverse of tenant-up (never touches provider-owned objects).
    TenantDown {
        root: PathBuf,
        prefix: String,
        network_id: String,
        bridge: String,
        tenant_ns: String,
    },
    /// Real ping from inside the tenant netns.
    Probe {
        tenant_ns: String,
        target: String,
        size: Option<u32>,
        count: u32,
        deadline: u32,
    },
    /// Dump the tenant netns neighbor table (real MAC learning evidence).
    Neighbors { tenant_ns: String },
    /// Provider remove_network.
    Teardown {
        root: PathBuf,
        prefix: String,
        network_id: String,
    },
    /// Provider remove_fabric_if_unused.
    FabricDown { root: PathBuf, prefix: String },
    /// Verify zero fabric objects remain in this host's kernel.
    LeakCheck { root: PathBuf, prefix: String },
}

/// Parse the argument vector (without the program name).
pub fn parse(args: &[String]) -> Result<Command, RunError> {
    let Some(subcommand) = args.first() else {
        return Err(RunError::Usage(format!("missing subcommand\n{USAGE}")));
    };
    let rest = &args[1..];
    match subcommand.as_str() {
        "identity" => {
            let flags = parse_flags(&["--root", "--prefix"], rest)?;
            Ok(Command::Identity {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
            })
        }
        "apply" => {
            let flags = parse_flags(&["--root", "--prefix", "--plan"], rest)?;
            Ok(Command::Apply {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
                plan: PathBuf::from(required(&flags, "--plan")?),
            })
        }
        "tenant-up" => {
            let flags = parse_flags(
                &[
                    "--root",
                    "--prefix",
                    "--network-id",
                    "--bridge",
                    "--tenant-ns",
                    "--ip",
                ],
                rest,
            )?;
            Ok(Command::TenantUp {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
                network_id: required(&flags, "--network-id")?,
                bridge: required(&flags, "--bridge")?,
                tenant_ns: required(&flags, "--tenant-ns")?,
                ip: required(&flags, "--ip")?,
            })
        }
        "tenant-down" => {
            let flags = parse_flags(
                &[
                    "--root",
                    "--prefix",
                    "--network-id",
                    "--bridge",
                    "--tenant-ns",
                ],
                rest,
            )?;
            Ok(Command::TenantDown {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
                network_id: required(&flags, "--network-id")?,
                bridge: required(&flags, "--bridge")?,
                tenant_ns: required(&flags, "--tenant-ns")?,
            })
        }
        "probe" => {
            let flags = parse_flags(
                &["--tenant-ns", "--target", "--size", "--count", "--deadline"],
                rest,
            )?;
            Ok(Command::Probe {
                tenant_ns: required(&flags, "--tenant-ns")?,
                target: required(&flags, "--target")?,
                size: optional_number(&flags, "--size")?,
                count: optional_number(&flags, "--count")?.unwrap_or(crate::probe::DEFAULT_COUNT),
                deadline: optional_number(&flags, "--deadline")?
                    .unwrap_or(crate::probe::DEFAULT_DEADLINE),
            })
        }
        "neighbors" => {
            let flags = parse_flags(&["--tenant-ns"], rest)?;
            Ok(Command::Neighbors {
                tenant_ns: required(&flags, "--tenant-ns")?,
            })
        }
        "teardown" => {
            let flags = parse_flags(&["--root", "--prefix", "--network-id"], rest)?;
            Ok(Command::Teardown {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
                network_id: required(&flags, "--network-id")?,
            })
        }
        "fabric-down" => {
            let flags = parse_flags(&["--root", "--prefix"], rest)?;
            Ok(Command::FabricDown {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
            })
        }
        "leak-check" => {
            let flags = parse_flags(&["--root", "--prefix"], rest)?;
            Ok(Command::LeakCheck {
                root: PathBuf::from(required(&flags, "--root")?),
                prefix: required(&flags, "--prefix")?,
            })
        }
        other => Err(RunError::Usage(format!(
            "unknown subcommand {other:?}\n{USAGE}"
        ))),
    }
}

/// Collect `--flag value` pairs; every present flag must be one of `known`.
fn parse_flags(known: &[&str], args: &[String]) -> Result<BTreeMap<String, String>, RunError> {
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !flag.starts_with("--") {
            return Err(RunError::Usage(format!(
                "unexpected positional argument {flag:?}\n{USAGE}"
            )));
        }
        if !known.contains(&flag) {
            return Err(RunError::Usage(format!(
                "unknown flag {flag} for this subcommand\n{USAGE}"
            )));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| RunError::Usage(format!("flag {flag} requires a value\n{USAGE}")))?;
        if value.starts_with("--") {
            return Err(RunError::Usage(format!(
                "flag {flag} requires a value, saw {value:?}\n{USAGE}"
            )));
        }
        flags.insert(flag.to_string(), value.clone());
        index += 2;
    }
    Ok(flags)
}

/// Fetch a required flag value.
fn required(flags: &BTreeMap<String, String>, name: &str) -> Result<String, RunError> {
    flags
        .get(name)
        .cloned()
        .ok_or_else(|| RunError::Usage(format!("missing required flag {name}\n{USAGE}")))
}

/// Fetch an optional numeric flag value.
fn optional_number(flags: &BTreeMap<String, String>, name: &str) -> Result<Option<u32>, RunError> {
    match flags.get(name) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u32>()
            .map(Some)
            .map_err(|_| RunError::Usage(format!("flag {name} needs a number, saw {raw:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_string()).collect()
    }

    #[test]
    fn parses_identity() -> Result<(), RunError> {
        let command = parse(&args(&["identity", "--root", "/work/h1", "--prefix", "ev"]))?;
        assert_eq!(
            command,
            Command::Identity {
                root: PathBuf::from("/work/h1"),
                prefix: "ev".to_string(),
            }
        );
        Ok(())
    }

    #[test]
    fn parses_apply() -> Result<(), RunError> {
        let command = parse(&args(&[
            "apply",
            "--root",
            "/work/h1",
            "--prefix",
            "ev",
            "--plan",
            "/work/plan-h1.json",
        ]))?;
        assert_eq!(
            command,
            Command::Apply {
                root: PathBuf::from("/work/h1"),
                prefix: "ev".to_string(),
                plan: PathBuf::from("/work/plan-h1.json"),
            }
        );
        Ok(())
    }

    #[test]
    fn parses_tenant_up() -> Result<(), RunError> {
        let command = parse(&args(&[
            "tenant-up",
            "--root",
            "/work/h1",
            "--prefix",
            "ev",
            "--network-id",
            "evidence-net",
            "--bridge",
            "brten",
            "--tenant-ns",
            "tns",
            "--ip",
            "10.42.0.11/24",
        ]))?;
        assert!(matches!(
            command,
            Command::TenantUp {
                ref network_id,
                ref bridge,
                ref tenant_ns,
                ref ip,
                ..
            } if network_id == "evidence-net"
                && bridge == "brten"
                && tenant_ns == "tns"
                && ip == "10.42.0.11/24"
        ));
        Ok(())
    }

    #[test]
    fn parses_tenant_down_and_teardown_like_commands() -> Result<(), RunError> {
        let command = parse(&args(&[
            "tenant-down",
            "--root",
            "/r",
            "--prefix",
            "ev",
            "--network-id",
            "n1",
            "--bridge",
            "brten",
            "--tenant-ns",
            "tns",
        ]))?;
        assert!(matches!(command, Command::TenantDown { .. }));

        let command = parse(&args(&[
            "teardown",
            "--root",
            "/r",
            "--prefix",
            "ev",
            "--network-id",
            "n1",
        ]))?;
        assert!(matches!(command, Command::Teardown { .. }));

        let command = parse(&args(&["fabric-down", "--root", "/r", "--prefix", "ev"]))?;
        assert!(matches!(command, Command::FabricDown { .. }));

        let command = parse(&args(&["leak-check", "--root", "/r", "--prefix", "ev"]))?;
        assert!(matches!(command, Command::LeakCheck { .. }));
        Ok(())
    }

    #[test]
    fn probe_defaults_and_overrides() -> Result<(), RunError> {
        let command = parse(&args(&[
            "probe",
            "--tenant-ns",
            "tns",
            "--target",
            "10.42.0.12",
        ]))?;
        assert_eq!(
            command,
            Command::Probe {
                tenant_ns: "tns".to_string(),
                target: "10.42.0.12".to_string(),
                size: None,
                count: crate::probe::DEFAULT_COUNT,
                deadline: crate::probe::DEFAULT_DEADLINE,
            }
        );
        let command = parse(&args(&[
            "probe",
            "--tenant-ns",
            "tns",
            "--target",
            "10.42.0.12",
            "--size",
            "1300",
            "--count",
            "3",
            "--deadline",
            "20",
        ]))?;
        assert_eq!(
            command,
            Command::Probe {
                tenant_ns: "tns".to_string(),
                target: "10.42.0.12".to_string(),
                size: Some(1300),
                count: 3,
                deadline: 20,
            }
        );
        Ok(())
    }

    #[test]
    fn parses_neighbors() -> Result<(), RunError> {
        let command = parse(&args(&["neighbors", "--tenant-ns", "tns"]))?;
        assert_eq!(
            command,
            Command::Neighbors {
                tenant_ns: "tns".to_string(),
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["nonsense"])).is_err());
        assert!(parse(&args(&["identity", "--root", "/r"])).is_err());
        assert!(
            parse(&args(&[
                "identity", "--root", "/r", "--prefix", "ev", "--extra", "x"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["probe", "--tenant-ns", "tns"])).is_err());
        assert!(
            parse(&args(&[
                "probe",
                "--tenant-ns",
                "tns",
                "--target",
                "x",
                "--size",
                "big"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["probe", "--tenant-ns"])).is_err());
    }
}
