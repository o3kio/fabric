# Changelog

## [0.1.2] - 2026-09-28
### Production-impacting fix — upgrade required
- **WireGuard socket now binds inside the fabric netns.** The WG interface is
  created from inside the fabric namespace (§3.10). Previously it was created in
  the root ns and moved — but a WireGuard UDP socket binds in the *creating*
  namespace and never follows the interface, so the socket stayed in the root
  namespace while the underlay DNAT rule steered every NEW inbound encrypted
  flow into the fabric netns, where no socket listens. Those flows were silently
  black-holed (cross-host reachability died intermittently, depending on
  conntrack tuple timing). Existing installs heal on the next apply via a
  one-time, crash-window-idempotent migration keyed on the ownership journal
  (`wireguard_born_in_fabric_ns`; recorded VXLANs are deleted before the wg so
  every interruption slice converges); ambiguous root+fabric duplicates fail
  closed.

### Fixed
- Flood lists now reconcile against **observed** kernel state, including
  duplicate counts: each unwanted or duplicate all-zeros
  (00:00:00:00:00:00) remote entry is deleted instance-by-instance (each
  `bridge fdb del` removes exactly one), so still-desired destinations with
  accumulated duplicates (bridge(8) `append` does not deduplicate —
  Launchpad #1531013) are trimmed to exactly one entry and repeated applies
  converge to exactly one entry per peer (§3.6).
- The root-ns stray-sweep is gated on ownership evidence: a foreign root-ns
  link colliding with the deterministic name on a fresh host is no longer
  deleted — the fail-closed collision check rejects it instead.
- Tolerant deletions match the real kernel's error strings
  (`RTNETLINK answers: No such process`, `FIB table does not exist`,
  `Cannot find device "x"`, `Device "x" does not exist.`) — previously a
  missing route on a real kernel could wedge teardown after a reboot or lost
  netns.
- Fake-kernel runner models real `ip`/`bridge`/`wg` placement and failure
  semantics (per-ns link placement, counting fdb entries with one-per-del
  removal, real kernel error strings), so a too-permissive provider cannot
  pass the conformance suite.
- Conformance suite extended with hardening cases (teardown convergence after
  a simulated reboot, re-apply healing, interrupted-heal slices, flood-list
  shrinking and duplicate convergence, MTU/addressing re-assertion) and new
  plan-identity validation.
- Evidence harness: cargo is located through the build user's login shell when
  run via `sudo`; post-failure diagnostics (nat counters, conntrack, wg show,
  per-ns sockets) are captured to the results dir; the WG socket-placement
  assertion (`wg_socket_in_fabric_ns_*`) cross-checks `ss` against `wg show`.

### Notes
- First tag whose `Cargo.toml` version matches the tag name. v0.1.0/v0.1.1 were
  tagged while the workspace version stayed 0.1.0; git-tag consumers (e.g. CHV)
  are unaffected (git deps ignore the version field), but version-keyed tooling
  could not distinguish those releases. No on-disk format break in this release.
- Contract §3.10 added; still contract v1.

## [0.1.1] - 2026-09-28
- **WireGuard MTU fix**: the WG interface MTU is set on every apply to the max
  live `fabric_mtu` (kernel default 1420 silently broke large tenant packets;
  contract §2.3).
- Multi-host evidence harness (`evidence/run-multinode.sh`, `fabric-evidence`).
- HER flood entries use `bridge fdb append` (not `replace`); realistic
  fake-kernel bridge semantics.
- Tagged without a Cargo.toml bump (workspace remained 0.1.0).

## [0.1.0] - 2026-09-28
- Initial shared provider: `fabric-plan` plan/identity types (strict
  deserialization, SHA-256 fingerprint), `fabric-linux` provider (VXLAN/HER
  over WireGuard, netns, journal-before-mutate, ownership fencing, key
  hygiene), `fabric-conformance` suite.
- Tagged without a Cargo.toml bump (workspace remained 0.1.0).
