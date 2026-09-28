# Changelog

## [0.1.2] - 2026-09-28
### Production-impacting fix — upgrade required
- **Deterministic NAT-free underlay.** The WireGuard interface is now created
  in the ROOT namespace and moved into the fabric namespace (§3.10), so its
  UDP transport socket — which binds in the *creating* namespace and never
  follows the interface — binds root-side. The underlay veth pair
  (169.254.253.0/30), the DNAT rule, and the MASQUERADE rule are gone:
  outbound encrypted packets take the host's normal routing with dynamic
  source selection, and inbound `<peer>:<port> → <host-ip>:<port>` flows are
  delivered directly to the root-ns listener. Two races made any NAT state
  on the transport fatal: (1) the DNAT rule black-holed every NEW inbound
  flow whenever the socket lived elsewhere than the rule's target, and
  (2) under simultaneous initiation the conntrack tuple collision forced
  MASQUERADE to remap the source port (observed 65001 → 37414 in the
  evidence run, evidence .3:37414), the peer roamed to the remapped port,
  and nothing steered return traffic back — the pair never recovered. The
  only escape is no NAT state at all. Existing installs converge on the
  next apply: the legacy rules and veth are deleted tolerantly on every
  apply (exact v0.1.1 rule specs); v0.1.0/v0.1.1 journals already describe
  a root-created wg and are left healthy; a journal carrying
  `wireguard_born_in_fabric_ns == true` (unpushed round-3..5 dev code only,
  whose wg was created inside the fabric ns and whose socket is therefore
  bound there) triggers a one-time, crash-window-idempotent full heal —
  recorded VXLANs deleted before the wg, then root-side recreation, key/port
  forced, flag cleared. Ambiguous root+fabric duplicates fail closed.

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
  `Cannot find device "x"`, `Device "x" does not exist.`,
  `iptables: Bad rule ...`) — previously a missing route on a real kernel
  could wedge teardown after a reboot or lost netns.
- Fake-kernel runner models real `ip`/`bridge`/`wg`/`iptables` placement
  and failure semantics (per-namespace link name tables and creation
  records — the WireGuard socket placement — veth pair deletion, counting
  fdb entries with one-per-del removal, the `Bad rule` wording of a
  non-matching `iptables -D`, real kernel error strings), so a
  too-permissive provider cannot pass the conformance suite.
- Hardening tests across the conformance suite and the `fabric-linux` unit
  tests: teardown convergence after a simulated reboot, re-apply healing,
  interrupted-heal slices at every crash window, flood-list shrinking and
  duplicate convergence, ownership-gated root-ns sweeps, no-NAT and
  legacy-cleanup regression cases.
- Evidence harness: cargo is located through the build user's login shell when
  run via `sudo`; post-failure diagnostics (the nat table — expected to hold
  only the container runtime's own chains under the NAT-free underlay —
  conntrack, wg show, per-ns sockets) are captured to the results dir; the
  WG socket-placement assertion (`wg_socket_in_root_ns_*`) cross-checks
  root-ns `ss` against `wg show` in the fabric ns.
- The evidence harness no longer requires root-ns `ip_forward`/`rp_filter`
  prerequisites: under the NAT-free underlay the root namespace terminates
  the WG transport socket and never forwards fabric packets.

### Notes
- First tag whose `Cargo.toml` version matches the tag name. v0.1.0/v0.1.1 were
  tagged while the workspace version stayed 0.1.0; git-tag consumers (e.g. CHV)
  are unaffected (git deps ignore the version field), but version-keyed tooling
  could not distinguish those releases. No on-disk format break in this release
  (the `wireguard_born_in_fabric_ns` journal field is reused with new
  semantics: `true` now marks the round-3..5 born-in-ns state needing the
  full heal; v0.1.0/v0.1.1 journals deserialize it as `false` = healthy).
- Contract §3.10 rewritten for the NAT-free underlay; still contract v1.

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
