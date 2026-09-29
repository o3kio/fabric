# Changelog

## [0.1.3] - 2026-09-29
### Documentation program — design doc, cross-implementation change control, fabric ADRs
- **`docs/design.md`** — the consolidated engineering design (explanatory;
  the contract remains normative): kernel-object inventory with exact names
  and paths, tenant datapath and MTU layering (with the evidence gate's
  golden arithmetic), the NAT-free underlay, plan model, the authoritative
  apply/teardown orderings, the three-way socket discriminator, journals,
  migration semantics, security model, a failure-mode → operator-remediation
  table (including the corrupt-plan-journal blast radius and its manual
  remediation, previously undocumented), stated limitations (incl. host-image
  binary/module requirements), evidence claims and scope, and the pinned
  per-product configuration values (prefixes `o3k`/`chv`/`ev`, WG port
  policy, single-tag fleet policy).
- **`docs/change-control.md`** — normative cross-implementation alignment:
  the six-layer normative hierarchy, change classes A–D with their required
  processes, eight hard rules for both consumers (no forking, no touching
  fabric kernel state, no contract reinterpretation, no consumer-private
  knobs, shared vocabulary, upstream-first, conformance as the shared gate),
  versioning/skew/fleet policy, stability commitments for contract v1, and
  escalation rules — the design does not bend to either product's local
  goals.
- **`docs/adr/`** — fabric decision records: ADR-0001 (NAT-free
  root-terminated transport, with the two-race postmortem), ADR-0002
  (runtime socket-placement verification and the three-way discriminator),
  plus the index/format README.
- **Contract §2.1** now defines exactly what "strict deserialization"
  means (unknown fields reject at deserialization; values — including
  endpoint values on the deserialized path — validated by `validate()`),
  and states that the plan fingerprint is recorded ground truth, never
  compared for change detection.
- **Documentation cohesion fixes (comprehensive-review findings D1–D6):**
  `fabric-conformance`'s crate docs no longer claim a nonexistent
  KVM/libvirt harness or an "executable suite" — it is the shared
  anti-drift suite proving provider behavior modulo configuration,
  runnable by consumers at their pinned tag; the evidence gate is
  described identically everywhere (three privileged host instances —
  containers — on one physical kernel); the evidence-gate assertion
  count is stated as **35** and verified against the recorded runs
  (`evidence/results/*/summary.json`); the crate table distinguishes
  provider-employed types from control-plane contract vocabulary;
  `AGENTS.md` gains the evidence gate's contract of record (who runs
  it, results never committed, what a release consumes) and the
  documentation-discipline section.
- **Keypair wording fixed (review S4):** one keypair **per host** (the key
  file is not domain-keyed; a host runs at most one fabric) — code and
  docs now agree.

### Fixed
- **Endpoint value validation on the deserialized path (review S1).**
  `UnderlayEndpoint::parse` validated host non-empty / no whitespace or
  control characters / nonzero port, but serde deserialization bypassed
  `parse`, so a plan JSON with `"underlay_endpoint": {"host": "", "port":
  0}` passed `StretchedL2Plan::validate()` and only failed later at the
  checked `wg set peer … endpoint`, after the plan had been journaled.
  Value rules now live in `UnderlayEndpoint::validate()` (single source of
  truth; `parse` delegates) and are enforced by `FabricPeer::validate()`
  and `FabricHostIdentity::validate()`. New regression tests
  `deserialized_endpoint_values_fail_peer_validation` and
  `deserialized_plan_with_invalid_endpoint_values_fails_validation`,
  verified to fail against v0.1.2 (9082ff9) in a throwaway worktree.
  Note: the `parse()` error *message wording* changed (e.g.
  `endpoint ":65001" has an empty host` → `endpoint host must not be
  empty`); the set of rejected inputs is unchanged.
- **Journaled plans are re-validated on read (review m4).** `live_plans()`
  deserialized every plan file under the state root and fed
  endpoint/MTU values into kernel commands without re-running
  `validate()` — a plan journal that still parses but fails validation
  (operator hand-edit, bit-rot that remains valid JSON) silently drove
  peer/MTU realization. It now fails the apply of ANY network closed
  with an `Ownership` error naming the file; re-applying the affected
  network with a corrected plan overwrites the file and converges.
  Regression test `apply_fails_closed_on_parseable_but_invalid_plan_journal`,
  verified to fail against the pre-fix commit in a throwaway worktree.
- **Conformance extension (review m5):** new suite case
  `plan_validation_rejects_invalid_endpoint_values` (23 cases now) —
  a plan with a port-0 peer endpoint must fail before any state is
  created.

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

### Fixed (review round 8)
- **Teardown re-gained the nat-residue fail-closed guard (MINOR).** The
  round-7 hoist moved the `iptables -t nat -S` residue listing to the
  start of every apply — and, unintentionally, off the teardown path:
  `remove_fabric_if_unused` ran only the tolerant exact-spec deletes,
  so a host carrying an operator VARIANT of a legacy rule (which the
  exact `-D`s cannot hit) tore down "successfully" and silently
  orphaned the variant rule in the root nat table. Teardown now runs
  the same read-only verification after its eligibility guards and
  BEFORE the WireGuard deletion, the namespace deletion, and its own
  tolerant legacy deletes, reusing the apply path's exact
  one-instance-per-exact-spec tolerance — a legacy host holding
  exactly its own two v0.1.1 rule specs still tears down (the tolerant
  deletes later in the same teardown remove them; documented migration
  convergence holds), while a variant, a duplicate instance, or any
  other signature hit fails closed with the wg link, the fabric
  namespace, and the ownership journal fully intact. A crash between
  the verification and the tolerant deletes converges: the next
  operation (apply or teardown) re-verifies with the same tolerance
  and re-runs the same idempotent deletes. Contract §3.8/§3.10
  updated; new tests
  `teardown_with_nat_residue_variant_fails_closed_state_preserved`
  (fails against 4e246c3: pre-fix teardown returned `Ok(true)` and
  orphaned the variant) and
  `teardown_on_legacy_host_with_exact_rules_converges` (forward pin
  for the tolerance semantics — it also passes pre-fix, by design);
  round-9 added
  `teardown_with_duplicated_exact_rule_fails_closed_state_preserved`
  (fails against 4e246c3 the same way: a duplicated exact spec was
  orphaned by the unguarded tolerant delete).
- **Honest note on the `-S` token-identity assumption (MINOR,
  docs).** Contract §3.10 now states that the one-instance tolerance —
  and the round-6 tolerant deletes — compare `iptables -t nat -S`
  output byte-for-byte against the provider's exact v0.1.0/v0.1.1
  rule-spec strings, why this is believed safe (simple two-rule specs,
  spec-for-spec verified against `git show v0.1.1` in round 6), what a
  real-kernel rendering divergence would cause (fail-closed on
  apply/teardown for a legacy host — loud, kernel intact, remediable
  by hand-deleting the residue), and that the multi-node evidence
  environment never exercises it (fresh hosts, no legacy rules). No
  code change.
- **"Nothing was modified" scoped truthfully (NIT).** The ambiguity
  error of the three-way socket discriminator now reads "No fabric
  state and no ownership-journal state was modified" — strictly, the
  plan JSON is persisted before the discriminator runs
  (journal-before-mutate), so the unscoped claim was true only for
  kernel state and the ownership journal. Contract §3.10 case 3
  wording scoped the same way; the error-text assertion updated.
- **Root-leg `ss` hard-failure branch covered (NIT).** The existing
  `socket_placement_check_failure_fails_closed` injects a substring
  `ss -uln` failure, which the fabric-ns leg (issued first on every
  healthy apply) consumes; the ROOT-ns leg's `Err` branch — reachable
  only when the fabric-ns leg is positive — had no direct test. New
  test `root_leg_ss_hard_failure_fails_closed` seeds an ns-born wg
  (positive fabric leg) and injects a failure for the bare root
  `ss -uln` only, via the new `RecordingRunner::fail_on_exact`
  test-kit helper (the root line is a strict suffix of the namespaced
  line, so substring injection cannot target it). Coverage pin,
  declared honestly: the branch exists and fails closed correctly at
  4e246c3 — only the test (and the helper) are new.

### Fixed (review round 7)
- **Three-way socket-placement discriminator (MAJOR).** The round-6
  runtime verification healed whenever `ss -uln` inside the fabric
  namespace showed a listener on the configured WG port. That
  observation alone is not attributable: a FOREIGN process binding the
  port inside the fabric namespace (namespace socket tables are
  separate, so the root-bound transport keeps working) triggered the
  destructive heal on every apply — a permanent, non-convergent loop,
  each iteration dropping the WG session. The discriminator is now
  three-way: (1) fabric-ns port absent → healthy, unchanged;
  (2) fabric-ns port present and root-ns port absent → genuinely
  ns-bound → the same ownership-gated, flag-first heal as before;
  (3) BOTH namespaces show the port → unattributable → the apply fails
  closed with a specific error naming both observations, the port, and
  the remediation (inspect both namespaces' listeners, remove the
  foreign one), deleting nothing and changing no journal state. The
  mirrored hole — healing only when the root dump is quiet — would
  silently keep a dead ns-born transport under a foreign root-ns
  listener, which is the exact failure class this design forbids, so
  ambiguity fails closed in both directions. The root-ns `ss` runs only
  when the fabric-ns observation is positive (nothing extra on the
  healthy fast path), through the same runner and exact-port parse, and
  a hard failure of either `ss` fails the apply closed. The two
  observations are read-only and precede any mutation; a concurrent
  external change between them can at worst produce case 3 (fail
  closed), never a wrongful heal. Contract §3.10 updated; the fake
  kernel can seed foreign UDP listeners per namespace
  (`add_foreign_udp_listener`), and the conformance suite gains
  `socket_listener_ambiguity_fails_closed_without_healing`.
- **Nat-residue verification hoisted before all destruction (NIT).**
  The residue check (`iptables -t nat -S` + signature match) now runs
  at the START of every apply, before any destructive action on any
  path — previously it ran inside the legacy cleanup, AFTER the heal
  path had already deleted the wg and the recorded VXLANs, so a
  residue hit failed closed over a destroyed transport. The tolerant
  exact-spec deletes stay where they are (they can only remove rules,
  never create residue). Exactly ONE instance of each exact v0.1.1
  rule specification is tolerated by the verification — those are the
  provider's own convergent legacy rules that the deletes are
  guaranteed to remove — while a second instance or any variant fails
  closed with every kernel object still in place.
- **Residue signature breadth documented truthfully (MINOR, docs).**
  Contract §3.10 and the error text now state the signature the code
  actually matches: any nat-table rule referencing the 169.254.253/24
  prefix (not just the legacy /30 or its exact forms), naming the
  legacy `<prefix>-u` veth, or any DNAT matching the WG port (no
  address tie). The breadth is deliberate and kept: a missed variant
  of residue NAT on the transport is silent death (the postmortem
  failure mode), while a false positive is loud and
  operator-remediable. No behavior change; a table-driven test pins
  the documented breadth (a 169.254.253.77 rule matches; a
  169.254.99.x rule does not).
- **Evidence failure diagnostics never silently skip (hardening).**
  `capture_diagnostics` in `evidence/run-multinode.sh` now always
  writes `diag-host-bridge.txt`: a failed `docker network inspect`
  (or an unresolvable bridge name) is recorded IN the file together
  with the name-independent host captures (`bridge link show`,
  `ip -s link`, `ip neigh`), and every diagnostic command is
  `||`-wrapped so one failure cannot abort the rest under `set -e`.
  In the failed evidence run this file was never produced — the
  inspect guard skipped the whole capture silently.

### Fixed (review round 6)
- **Runtime socket-placement verification (MAJOR).** The journal can only
  record intent; the kernel is the ground truth. On every apply where the
  wg exists in the fabric namespace and no heal is pending, the provider
  now runs `ip netns exec <fabric-ns> ss -uln` and fails the apply (or
  heals) when a UDP listener sits on the configured WG port INSIDE the
  fabric namespace — positive evidence of an ns-bound transport socket
  (round-3..5 crash residue with the flag lost, or an operator-created
  ns-born wg; previously such a host passed green forever on a dead
  binding, since no NAT steers anything back to it). The heal is the same
  full procedure as the journal-flag heal, with the flag journaled BEFORE
  the first deletion so every interruption slice converges; it stays
  ownership-gated (an unowned host with an ns-born listener fails closed
  as foreign state), the port match is exact (a listener on 6500 never
  matches 65001), and a hard failure of `ss` itself fails closed rather
  than reading as "port absent". The healthy case (no listener) is a
  no-op — no state churn, no WG session drop.
- **Nat-residue verification after the tolerant legacy deletes (MINOR).**
  After the exact-spec `iptables -t nat -D` deletions, the nat table is
  listed and the apply fails closed on any residue rule still referencing
  the legacy underlay signature (the 169.254.253 subnet, the `<prefix>-u`
  veth, a DNAT targeting the WG port): exact-spec deletes silently miss
  operator-installed VARIANTS of the legacy rules, and residue NAT state
  on the transport is the postmortem's silent-death mode.
- **Ownership-gated legacy veth deletion (MINOR).** The `<prefix>-u`
  underlay veth is deleted only when the journal shows the provider owns
  (or owned) fabric state; on a fresh host a colliding link is foreign
  state and survives (the veth is inert under the NAT-free underlay, so
  the apply proceeds).
- **Creation claim before the root add (MINOR).** The new journal field
  `fabric_creation_claimed` is persisted BEFORE the root
  `ip link add <wg> type wireguard`, so both crash slices of the
  add→move sequence converge on the next apply instead of the second
  slice wedging permanently on `File exists` (empty journal → sweep
  gated off). The v0.1.0/v0.1.1 first-apply wedge (journal saved only
  at end of apply) remains fail-closed by design; manual cleanup.
- Fake-kernel runner additionally models `ss -uln` per-namespace
  listening-socket dumps (a wg listens in its creating namespace when it
  has a listen port), `wg set listen-port` from inside a namespace, and
  `wg set` on a missing device failing like the real wg.
- Conformance suite gains `runtime_socket_placement_heals_unflagged_ns_born_wg`
  (MAJOR-1 heal path); unit tests cover the heal, the healthy no-op, the
  foreign fail-closed case, the `ss` hard-failure seam, the exact-port
  parse, the nat-residue signatures and variant, the gated veth, the
  claim crash slices, and the fresh-host retry guard.

### Notes
- First tag whose `Cargo.toml` version matches the tag name. v0.1.0/v0.1.1 were
  tagged while the workspace version stayed 0.1.0; git-tag consumers (e.g. CHV)
  are unaffected (git deps ignore the version field), but version-keyed tooling
  could not distinguish those releases. No on-disk format break in this release
  (the `wireguard_born_in_fabric_ns` journal field is reused with new
  semantics: `true` now marks the round-3..5 born-in-ns state needing the
  full heal; v0.1.0/v0.1.1 journals deserialize it as `false` = healthy).
- The `fabric_creation_claimed` journal field is additive
  (`serde(default)`): journals written by older code parse as `false`, and
  older code reading a journal that carries it ignores the unknown field.
- Downgrade notes: v0.1.1 reading a v0.1.2 journal parses it (serde
  ignores the unknown `fabric_creation_claimed` /
  `wireguard_born_in_fabric_ns` fields) but silently strips them on its
  next save — re-upgrading then re-runs the one-time migrations (legacy
  rule/veth cleanup, and the born-in-ns heal only if its trigger is
  present again), which are idempotent; the only observable cost is a
  single WireGuard session drop if the socket-placement heal trigger was
  present. Downgrading mid-heal (a journal with
  `wireguard_born_in_fabric_ns == true` and the wg already deleted) is
  likewise recoverable: v0.1.1 ignores the unknown flag and re-creates
  the wg its own way; re-upgrading cleans up after it again.
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
