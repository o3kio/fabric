# AGENTS.md

Guidance for code agents working in this repository.

## What this repo is

The shared **provider layer** of the Kubedo stretched-L2 edge fabric,
consumed by both `o3kio/o3k` and `kubedoio/chv`. The decision trail lives in
the product repos; the executable contract lives here:

- `contracts/fabric-provider-v1.md` — normative behavioral invariants. Read
  it before changing provider behavior. Changes require a new contract
  version.
- `crates/fabric-plan` — portable input types. No I/O, ever.
- `crates/fabric-linux` — Linux realization. All kernel access goes through
  the `FabricCommand` seam; no direct netlink/syscalls in Phase 1.
- `crates/fabric-conformance` — the suite both products run in CI. Any
  behavioral change must keep it green (or extend it deliberately).

## Hard rules

1. **Never weaken an invariant to make a test pass.** If a conformance case
   conflicts with reality, change the contract first (with a version bump),
   then the code.
2. **Key hygiene is absolute.** Private key material never appears in argv,
   serialized plans, ownership journals, error text, or logs. It travels by
   file path or stdin only.
3. **Fail closed.** Foreign or corrupt state is rejected, never adopted,
   silently repaired, or deleted.
4. **No new dependencies without review** (see `deny.toml`).
5. Provenance: clean Kubeko implementations only. No ports or translations
   of third-party source. See O3K `docs/CLEAN_IMPLEMENTATION.md` for the
   policy this repo follows.
6. Lints are part of the contract: `unsafe_code` forbidden;
   `clippy::unwrap_used`/`expect_used`/`panic` denied everywhere, tests
   included. Use `?`, `Result`-returning tests, and `assert!`.

## Testing layers

- Unit + conformance tests here run unprivileged against the recorded fake
  kernel (`RecordingRunner`).
- Privileged multi-host evidence (three privileged host instances —
  containers — on one physical kernel: real WireGuard handshakes,
  cleartext-underlay capture, zero-leak teardown) lives in
  `evidence/run-multinode.sh`. It is required before any production
  evidence claim; do not fake it.

## Evidence gate — contract of record

- **Who runs it:** the fabric maintainer, on a quiesced orchestrator host
  (no parallel bridge lifecycle churn — see `evidence/README.md` →
  Limitations for the interference attribution recipe), before tagging a
  release whose diff touches the datapath, underlay, or teardown.
- **Where results live:** `evidence/results/<timestamp>/` — git-ignored by
  design (they can contain environment detail); the release record is the
  PR description + CHANGELOG entry stating the run's outcome and the
  commit it ran on. Do not commit results.
- **What a release consumes:** a green 10-run acceptance loop (or a
  failure root-caused as external interference, per the recipe) on the
  exact release commit, stated in the release PR. CI does not and cannot
  run the gate (privileged docker); absence of a gate run in CI is not
  evidence of absence of a run.
- **Honesty rule:** state the evidence scope exactly as
  `evidence/README.md` → Limitations does (one physical kernel; not
  geographic distance, NIC heterogeneity, or real-internet path MTU;
  cross-machine runs remain the final production gate).

## Documentation discipline

- `docs/design.md` (design details), `docs/change-control.md`
  (cross-implementation alignment and change classes), and `docs/adr/`
  (provider decision records) are normative-adjacent: update them in the
  same change as any behavior they describe, and classify changes per
  `docs/change-control.md` in the PR description.
- Never weaken the contract to make code or docs agree — fix whichever is
  wrong, contract first if behavior must change.
