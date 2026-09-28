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
- Privileged multi-host evidence (three real hosts, real WireGuard
  handshakes, cleartext-underlay capture, zero-leak teardown) lives in
  `evidence/run-multinode.sh`. It is required before any production
  evidence claim; do not fake it.
