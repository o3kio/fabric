# ADR-0002 — Runtime socket-placement verification (three-way discriminator)

Status: Accepted (2026-09-28, hardened through review rounds 6–8, shipped in
v0.1.2)

## Context

ADR-0001 makes the WireGuard transport socket's root-namespace placement a
correctness invariant. But invariants that are only *established* can be
broken later: a v0.1.x-era installation, an unreleased experiment, or an
operator following an old runbook can leave a wg whose socket was born in
the fabric ns (dead transport — inbound flows reach the root ns where
nothing listens) or, worse, listeners on the WG port in **both** namespaces.

The provider therefore cannot assume placement; it must observe it. The
observation is `ss -uln` per namespace on the WG port. Three observations
are possible, and the hardening rounds (6–8) established that each needs a
*different* response — one review round rejected the simpler "root shows the
port → skip heal" rule because it would silently keep a dead transport
whenever the fabric-ns listener was ns-born and the root listener foreign.

## Decision

On every apply, after `ensure_fabric`, run the discriminator **before any
destructive action**:

| Fabric-ns `ss -uln` on the WG port | Root-ns `ss -uln` on the WG port | Response |
|---|---|---|
| quiet | not queried | Healthy — the socket is root-side as designed. No root query (fast path). |
| listening | quiet | The socket is ns-born → **heal**: delete the wg and recreate it root-side (ADR-0001), journaled via the `wireguard_born_in_fabric_ns` heal flag. |
| listening | listening | **Unattributable** → fail the apply closed with a `ForeignState` ambiguity error naming both observations and the remediation. Nothing is deleted; no fabric state and no ownership-journal state is modified. |

A hard failure of either `ss` leg is a `Command` error, never treated as
"quiet" — an unverified observation is not a negative one.

## Consequences

- A healthy transport can never be destructively healed: the heal path is
  reachable only through the discriminator, and the only observation pattern
  that triggers it (fabric-ns listener + provably quiet root ns) cannot
  occur for a root-terminated socket.
- Ambiguity is loud, cheap, and safe: the error tells the operator exactly
  what was seen in both namespaces; resolution is manual identification of
  the foreign listener, then re-apply.
- Every apply carries two cheap observations (one `ss` in the healthy case)
  — accepted cost.
- The discriminator must run before the ownership gate's mutations (it does
  — after `persist_plan`, which is journal-before-mutate and writes no
  kernel or ownership state), a scoping the error text states exactly.
- The fake kernel models per-namespace `ss` (including foreign-listener
  seeding), so all three arms and both hard-failure legs are unit-tested;
  the healthy arm is additionally asserted by the multi-host evidence gate
  (`wg_socket_in_root_ns_*`).

## References

- Contract §3.10 (discriminator semantics and the ambiguity error);
  `crates/fabric-linux/src/provider.rs` (`ensure_fabric`); CHANGELOG entries
  for review rounds 6–8.
- ADR-0001 (the invariant being verified).
