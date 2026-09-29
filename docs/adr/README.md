# Fabric ADRs

Provider-level architecture decision records for the shared stretched-L2
fabric. These record decisions that outlive a CHANGELOG entry: why the
underlay is NAT-free, why ambiguity fails closed, and so on. They are
referenced by the [contract](../../contracts/fabric-provider-v1.md) and
[`docs/design.md`](../design.md), and governed by
[`docs/change-control.md`](../change-control.md) (Class A changes require an
ADR here).

Product-level decisions (whether the fabric exists, product scope, rollout)
live in the product repos: O3K ADR-0186 / SPEC-0049, CHV ADR-021. A fabric
ADR references them; it never replaces them.

## Index

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-nat-free-root-terminated-transport.md) | NAT-free, root-terminated WireGuard transport | Accepted |
| [0002](0002-runtime-socket-placement-verification.md) | Runtime socket-placement verification (three-way discriminator) | Accepted |

## Format

Numbered sequentially, never reused. One file per ADR,
`NNNN-kebab-case-title.md`, with sections:

- **Status** — Accepted / Superseded by ADR-NNNN / Rejected
- **Context** — the forces and evidence that forced a decision
- **Decision** — the change, in one paragraph
- **Consequences** — what becomes true/false, including accepted limitations
- **References** — kernel sources, evidence artifacts, contract sections

An ADR is never edited to change its mind — a reversal is a new ADR that
supersedes it.
