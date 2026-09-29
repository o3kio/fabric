# Cross-Implementation Alignment & Change Control

Status: Accepted · Normative for every change to the shared fabric and to how
O3K and CHV consume it.

## 1. Why this document exists

The stretched-L2 fabric is **one design with two control planes**: O3K
(`o3kio/o3k` → `o3k-network`) and CHV (`kubedoio/chv` → `chv-nwd`) both
consume this repository by git tag. The value of that arrangement — one
datapath, one security posture, one migration story, half the maintenance —
survives only if the design does **not** drift to satisfy one consumer's
local goals.

The failure mode this document prevents is well known in shared-platform
engineering: consumer A needs a tweak, gets it shipped as a private behavior
difference; consumer B's assumptions silently break; the conformance suite
still passes because the tweak hides behind a config knob; two years later
there are two fabrics in everything but name. Therefore:

> **The design changes rarely, deliberately, and for fabric-wide reasons —
> never per-project.** If a consumer's goal conflicts with the design, the
> conflict is escalated and resolved at the ADR level, not worked around in
> a fork, a config flag, or a reinterpretation of the contract.

## 2. The normative hierarchy

Each layer is normative for the layers below it, and each owns a distinct
kind of decision. **A question is decided at exactly one layer** — the lowest
one that owns it — and is referenced, never re-decided, above it.

| Layer | Document | Owns | Lives in |
|---|---|---|---|
| 1. Product decision | O3K ADR-0186, CHV ADR-021 | *Whether and why* a stretched-L2 fabric exists; product scope, trust model, phased rollout | product repos |
| 2. Specification | O3K SPEC-0049 | The fabric's external behavior: topology, VXLAN/HER/WG model, key management, VNI allocation, evidence requirements | o3k repo (CHV ADR-021 records the aligned decision) |
| 3. Provider contract | `contracts/fabric-provider-v1.md` | The provider's behavioral invariants: input rules, idempotency, fail-closed semantics, key hygiene, teardown, migration | **this repo** |
| 4. Executable contract | `crates/fabric-conformance` | The contract as a suite, run against the pinned provider tag | this repo |
| 5. Reference implementation | `crates/fabric-linux` (+ `fabric-plan`) | How the invariants are realized on Linux; naming, journals, exact kernel commands | this repo |
| 6. Consumers | `o3k-network`, `chv-nwd` | Plan compilation, lifecycle orchestration, their own host state | product repos |

Two structural rules keep this hierarchy honest:

- **No layer skipping.** A consumer cannot change provider behavior (layer
  3/5) to serve a product decision (layer 1) without the change being made
  *at* layer 3 — contract first, then conformance, then implementation.
- **No duplication.** The design rationale lives in the ADRs; the
  specification in SPEC-0049; the invariants in the contract; the details in
  [`docs/design.md`](design.md). When a lower layer changes, every document
  above it that references the change is updated **in the same change**, or
  the change is not merged.

One honesty boundary on layer 4: the conformance suite proves provider
behavior **modulo configuration** — it runs the reference provider over the
fake kernel and cannot see a consumer's plan compilation, integration code,
or configuration choices (prefix, ports). Those are pinned by
[`docs/design.md` §15](design.md#15-cross-implementation-configuration-pinned-values)
and verified by review, not by the suite.

## 3. Change classes and the required process

Every change to this repository (or to a consumer's use of it) falls into
exactly one class. The process is the price of admission — deliberately
heavier than a normal PR when behavior is involved, deliberately light when
it is not. The class is stated in the PR description.

### Class A — design change (datapath, underlay, security, or plan semantics)

*Examples: replacing the underlay transport (as v0.1.2 did), changing the
encryption model, altering the plan schema's meaning, changing key hygiene.*

1. **Fabric ADR** in `docs/adr/`: context, decision, consequences, kernel
   references, migration. Numbered sequentially.
2. **Contract change with version bump** (`fabric-provider-v1.md` → `-v2.md`
   when invariants change; in-place amendment when provably compatible) —
   in the same PR or a tightly linked one, never after the fact.
3. **Conformance extension**: new/changed suite cases that fail against the
   pre-change provider (verified, not assumed).
4. **Implementation + unit tests** following the workspace hard rules.
5. **Evidence rerun** on the affected scenario (multi-host gate) before tag.
6. **Consumer alignment**: both O3K and CHV open tracking issues; consumers
   upgrade within the supported skew window (§5).

### Class B — behavioral change (observable provider behavior, no design change)

*Examples: a new fail-closed check, heal semantics, teardown ordering.*

Contract amendment + conformance case + implementation, in one PR. A fabric
ADR is required only if the rationale is more than a paragraph. Evidence
rerun if the datapath or teardown is touched.

### Class C — compatible addition

*Examples: a new optional config knob defaulting to current behavior, a new
read-only field in `ApplyReport`, new diagnostics.*

Contract amended (additive section), conformance extended, implementation.
No version bump required as long as *no existing input or output changes
meaning* — that is the test for "compatible".

### Class D — internal implementation

*Examples: refactors, error-message wording, test additions, docs.*

Normal PR; conformance must stay green; no contract change. **The test for
Class D is observable behavior**: if any command sequence, journal field
meaning, error variant, or report field changes, it is not Class D.

## 4. Hard rules (both consumers)

Binding on O3K and CHV alike; enforced socially by review, mechanically by
the conformance suite in each product's CI.

1. **Pin by tag, consume the crates, do not fork.** Consumers import
   `fabric-plan`/`fabric-linux` from an exact git tag and run
   `fabric-conformance`'s `run_suite()` in their CI at that tag (add it as a
   dev-dependency pinned to the same tag). Vendoring, patching, or wrapping
   the provider to change its behavior is prohibited — a wrapped provider is
   a fork with extra steps.
2. **Never touch fabric kernel state.** Control planes do not run
   `ip`/`wg`/`bridge`/`iptables` against fabric objects, ever — not "just to
   fix it up". If the provider cannot reach a needed state, that is a Class
   A/B change here, not an operational workaround there.
3. **Never reinterpret the contract.** If the contract is ambiguous for a
   consumer's use case, the ambiguity is fixed here (Class B) — the consumer
   does not pick the interpretation it prefers and ship it.
4. **No consumer-private config knobs in the provider.** A knob whose only
   purpose is to let one product diverge from the shared behavior is a
   design smell and will be rejected. Knobs are fabric-wide concepts (name
   prefix, WG port, state root) or they do not exist; their per-product
   values are pinned in `docs/design.md` §15.
5. **Plans are compiled, not negotiated.** The provider validates and
   rejects; it never repairs. Consumers must not rely on any repair-like
   behavior, and must surface `ForeignState` errors to operators rather
   than retry-looping them away.
6. **Use the shared vocabulary.** Control planes build identity, binding,
   and MTU decisions from `fabric-plan`'s exported types and constants
   (`FabricHostIdentity`, `FabricVniBinding`/`BindingState` — including the
   Withdrawn-before-reuse check — `tenant_mtu_for`, the overhead constants,
   `validate_endpoint`, `validate_public_key`). Hand-rolled equivalents in
   two places are where cross-product drift starts.
7. **Upstream-first.** A consumer-local patch to this repo that survives
   longer than one release cycle without an upstream PR is a violation,
   regardless of how it got there.
8. **Conformance is the shared gate.** A consumer upgrade that fails
   conformance at the pinned tag blocks the upgrade, not the suite.

## 5. Versioning and skew

- **Repos and tags:** this repository ships lightweight git tags
  (`v0.1.3`, …) at merge commits on `main`; the tag's `Cargo.toml` version
  matches the tag, and the version bump + CHANGELOG entry land in the same
  PR as the change. Consumers pin exact tags, never branches.
- **Contract version** (`fabric-provider-v1.md`): vN identifies the
  invariant set. Incompatible invariant changes bump to vN+1 with a
  migration section; provably compatible amendments stay in-place with a
  CHANGELOG entry.
- **Crate semver:** `fabric-plan`/`fabric-linux` follow normal semver
  *within* a contract version; a contract version bump is a semver major.
- **Fleet policy:** control planes pin **one provider tag fleet-wide**.
  Mixed-tag clusters have no test coverage, and journals round-tripped
  through older code silently strip newer flags. The one documented
  migration exception is v0.1.1 → v0.1.2 (mixed hosts converge via the
  tolerant cleanup, contract §3.10); any future mixed-version window must
  be as explicitly documented.
- **Both consumers upgrade on their own schedules**, but a fabric-wide
  design decision (Class A) lands with tracking issues in both repos and
  each consumer upgrades within one release cycle of the provider tag it
  needs.

## 6. Consumer obligations checklist

For each provider tag a consumer adopts:

- [ ] Pin the exact tag in the manifest; run `cargo update` for the fabric
      crates only.
- [ ] `fabric-conformance` `run_suite()` green in the consumer's CI at that
      tag.
- [ ] Read this repo's CHANGELOG between the old and new tag; classify each
      entry against the consumer's own usage; open issues for anything
      touched.
- [ ] If the contract version changed: follow its migration section
      end-to-end before shipping; do not run a mixed contract-version
      cluster.
- [ ] No new consumer-side handling of fabric kernel state (rule 2) or
      hand-rolled shared-vocabulary equivalents (rule 6) snuck in with the
      upgrade.

## 7. Decision records (`docs/adr/`)

Provider-level design decisions that outlive a CHANGELOG entry are recorded
as numbered fabric ADRs in `docs/adr/` — see
[`docs/adr/README.md`](adr/README.md) for the format and index. The seeds:

- [ADR-0001 — NAT-free, root-terminated WireGuard transport](adr/0001-nat-free-root-terminated-transport.md)
- [ADR-0002 — Runtime socket-placement verification and the three-way
  discriminator](adr/0002-runtime-socket-placement-verification.md)

Product-level decisions stay in the product repos' ADR series (O3K
ADR-0186, CHV ADR-021); a fabric ADR references them, never replaces them.

## 8. Stability commitments

The following are **frozen** for contract v1 — changing any of them is a
Class A change requiring a new contract version, not an amendment:

- The plan schema's field semantics and validation rules.
- The naming scheme and the name-prefix contract (1–4 ASCII chars, IFNAMSIZ,
  prefixes pinned per product in `docs/design.md` §15).
- Default ports (WG 65001, VXLAN 4789) and the MTU layering arithmetic and
   constants.
- Key hygiene mechanics (file-path/stdin only; one keypair per host; key
  survives teardown).
- Fail-closed-on-foreign-state as the answer to every unexpected
  observation.
- The NAT-free, root-terminated transport (ADR-0001).

Everything else (internal commands, the journal's private encoding, test
infrastructure, diagnostics) may evolve as Class D/C, provided observable
behavior and the conformance suite hold.

## 9. Escalation and dispute resolution

When a consumer's need conflicts with the design:

1. Open an issue in **this** repository describing the need, not the
   solution.
2. The change is classified (§3) here — in public, with both products'
   maintainers able to see it.
3. If it is Class A, the fabric ADR must argue the change is right for the
   **fabric**, not for one consumer; an ADR that cannot articulate the
   fabric-wide case is rejected, and the consumer's need is met at the
   consumer's own layer (layer 6) instead.
4. Ties are broken by the normative hierarchy, lowest layer wins — a
   product deadline is never a reason to skip a layer.

## 10. Pre-merge checklists

**For changes to this repository:**

- [ ] Class identified (A/B/C/D) and stated in the PR; process for that
      class followed.
- [ ] Contract checked first: invariant changes amended/bumped in the same
      change; docs referencing changed behavior updated in the same change.
- [ ] Conformance extended for any behavioral change; new tests verified to
      fail pre-change (or declared coverage pins).
- [ ] Workspace hard rules: no `unsafe`, no `unwrap`/`expect`/`panic`
      (tests included), clippy/fmt clean, no new dependencies without
      review.
- [ ] Evidence gate rerun if the datapath, underlay, or teardown changed.

**For changes to a consumer's fabric integration:**

- [ ] No fabric kernel state touched by the consumer (rule 2).
- [ ] No behavior depends on contract ambiguities (rule 3).
- [ ] No hand-rolled shared vocabulary (rule 6).
- [ ] Conformance still green at the pinned tag.
- [ ] Anything that needed provider behavior to change went through §3
      here, not around it.
