# The Kubedo Stretched-L2 Fabric — Design Document

Status: Accepted · Applies to: fabric v0.1.3 (`fabric-plan`/`fabric-linux`/`fabric-conformance`) · Maintained in this repository

This document is the consolidated **engineering design** of the shared
stretched-L2 fabric: what it builds in the host kernel, why it is built that
way, and how it behaves across every lifecycle path. It is *descriptive and
explanatory* — the **normative** sources remain, in order:

1. O3K [ADR-0186](https://github.com/o3kio/o3k/blob/main/docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
   and [SPEC-0049](https://github.com/o3kio/o3k/blob/main/docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
   — the product-level decision and specification.
2. CHV [ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)
   — the aligned consumer decision (including its postmortem addendum).
3. [`contracts/fabric-provider-v1.md`](../contracts/fabric-provider-v1.md) —
   the provider contract: the behavioral invariants every implementation and
   both consumers (O3K `o3k-network`, CHV `chv-nwd`) are held to.
4. `crates/fabric-conformance` — the contract's executable expression.

If this document and the contract ever disagree, **the contract wins** and
this document is buggy. How the layers may change — and why neither consumer
may bend the design to local goals — is governed by
[`docs/change-control.md`](change-control.md).

---

## 1. Purpose

A tenant network in Kubedo is **one literal L2 broadcast domain stretched
across all enrolled hosts** — the same VLAN, everywhere. Concretely: a VM on
host A ARPs for a VM on host B and gets a real answer; the neighbor tables on
both sides hold each other's real MACs; ICMP and near-MTU frames cross hosts
identically to how they cross hypervisors. There is no proxy-ARP, no host-NAT
of tenant traffic, and no learning slow path in userspace.

The fabric is split along one seam:

- **Control planes** (O3K `o3kd`, CHV control plane): own identity enrollment,
  VNI allocation, placement, flood-set derivation, and lifecycle. They compile
  canonical state into `StretchedL2Plan`s.
- **The provider** (this repository): the *only* component permitted to
  manipulate the fabric's kernel objects. It realizes plans idempotently,
  fails closed on foreign state, and reconciles after crashes.

Both products consume the same provider code by git tag, so the datapath a
Kubedo customer gets is identical regardless of which control plane manages
the host.

## 2. Architecture overview

Per enrolled host, the provider builds:

```
            root netns                              fabric netns  (ev-fabric)
 ┌───────────────────────────────┐      ┌──────────────────────────────────────┐
 │  consumer veth (per network)  │      │  learning bridge (per network)       │
 │  <prefix>-c-<hash8>           │      │  <prefix>-b-<hash8>                  │
 │        │                      │      │     │            │                   │
 │        │ (tenant MTU)         │      │  fabric veth  VXLAN (per network)    │
 │  ──────┴──────────────────────┼──────┼─ <prefix>-p-..  <prefix>-x-<hash8>    │
 │                              peer   │                  local=<tport>,       │
 │   WireGuard <prefix>-wg ─────┼──────┼────────────────── dev <wg>            │
 │   (UDP :65001, socket HERE)  │      │  allowed-ip per peer = <tport>/32     │
 └───────────────────────────────┘      └──────────────────────────────────────┘
        │ encrypted UDP, host routing (no NAT anywhere)
        ▼
        underlay network / internet
```

- **One shared WireGuard mesh per host** carries all networks of one fabric
  domain. Peers are keyed by public key; each peer's fabric transport address
  is installed as a `/32` route + `allowed-ip` — never a tenant prefix.
- **One VXLAN device per network** (learning **enabled** — no `nolearning`)
  with head-end replication (HER): the control plane computes the bounded set
  of peer transport IPs currently hosting endpoints of that network, and the
  provider programs one `bridge fdb append … dst <peer-tport>` entry per peer
  on the VXLAN device. Unknown-destination (BUM) frames are replicated to
  exactly that set; after the first frame, kernel FDB learning pins the MAC
  and subsequent frames are unicast.
- **One attachment veth pair per network**: the fabric end
  (`<prefix>-p-<hash8>`) lives in the fabric netns enslaved to the learning
  bridge; the consumer end (`<prefix>-c-<hash8>`) stays in the root netns for
  the host's own attachment logic (CHV enslaves it to its tenant bridge, O3K
  moves it into its realm bridge). The provider never touches anything on the
  far side of the consumer end.

Everything tenant-facing (VXLAN, bridge, veths, tenant MTU) is fully
namespaced. The single deliberate exception is the WireGuard **transport
socket**, which lives in the root netns by design (§4.2).

## 3. Kernel object inventory

All per-network names are deterministic:
`<prefix>-<kind>-<fnv1a32-8hex-of-network-id>` with kind ∈ {`x` VXLAN, `b`
bridge, `p` fabric veth, `c` consumer veth}; shared names are `<prefix>-wg`,
`<prefix>-fabric`; the legacy v0.1.x underlay veth was `<prefix>-u` (host
end) / `<prefix>-v` (fabric end — never named by the cleanup; deleting the
host end removes the pair). The prefix is 1–4 ASCII characters, so every link
name fits IFNAMSIZ (15 bytes). Names are operator *hints*; ownership is
proven only by the journal (§7) plus identity re-verification against
observed kernel state before any mutation.

| Object | Name / path | Namespace | Scope | Notes |
|---|---|---|---|---|
| Fabric network namespace | `<prefix>-fabric` | root | one per host | |
| WireGuard interface | `<prefix>-wg` | fabric ns (moved from root) | one per host | created root-side (§4.2) |
| WG UDP socket | port 65001 (default) | **root** ns (creating ns) | one per host | kernel-owned; *verified* every apply (§6.3) |
| VXLAN device | `<prefix>-x-<hash8>` | fabric ns | per network | learning on, `dev <wg>`, `local <tport>` |
| Learning bridge | `<prefix>-b-<hash8>` | fabric ns | per network | |
| Fabric veth end | `<prefix>-p-<hash8>` | fabric ns | per network | bridge port |
| Consumer veth end | `<prefix>-c-<hash8>` | root ns | per network | consumer enslaves/moves it |
| HER flood entries | on the VXLAN device | fabric ns | per (network, peer) | §6.5 |
| Private key file | `<state-root>/wireguard-private.key` | filesystem, 0600 | one per host | §9 |
| Ownership journal | `<state-root>/ownership.json` | filesystem | one per host | §7 |
| Per-network plans | `<state-root>/plans/<network_id>.json` | filesystem | per network | written before any mutation |

Defaults: WG port 65001, VXLAN port 4789. The legacy underlay constants
(169.254.253.1/.2, `169.254.253.0/30`, signature token `169.254.253`) exist
only as operands of the tolerant v0.1.x cleanup (§8).

## 4. The two planes

### 4.1 Tenant datapath (per network)

Frame path for a tenant frame from host A to host B:

1. Frame arrives on the consumer veth (root ns) → fabric veth (fabric ns) →
   learning bridge.
2. The bridge's FDB either knows the destination MAC (learned from earlier
   reverse traffic → unicast to the VXLAN device) or does not (BUM →
   replicated to every HER flood entry).
3. VXLAN encapsulates (outer UDP 4789, outer addresses = fabric transport
   IPs) and hands the packet to the WG interface (its `dev`).
4. WireGuard encrypts and authenticates, sends UDP :65001 to the peer's
   underlay endpoint via **normal host routing** — there is no NAT, no DNAT,
   no MASQUERADE, and no policy routing installed by the fabric.
5. On host B the reverse happens in the fabric ns; kernel MAC learning on the
   VXLAN device populates the FDB from real traffic (this is what the
   evidence gate asserts with `REACHABLE` neighbor entries carrying peers'
   real MACs).

**MTU layering.** The plan validates `tenant_mtu + 50 (VXLAN_OVERHEAD_BYTES)
≤ fabric_mtu` and `tenant_mtu ≥ 576 (MIN_TENANT_MTU)`; `MAX_MTU` is 65535.
The VXLAN device and both veth ends carry `tenant_mtu` (the learning bridge's
own MTU is not set — it never gates delivery between tenant-MTU ports); the
WG interface carries `fabric_mtu` — specifically the **maximum live
`fabric_mtu` across applied networks, re-asserted every apply and never
shrunk below it** (shrinking would black-hole existing networks; after the
last high-MTU network is removed, the next apply re-converges downward
safely). The
outermost inequality is control-plane responsibility:
`fabric_mtu + 60 (WIREGUARD_OVERHEAD_BYTES_IPV4; 80 for IPv6 outer) ≤
underlay path MTU`. Golden worked example from the evidence gate: tenant
1380, fabric 1440, underlay 1500 (1328-byte ping ≤ 1380; encapsulated 1378 ≤
1440; +60 = 1438 ≤ 1500). **Both consumers must use `fabric-plan`'s exported
constants and helpers (`tenant_mtu_for`, the overhead constants) for this
arithmetic** — hand-rolled MTU math in two places is where a
divergence would hide.

**BUM bound.** The flood set is bounded by construction: it contains exactly
the enrolled hosts that currently host at least one endpoint of that network
(control-plane placement state). It is never "all fabric peers".

### 4.2 Transport underlay — NAT-free, root-terminated (design F)

The v0.1.x underlay steered the WG transport through a veth into the fabric
ns with `PREROUTING DNAT` (inbound) and `POSTROUTING MASQUERADE` (outbound).
Both NAT directions raced in production-like evidence loops:

1. **DNAT black-holes NEW inbound flows.** A WireGuard interface's UDP socket
   binds in its **creating** namespace and never follows
   `ip link set netns` (kernel `creating_net` is immutable; verified on
   kernel 6.8 against `drivers/net/wireguard/socket.c`). A wg created in the
   root ns and moved keeps its socket in the root ns while DNAT rewrites
   every NEW inbound flow into the fabric ns, where nothing listens. Pairs
   survived only behind conntrack reply-tuple shields — an intermittent
   dead-pair flake (≈1-in-3).
2. **MASQUERADE remaps the source port under simultaneous initiation.** For a
   same-port peer pair the outbound MASQ flow's reply tuple *always* equals
   the peer's inbound DNAT entry's orig tuple; conntrack requires global
   tuple uniqueness, so simultaneous initiation remaps one side's source
   port, and the peer's WireGuard roams to a port the DNAT rule does not
   steer (≈1-in-10 dead pairs). No iptables formulation avoids this.

**Resolution (v0.1.2):** the wg interface is created in the **root** ns and
then moved into the fabric ns — so its UDP socket (bound in the creating ns)
lives in the root ns. Outbound rides normal host routing; inbound is
delivered directly to the root-ns listener. **There is no NAT state left to
race.** Full postmortem and migration semantics: contract §3.10, the
CHANGELOG at v0.1.2, and
[`docs/adr/0001-nat-free-root-terminated-transport.md`](adr/0001-nat-free-root-terminated-transport.md).

Because the socket's placement is now a correctness invariant, the provider
does not merely assume it — **every apply verifies it at runtime** with a
three-way `ss -uln` discriminator (§6.3).

**Limitation (accepted):** one fabric per WG port per host. The root-ns
socket occupies the port host-wide. CHV and O3K each run exactly one fabric
per host; distinct fabrics on one host must use distinct ports *and* distinct
name prefixes. Today the two products run on disjoint hosts; if they ever
co-locate, they must coordinate ports explicitly (default 65001 collides —
see §15.2).

**Operator prerequisite (unchecked by the provider):** the root namespace
must be able to route to every peer `underlay_endpoint`. The provider does
not verify reachability (a WG endpoint that never connects produces a
transport that is plumbed but silent); control planes should treat
handshake/endpoint reachability as part of host health. Endpoint hosts are
recommended to be IP literals so all hosts resolve them identically.

## 5. The plan model (`fabric-plan`)

`StretchedL2Plan` is the sole provider input: a serde-serializable,
`deny_unknown_fields`, strictly-validated record of one (fabric domain,
local host, network) triple:

| Field | Meaning / invariant |
|---|---|
| `fabric_domain_id`, `local_host_id`, `network_id` | identifiers: non-empty, ≤64 chars, ASCII `[A-Za-z0-9_-]` |
| `local_transport_ip` | this host's address inside the WG mesh; must be specified |
| `vni` + `binding_generation` | the network's current VNI binding and its generation (VNI ∈ 1..=0x00ff_ffff; generation nonzero) |
| `tenant_mtu`, `fabric_mtu` | MTU layering (§4.1) |
| `peers` | bounded HER set; per peer: `host_id`, `public_key` (44-char base64), `underlay_endpoint` (non-empty host, no whitespace/control, nonzero port), `fabric_transport_ip`. No self entries; host IDs, transport IPs, and public keys each unique |
| `plan_generation` | monotonic, fences stale plans |

"Strict" means exactly (contract §2.1): unknown fields reject at
deserialization, and **values** — including endpoint values on the
deserialized path — are validated by `validate()`, which must run before
realization. The provider additionally computes a SHA-256 fingerprint over
the canonical serialization and records it in the journal; the fingerprint is
**ground truth, never compared** — idempotency is re-assertive, not
fingerprint-based.

The crate contains **no I/O** — plans are compiled by the control plane from
its own canonical state (VNI binding registry, enrollment, placement) and are
the *only* channel through which control-plane intent reaches the kernel.

### 5.1 Control-plane contract types (agreed API, not provider-employed)

`fabric-plan` also exports types the provider itself does not exercise, as
the **agreed vocabulary both control planes must share** (this is the
deliberate disposition — they are contract surface, not dead code):
`FabricHostIdentity` (enrollment record shape), `FabricVniBinding` +
`BindingState` (the binding registry record; **`Withdrawn` ordering is a
control-plane promise**: owned tunnel state must be proven absent before a
VNI is reused — both products must implement the same check), and the MTU
constants/helpers of §4.1. `validate_endpoint`/`validate_public_key` are
convenience validators for control planes building these records.

## 6. Provider lifecycle (`fabric-linux`)

The provider is synchronous and runtime-agnostic (consumers wrap it, e.g.
`spawn_blocking`). All kernel access goes through the `FabricCommand` seam —
real subprocesses in production, the recorded fake kernel in tests. No
netlink, no direct syscalls (Phase 1; the seam keeps a netlink backend
possible without observable behavior change).

### 6.1 `apply_plan` — the only write path

Authoritative ordering:

```
validate plan → compute fingerprint
  1. persist plan + fingerprint            (journal-before-mutate)
  2. verify_no_legacy_nat_residue()        (read-only; fail-closed, §8)
  3. ensure_fabric()                        (ns, wg create-in-root + move,
                                             identity verification, §6.2–6.3)
  4. configure_peers()                      (stale peer withdrawal, endpoints,
                                             allowed-ips + /32 routes)
  5. enforce_wireguard_mtu()                (max live fabric_mtu, never shrinks)
  6. ensure_network()                       (vxlan, bridge, veths, MTU,
                                             link up, flood reconcile §6.5)
  7. ownership.save()                       (only after everything succeeded)
```

Properties: re-applying an unchanged plan performs observations only
(idempotent, contract §3.2); enslavement/MTU/link-state are unconditional
re-asserts so a crash between creation steps never leaves a half-plumbed
network that re-apply reports as healthy; every observed-but-unexpected
object is **foreign state** — rejected, never adopted, never deleted.

### 6.2 `ensure_fabric` — creation, healthy path, healing

- **Create:** netns → wg created **in the root ns** (`ip link add … type
  wireguard`) → moved into the fabric ns (`ip link set <wg> netns
  <fabric-ns>`) → `wg set` from inside the fabric ns (private key **by file
  path**, listen port) → transport `/32` address → peer set →
  `fabric_mtu`. The pre-add journal claim (`fabric_creation_claimed`) closes
  the crash window between `ip link add` and the move.
- **Healthy:** observe and verify identity (ns exists, wg present with the
  right port/MTU/address, no unexpected peers), mutate nothing.
- The root-ns stray sweep (deleting `<prefix>-wg`-colliding links on a fresh
  host) is **ownership-gated**: a name collision with an empty journal is
  foreign state, never adopted.

### 6.3 Runtime socket-placement verification (three-way discriminator)

Every apply, after `ensure_fabric`:

| Fabric-ns `ss -uln` on :65001 | Root-ns `ss -uln` on :65001 | Verdict |
|---|---|---|
| quiet | (not queried) | **healthy fast path** — the socket is root-side as designed |
| listening | quiet | ns-born socket → **heal**: delete + recreate root-side, journaled via the `wireguard_born_in_fabric_ns` flag |
| listening | listening | **unattributable** → apply fails closed with a `ForeignState` ambiguity error naming both observations; no fabric state and no ownership-journal state is modified |

The discriminator runs before any destructive action; the heal path is only
reachable through it, so a foreign fabric-ns listener can never trigger a
destructive heal of a healthy transport, and ambiguity is loud instead of a
silently dead transport. A hard failure of *either* `ss` observation leg is a
`Command` error — an unverified observation is never treated as "quiet".
Full rationale: [ADR-0002](adr/0002-runtime-socket-placement-verification.md).

### 6.4 Removal paths

- `remove_network`: deletes only the journal-recorded per-network objects
  (vxlan, bridge, both veth ends, flood entries), then drops the plan and
  journal entry unconditionally. Never touches shared fabric objects or NAT
  state.
- `remove_fabric_if_unused`: eligibility guards (no networks left, no plan
  files) → **residue verification** (§8) → wg deletion → tolerant legacy
  cleanup → namespace deletion → journal cleared. The private key
  intentionally survives so control-plane records of the public key stay
  valid.
- Crash between any steps: the next operation re-observes, re-verifies, and
  converges — every deletion is idempotent (absent objects count as removed),
  and the journal is only rewritten after the deletions it describes have
  succeeded.

### 6.5 Flood reconciliation

Desired HER entries = the plan's peer set. `bridge fdb append` does not
deduplicate (bridge(8), Launchpad #1531013), so reconciliation is
count-aware: still-desired entries with accumulated duplicates are trimmed to
exactly one; unwanted entries are deleted instance-by-instance; the fake
kernel models real one-instance `fdb del` semantics. Repeated applies
converge to exactly one entry per desired peer. (FDB/IP behavior is
kernel-version-sensitive; the fake kernel models the observed mainline
semantics — see §14 on evidence scope.)

## 7. Ownership journal

`<state-root>/ownership.json`, format `state_version = 1`, written with
temp-file + fsync + atomic rename. Records:

- `fabric_creation_claimed` — pre-`ip link add` claim (crash window).
- `fabric_configured` — set only after the wg configuration succeeded; gates
  key/port re-forcing.
- `wireguard_born_in_fabric_ns` — the heal flag (§6.3).
- `peers: Vec<PeerRecord>` — host_id, public key, underlay endpoint,
  fabric transport IP.
- `networks: BTreeMap<network_id, NetworkOwnership>` — plan fingerprint
  (ground truth), VNI, owned object names, flood list.

Additive flags are `serde(default)`, so journals are backward/forward
read-compatible; round-tripping through *older* code silently strips unknown
flags (hence the single-tag fleet policy, §15.3). Load fails closed on
corrupt content or unsupported versions.

Two invariants worth internalizing:

- **Journal-before-mutate** is absolute: the plan is on disk (fsynced) before
  any kernel object exists, so a crash at any point leaves a truthful record
  of intent to reconcile against.
- **The journal describes, it does not authorize**: an object matching the
  journal is still identity-verified against the *plan* before it is reused.

## 8. Migration and compatibility (v0.1.0 / v0.1.1 hosts)

Legacy hosts carry the v0.1.x NAT underlay: a host↔fabric veth pair
(169.254.253.1/30 ↔ .2) and two `iptables -t nat` rules (DNAT
`--dport 65001 → .2`, MASQ for the /30). v0.1.2+ converges them
**tolerantly**:

- Every apply and every fabric teardown first runs a read-only
  `iptables -t nat -S` **residue verification**. It tolerates exactly one
  instance of each exact v0.1.1 rule spec — the same specs the tolerant
  deletes later in the same operation remove — so a converged legacy host
  migrates cleanly. A variant, a duplicate instance, or any other rule
  referencing the legacy signature (the whole 169.254.253/24 prefix, any rule
  naming the legacy `<prefix>-u` veth, or any `-j DNAT` with `--dport
  <wg_port>`) fails **closed before any destructive action**, with the kernel
  fully intact and an error that names the residue and its remediation.
- The migration is **per-product, not fleet-wide**: the tolerance covers each
  product's *own* historical specs (prefix/port-keyed); anything else fails
  loudly. A design that promised universal legacy cleanup would be wrong.
- Known assumption, stated honestly (contract §3.10): the tolerant compares
  and deletes are byte-for-byte against the provider's exact rule-spec
  strings; a real kernel that renders `-S` differently would fail closed
  (loud, hand-remediable) rather than mis-delete. The multi-node evidence
  environment never exercises this path (fresh hosts carry no legacy rules).
- One migration residual, for completeness: journals are re-validated on
  read (§11), and the only theoretical way a converged old journal could
  fail current validation is an endpoint value old code realized without
  the real `wg` tool rejecting it (e.g. port 0 — the S1 analysis holds this
  impossible, but nothing in this repo pins real-wireguard-tools behavior).
  Such a journal fails closed on read with the §11 remediation (re-apply
  the corrected plan, or delete the file) — contained, never a wedge.

## 9. Identity and key hygiene

One keypair **per host** (a host runs at most one fabric; the key file is not
domain-keyed — see §4.2's one-fabric-per-port limitation). `ensure_private_key`
generates with `wg genkey` if absent (0600, atomic create), adopts an
existing non-empty key as-is (control-plane public-key records stay valid),
and **never** overwrites. The private key travels only by file path
(`wg set … private-key <path>`) or stdin (`wg pubkey`); it never appears in
argv, serialized plans, journals, error text, or logs, and it survives fabric
teardown by design.

## 10. Security model

- **Confidentiality/integrity of tenant traffic in transit:** all inter-host
  tenant frames ride the WireGuard mesh (authenticated, encrypted). The
  evidence gate proves no tenant-addressed cleartext appears on the underlay.
- **Not encrypted:** intra-hypervisor traffic (bridge-local, same host) —
  same trust domain as any hypervisor bridge.
- **Fail-closed posture:** foreign or corrupt state is rejected, never
  adopted, silently repaired, or deleted. Ambiguity (e.g. both-ns socket
  listeners) is an error, not a guess.
- **No site-local bridging:** transport `/32`s only; the mesh never routes
  tenant prefixes.
- **Provider exclusivity:** control planes never manipulate fabric kernel
  objects; the provider never touches consumer-side state beyond the
  consumer veth end.

## 11. Failure modes and operator remediation

| Error | Meaning | Operator action |
|---|---|---|
| `ForeignState` (object identity) | An object with an owned name exists but does not match the plan (e.g. VXLAN with a different VNI, changed transport IP on an existing network) | Inspect with `ip -d`; delete by hand only if truly foreign, then re-apply |
| `ForeignState` (residue) | Legacy/v0.1.x NAT residue in the root nat table (variant, duplicate, or signature hit) | The error names the rule; `iptables -t nat -D` it by hand, then re-apply — the kernel is intact |
| `ForeignState` (ambiguity) | WG-port listeners in *both* the fabric ns and root ns | Identify the fabric-ns listener's owner; remove it; re-apply (nothing was modified) |
| `ForeignState` (fresh-host stray) | Owned-name collision on a host with an empty journal | The object predates this installation; adopt-by-name is forbidden — investigate and remove |
| `Invalid` (plan) | Plan validation failed (including endpoint values) | Fix the control plane's plan compilation; nothing was touched |
| Corrupt/invalid plan file | A truncated `<state-root>/plans/<id>.json`, or one that still parses but fails validation (hand-edit, bit-rot), fails **every apply and `remove_network` of any other network** closed (the whole state root must be readable *and valid* to reconcile peer sets). Removing the **offending** network itself still succeeds — it deletes its plan file before the reconciliation read, which is a natural recovery path. | Inspect the named file; if it is unrecoverable, hand-delete that one plan file — or re-apply that network with a corrected plan, which overwrites it — the provider re-converges. Do not delete healthy plans. |
| `Command` (ss leg) | A socket-placement observation itself failed | Treat as unverified, not quiet; fix the tooling/environment and re-apply |
| `Command` (general) | A kernel command failed | The error carries the command and stderr; journal-before-mutate bounds the half-applied window to idempotent re-apply |

The corrupt-journal row is fail-closed by design (blast radius: the whole
host's fabric operations), and the remediation is deliberately manual —
auto-deleting an unreadable plan file would be exactly the silent-repair
posture the fabric forbids.

## 12. Limitations (stated, not hidden)

1. **One fabric per WG port per host** (root-ns socket occupies the port);
   one keypair per host.
2. **Container evidence scope:** the multi-host gate (three privileged
   containers on one kernel) proves datapath, protocol behavior, crypto, MTU
   layering, and teardown discipline — not NIC heterogeneity, geographic
   distance, or real-internet path MTU. Cross-machine runs over real networks
   remain the production gate (`evidence/README.md` → Limitations).
3. **No netlink backend:** Phase 1 shells out through `FabricCommand`; the
   seam is the compatibility promise for a future netlink backend with
   identical observable behavior.
4. **IPv4 transport addresses and IPv4 outer WG** in v1.
5. **Host-image requirements (implicit, must be provisioned):** the host
   image needs `ip` (iproute2), `wg` (wireguard-tools), `bridge`
   (iproute2), `ss` (iproute2 — the discriminator's hard dependency), and
   `iptables`; kernel modules `wireguard` and `vxlan`; and root-ns routing
   to every peer underlay endpoint.

## 13. Testing and evidence layers

| Layer | What it is | What it proves |
|---|---|---|
| Unit (`fabric-linux`, recorded fake kernel) | 79 tests against `RecordingRunner`, which models real kernel semantics (per-ns name tables, socket-creation placement, per-ns `ss`, one-instance `fdb del`, real error wording) | Every lifecycle path, heal slice, residue vector, and crash window at the behavior level |
| `fabric-plan` | 20 tests | Input validation (including deserialized endpoint values) and fingerprinting |
| `fabric-conformance` | 23-case suite (runs as one cargo test), executable via `run_suite()` | Provider behavior **modulo configuration** — consumers run it in CI at their pinned tag to re-verify that tag's behavior; it cannot exercise consumer integration or config choices |
| Multi-host evidence (`evidence/run-multinode.sh`) | Three privileged containers, **35 assertions** per green run, real ARP/ICMP/MACs/handshakes/captures | The fabric itself: the stretched L2 actually works, encrypted, and tears down without leaks |

New behavioral tests must genuinely fail against pre-fix code (hybrid
worktree verification, documented in the commits); coverage pins are declared
as such.

**Evidence-gate-to-release binding:** the gate is run by the fabric
maintainer on a quiesced orchestrator host before tagging any release whose
diff touches the datapath, underlay, or teardown; results live under
`evidence/results/<timestamp>/` (git-ignored — the release record is the
release PR's stated outcome: a green 10-run acceptance loop, or a failure
root-caused as external interference per the recipe in `evidence/README.md`).
CI runs fmt/clippy/tests/deny only — it cannot run the privileged gate, and
that is not evidence of absence of a run.

## 14. Evidence claims and scope (honest statement)

A green multi-host run means: on three privileged host instances sharing one
physical kernel (6.8 at the time of writing), the compiled plans produced a
single L2 broadcast domain — ARP and ICMP flow between tenant namespaces
with real MACs, the only traffic on the underlay is WireGuard UDP, near-MTU
packets survive the documented MTU layering, the WG socket is root-side, and
teardown leaves zero fabric residue while preserving the host keypair. It
does **not** mean: geographic distance, NIC/driver heterogeneity, kernel
version diversity, or real-internet path-MTU behavior. Cross-machine runs
over real networks remain the final production gate. Concurrent host-network
mutations on the orchestrator invalidate a run (attribution recipe in
`evidence/README.md`).

## 15. Cross-implementation configuration (pinned values)

The provider's knobs are fabric-wide concepts; their **values are pinned per
product** and recorded here so neither drifts (enforced socially by review;
conformance cannot see configuration):

1. **Name prefixes** (must be 1–4 ASCII chars, mutually distinct):
   O3K = `o3k`, CHV = `chv`, evidence harness = `ev`. A prefix (or port)
   change between create and teardown leaves the old-prefix wg and legacy
   veth behind and trips the residue fail-closed until an operator cleans
   it — prefixes are for the life of the installation.
2. **WG listen port:** both products default to 65001. One fabric per port
   per host; the products run on disjoint hosts today, and any future
   co-location must assign distinct ports and prefixes explicitly.
3. **Fleet versioning:** control planes pin **one provider tag
   fleet-wide** (mixed-tag clusters have no test coverage, and journal
   round-trips through older code strip newer flags). Mixed v0.1.1/v0.1.2
   is the one documented migration exception (§8).

The full change process, consumer obligations, and dispute rules are
normative in [`docs/change-control.md`](change-control.md).

## 16. Consumer integration (summary)

Both consumers: pin the provider by git tag; run `fabric-conformance`'s
`run_suite()` in CI at that tag; construct `FabricLinuxConfig` (state root,
name prefix, WG port); compile plans from canonical state using
`fabric-plan`'s types and MTU constants; call `apply_plan` /
`remove_network` / `remove_fabric_if_unused`; treat `ApplyReport`'s
`created_fabric`/`created_network` as facts, not permissions; surface
`ForeignState` errors to operators rather than retry-looping them away.
