# Fabric Provider Contract — v1

Status: Accepted (Phase 1 skeleton)

Authors: Kubeko

Normative sources:

- O3K [ADR-0186 — Stretched-L2 Edge Fabric (VXLAN/HER over WireGuard)](https://github.com/o3kio/o3k/blob/main/docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
- O3K [SPEC-0049 — Stretched-L2 Edge Fabric v3](https://github.com/o3kio/o3k/blob/main/docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
- CHV [ADR-021 — Stretched-L2 VXLAN/HER + WireGuard fabric](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)

This contract defines what any implementation of the shared stretched-L2
fabric provider MUST and MUST NOT do. `fabric-plan` is the type-level
expression of the input; `fabric-linux` is the reference Linux
implementation; `fabric-conformance` is the executable expression of this
document.

## 1. Scope

One provider instance realizes, on one Linux host, the networks described by
[`StretchedL2Plan`]s compiled by a host control plane. The provider is the
**only** component permitted to manipulate the fabric's kernel objects.
Control planes never touch `ip`/`wg`/`bridge` for fabric state directly.

Shared (one per host): fabric network namespace, WireGuard interface,
underlay veth attachment, NAT rules.
Per-network: VXLAN device, fabric-side learning bridge, attachment veth pair,
head-end replication (HER) flood entries.

Not in scope (host-owned): tenant bridges, TAP anti-spoof policy, VM
attachment, VNI binding allocation, placement, FIPs, lifecycle.

## 2. Input contract

1. The sole input is a validated `StretchedL2Plan` (see `fabric-plan`).
   Plans are serde-serializable, versioned by generation numbers, and carry
   a SHA-256 content fingerprint.
2. The peer list is the **bounded HER flood list**: exactly the enrolled
   hosts that currently host at least one endpoint of the network, derived
   from accepted control-plane placement state — never from ARP/FDB
   observation or traffic.
3. MTU layering is mandatory and validated: `tenant_mtu + 50 ≤ fabric_mtu`
   (VXLAN overhead), and the control plane is responsible for
   `fabric_mtu ≤ underlay_mtu − WireGuard overhead` at enrollment time.
   The provider sets the shared WireGuard interface's MTU, on **every
   apply**, to the **maximum `fabric_mtu` across all live plans** (the plan
   being applied included, because the plan journal is persisted before any
   mutation). `ip link add <if> type wireguard` alone leaves the
   kernel-default MTU (1420) in place, which validated plans may exceed;
   without this re-assert, large tenant packets fail with EMSGSIZE or
   fragment on the underlay. Re-setting an identical MTU is a benign
   re-assert (like `ip addr replace`). Teardown never shrinks the WireGuard
   MTU — a conservatively larger value is always safe — and the next apply
   re-converges to the true maximum.

   **Host prerequisites (operator responsibility, not provider-managed):**
   the *root* network namespace must have `net.ipv4.ip_forward=1` — the
   provider enables forwarding only inside the fabric namespace, while
   forwarding between the host underlay veth and the physical underlay
   happens in the root namespace — and the underlay device must tolerate
   the fabric's asymmetric return path (`net.ipv4.conf.<underlay_dev>.rp_filter`
   set to loose or off), since fabric replies leave through a different
   veth than the underlay traffic arrives on.
4. Private keys are not representable in a plan. Only public keys travel in
   control-plane state.

## 3. Behavioral invariants

### 3.1 Journal before mutate
The plan is persisted under the provider state root
(`plans/<network_id>.json`) before any kernel mutation. The ownership
journal (`ownership.json`) is updated after mutations succeed.

### 3.2 Idempotency
Re-applying an unchanged plan performs observations and diff-free
reconciliation only. It must not recreate existing objects. Peer
reconfiguration with identical parameters is permitted (WireGuard `set` is
idempotent).

### 3.3 Fail-closed on foreign state
If a kernel object exists where the provider expects to create one — or an
observed object (e.g. a VXLAN device) carries different identity (VNI,
port) than the plan — the provider MUST reject the plan with a foreign
state error. It MUST NOT adopt, overwrite, or delete the object.

### 3.4 Ownership fencing
The provider only deletes objects it recorded in its ownership journal.
Names are deterministic hints (FNV-1a hash suffixes), never proof of
ownership. Journal files that are corrupt or of an unsupported version fail
closed.

### 3.5 Key hygiene
- One keypair per host; generated with `wg genkey` if absent; adopted
  as-is if present (never overwritten).
- Stored 0600 via atomic create under the state root.
- Referenced by **file path** in commands (`wg set <if> private-key <path>`)
  or piped via **stdin** (`wg pubkey`). Never in argv, never in serialized
  plans/ownership/errors.
- Survives network and fabric teardown.

### 3.6 Bounded flood list
HER entries (`bridge fdb replace 00:00:00:00:00:00 dev <vxlan> dst <ip>`)
exist only for the plan's peer set, diffed against ownership on every
apply. Stale entries are removed when the peer set shrinks.

### 3.7 Learning stays on
VXLAN devices are created **without** `nolearning`: the kernel performs MAC
learning; unknown unicast, ARP, and DHCP are flooded to the bounded peer
list. This is what makes the network one literal VLAN across hosts.

### 3.8 Teardown ordering
Network teardown removes, in order: HER flood entries, attachment veth
pair, VXLAN device, fabric-side bridge; then reconciles the WireGuard peer
set against remaining live plans. Fabric teardown (netns, WireGuard,
underlay veths, NAT rules) is permitted only when zero networks are owned.

### 3.9 No site-local bridging
The provider never bridges fabric traffic into site-local switches; the
only tenant-side exposure is the consumer attachment veth, which the host
enslaves to its own tenant bridge under its own anti-spoof policy.

## 4. Conformance

Every provider integration MUST pass `fabric-conformance::run_suite()`
(reference fake-kernel runner) in CI, covering: plan validation, idempotent
replay, flood-list scoping, foreign-state rejection, teardown cleanliness,
key non-leakage, peer withdrawal, and fabric-removal fencing.

The privileged multi-host gate (three real hosts, real handshakes,
cleartext underlay capture proving encryption, zero-leak teardown) is a
separate harness planned in this repository; it is required before any
production evidence claim.

## 5. Versioning

This is contract v1. Breaking changes to plan types, journal formats, or
invariants require a new contract version and a migration note in both
O3K and CHV decision records.
