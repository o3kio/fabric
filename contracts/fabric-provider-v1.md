# Fabric Provider Contract — v1

Status: Accepted

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
   a SHA-256 content fingerprint. Plan deserialization is strict:
   unknown fields are rejected (`deny_unknown_fields` on the plan, peer,
   and endpoint types), so a control plane compiling against a newer plan
   schema fails loudly instead of silently dropping fields. The peer list
   must not contain duplicate public keys — peers are keyed by public key
   during realization, and a duplicate would silently drop a peer from the
   WireGuard set.
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
journal (`ownership.json`) is updated after mutations succeed. Both
journals are written crash-durably: the content is fsynced before the
atomic rename, and the parent directory is fsynced after it, so a power
loss cannot leave an empty or half-written journal in place of a valid
one.

### 3.2 Idempotency and re-assertion
Re-applying an unchanged plan performs observations and diff-free
reconciliation only. It must not recreate existing objects. Peer
reconfiguration with identical parameters is permitted (WireGuard `set` is
idempotent).

Reconciliation is **re-assertive, not create-only**: enslavement
(`ip link set <vxlan|port veth> master <bridge>`), link state
(`ip link set ... up`), the per-network MTUs (VXLAN, consumer veth,
fabric-side port veth — all `tenant_mtu`), the underlay attachment
(addressing via `ip addr replace`, link state, default route via
`ip route replace`), and the local transport /32 on the WireGuard
interface are re-asserted on **every** apply. All of these verbs are
idempotent; a crash between object creation and any of these steps — or a
mutated plan field such as `tenant_mtu` — heals on the next apply instead
of leaving a half-plumbed network that reports as healthy. Only the
WireGuard private key and listen port remain guarded by their
create/configure flags (re-asserting them would be harmless but is
unnecessary).

### 3.3 Fail-closed on foreign state
If a kernel object exists where the provider expects to create one — or an
observed object carries different identity than the plan — the provider
MUST reject the plan with a foreign state error. It MUST NOT adopt,
overwrite, or delete the object. VXLAN identity is verified at the token
level: the tokens following `id`, `dstport`, and `local` in
`ip -d link show` output must equal the plan's VNI, the configured VXLAN
port, and the plan's local transport IP exactly. Substring matching is
forbidden — `id 100` must not accept a foreign `id 1000`, and a foreign
destination port or local address is equally rejected. Identity
verification covers the `id`, `dstport`, and `local` tokens only; it
does **not** verify the VXLAN's `dev <wg>` underlay binding (the
binding is not visible in the parsed tokens). A VXLAN whose lower
device was replaced therefore cannot be repaired in place — it must be
deleted and re-created, which the legacy heal (§3.10) does by
journal-recorded name.

### 3.4 Ownership fencing
The provider only deletes objects it recorded in its ownership journal.
Names are deterministic hints (FNV-1a hash suffixes), never proof of
ownership. Journal files that are corrupt or of an unsupported version fail
closed.

### 3.5 Key hygiene
- One keypair per host; generated with `wg genkey` if absent; adopted
  as-is if present (never overwritten).
- Stored 0600 via atomic create under the state root. The temp file is
  created with `O_CREAT|O_EXCL` and mode 0600 in one step, so it never
  exists world-readable and cannot be pre-created or pre-planted (e.g. as
  a symlink); a stale temp from an earlier crash is removed and the
  create retried once.
- Referenced by **file path** in commands (`wg set <if> private-key <path>`)
  or piped via **stdin** (`wg pubkey`). Never in argv, never in serialized
  plans/ownership/errors.
- Survives network and fabric teardown.

### 3.6 Bounded flood list
HER entries (`bridge fdb append 00:00:00:00:00:00 dev <vxlan> dst <ip>`)
exist only for the plan's peer set, and the provider reconciles the flood
list against **observed** state on every apply: it ensures every desired
entry exists, then reads `bridge fdb show dev <vxlan>` and deletes every
all-zeros remote entry whose destination is not in the desired set.
Reconciliation is append-missing / delete-unwanted — `replace` is never
used (the kernel rejects it for non-unicast entries, and it would clobber
the other remotes).

Reconciling against observation, rather than blindly re-appending, is
required because `bridge fdb append` is **not** guaranteed idempotent per
(dev, mac, dst): bridge(8) documents `append` as adding a new entry
"without deleting any existing one", and real kernels have accumulated
duplicate all-zeros flood entries this way (Ubuntu Launchpad #1531013).
Duplicates both violate the bounded-peer-set invariant and double-flood
BUM traffic to the same remote. Reconciliation keeps the healing property
that motivated re-assertion in the first place: a recreated (post-reboot)
VXLAN with an empty fdb has every desired entry appended as missing,
while a healthy replay appends nothing and deletes nothing.
Reconciliation is **instance-count aware**: `bridge fdb show` prints one
line per entry instance, and each `bridge fdb del` removes exactly one
instance (one RTM_DELNEIGH), so a destination observed N times is issued
N−1 tolerant deletes when it is still desired and N when it is not.
Pre-existing duplicates of a still-desired destination — the exact fleet
state this guards against — therefore converge in a single apply, and
repeated applies converge to exactly one entry per desired destination
and zero per undesired one. Deleting an entry that is already absent is
tolerated as done.

### 3.7 Learning stays on
VXLAN devices are created **without** `nolearning`: the kernel performs MAC
learning; unknown unicast, ARP, and DHCP are flooded to the bounded peer
list. This is what makes the network one literal VLAN across hosts.

### 3.8 Teardown ordering and convergence
Network teardown removes, in order: HER flood entries, attachment veth
pair, VXLAN device, fabric-side bridge; then reconciles the WireGuard peer
set against remaining live plans. Fabric teardown (netns, WireGuard,
underlay veths, NAT rules) is permitted only when zero networks are owned.

Teardown is idempotent and converges to the desired end state: deleting an
object that is already absent is success (a deletion whose stderr
indicates the object does not exist — missing device, missing namespace,
missing rule or entry, or a missing route (`RTNETLINK answers: No such
process`) — counts as done; any other failure is a hard error). When the fabric namespace itself is absent, all ns-scoped
deletions are skipped: a kernel that was rebooted while the journals
survived must still tear down cleanly. The plan journal file and the
ownership entry are removed **unconditionally** — regardless of which
object deletions were tolerated — so an interrupted teardown always
converges on retry instead of wedging the ownership entry forever. A kept
WireGuard peer that moves to a new fabric transport IP has its stale /32
route withdrawn before the new one is installed.

### 3.9 No site-local bridging
The provider never bridges fabric traffic into site-local switches; the
only tenant-side exposure is the consumer attachment veth, which the host
enslaves to its own tenant bridge under its own anti-spoof policy.

### 3.10 WireGuard socket placement
The WireGuard interface is created from **inside** the fabric namespace
(`ip netns exec <fabric-ns> ip link add <wg> type wireguard`). A
WireGuard interface's UDP socket binds in the namespace where the
interface is **created** and never follows a later
`ip link set netns` — verified empirically on kernel 6.8, including that
a down/up toggle inside the destination namespace does not re-bind it.
An interface created in the root namespace and then moved into the
fabric namespace therefore leaves its listening socket in the root
namespace, where the fabric's underlay DNAT rules do not apply: inbound
encrypted flows are DNAT'ed toward the fabric namespace, where no socket
listens, and are black-holed.

Legacy state — journals written by provider versions predating this
invariant, detectable via the absent `wireguard_born_in_fabric_ns`
journal flag, which old journals deserialize as `false` — is healed by a
one-time, idempotent procedure: a stray root-namespace interface of the
same name is swept tolerantly, but **only when the journal shows the
provider owns (or owned) fabric state** — journal-before-mutate means a
genuine legacy add-then-crash-before-move stray implies a journal, with
one exception: the released v0.1.0/v0.1.1 code saved the ownership
journal only at the end of apply, so a crash on the very first apply in
the add→move window leaves a stray with an empty journal; that state
wedges fail-closed and requires manual cleanup (it is no worse than the
released baseline, which also wedged). On a fresh host (no journal) a
colliding root-namespace link is foreign state
and is never deleted, and the both-namespaces check below fails closed
on it instead. Every VXLAN recorded in the ownership journal is deleted
**first** (their `dev <wg>` underlay binding dies with the old
interface, and identity verification cannot see that — §3.3; each
network fully heals on its own next apply), then the namespace-scoped
interface is deleted, and the interface is recreated from inside the
fabric namespace with the private key and listen port forced. The
journal flag is set only after the key/port configuration succeeds.
This deletion order makes every interruption slice of the heal
convergent: interrupted before the interface deletion, the next apply
re-enters the heal and finishes; interrupted after it, the next apply
takes the WireGuard-absent path, which recreates the interface inside
the namespace and — when the journal is legacy (flag unset) and still
records networks — also tolerantly deletes the recorded VXLANs, the
same way. That wg-absent branch covers a legacy fabric whose WireGuard
was lost entirely, including the crash window of heal implementations
that deleted the interface before the VXLANs. If an interface of the
WireGuard name exists in **both** the root and the fabric namespace,
the provider fails closed (foreign state) rather than guessing which
one is its own.

## 4. Conformance

Every provider integration MUST pass `fabric-conformance::run_suite()`
(reference fake-kernel runner) in CI, covering: plan validation, idempotent
replay, WireGuard creation inside the fabric namespace, flood-list
reconciliation without duplicates after repeated replays, flood-list
scoping, foreign-state rejection (including prefix-VNI rejection),
teardown cleanliness, key non-leakage, peer withdrawal, and
fabric-removal fencing — plus the hardening cases: teardown convergence
after a simulated kernel restart, re-apply healing of partial state,
flood-list shrinking, duplicate flood-entry convergence, and
MTU/addressing re-assertion. The fake kernel
models the real `ip`/`bridge`/`wg` failure and placement semantics
(missing devices, duplicate names, missing namespaces, missing
fdb/route entries with real kernel error strings, per-namespace link
placement, counting fdb entries), so a permissive provider flow fails
the suite rather than silently passing.

The privileged multi-host gate (three real hosts on one kernel, real
WireGuard handshakes, cross-host L2 and near-MTU tenant traffic,
cleartext underlay capture proving encryption, per-host assertion that
the WireGuard UDP socket listens inside the fabric namespace and not in
the root namespace, idempotent replay, and zero-leak teardown) is the
separate harness `evidence/run-multinode.sh`; it is required before any
production evidence claim.

## 5. Versioning

This is contract v1. Breaking changes to plan types, journal formats, or
invariants require a new contract version and a migration note in both
O3K and CHV decision records.
