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

Shared (one per host): fabric network namespace, WireGuard interface
(created in the root namespace and moved into the fabric namespace, so
its UDP transport socket binds root-side — §3.10).
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
   the root namespace must have working routes to every peer's underlay
   endpoint (the host's normal routing, however the host acquires it).
   Nothing else: the v0.1.2 NAT-free underlay (§3.10) terminates the
   WireGuard transport socket in the root namespace and hands encrypted
   packets to the host's normal routing with dynamic source selection,
   so the root namespace does not forward fabric packets and no
   `ip_forward` or `rp_filter` tuning is required.
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
fabric-side port veth — all `tenant_mtu`), and the local transport /32
on the WireGuard interface are re-asserted on **every** apply. All of
these verbs are idempotent; a crash between object creation and any of
these steps — or a mutated plan field such as `tenant_mtu` — heals on
the next apply instead of leaving a half-plumbed network that reports
as healthy. Only the WireGuard private key and listen port remain
guarded by their create/configure flags (re-asserting them would be
harmless but is unnecessary).

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
set against remaining live plans. Fabric teardown (netns, WireGuard, and
the legacy underlay machinery of §3.10) is permitted only when zero
networks are owned.

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

### 3.10 WireGuard transport: root-created, moved in, NAT-free

The WireGuard interface is created in the **root** namespace and then
moved into the fabric namespace:

```
ip link add <wg> type wireguard        # root namespace
ip link set <wg> netns <fabric-ns>     # move
ip netns exec <fabric-ns> ip addr replace <transport-ip>/32 dev <wg>
ip netns exec <fabric-ns> ip link set <wg> up
ip netns exec <fabric-ns> wg set <wg> private-key <path> listen-port <port>
```

A WireGuard interface's UDP socket binds in the namespace where the
interface is **created** and never follows a later
`ip link set netns` — verified empirically on kernel 6.8, including
that a down/up toggle inside the destination namespace does not re-bind
it. Creating the interface root-side is therefore what places the
transport socket in the root namespace, and that placement is the
design:

- **Outbound**: encrypted packets leave through the host's normal
  routing with dynamic source selection; the peer always observes
  `<host-underlay-ip>:<port>`, stable across interface moves and
  address changes.
- **Inbound**: `<peer>:<port> → <host-ip>:<port>` is delivered directly
  to the root-namespace listener.

The provider MUST NOT install any iptables NAT rule for the transport.
Two races make any NAT state on the transport fatal (the v0.1.2
postmortem):

1. **DNAT black-hole**: a PREROUTING DNAT rule rewrites every NEW
   inbound flow toward the address the rule was written for; when the
   listening socket lives elsewhere (as it does under the pre-v0.1.2
   underlay), the flow is delivered where nothing listens and is
   silently dropped — handshake initiation from the peer side never
   completes.
2. **MASQUERADE port remap**: under simultaneous bidirectional
   initiation, the conntrack tuple for the host's own outbound flow
   collides with the inbound flow's expectation and forces MASQUERADE
   to remap the source port (observed: 65001 → 37414). WireGuard
   endpoint roaming then latches the peer onto the remapped port, and
   nothing steers return traffic back to it — the pair never recovers
   without manual intervention.

The only escape from both races is for the transport to carry no NAT
state at all; the root-side socket gives the outbound direction the
host's normal source selection and the inbound direction a directly
addressed listener, so no rule is needed. Consequence: exactly one
fabric per WireGuard listen port per host (two fabrics sharing a port
would bind their sockets to the same `<host-ip>:<port>` and interleave
each other's handshakes — deterministically rejected at creation time
by the port collision instead).

**Legacy migration.** The v0.1.0/v0.1.1 underlay (underlay veth pair,
169.254.253.0/30, DNAT + MASQUERADE rules) is deleted **tolerantly on
every apply** — rules first, with EXACTLY the rule specifications the
old code installed (`iptables -t nat -D` only matches spec-for-spec),
then the veth pair via its root end. Absence is this design's normal
case, so the deletions are unconditional and idempotent. Journals
written by v0.1.0/v0.1.1 (the `wireguard_born_in_fabric_ns` field
absent, deserialized as `false`) already describe a root-created and
moved WireGuard — exactly the placement mandated here — so no heal
runs for them; only the legacy cleanup does. A journal with
`wireguard_born_in_fabric_ns == true` (written only by the unpushed
round-3..5 development code, whose WireGuard was created **inside**
the fabric namespace and whose socket is therefore bound there) is
healed by a one-time, idempotent, full procedure:

1. A stray root-namespace interface of the same name is swept
   tolerantly — but **only when the journal shows the provider owns
   (or owned) fabric state** (journal-before-mutate means a genuine
   crash stray implies such a journal; the same gate covers this
   design's own add→move crash window). On a fresh host (no journal) a
   colliding root-namespace link is foreign state and is never
   deleted; the root-side `ip link add` fails closed on the name
   instead. One exception wedges fail-closed by design: the released
   v0.1.0/v0.1.1 code saved the ownership journal only at the end of
   apply, so a crash on the very first apply in the add→move window
   leaves a stray with an empty journal — manual cleanup is the remedy
   (no worse than the released baseline, which also wedged).
2. Every VXLAN recorded in the ownership journal is deleted **before**
   the namespace-scoped interface (their `dev <wg>` underlay binding
   dies with the old interface, and identity verification cannot see
   that — §3.3; each network fully heals on its own next apply). This
   order makes every interruption slice convergent: interrupted before
   the interface deletion, the next apply re-enters the heal and
   finishes; interrupted after it, the next apply takes the
   WireGuard-absent path, which recreates the interface root-side and —
   while the flag is still set and the journal still records networks —
   also tolerantly deletes the recorded VXLANs, the same way.
3. The namespace-scoped interface is deleted, the legacy underlay
   machinery is cleaned up, and the interface is re-created in the
   ROOT namespace, moved in, and configured with the private key and
   listen port forced.
4. The journal flag is cleared only after the key/port configuration
   succeeds, so a crash anywhere in the heal simply re-runs it.

If an interface of the WireGuard name exists in **both** the root and
the fabric namespace while the journal claims a healthy fabric, the
provider fails closed (foreign state) rather than guessing which one
is its own.

## 4. Conformance

Every provider integration MUST pass `fabric-conformance::run_suite()`
(reference fake-kernel runner) in CI, covering: plan validation, idempotent
replay, WireGuard creation in the root namespace with the move into the
fabric namespace, absence of any NAT rule for the transport, legacy
underlay cleanup (exact-spec rule deletions plus the veth pair) on every
apply, the born-in-fabric-namespace journal healing to the root-creation
sequence, flood-list reconciliation without duplicates after repeated
replays, flood-list scoping, foreign-state rejection (including
prefix-VNI rejection), teardown cleanliness, key non-leakage, peer
withdrawal, and fabric-removal fencing — plus the hardening cases:
teardown convergence after a simulated kernel restart, re-apply healing
of partial state, flood-list shrinking, duplicate flood-entry
convergence, and MTU/addressing re-assertion. The fake kernel
models the real `ip`/`bridge`/`wg`/`iptables` failure and placement
semantics (missing devices, duplicate names, missing namespaces, missing
fdb/route entries with real kernel error strings, per-namespace link
placement and name tables, per-namespace link-creation records — the
WireGuard socket placement — the `Bad rule` wording of a non-matching
`iptables -D`, and counting fdb entries), so a permissive provider flow
fails the suite rather than silently passing.

The privileged multi-host gate (three real hosts on one kernel, real
WireGuard handshakes, cross-host L2 and near-MTU tenant traffic,
cleartext underlay capture proving encryption, per-host assertion that
the WireGuard UDP socket listens in the ROOT namespace (`ss -uln` in
the root namespace shows the listen port; inside the fabric namespace
it does not, while `wg show` there still reports the port — the device
lives in the namespace, the socket does not), idempotent replay, and
zero-leak teardown) is the separate harness `evidence/run-multinode.sh`;
it is required before any production evidence claim.

## 5. Versioning

This is contract v1. Breaking changes to plan types, journal formats, or
invariants require a new contract version and a migration note in both
O3K and CHV decision records.
