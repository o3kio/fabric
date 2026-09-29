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
   a SHA-256 content fingerprint (recorded in the ownership journal as
   ground truth; never compared for change detection — idempotency is
   re-assertive, §3.2). Plan deserialization is strict, where "strict"
   means exactly: unknown fields are rejected (`deny_unknown_fields` on
   the plan, peer, and endpoint types), so a control plane compiling
   against a newer plan schema fails loudly instead of silently dropping
   fields; and **values are validated by `validate()`**, which must run
   before realization — including endpoint values (non-empty host, no
   whitespace/control characters, nonzero port) and public-key shape
   (44 base64 characters: 43 alphabet characters plus one trailing `'='`
   pad) on both the parsed and the deserialized path. The peer list
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
networks are owned, and is preceded by the same read-only nat-residue
verification as apply (§3.10): a legacy-rule variant the tolerant deletes
cannot hit fails the teardown closed with the WireGuard, the fabric
namespace, and the ownership journal intact, while a host holding exactly
its own two exact v0.1.1 rules still tears down (the same
one-instance-per-exact-spec tolerance).

Teardown is idempotent and converges to the desired end state: deleting an
object that is already absent is success (a deletion whose stderr
indicates the object does not exist — missing device, missing namespace,
missing rule or entry, or a missing route (`RTNETLINK answers: No such
process`) — counts as done; any other failure is a hard error). When the fabric namespace itself is absent, all ns-scoped
deletions are skipped: a kernel that was rebooted while the journals
survived must still tear down cleanly. The same holds when the namespace
survives but the WireGuard link does not (module unload, operator
deletion, a partial teardown): the peer-set reconciliation observes the
link and skips its WireGuard/route commands rather than failing — there
is nothing to program, and failing would wedge the removal after the
journals were already dropped. The plan journal file and the
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
case, so the rule deletions are unconditional and idempotent. Because
the exact-spec deletes can silently miss operator-installed
**variants** of the legacy rules (a DNAT with `-i eth0` instead of
`! -i <prefix>-u`, a different address inside 169.254.253.0/30, ...),
the nat table is LISTED (`iptables -t nat -S`, read-only) at the
**start of every apply — before any destructive action on any path**
(before the heal's WireGuard and recorded-VXLAN deletions, before the
root stray sweep, before the tolerant deletes themselves), and the
apply **fails closed** on any residue rule matching the legacy
underlay signature, so a hit leaves every kernel object in place.
**Fabric teardown enforces the same pre-destruction verification**
(round-8): `remove_fabric_if_unused` runs the identical read-only
listing — after its eligibility guards, before the WireGuard deletion,
the namespace deletion, and its own tolerant legacy deletes — so a
residue variant fails the teardown closed with the WireGuard link, the
fabric namespace, and the ownership journal fully intact (fail closed
with state preserved, the same guarantee the apply path gives). A
crash between the teardown's verification and its tolerant deletes is
covered by the same convergence argument as every other slice: the
ownership journal is only rewritten after the deletions succeed, and
the next operation — apply or teardown — re-verifies with the same
tolerance and re-runs the same idempotent deletes. The
signature is deliberately **broad**, and each arm carries its
rationale:

- any nat-table rule referencing the **169.254.253/24 prefix** — the
  whole /24, not just the legacy /30 or its exact `.2`/`.0/30` forms:
  a missed variant of residue NAT on the WireGuard transport is silent
  death (the postmortem failure mode), while a false positive is loud
  and operator-remediable;
- any rule naming the legacy host-veth (`<prefix>-u`) as a token;
- any **DNAT matching the WireGuard listen port** (`--dport <port>` in
  a `-j DNAT` rule), with no address tie: any DNAT on the transport
  port is black-hole state for inbound flows, wherever it points.

The only tolerance is exactly ONE instance of each exact v0.1.1 rule
specification — the tolerant deletes are guaranteed to remove those,
so they are this provider's own convergent legacy state, not foreign
variants; a second instance of either, or any variant, fails closed.
The tolerance applies identically on the teardown path: the tolerant
deletes later in the same teardown remove exactly those specs, so a
legacy host holding its own exact v0.1.0/v0.1.1 rules still tears down
— the documented migration convergence holds in both directions.

**Byte-identity assumption of the `-S` tolerance (validation gap,
documented honestly).** The one-instance tolerance — and the round-6
tolerant deletes themselves — compare `iptables -t nat -S` output
lines byte-for-byte against the provider's exact v0.1.0/v0.1.1
rule-spec strings. The conformance fake kernel canonically re-joins
the provider's own tokens, so it cannot detect a divergence between
the ADD-time specification and a real kernel's `-S` rendering of the
same rule (negation token order, option rewrites or re-ordering by
iptables-versions). The assumption is believed safe because the two
specs are simple (a three-operand MASQUERADE and a single-negation
DNAT), were verified spec-for-spec against `git show
v0.1.1:crates/fabric-linux/src/provider.rs` in round 6, and the same
byte identity already underpinned the round-6 deletes. A real-kernel
divergence would NOT silently pass: the would-be tolerated line would
miss the exact-spec comparison, match the broad residue signature, and
fail the apply or teardown closed — loud, kernel intact, remediable by
hand-deleting the residue. The multi-node evidence environment never
exercises this path (fresh hosts, no legacy rules), so the assumption
is covered by the argument above, not by the evidence loop.
The veth deletion is likewise **ownership-gated** (the same
discipline as the stray sweep below): on a fresh host whose journal
owns no fabric state, a root-ns link colliding with the deterministic
`<prefix>-u` name is foreign state and is never deleted — the veth is
inert under this design, so not deleting it is safe. Journals
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
   (or owned) fabric state**. This design closes its OWN add→move
   crash window with a journal claim: the field
   `fabric_creation_claimed` is persisted BEFORE the root
   `ip link add` (journal-before-mutate), so both crash slices of the
   create-then-move sequence converge on the next apply — a crash
   after the claim but before the add finds the sweep gated open with
   no stray to delete; a crash after the add but before the move finds
   the sweep deleting our own stray. The released v0.1.0/v0.1.1 code
   saved the ownership journal only at the end of apply, so a crash on
   the very first apply in the add→move window still leaves a stray
   with an empty journal — that state wedges fail-closed by design
   (manual cleanup is the remedy; no worse than the released baseline,
   which also wedged). On a fresh host (no journal) a colliding
   root-namespace link is foreign state and is never deleted; the
   root-side `ip link add` fails closed on the name instead — and the
   fail-closed check fires BEFORE the claim is persisted, so retries
   stay fail-closed rather than flipping into an authorized deletion.
2. Every VXLAN recorded in the ownership journal is deleted **before**
   the namespace-scoped interface (their `dev <wg>` underlay binding
   dies with the old interface, and identity verification cannot see
   that — §3.3; each network fully heals on its own next apply). This
   order makes every interruption slice of the heal convergent:
   interrupted before any VXLAN deletion, mid-way through the VXLAN
   deletions, after the VXLANs but before the wg deletion, after the
   wg deletion, after the root-side re-creation, or after the
   key/port configuration but before the flag clear — each slice
   re-enters the heal (or the WireGuard-absent path, which recreates
   the interface root-side and, while the flag is still set and the
   journal still records networks, tolerantly deletes the recorded
   VXLANs the same way) and finishes it.
3. The namespace-scoped interface is deleted, the legacy underlay
   machinery is cleaned up, and the interface is re-created in the
   ROOT namespace, moved in, and configured with the private key and
   listen port forced.
4. The journal flag is cleared only after the key/port configuration
   succeeds, so a crash anywhere in the heal simply re-runs it.

**Runtime socket-placement verification.** The heal above triggers on
the journal flag, but the journal can only record intent — the kernel
is the ground truth, and two states leave an ns-bound socket with the
flag reading false: a round-3..5 host crashed between the ns-side
re-creation and the end-of-apply journal save, and an operator-created
ns-born WireGuard (which no journal scheme can represent). So on every
apply where the interface exists in the fabric namespace and no heal
is pending, the provider verifies the placement from the kernel with a
**three-way discriminator** over `ss -uln` dumps (the match is on the
port exactly — `0.0.0.0:<port>`, `[::]:<port>`, `*:<port>` — so a
listener on 6500 never matches a configured 65001):

1. The fabric-namespace dump shows the port **absent** → healthy: no
   heal, no error, no state churn (a spurious heal would cost a
   WireGuard session drop).
2. The fabric-namespace dump shows the port **present** and the
   root-namespace dump (taken only now — one extra command, only in
   this rare case, through the same runner and exact-port parse)
   shows it **absent** → the socket is genuinely ns-bound → the full
   heal above, with the journal flag written BEFORE the first
   deletion, so every interruption slice of the runtime-triggered
   heal converges through the same flag path.
3. **Both** dumps show the port → **unattributable**: our socket could
   be the root one (a healthy root-created transport plus a FOREIGN
   listener inside the fabric namespace — namespace socket tables are
   separate, so that listener does not break the root-bound
   transport), or the fabric one (an ns-born, dead transport plus a
   FOREIGN root-namespace listener). The provider MUST fail the apply
   closed with a specific error naming both observations, the
   configured port, and the remediation (inspect both namespaces'
   listeners on that port and remove the foreign one), and MUST NOT
   delete anything or change any ownership-journal state. (The plan
   journal for the applied network has already been persisted before
   the discriminator runs — journal-before-mutate, §3.1 — so the
   nothing-modified guarantee is scoped to fabric state and the
   ownership journal; that plan-journal write is intent, not fabric
   state.) Healing on the
   fabric-namespace observation alone would destroy a healthy
   transport and never converge — the healed interface plus the
   surviving foreign listener reproduces the same observation on
   every apply, an endless delete/recreate session-drop loop. Refusing
   to heal whenever the root dump is non-quiet would silently keep a
   dead transport in the mirrored case — the exact class this
   contract forbids. Fail closed on ambiguity: never silently keep a
   dead transport, never destroy a healthy one; both underlying
   causes converge to a good state once the operator removes the
   foreign listener, and an apply failing this way leaves the existing
   datapath unaffected.

The two `ss` observations are not atomic, but both are read-only, both
precede any mutation, and the discriminator runs only on the healthy
path (a pending heal is flag-driven and skips it): a concurrent
external mutation between the two observations can at worst turn a
would-be case 2 into case 3 — fail closed — never produce a wrongful
heal. The heal itself stays ownership-gated: on a host whose journal
owns no fabric state, a listener on the configured port inside the
fabric namespace is foreign state and fails closed — never healed by
deletion. A hard failure of either `ss` command itself is NOT "port
absent" and fails the apply closed (iproute2, which provides `ss`, is
already a hard dependency of the provider).

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
sequence, runtime socket-placement verification healing an unflagged
ns-born WireGuard (an `ss -uln` listener on the transport port inside
the fabric namespace, journal flag false, journal owned), the
three-way socket-placement discriminator failing closed on the
unattributable two-namespace listener case without healing, flood-list
reconciliation without duplicates after repeated
replays, flood-list scoping, foreign-state rejection (including
prefix-VNI rejection), teardown cleanliness, key non-leakage, peer
withdrawal, and fabric-removal fencing — plus the hardening cases:
teardown convergence after a simulated kernel restart, re-apply healing
of partial state, flood-list shrinking, duplicate flood-entry
convergence, and MTU/addressing re-assertion. The fake kernel
models the real `ip`/`bridge`/`wg`/`ss`/`iptables` failure and placement
semantics (missing devices, duplicate names, missing namespaces, missing
fdb/route entries with real kernel error strings, per-namespace link
placement and name tables, per-namespace link-creation records — the
WireGuard socket placement — the per-namespace listening-socket dumps of
`ss -uln`, including seedable foreign per-namespace UDP listeners, the
`Bad rule` wording of a non-matching
`iptables -D`, and counting fdb entries), so a permissive provider flow
fails the suite rather than silently passing.

The privileged multi-host gate (three privileged host instances —
containers — on one physical kernel: real
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
