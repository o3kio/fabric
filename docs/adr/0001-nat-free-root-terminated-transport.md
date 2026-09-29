# ADR-0001 — NAT-free, root-terminated WireGuard transport

Status: Accepted (2026-09-28, shipped in v0.1.2)

## Context

The v0.1.x underlay kept the WireGuard interface fully inside the fabric
network namespace and reached it from the host through a veth pair plus two
`iptables -t nat` rules: `PREROUTING DNAT` steering inbound UDP :65001 into
the fabric ns, and `POSTROUTING MASQUERADE` giving outbound traffic the host
address. The multi-host evidence gate falsified this design twice, with
root-causes verified against the mainline kernel:

1. **DNAT black-holes NEW inbound flows.** A WireGuard interface's UDP socket
   binds in its **creating** namespace and never follows
   `ip link set netns` — `creating_net` is immutable
   (`drivers/net/wireground/socket.c`; verified empirically on kernel 6.8).
   A wg created in the root ns and moved into the fabric ns keeps its socket
   in the root ns, while the DNAT rule rewrites every NEW inbound flow into
   the fabric ns, where nothing listens. Peer pairs survived only when an
   established conntrack reply-tuple shield happened to cover the path —
   an intermittent dead-pair flake, ≈1-in-3 in evidence loops.
2. **MASQUERADE remaps the source port under simultaneous initiation.** For
   a same-port peer pair, the outbound MASQ flow's reply tuple *always*
   equals the peer's inbound DNAT entry's orig tuple; conntrack requires
   global tuple uniqueness, so when both peers initiate in the same instant,
   one side's source port is remapped. The peer's WireGuard then roams to
   the remapped port — which the DNAT rule (`--dport 65001` only) does not
   steer — and the pair never recovers (≈1-in-10 dead pairs). No iptables
   formulation avoids this: any port-preserving outbound NAT has the
   collision.

Both failure modes share one root property: **NAT state on the transport
path races with WireGuard's own endpoint roaming.**

## Decision

Remove the NAT machinery entirely. The WireGuard interface is created in the
**root** namespace (`ip link add … type wireguard`, `wg set … private-key
<path> listen-port …`) and then moved into the fabric namespace — so its UDP
socket, bound in the creating namespace, lives in the root ns. Outbound
transport rides normal host routing; inbound transport is delivered directly
to the root-ns listener. The veth pair, DNAT, MASQ, and the 169.254.253.0/30
attachment are gone. Everything tenant-facing (VXLAN, learning bridge, veth
attachment, tenant MTU) remains fully namespaced.

Socket placement becomes a correctness invariant, verified at runtime on
every apply (ADR-0002). Legacy v0.1.x hosts migrate via tolerant exact-spec
cleanup on apply and teardown, with pre-destruction residue verification
(contract §3.10).

## Consequences

- There is no NAT state left to race: both flake classes are designed out,
  confirmed by 10/10 acceptance loops (previously ≈1-in-3 and ≈1-in-10).
- The WG transport socket is visible host-wide in the root ns — an accepted
  consequence, and the de-facto placement of every released version.
- **One fabric per WG port per host** (the root-ns socket occupies the port).
  CHV and O3K each run one fabric per host; distinct fabrics on one host
  need distinct ports and prefixes. Accepted limitation.
- The transport underlay now depends on the host's own routing (and, in
  container environments, on host bridge forwarding) — documented in the
  evidence README's interference attribution, since external bridge
  teardowns can black-hole the underlay exactly as they would for any
  container workload.
- The v0.1.x NAT residue story becomes a permanent migration surface
  (tolerant deletes + fail-closed residue verification), to be removed only
  by a future ADR once no v0.1.x installation can exist.

## References

- Kernel: `drivers/net/wireguard/socket.c` (`creating_net` immutability).
- Contract §3.10 (underlay, socket placement, residue semantics); CHANGELOG
  at v0.1.2; `evidence/README.md` → Limitations for the interference
  attribution recipe and the honest evidence-scope statement.
- O3K ADR-0186 / SPEC-0049 and CHV ADR-021 (with its postmortem addendum)
  describe the original NAT underlay this ADR supersedes at the provider
  layer.
