# Multi-host evidence harness (Phase 3 gate)

This directory contains the privileged evidence harness for the Kubedo
stretched-L2 edge fabric: **roadmap issue #2, Phase 3**, the executable
expression of the evidence gate required by
[CHV ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)
and
[O3K ADR-0186](https://github.com/o3kio/o3k/blob/main/docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
before any "one L2 segment across hosts" production claim.

The fake-kernel conformance suite (`fabric-conformance`) proves the
provider's *behavior*. This harness proves the *fabric itself*: real ARP,
real MACs, real pings, real WireGuard handshakes, real encryption on the
wire, and a zero-leak teardown.

## Layout

| Path | What it is |
|---|---|
| `run-multinode.sh` | Orchestrator script: builds the binary, launches three privileged containers (`fev-h1..h3`) on a dedicated docker bridge network, and drives the whole scenario with per-assertion PASS/FAIL records. |
| `results/<timestamp>/` | Output of a run (assertion table, JSON summaries, text captures). Written at runtime, never committed. |
| `../crates/fabric-evidence` | The per-host binary the script executes inside each container. |

## How to run

From the repository root, on an orchestrator machine with docker (directly
or via passwordless sudo), python3, and the repo's Rust toolchain:

```sh
bash evidence/run-multinode.sh        # or: sudo bash evidence/run-multinode.sh
KEEP=1 bash evidence/run-multinode.sh # keep containers + network for inspection
```

The script is re-runnable and cleans up after itself (containers and the
docker network are removed on exit unless `KEEP=1`; the results directory
is always kept). It exits nonzero if any assertion failed.

## What each assertion proves

| Assertion | Evidence |
|---|---|
| `identity_*` | Each host derives a stable WireGuard keypair; only public keys are ever recorded. |
| `apply_*` | The provider creates the shared fabric and the per-network objects from the compiled plan. |
| `tenant_up_*` | The consumer side (tenant bridge + tenant netns + veth) attaches to the provider's consumer veth. |
| `wg_handshakes_*` | Real WireGuard handshakes with both peers inside the fabric namespace. |
| `ping_h1_to_*` | Real ICMP across hosts over the stretched segment. |
| `real_mac_learned_*` | h1's tenant neighbor table holds a **REACHABLE** entry for the peer's tenant IP whose MAC equals the peer's real `eth0` MAC — real kernel MAC learning over VXLAN, not synthetic state. |
| `near_mtu_ping` | An ICMP payload of 1300 bytes (1328 on the wire) crosses the segment: 1328 ≤ tenant MTU 1380; encapsulated 1378 ≤ fabric MTU 1440; +60 WireGuard overhead = 1438 ≤ 1500 underlay. Regression evidence for the WireGuard-MTU fix (contract §2.3). |
| `wg_mtu_is_1440` | The WireGuard interface carries the plan's fabric MTU (not the kernel default 1420). |
| `wg_udp_captured`, `wg_udp_visible_on_underlay` | Encrypted WireGuard UDP (port 65001) is what is actually on the underlay wire. |
| `wg_socket_in_root_ns_*` | The WireGuard UDP socket (`ss -uln`, cross-checked against `wg show` inside the fabric ns, which must still report the listen port — the device lives there, the socket does not) listens in the **root** netns and never inside the fabric ns — regression evidence for the NAT-free underlay redesign (contract §3.10). |
| `no_cleartext_tenant_traffic` | While tenant traffic flows over the fabric, an underlay capture filtered for plaintext ARP/ICMP contains **zero tenant-addressed packets**. |
| `reapply_idempotent` | Replaying an unchanged plan creates no objects (contract §3.2). |
| `bum_arp_reflooded` | After flushing h1's tenant neighbor table, ARP resolves again over the fabric — BUM flooding works, not just cached unicast. |
| `tenant_down_*`, `teardown_*`, `fabric_down_*`, `leak_check_*` | Full teardown in every host; the leak check verifies zero fabric objects remain in the kernel (no netns, no prefixed links — under the NAT-free underlay there are no provider NAT rules or underlay routes to leak, contract §3.10). |
| `key_survives_*` | The host private key file survives fabric teardown by design (contract §3.5). Presence is recorded; content is never displayed. |

Note on the encryption assertions: `wg_udp_visible_on_underlay` and
`no_cleartext_tenant_traffic` are derived from **one combined capture**
(`tcpdump -i eth0 -c 40 -l -n 'udp port 65001 or arp or icmp'`) taken in a
single traffic window, recorded in full as
`results/<timestamp>/tcpdump-underlay-combined.txt`. The assertion requires
both (a) at least one WireGuard-UDP line — proving the capture actually
observed the fabric's traffic — and (b) zero tenant-addressed
(`10.42.0.0/24`) lines. Two separate captures could pass vacuously: a
cleartext-only capture that simply missed the traffic window would contain
no tenant packets for the wrong reason.

## Prerequisites

- Linux orchestrator with the `wireguard` and `vxlan` kernel modules
  available (the privileged containers share the host kernel).
- docker (usable directly or through passwordless `sudo` — auto-detected).
- `python3` (or `jq`) on the orchestrator.
- The repo's stable Rust toolchain (for `cargo build --release -p
  fabric-evidence`, which always runs as the invoking user, outside sudo
  when the script is started via `sudo`).
- Internet access to pull `debian:bookworm-slim` and its packages on first
  run (the image is built on the fly and cached as `fabric-ev-image`).

## Interpretation

A green run means: on three independent host instances (privileged
containers sharing one physical kernel), the compiled plans produced a
single L2 broadcast domain — ARP and
ICMP flow between tenant namespaces with real MACs, the only traffic on
the underlay is WireGuard UDP, near-MTU packets survive the documented MTU
layering, and teardown leaves zero fabric residue while preserving the
host keypair. Every step writes machine-readable artifacts to
`results/<timestamp>/` (`assertions.tsv`, `summary.json`, probe/neighbor
JSON, `wg show`, tcpdump text captures) plus a binary pcap in the workdir
(printed at the end, never committed).

## Limitations (honest scope)

- **One physical kernel.** The three "hosts" are privileged containers on
  a single docker bridge. This proves the datapath, protocol, and crypto
  layering (VXLAN/HER over WireGuard, MTU arithmetic, MAC learning,
  teardown discipline), **not** geographic distance, NIC heterogeneity, or
  real-internet path MTU behavior. Cross-machine runs over real networks
  remain the final production gate; this harness is the prerequisite for
  it, not a substitute.
- **Concurrent host-network mutations invalidate a run (root-caused).** The
  orchestrator host is shared with other workloads; on 2026-09-28 a parallel
  CHV qualification session's cleanup deleted every host bridge matching
  `chvbr0|br-*` — which includes docker's per-network bridges — mid-run,
  twice. Both affected evidence runs are preserved: `results/
  20260928T175355Z/` (failed 17:54:06; **pre-NAT-free code** — its socket
  assertions are the old `wg_socket_in_fabric_ns_*` and its container
  diagnostics show the legacy DNAT/MASQ rules) and `results/
  20260928T185004Z/` (failed 18:50:33 at `bum_arp_reflooded`; NAT-free
  code with a healthy fabric up to the blackout). Both failed with an
  identical signature: all bridge ports `entered disabled state` in the
  kernel journal at the same second, after which every host's root-ns ARP
  for its peers went unanswered (requests leave each container, nothing
  arrives anywhere — captured per-host by `arp-monitor-h*.txt`). This is
  external interference, not a fabric defect: the fabric's underlay depends
  on host bridge forwarding, as does any container networking. (The full
  run history is preserved under `results/`: the 16:36/16:47 failures are
  the pre-redesign NAT-race signature — "only 1 peers have handshakes" —
  that motivated the v0.1.2 underlay; a few interrupted runs record fewer
  assertions and no summary.) Attribution
  recipe for a failed run: check the kernel journal for `bridge ...
  entered disabled state` events inside the run window (they must only
  appear at container bring-up and teardown), and the ARP monitors for the
  requests-without-replies blackout signature. The evidence environment
  must be quiesced (no parallel bridge lifecycle churn) for a run to count
  toward acceptance; cross-machine runs remain the final production gate.
- **Underlay housekeeping ARP.** The docker bridge itself occasionally
  emits ARP for container management (172.31.250.0/24). The cleartext
  check therefore asserts on the absence of *tenant-addressed*
  (10.42.0.0/24) plaintext, which is the actual leak signal; the raw
  capture is kept so a reviewer can verify.
- **Trusted orchestrator.** The script runs with elevated privileges and
  execs into the containers; it is an evidence tool, not a production
  deployment path.
