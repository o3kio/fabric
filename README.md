# fabric

Shared provider implementation of the **Kubedo stretched-L2 edge fabric** —
the one codebase that both [O3K](https://github.com/o3kio/o3k) and
[CHV](https://github.com/kubedoio/chv) use to literally connect distant
locations to the same VLAN: VMs in one network ARP and ping each other with
real MACs, identically on the same hypervisor and across hypervisors.

Status: **hardened provider + green multi-host evidence gate.** The
fake-kernel conformance suite and the 35-assertion multi-host evidence run
(three real kernels via privileged docker: real ARP/ICMP with real MACs,
encrypted underlay, zero-leak teardown, WG socket in the fabric netns) both
pass at HEAD. Consumed by O3K and CHV via git tag. Cross-machine runs over
real networks remain the final production gate (see `evidence/README.md` →
Limitations).

## Design (one paragraph)

Each tenant network is one L2 broadcast domain stretched across all
enrolled hosts: a per-network kernel **VXLAN** device with head-end
replication (HER) and kernel MAC learning (no `nolearning`), carried inside
one shared, authenticated, encrypted **WireGuard** mesh. The provider
realizes compiled plans idempotently with journal-before-mutate discipline,
ownership fencing, fail-closed foreign-state rejection, and strict key
hygiene. Normative sources:

- [contracts/fabric-provider-v1.md](contracts/fabric-provider-v1.md) — the provider contract (this repo)
- O3K [ADR-0186](https://github.com/o3kio/o3k/blob/main/docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md) / [SPEC-0049](https://github.com/o3kio/o3k/blob/main/docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
- CHV [ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)

## Crates

| Crate | Contents |
|---|---|
| `fabric-plan` | Portable, serde-serializable plan types: `Vni`, `PublicKey`, `FabricHostIdentity`, `FabricPeer`, `FabricVniBinding`, `StretchedL2Plan`, plan validation, SHA-256 fingerprint. No I/O. |
| `fabric-linux` | The Linux provider: `FabricCommand` runner seam (+ real subprocess runner and a recorded fake-kernel runner), deterministic IFNAMSIZ-safe naming, WireGuard key hygiene, ownership/plan journals, `LinuxFabricProvider` (`apply_plan` / `remove_network` / `remove_fabric_if_unused`). |
| `fabric-conformance` | The shared anti-drift conformance suite both products run in CI. |
| `fabric-evidence` | Privileged per-host evidence binary for the multi-host gate (`evidence/run-multinode.sh`): identity/apply/tenant-up/probe/neighbors/teardown/leak-check against the real provider. |

## What is shared — and what is not

Shared: the **provider layer** (plan types, Linux realization, conformance).
Not shared: canonical models, control planes, daemons, tenant-facing APIs —
those stay per-product. O3K consumes this via `crates/o3k-network`; CHV via
`crates/chv-nwd`. The full rationale is in O3K ADR-0186 and the CHV issue
#270 resolution thread.

## Kernel shape (per host)

```
 tenant bridges (host-owned, anti-spoof policy)
        │  consumer veth  <prefix>-c-<hash8>   (host ns)
 ───────┼──────────────────────────────────────────────
        │  fabric port    <prefix>-p-<hash8>   (fabric netns <prefix>-fabric)
    learning bridge <prefix>-b-<hash8>
        │
    vxlan <prefix>-x-<hash8>  (id <VNI>, learning ON, HER via
        │                     00:00:00:00:00:00 fdb entries → peer transport IPs)
    wg <prefix>-wg  (transport /32s only in AllowedIPs, UDP <port>)
        │
 underlay veth 169.254.253.1/30 ↔ .2/30 + MASQUERADE/DNAT
```

## Usage sketch

```rust
use fabric_linux::{FabricLinuxConfig, LinuxFabricProvider, RealCommandRunner};
use fabric_plan::StretchedL2Plan;

let config = FabricLinuxConfig::new("/var/lib/o3k/fabric") // CHV: .with_name_prefix("chv")
    .with_wireguard_port(65001);
let mut provider =
    LinuxFabricProvider::open(config, RealCommandRunner::default())?;
provider.apply_plan(&plan)?;   // idempotent; journals first
provider.remove_network(&plan.network_id)?;
```

## Development

```sh
cargo fmt --all && cargo clippy --workspace --all-targets && cargo test --workspace
```

Workspace lints: `unsafe_code` forbidden; `clippy::unwrap_used`,
`clippy::expect_used` and `clippy::panic` denied — including tests.

## Multi-host evidence

The privileged evidence gate (three hosts, real WireGuard handshakes,
cross-host ARP/ping with real MACs, encrypted-underlay capture, zero-leak
teardown) lives in [`evidence/`](evidence/README.md) — see
`evidence/run-multinode.sh`. It is required before any production evidence
claim.

## Releasing

Tags are lightweight and point at the **merge commit on `main`** of the PR
being released. A release MUST bump the workspace `version` in `Cargo.toml`
(and commit the regenerated `Cargo.lock`) and add a `CHANGELOG.md` entry in
the same PR — v0.1.0/v0.1.1 were tagged without manifest bumps and are
indistinguishable to version-keyed tooling; do not repeat that.

## Provenance

Clean Kubeko implementation, written from the public Kubedo decision
documents listed above. No third-party source was translated or copied.
License: Apache-2.0.
