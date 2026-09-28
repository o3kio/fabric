#!/usr/bin/env bash
#
# evidence/run-multinode.sh — privileged multi-host evidence harness for the
# Kubedo stretched-L2 edge fabric.
#
# This is the Phase 3 deliverable of roadmap issue #2 (the evidence gate
# referenced by CHV ADR-021 / O3K ADR-0186): it produces REAL evidence that
# the fabric delivers "one L2 segment across hosts".
#
# WHAT IT PROVES (three privileged containers on one physical kernel):
#   1. Real WireGuard handshakes between every pair of hosts.
#   2. Real cross-host L2: ARP resolution with real MACs and ICMP over the
#      stretched segment, including BUM re-flooding after a neigh flush.
#   3. MTU layering: near-MTU tenant pings (ICMP size 1300) survive
#      VXLAN-over-WireGuard encapsulation — regression evidence for the
#      WireGuard-MTU provider fix (contract §2.3).
#   4. Encryption: only WireGuard UDP (port 65001) is visible on the
#      underlay; one combined capture in a single traffic window shows
#      both that WG UDP flowed and that no tenant-addressed (10.42.0.0/24)
#      packets appear in cleartext.
#   5. Idempotent re-apply, zero-leak teardown in every host, and survival
#      of the host keypair across fabric teardown (by design).
#   6. WireGuard socket placement: the WG UDP socket listens in the ROOT
#      namespace — never inside the fabric namespace (contract §3.10,
#      the NAT-free underlay: the interface is created root-side and
#      moved in, and the socket binds in the creating namespace).
#
# PREREQUISITES (orchestrator machine):
#   - Linux with the wireguard and vxlan kernel modules available (the
#     containers share the host kernel).
#   - docker (directly or via passwordless sudo — auto-detected).
#   - python3 (plan generation and JSON parsing).
#   - cargo + the repo's stable Rust toolchain.
#
# USAGE:
#   bash evidence/run-multinode.sh          # normal run
#   sudo bash evidence/run-multinode.sh     # when docker needs root
#   KEEP=1 bash evidence/run-multinode.sh   # keep containers+network for
#                                           # manual inspection
#
# The build always runs as the invoking (non-root) user when started via
# sudo; docker calls are prefixed with sudo only when needed. Every
# assertion is recorded under evidence/results/<timestamp>/ and echoed to
# stdout; the script exits nonzero if ANY assertion failed. Results and
# workdir paths (including pcaps) are printed at the end and never
# committed to git.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/fabric-evidence"
EVIDENCE_DIR="$REPO_ROOT/evidence"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="$EVIDENCE_DIR/results/$STAMP"
WORK_DIR="$(mktemp -d /tmp/fabric-ev-XXXXXX)"

IMAGE="fabric-ev-image"
NET_NAME="fabric-ev"
NET_SUBNET="172.31.250.0/24"
PREFIX="ev"
WG_PORT="65001"
VNI="4711"
NETWORK_ID="evidence-net"
BRIDGE="brten"
TNS="tns"
TENANT_H1="10.42.0.11"
TENANT_H2="10.42.0.12"
TENANT_H3="10.42.0.13"
TENANT_MTU="1380"
FABRIC_MTU="1440"
HOSTS=(h1 h2 h3)

KEEP="${KEEP:-0}"
FAILED=0
mkdir -p "$RESULTS_DIR"

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# record NAME true|false DETAIL — one assertion line (tsv + stdout).
record() {
  local name="$1" ok="$2" detail="${3//$'\n'/ | }"
  printf '%s\t%s\t%s\n' "$name" "$ok" "$detail" >>"$RESULTS_DIR/assertions.tsv"
  if [[ "$ok" == "true" ]]; then
    log "PASS  $name — $detail"
  else
    log "FAIL  $name — $detail"
    FAILED=1
  fi
  return 0
}
pass() { record "$1" true "$2"; }
fail() {
  record "$1" false "$2"
  capture_diagnostics "$1"
}

# Post-failure diagnostics. Under the NAT-free underlay (contract §3.10)
# the provider installs NO nat rules of its own, so the nat table's
# packet counters are expected to show only the container runtime's own
# chains (e.g. docker's MASQUERADE) — any rule referencing port 65001 or
# 169.254.253.0/30 in this dump is itself a regression signal; conntrack
# shows the tuple classification. Captured into the results dir on every
# failure for post-mortem analysis.
capture_diagnostics() {
  local triggering="$1"
  for h in "${HOSTS[@]}"; do
    local out="$RESULTS_DIR/diag-$h.txt"
    {
      echo "# diagnostics after failure: $triggering"
      echo "## iptables -t nat -L -n -v (root ns)"
      "${DOCKER[@]}" exec "fev-$h" iptables -t nat -L -n -v 2>&1
      echo "## wg show (fabric ns)"
      "${DOCKER[@]}" exec "fev-$h" ip netns exec "$PREFIX-fabric" wg show 2>&1
      echo "## conntrack entries for the fabric port (root ns view)"
      "${DOCKER[@]}" exec "fev-$h" sh -c "grep $WG_PORT /proc/net/nf_conntrack 2>/dev/null || true" 2>&1
      echo "## ip -s link (root ns)"
      "${DOCKER[@]}" exec "fev-$h" ip -s link 2>&1
      echo "## ip neigh show (root ns)"
      "${DOCKER[@]}" exec "fev-$h" ip neigh show 2>&1
      echo "## /proc/net/arp (root ns)"
      "${DOCKER[@]}" exec "fev-$h" cat /proc/net/arp 2>&1
      echo "## ip neigh show (fabric ns)"
      "${DOCKER[@]}" exec "fev-$h" ip netns exec "$PREFIX-fabric" ip neigh show 2>&1
      echo "## 3s ARP watch on eth0 (requests and replies from this vantage)"
      "${DOCKER[@]}" exec "fev-$h" timeout 3 tcpdump -i eth0 -n -c 40 arp 2>&1
    } >"$out" 2>&1
  done
  # Host-side view of the docker bridge: counters, FDB and port states —
  # distinguishes "the request never left the container" from "the bridge
  # never delivered it". Requires the script's sudo/root context.
  local bridge_id bridge_name
  bridge_id="$("${DOCKER[@]}" network inspect -f '{{.Id}}' "$NET_NAME" 2>/dev/null || true)"
  if [[ -n "$bridge_id" ]]; then
    bridge_name="br-${bridge_id:0:12}"
    {
      echo "## host bridge $bridge_name link stats"
      ip -s link show "$bridge_name" 2>&1
      echo "## host bridge $bridge_name fdb"
      bridge fdb show dev "$bridge_name" 2>&1
      echo "## host bridge ports"
      bridge link show 2>&1
      echo "## host neigh (container subnet)"
      ip neigh show 2>&1
    } >"$RESULTS_DIR/diag-host-bridge.txt" 2>&1
  fi
}

# docker, with sudo fallback (the script may run as a user without the
# docker group or via `sudo bash`).
if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo -n docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
else
  echo "fabric-evidence: docker is not usable (tried 'docker' and 'sudo docker')" >&2
  exit 1
fi

# JSON field extraction (dotted paths). jq when present, python3 otherwise.
HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
elif ! command -v python3 >/dev/null 2>&1; then
  echo "fabric-evidence: need jq or python3 on the orchestrator" >&2
  exit 1
fi
json_field() { # json_field FILE KEY -> value on stdout
  local file="$1" key="$2"
  if [[ "$HAVE_JQ" -eq 1 ]]; then
    jq -r ".$key" "$file"
  else
    python3 - "$file" "$key" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    doc = json.load(handle)
for part in sys.argv[2].split("."):
    doc = doc[part]
print(doc)
PY
  fi
}

fev() { # fev HOST ARGS... — fabric-evidence inside container HOST
  "${DOCKER[@]}" exec "fev-$1" fabric-evidence "${@:2}"
}
hexec() { # hexec HOST ARGS... — arbitrary command inside container HOST
  "${DOCKER[@]}" exec "fev-$1" "${@:2}"
}

cleanup() {
  local rc=$?
  if [[ "$KEEP" != "1" ]]; then
    for h in "${HOSTS[@]}"; do
      "${DOCKER[@]}" rm -f "fev-$h" >/dev/null 2>&1 || true
    done
    "${DOCKER[@]}" network rm "$NET_NAME" >/dev/null 2>&1 || true
  else
    log "KEEP=1: containers (fev-h1..h3) and network $NET_NAME left running"
  fi
  log "results dir: $RESULTS_DIR"
  log "work dir (state roots, pcaps): $WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# 1. build (as the invoking user, outside sudo when possible)
# --------------------------------------------------------------------------
# Static musl build: the binary must run inside the containers regardless
# of the orchestrator's glibc version.
log "1/8 building fabric-evidence (release, static musl)"
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]] && command -v runuser >/dev/null 2>&1; then
  # Root's PATH does not carry the invoking user's rustup toolchain
  # (~/.cargo/bin), and runuser does not start a login shell: resolve
  # cargo through a login shell of the build user and invoke it by
  # absolute path.
  CARGO_BIN="$(runuser -u "$SUDO_USER" -- sh -lc 'command -v cargo')" || CARGO_BIN=""
  [[ -n "$CARGO_BIN" ]] || {
    echo "cargo not on PATH for build user $SUDO_USER" >&2
    exit 1
  }
  runuser -u "$SUDO_USER" -- "$CARGO_BIN" build --release --target x86_64-unknown-linux-musl -p fabric-evidence
else
  cargo build --release --target x86_64-unknown-linux-musl -p fabric-evidence
fi
[[ -x "$BIN" ]] || { echo "fabric-evidence: binary missing at $BIN" >&2; exit 1; }

# --------------------------------------------------------------------------
# 2. docker network + image + three privileged containers
# --------------------------------------------------------------------------
log "2/8 creating docker network $NET_NAME ($NET_SUBNET) and containers"
if ! "${DOCKER[@]}" network inspect "$NET_NAME" >/dev/null 2>&1; then
  "${DOCKER[@]}" network create --subnet "$NET_SUBNET" "$NET_NAME" >/dev/null
fi

BUILD_DIR="$(mktemp -d /tmp/fabric-ev-build-XXXXXX)"
cat >"$BUILD_DIR/Dockerfile" <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 \
      wireguard-tools \
      iptables \
      iputils-ping \
      iputils-arping \
      tcpdump \
      procps \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
"${DOCKER[@]}" build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null
rm -rf "$BUILD_DIR"

for h in "${HOSTS[@]}"; do
  "${DOCKER[@]}" rm -f "fev-$h" >/dev/null 2>&1 || true
  # One shared workdir mount; each host uses its own state root /work/<h>.
  # No ip_forward/rp_filter sysctls: under the NAT-free underlay the
  # root namespace terminates the WG transport socket and hands packets
  # to the container's normal routing — it never forwards fabric
  # packets (contract §2.3).
  "${DOCKER[@]}" run -d --name "fev-$h" \
    --privileged \
    --network "$NET_NAME" \
    --hostname "$h" \
    -v "$BIN:/usr/local/bin/fabric-evidence:ro" \
    -v "$WORK_DIR:/work" \
    "$IMAGE" sleep infinity >/dev/null
  mkdir -p "$WORK_DIR/$h"
done

# --------------------------------------------------------------------------
# 3. identities (public keys only — never private material)
# --------------------------------------------------------------------------
log "3/8 collecting host identities"
declare -A PUBKEY
for h in "${HOSTS[@]}"; do
  fev "$h" identity --root "/work/$h" --prefix "$PREFIX" >"$RESULTS_DIR/identity-$h.json"
  PUBKEY[$h]="$(json_field "$RESULTS_DIR/identity-$h.json" public_key)"
  if [[ "${PUBKEY[$h]}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    pass "identity_$h" "host keypair present (public key recorded, private key never logged)"
  else
    fail "identity_$h" "unexpected public key shape: ${PUBKEY[$h]}"
  fi
done

ip_of() {
  "${DOCKER[@]}" inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "fev-$1"
}
declare -A CONN_IP
for h in "${HOSTS[@]}"; do
  CONN_IP[$h]="$(ip_of "$h")"
done
log "container underlay IPs: h1=${CONN_IP[h1]} h2=${CONN_IP[h2]} h3=${CONN_IP[h3]}"

# --------------------------------------------------------------------------
# 4. plan generation (on the orchestrator)
# --------------------------------------------------------------------------
log "4/8 generating plans (vni $VNI, tenant_mtu $TENANT_MTU, fabric_mtu $FABRIC_MTU)"
python3 - "$WORK_DIR" "$WG_PORT" "$VNI" "$NETWORK_ID" "$TENANT_MTU" "$FABRIC_MTU" \
  "${CONN_IP[h1]}" "${CONN_IP[h2]}" "${CONN_IP[h3]}" \
  "${PUBKEY[h1]}" "${PUBKEY[h2]}" "${PUBKEY[h3]}" <<'PY'
import json, sys
(work, port, vni, network_id, tenant_mtu, fabric_mtu,
 ip1, ip2, ip3, k1, k2, k3) = sys.argv[1:14]
hosts = [
    ("h1", ip1, k1, "100.100.0.1"),
    ("h2", ip2, k2, "100.100.0.2"),
    ("h3", ip3, k3, "100.100.0.3"),
]
for host_id, conn_ip, pubkey, transport_ip in hosts:
    peers = [
        {
            "host_id": other_id,
            "public_key": other_key,
            "underlay_endpoint": {"host": other_ip, "port": int(port)},
            "fabric_transport_ip": other_transport,
        }
        for other_id, other_ip, other_key, other_transport in hosts
        if other_id != host_id
    ]
    plan = {
        "fabric_domain_id": "fabric-evidence",
        "local_host_id": host_id,
        "local_transport_ip": transport_ip,
        "network_id": network_id,
        "vni": int(vni),
        "binding_generation": 1,
        "tenant_mtu": int(tenant_mtu),
        "fabric_mtu": int(fabric_mtu),
        "peers": peers,
        "plan_generation": 1,
    }
    with open(f"{work}/plan-{host_id}.json", "w") as handle:
        json.dump(plan, handle, indent=2)
        handle.write("\n")
PY

# --------------------------------------------------------------------------
# 5. apply + tenant-up on every host
# --------------------------------------------------------------------------
log "5/8 applying plans and bringing tenants up"
for h in "${HOSTS[@]}"; do
  if fev "$h" apply --root "/work/$h" --prefix "$PREFIX" --plan "/work/plan-$h.json" \
      >"$RESULTS_DIR/apply-$h.json" 2>"$RESULTS_DIR/apply-$h.stderr"; then
    cf="$(json_field "$RESULTS_DIR/apply-$h.json" created_fabric)"
    cn="$(json_field "$RESULTS_DIR/apply-$h.json" created_network)"
    if [[ "$cf" == "true" && "$cn" == "true" ]]; then
      pass "apply_$h" "first apply created the fabric and the network"
    else
      fail "apply_$h" "first apply reported created_fabric=$cf created_network=$cn"
    fi
  else
    fail "apply_$h" "fabric-evidence apply failed: $(cat "$RESULTS_DIR/apply-$h.stderr")"
    log "aborting: apply failed on $h"
    exit 1
  fi
done

# WireGuard socket placement (regression evidence for the NAT-free
# underlay, contract §3.10): the WG UDP socket must live in the ROOT
# namespace — never inside the fabric namespace. A WireGuard socket
# binds in the netns where the interface is CREATED and never follows a
# later `ip link set netns`; the provider therefore creates the
# interface root-side and moves it in, so the socket binds in the root
# namespace, where outbound encrypted packets take the host's normal
# routing (dynamic source selection, no NAT rewriting the port) and
# inbound flows to <host-ip>:<port> reach the listener directly. ss(8)
# lists listening UDP sockets per network namespace, so the root-ns
# side of the invariant is directly observable; and because ss alone
# proves only "a listener", `wg show <wg>` inside the fabric namespace
# is additionally required to succeed and report the configured listen
# port, proving the device (which lives in the fabric ns) owns the
# root-ns listener.
for h in "${HOSTS[@]}"; do
  ns_ss="$(hexec "$h" ip netns exec "$PREFIX-fabric" ss -uln)"
  root_ss="$(hexec "$h" ss -uln)"
  printf '%s\n' "$ns_ss" >"$RESULTS_DIR/ss-fabric-ns-$h.txt"
  printf '%s\n' "$root_ss" >"$RESULTS_DIR/ss-root-ns-$h.txt"
  ns_listening="$(printf '%s\n' "$ns_ss" | grep -E ":${WG_PORT}\b" || true)"
  root_listening="$(printf '%s\n' "$root_ss" | grep -E ":${WG_PORT}\b" || true)"
  # ss(8) alone proves only "a listener on the port in the root
  # namespace" — not that the listener belongs to OUR WireGuard device.
  # Prove ownership from the device side: `wg show <wg>` inside the
  # fabric namespace (where the device lives) must succeed and report
  # the configured listen port.
  wg_ns_show=""
  if wg_ns_show="$(hexec "$h" ip netns exec "$PREFIX-fabric" wg show "$PREFIX-wg" 2>&1)"; then
    printf '%s\n' "$wg_ns_show" >"$RESULTS_DIR/wg-show-fabric-ns-$h.txt"
  else
    wg_show_rc=$?
    printf 'wg show %s exited %s\n' "$PREFIX-wg" "$wg_show_rc" \
      >"$RESULTS_DIR/wg-show-fabric-ns-$h.txt"
  fi
  wg_port_reported="$(printf '%s\n' "$wg_ns_show" \
    | grep -E "listening port: ${WG_PORT}$" || true)"
  if [[ -z "$ns_listening" && -n "$root_listening" && -n "$wg_port_reported" ]]; then
    pass "wg_socket_in_root_ns_$h" \
      "WG device $PREFIX-wg reports listen port $WG_PORT in $PREFIX-fabric ns; UDP $WG_PORT listens in the root ns, not in the fabric ns"
  else
    fail "wg_socket_in_root_ns_$h" \
      "root match: '${root_listening:-<none>}', ns match: '${ns_listening:-<none>}', wg-reported port: '${wg_port_reported:-<none>}'"
  fi
done

declare -A TENANT_IP=( [h1]="$TENANT_H1" [h2]="$TENANT_H2" [h3]="$TENANT_H3" )
for h in "${HOSTS[@]}"; do
  if fev "$h" tenant-up --root "/work/$h" --prefix "$PREFIX" \
      --network-id "$NETWORK_ID" --bridge "$BRIDGE" --tenant-ns "$TNS" \
      --ip "${TENANT_IP[$h]}/24" \
      >"$RESULTS_DIR/tenant-up-$h.json" 2>"$RESULTS_DIR/tenant-up-$h.stderr"; then
    pass "tenant_up_$h" "tenant ${TENANT_IP[$h]}/24 attached via $BRIDGE/$TNS"
  else
    fail "tenant_up_$h" "tenant-up failed: $(cat "$RESULTS_DIR/tenant-up-$h.stderr")"
    log "aborting: tenant-up failed on $h"
    exit 1
  fi
done

# --------------------------------------------------------------------------
# 6. evidence collection
# --------------------------------------------------------------------------
log "6/8 collecting evidence"

# Continuous ARP monitor per host (root-ns eth0): the full ARP timeline —
# requests AND replies from each vantage — is the decisive instrument for
# underlay flap diagnosis. A snapshot cannot show whether a request ever
# arrived at the peer or whether a reply left it. Bounded by timeout; the
# cleanup path removes the containers (and with them the captures).
for h in "${HOSTS[@]}"; do
  "${DOCKER[@]}" exec "fev-$h" timeout 300 tcpdump -i eth0 -n -l arp \
    >"$RESULTS_DIR/arp-monitor-$h.txt" 2>/dev/null &
done

# Always record neighbor (ARP) state per host: the underlay depends on
# root-ns neighbor resolution for the WG endpoints; pass/fail comparison
# of these tables is a primary discriminator for underlay flaps.
for h in "${HOSTS[@]}"; do
  {
    echo "## ip neigh show (root ns)"
    hexec "$h" ip neigh show 2>&1
    echo "## /proc/net/arp (root ns)"
    hexec "$h" cat /proc/net/arp 2>&1
    echo "## ip neigh show (fabric ns)"
    hexec "$h" ip netns exec "$PREFIX-fabric" ip neigh show 2>&1
  } >"$RESULTS_DIR/neigh-$h.txt" 2>&1
done

# 7a. WireGuard handshakes (lazy: appear after first traffic — warm up).
fev h1 probe --tenant-ns "$TNS" --target "$TENANT_H2" --count 2 --deadline 10 \
  >"$RESULTS_DIR/probe-warmup.json" || true
for h in "${HOSTS[@]}"; do
  wg_show=""
  handshakes=0
  for _ in $(seq 1 30); do
    wg_show="$(hexec "$h" ip netns exec "$PREFIX-fabric" wg show)"
    handshakes="$(printf '%s\n' "$wg_show" | grep -c 'latest handshake' || true)"
    [[ "$handshakes" -ge 2 ]] && break
    sleep 1
  done
  printf '%s\n' "$wg_show" >"$RESULTS_DIR/wg-show-$h.txt"
  if [[ "$handshakes" -ge 2 ]]; then
    pass "wg_handshakes_$h" "both peers show a latest handshake"
  else
    fail "wg_handshakes_$h" "only '$handshakes' peers have handshakes after 30 s"
  fi
done

# 7b. cross-host ping with real MACs.
for target_host in h2 h3; do
  target="${TENANT_IP[$target_host]}"
  fev h1 probe --tenant-ns "$TNS" --target "$target" \
    >"$RESULTS_DIR/probe-h1-$target.json"
  ok="$(json_field "$RESULTS_DIR/probe-h1-$target.json" ok)"
  if [[ "$ok" == "true" ]]; then
    pass "ping_h1_to_$target" "ICMP across hosts over the stretched segment"
  else
    fail "ping_h1_to_$target" "ping failed: $(cat "$RESULTS_DIR/probe-h1-$target.json")"
  fi
done
fev h1 neighbors --tenant-ns "$TNS" >"$RESULTS_DIR/neighbors-h1.json"
NEIGH="$(json_field "$RESULTS_DIR/neighbors-h1.json" entries)"
printf '%s\n' "$NEIGH" >"$RESULTS_DIR/neighbors-h1.txt"
for target_host in h2 h3; do
  target="${TENANT_IP[$target_host]}"
  expected_mac="$(hexec "$target_host" ip netns exec "$TNS" ip link show eth0 \
    | awk '/link\/ether/ {print $2}')"
  entry="$(printf '%s\n' "$NEIGH" | grep "$target" | head -n1 || true)"
  if [[ -n "$entry" && "$entry" == *"REACHABLE"* && "$entry" == *"$expected_mac"* ]]; then
    pass "real_mac_learned_$target" "REACHABLE entry with the peer's real MAC $expected_mac"
  else
    fail "real_mac_learned_$target" \
      "expected REACHABLE + MAC $expected_mac, saw: ${entry:-<no entry>}"
  fi
done

# 7c. near-MTU ping + the WireGuard MTU itself.
fev h1 probe --tenant-ns "$TNS" --target "$TENANT_H2" --size 1300 --count 3 --deadline 20 \
  >"$RESULTS_DIR/probe-near-mtu.json"
ok="$(json_field "$RESULTS_DIR/probe-near-mtu.json" ok)"
if [[ "$ok" == "true" ]]; then
  pass "near_mtu_ping" "ICMP size 1300 (1328 on the wire) crosses VXLAN+WG (1380/1440/1500 layering)"
else
  fail "near_mtu_ping" "near-MTU ping failed: $(cat "$RESULTS_DIR/probe-near-mtu.json")"
fi
wg_link="$(hexec h1 ip netns exec "$PREFIX-fabric" ip link show "$PREFIX-wg")"
printf '%s\n' "$wg_link" >"$RESULTS_DIR/wg-link-h1.txt"
if [[ "$wg_link" == *"mtu $FABRIC_MTU"* ]]; then
  pass "wg_mtu_is_$FABRIC_MTU" "WireGuard interface carries the plan's fabric MTU"
else
  fail "wg_mtu_is_$FABRIC_MTU" "wg link does not show mtu $FABRIC_MTU: $wg_link"
fi

# 7d. encryption evidence.
# Binary capture: WireGuard UDP on h2's underlay (pcap stays in the workdir).
"${DOCKER[@]}" exec fev-h2 timeout 20 tcpdump -i eth0 -c 200 -w /work/capture-h2.pcap udp \
  >/dev/null 2>&1 &
TCPDUMP_PID=$!
fev h1 probe --tenant-ns "$TNS" --target "$TENANT_H2" --count 50 --deadline 15 \
  >"$RESULTS_DIR/probe-encrypted-round.json" || true
wait "$TCPDUMP_PID" || true
if [[ -s "$WORK_DIR/capture-h2.pcap" ]]; then
  pass "wg_udp_captured" "udp pcap recorded at $WORK_DIR/capture-h2.pcap"
else
  fail "wg_udp_captured" "no udp packets captured on h2's underlay"
fi

# Warm h1's underlay ARP entry for h2 so the capture below is not polluted
# by docker-bridge housekeeping ARP (172.31.250.0/24).
hexec h1 ping -c 1 -w 2 "${CONN_IP[h2]}" >/dev/null 2>&1 || true

# Combined capture in ONE traffic window: the same packets must show
# WireGuard UDP (port $WG_PORT) AND no tenant-addressed (10.42.0.0/24)
# cleartext. Two separate captures could pass vacuously — the cleartext
# capture might simply have missed the traffic window and seen nothing at
# all. The full capture is recorded in the results dir.
"${DOCKER[@]}" exec fev-h2 timeout 15 tcpdump -i eth0 -c 40 -l -n \
  "udp port $WG_PORT or arp or icmp" \
  >"$RESULTS_DIR/tcpdump-underlay-combined.txt" 2>/dev/null &
COMBINED_PID=$!
fev h1 probe --tenant-ns "$TNS" --target "$TENANT_H2" --count 10 --deadline 10 >/dev/null || true
wait "$COMBINED_PID" || true
CAPTURE="$RESULTS_DIR/tcpdump-underlay-combined.txt"
# tcpdump line format: "... 172.31.250.x.port > 172.31.250.y.port: UDP ..."
wg_lines="$(grep -Ec "\.${WG_PORT}:" "$CAPTURE" || true)"
tenant_leak="$(grep -c '10\.42\.' "$CAPTURE" || true)"
if [[ "$wg_lines" -ge 1 ]]; then
  pass "wg_udp_visible_on_underlay" \
    "encrypted WG UDP $WG_PORT observed on the underlay ($wg_lines capture lines)"
else
  fail "wg_udp_visible_on_underlay" \
    "no WG UDP $WG_PORT seen on h2's underlay: $(cat "$CAPTURE")"
fi
if [[ "$tenant_leak" -eq 0 ]]; then
  pass "no_cleartext_tenant_traffic" \
    "zero tenant-addressed packets in the combined capture (wg lines: $wg_lines)"
else
  fail "no_cleartext_tenant_traffic" \
    "$tenant_leak plaintext tenant packets captured: $(cat "$CAPTURE")"
fi

# 7e. idempotency: replaying the same plan must create nothing.
fev h1 apply --root "/work/h1" --prefix "$PREFIX" --plan "/work/plan-h1.json" \
  >"$RESULTS_DIR/apply2-h1.json"
cf="$(json_field "$RESULTS_DIR/apply2-h1.json" created_fabric)"
cn="$(json_field "$RESULTS_DIR/apply2-h1.json" created_network)"
if [[ "$cf" == "false" && "$cn" == "false" ]]; then
  pass "reapply_idempotent" "second apply created no fabric and no network objects"
else
  fail "reapply_idempotent" "replay reported created_fabric=$cf created_network=$cn"
fi

# 7f. BUM flooding: flush h1's tenant neighbor table and re-resolve.
hexec h1 ip netns exec "$TNS" ip neigh flush all >/dev/null
fev h1 probe --tenant-ns "$TNS" --target "$TENANT_H2" --count 4 --deadline 20 \
  >"$RESULTS_DIR/probe-bum.json"
ok="$(json_field "$RESULTS_DIR/probe-bum.json" ok)"
fev h1 neighbors --tenant-ns "$TNS" >"$RESULTS_DIR/neighbors-h1-after-flush.json"
NEIGH2="$(json_field "$RESULTS_DIR/neighbors-h1-after-flush.json" entries)"
printf '%s\n' "$NEIGH2" >"$RESULTS_DIR/neighbors-h1-after-flush.txt"
relearned="$(printf '%s\n' "$NEIGH2" | grep -c "$TENANT_H2" || true)"
if [[ "$ok" == "true" && "$relearned" -ge 1 ]]; then
  pass "bum_arp_reflooded" "ARP re-resolved over the fabric after a neigh flush"
else
  fail "bum_arp_reflooded" "ping ok=$ok, relearned entries=$relearned"
fi

# 7g. teardown + zero leak, in EVERY container.
for h in "${HOSTS[@]}"; do
  fev "$h" tenant-down --root "/work/$h" --prefix "$PREFIX" \
    --network-id "$NETWORK_ID" --bridge "$BRIDGE" --tenant-ns "$TNS" \
    >"$RESULTS_DIR/tenant-down-$h.json" \
    || fail "tenant_down_$h" "tenant-down exited nonzero"
  fev "$h" teardown --root "/work/$h" --prefix "$PREFIX" --network-id "$NETWORK_ID" \
    >"$RESULTS_DIR/teardown-$h.json" \
    || fail "teardown_$h" "teardown exited nonzero"
  fev "$h" fabric-down --root "/work/$h" --prefix "$PREFIX" \
    >"$RESULTS_DIR/fabric-down-$h.json" \
    || fail "fabric_down_$h" "fabric-down exited nonzero"
  removed="$(json_field "$RESULTS_DIR/fabric-down-$h.json" removed)"
  if [[ "$removed" == "true" ]]; then
    pass "fabric_down_$h" "shared fabric removed once no networks remain"
  else
    fail "fabric_down_$h" "fabric-down reported removed=$removed"
  fi
  if fev "$h" leak-check --root "/work/$h" --prefix "$PREFIX" \
      >"$RESULTS_DIR/leak-check-$h.json" 2>"$RESULTS_DIR/leak-check-$h.stderr"; then
    clean="$(json_field "$RESULTS_DIR/leak-check-$h.json" clean)"
    if [[ "$clean" == "true" ]]; then
      pass "leak_check_$h" "zero fabric objects left in the kernel"
    else
      fail "leak_check_$h" \
        "residue: $(json_field "$RESULTS_DIR/leak-check-$h.json" residue)"
    fi
  else
    fail "leak_check_$h" "leak-check exited nonzero: $(cat "$RESULTS_DIR/leak-check-$h.stderr")"
  fi
  # The private key file must survive fabric teardown BY DESIGN. Presence
  # only — its content is never read, logged, or committed.
  if [[ -f "$WORK_DIR/$h/wireguard-private.key" ]]; then
    pass "key_survives_$h" "private key file present after fabric-down (never displayed)"
  else
    fail "key_survives_$h" "private key file missing after fabric-down"
  fi
done

# --------------------------------------------------------------------------
# 7. summary
# --------------------------------------------------------------------------
log "7/8 writing summary"
python3 - "$RESULTS_DIR" <<'PY' >"$RESULTS_DIR/summary.json"
import json, sys
results = sys.argv[1]
cases = []
with open(f"{results}/assertions.tsv") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) != 3:
            continue
        name, ok, detail = parts
        cases.append({"name": name, "pass": ok == "true", "detail": detail})
summary = {
    "passed": sum(1 for c in cases if c["pass"]),
    "failed": sum(1 for c in cases if not c["pass"]),
    "cases": cases,
}
print(json.dumps(summary, indent=2))
PY

log "8/8 assertion table"
echo "=================================================================="
while IFS=$'\t' read -r name ok detail; do
  if [[ "$ok" == "true" ]]; then status="PASS"; else status="FAIL"; fi
  printf '  [%s] %s — %s\n' "$status" "$name" "$detail"
done <"$RESULTS_DIR/assertions.tsv"
echo "=================================================================="
if [[ "$FAILED" -ne 0 ]]; then
  log "EVIDENCE RUN FAILED — see $RESULTS_DIR"
  exit 1
fi
log "ALL ASSERTIONS PASSED — evidence recorded in $RESULTS_DIR"
exit 0
