#!/usr/bin/env bash
# Verifies signed Link-State flooding and automatic A -> B -> C path setup.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-auto-path}"
AB_MTU="${AB_MTU:-1500}"
BC_MTU="${BC_MTU:-1500}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-auto}"
source "$PWD/tests/lib/remote.sh"
NS_A="$TINECT_NS_PREFIX-a"
NS_B="$TINECT_NS_PREFIX-b"
NS_C="$TINECT_NS_PREFIX-c"
PIDS=()
cleanup() {
  local pid ns
  for pid in "${PIDS[@]:-}"; do sudo -n kill -TERM "$pid" 2>/dev/null || true; done
  # Killing the `ip netns exec` wrapper alone can leave the daemon alive in
  # a deleted namespace. Reap every process still attached to each fixture
  # namespace before deleting it, so the next CI script starts isolated.
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    while read -r pid; do
      [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; done
  sudo -n rm -f "$WORK/a.sock" "$WORK/b.sock" "$WORK/c.sock"
}
trap cleanup EXIT

sudo -n true
for value in "$AB_MTU" "$BC_MTU"; do
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1200 || value > 9000 )); then
    echo "AB_MTU and BC_MTU must be integer values in 1200..=9000" >&2
    exit 2
  fi
done
sudo -n rm -rf "$WORK"
mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"
CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"

for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; sudo -n ip netns add "$ns"; sudo -n ip -n "$ns" link set lo up; done
remote_veth_between ab-a ab-b "$NS_A" "$NS_B" 10.210.0.1/24 10.210.0.2/24
remote_veth_between bc-b bc-c "$NS_B" "$NS_C" 10.211.0.1/24 10.211.0.2/24
sudo -n ip -n "$NS_A" link set ab-a mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set ab-b mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set bc-b mtu "$BC_MTU"
sudo -n ip -n "$NS_C" link set bc-c mtu "$BC_MTU"
# `c` is an exit in this isolated namespace. Keep the production daemon's
# administrator-owned forwarding precondition explicit in the fixture.
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.210.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
peers:
  b: {public_key: $BK, endpoints: [quic://10.210.0.2:4434]}
  c: {public_key: $CK, endpoints: [], routes: [{ip_cidr: 10.64.2.2/32, priority: 100}]}
path_policies:
  c: {max_hops: 3}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
peers:
  a: {public_key: $AK, endpoints: [quic://10.210.0.1:4433]}
  c: {public_key: $CK, endpoints: [quic://10.211.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://10.211.0.2:4435
tun: {name: tunc, addresses: [10.64.2.2/32]}
runtime: {status_socket: $WORK/c.sock}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [c, b, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.211.0.1:4434]}
allowed_routes:
  - allow: [10.64.2.2/32]
    for: [a]
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF

sudo -n ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PIDS+=("$!")

active_circuit_path() {
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$WORK/a.sock" 2>/dev/null)" python3 -c '
import json, os
expected = ["a", "b", "c"]
raise SystemExit(not any(
    circuit.get("destination") == "c"
    and circuit.get("healthy")
    and circuit.get("active_path_names") == expected
    for circuit in json.loads(os.environ["STATUS_JSON"])["circuits"]
))
' 2>/dev/null
}

for _ in $(seq 1 180); do
  if sudo -n ip -n "$NS_A" link show tinea >/dev/null 2>&1 && sudo -n ip -n "$NS_C" link show tunc >/dev/null 2>&1; then break; fi
  sleep 0.1
done
sudo -n ip -n "$NS_A" link show tinea >/dev/null
sudo -n ip -n "$NS_C" link show tunc >/dev/null
for _ in $(seq 1 100); do
  grep -q 'inbound QUIC link authenticated peer_name=b' "$WORK/c.log" && break
  sleep 0.1
done
grep -q 'inbound QUIC link authenticated peer_name=b' "$WORK/c.log"
# Link-State advertisements are emitted every fifteen seconds and the circuit
# supervisor reconciles independently. Assert the published Circuit snapshot,
# rather than an implementation-detail log message, after two advertisements.
for _ in $(seq 1 450); do
  active_circuit_path && break
  sleep 0.1
done
if ! active_circuit_path; then
  cat "$WORK/a.log" "$WORK/b.log" "$WORK/c.log"
  exit 1
fi
PING_STATUS=1
for _ in $(seq 1 20); do
  if sudo -n ip netns exec "$NS_A" ping -I tinea -c 1 -W 1 10.64.2.2; then
    PING_STATUS=0
    break
  fi
  sleep 0.1
done
if [[ "$PING_STATUS" -ne 0 ]]; then
  cat "$WORK/a.log" "$WORK/b.log" "$WORK/c.log"
  sudo -n ip -n "$NS_A" -br link show tinea 2>/dev/null || true
  sudo -n ip -n "$NS_B" -br link show ab-b 2>/dev/null || true
  sudo -n ip -n "$NS_B" -br link show bc-b 2>/dev/null || true
  sudo -n ip -n "$NS_C" -br link show tunc 2>/dev/null || true
  exit "$PING_STATUS"
fi
sudo -n ip netns exec "$NS_A" "$BIN" status "$WORK/a.yaml" | grep -q '"topology_nodes":'
sudo -n ip netns exec "$NS_A" "$BIN" status "$WORK/a.yaml" | grep -q '"flow_count":'
echo "automatic signed link-state path test passed"
