#!/usr/bin/env bash
# Verifies that a path change after the first hop still rebuilds the Circuit.
# A-B-C-D is preferred and A-B-E-D is the fallback; both share A-B.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"

TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-same-hop}"
WORK="${WORK:-/tmp/tinect-same-hop-$TINECT_NS_PREFIX}"
NS_A="$(remote_ns tinect-sha)"
NS_B="$(remote_ns tinect-shb)"
NS_C="$(remote_ns tinect-shc)"
NS_E="$(remote_ns tinect-she)"
NS_D="$(remote_ns tinect-shd)"

TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"
AB_A="sh${TOKEN:0:7}a"; AB_B="sh${TOKEN:0:7}b"
BC_B="sh${TOKEN:0:7}c"; BC_C="sh${TOKEN:0:7}d"
CD_C="sh${TOKEN:0:7}e"; CD_D="sh${TOKEN:0:7}f"
BE_B="sh${TOKEN:0:7}g"; BE_E="sh${TOKEN:0:7}h"
ED_E="sh${TOKEN:0:7}i"; ED_D="sh${TOKEN:0:7}j"

fail() {
  echo "same-first-hop path switch test failed: $*" >&2
  remote_finish 1
}

start_node() {
  local node="$1" fixture="$2" socket="$WORK/$1.sock"
  REMOTE_SOCKETS+=("$socket")
  REMOTE_LOG_NODES+=("$node")
  sudo -n ip netns exec "$(remote_ns "$fixture")" "$BIN" up "$WORK/$node.yaml" \
    >>"$WORK/$node.log" 2>&1 &
  REMOTE_PIDS+=("$!")
}

# Start nodes one at a time and wait for each daemon's status socket before
# starting the next. All five endpoints dial each other simultaneously, and a
# simultaneous startup burst makes the QUIC accept/dial race significantly
# worse (connections are superseded and re-dialed, and handshakes time out
# while every daemon competes for CPU). The fixture is about path switching,
# not about startup convergence, so serialize node startup to keep the test
# focused and stable.
start_node_ready() {
  local node="$1" fixture="$2"
  start_node "$node" "$fixture"
  for _ in $(seq 1 100); do
    [[ -S "$WORK/$node.sock" ]] && break
    sleep 0.1
  done
  sleep 1
}

status_json() { sudo -n "$BIN" status --socket "$WORK/$1.sock" 2>/dev/null; }

path_is() {
  local node="$1" destination="$2" expected="$3"
  STATUS_JSON="$(status_json "$node")" DESTINATION="$destination" EXPECTED="$expected" \
    python3 -c '
import json
import os
try:
    status = json.loads(os.environ["STATUS_JSON"])
except (KeyError, json.JSONDecodeError):
    raise SystemExit(1)
expected = os.environ["EXPECTED"].split(",")
raise SystemExit(not any(
    circuit.get("destination") == os.environ["DESTINATION"]
    and circuit.get("healthy")
    and circuit.get("active_path_names") == expected
    for circuit in status.get("circuits", [])
))
' 2>/dev/null
}

wait_paths() {
  local a_path="$1" d_path="$2" timeout_secs="$3"
  for _ in $(seq 1 "$((timeout_secs * 10))"); do
    if path_is a d "$a_path" && path_is d a "$d_path"; then return 0; fi
    sleep 0.1
  done
  fail "expected A=[$a_path], D=[$d_path]"
}

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
[[ -x "$BIN" ]] || fail "build the release binary first"
sudo -n true || fail "passwordless sudo is required"

for node in a b c e d; do remote_keygen "$node"; done
AK="$(remote_public_key a)"; BK="$(remote_public_key b)"; CK="$(remote_public_key c)"
EK="$(remote_public_key e)"; DK="$(remote_public_key d)"

for fixture in tinect-sha tinect-shb tinect-shc tinect-she tinect-shd; do
  remote_namespace "$fixture"
done
remote_veth "$AB_A" "$AB_B" tinect-sha tinect-shb 10.231.11.1/24 10.231.11.2/24
remote_veth "$BC_B" "$BC_C" tinect-shb tinect-shc 10.231.12.1/24 10.231.12.2/24
remote_veth "$CD_C" "$CD_D" tinect-shc tinect-shd 10.231.13.1/24 10.231.13.2/24
remote_veth "$BE_B" "$BE_E" tinect-shb tinect-she 10.231.14.1/24 10.231.14.2/24
remote_veth "$ED_E" "$ED_D" tinect-she tinect-shd 10.231.15.1/24 10.231.15.2/24
for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_E" "$NS_D"; do
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
done

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.65.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.231.11.2:4434]}
  c: {public_key: $CK, endpoints: []}
  e: {public_key: $EK, endpoints: []}
  d: {public_key: $DK, endpoints: [], routes: [{ip_cidr: 10.65.3.3/32, priority: 100}], paths: [{path: [a, b, c, d]}, {path: [a, b, e, d]}]}
allowed_routes: [{allow: [10.65.0.1/32], for: [d]}]
allowed_local_ports: [{allow: [icmp], for: [d]}]
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.65.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  c: {public_key: $CK, endpoints: [quic://10.231.12.2:4435]}
  e: {public_key: $EK, endpoints: [quic://10.231.14.2:4437]}
  d: {public_key: $DK, endpoints: [], paths: [{path: [b, c, d]}, {path: [b, e, d]}]}
  a: {public_key: $AK, endpoints: [quic://10.231.11.1:4433], paths: [{path: [b, a]}]}
connect_to: [c, e]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
allow_transit: true
identity_key_path: $WORK/c.key
listen: quic://0.0.0.0:4435
tun: {name: tunc, addresses: [10.65.2.1/32]}
runtime: {status_socket: $WORK/c.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.231.12.1:4434]}
  d: {public_key: $DK, endpoints: [quic://10.231.13.2:4438], paths: [{path: [c, d]}]}
  a: {public_key: $AK, endpoints: [], paths: [{path: [c, b, a]}]}
connect_to: [d]
EOF
cat >"$WORK/e.yaml" <<EOF
id: e
allow_transit: true
identity_key_path: $WORK/e.key
listen: quic://0.0.0.0:4437
tun: {name: tune, addresses: [10.65.4.1/32]}
runtime: {status_socket: $WORK/e.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.231.14.1:4434]}
  d: {public_key: $DK, endpoints: [quic://10.231.15.2:4438], paths: [{path: [e, d]}]}
  a: {public_key: $AK, endpoints: [], paths: [{path: [e, b, a]}]}
connect_to: [d]
EOF
cat >"$WORK/d.yaml" <<EOF
id: d
identity_key_path: $WORK/d.key
listen: quic://0.0.0.0:4438
tun: {name: tund, addresses: [10.65.3.3/32]}
runtime: {status_socket: $WORK/d.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.65.0.1/32, priority: 100}], paths: [{path: [d, c, b, a]}, {path: [d, e, b, a]}]}
  b: {public_key: $BK, endpoints: []}
  c: {public_key: $CK, endpoints: [quic://10.231.13.1:4435]}
  e: {public_key: $EK, endpoints: [quic://10.231.15.1:4437]}
allowed_routes: [{allow: [10.65.3.3/32], for: [a]}]
allowed_local_ports: [{allow: [icmp], for: [a]}]
connect_to: [c, e]
EOF

start_node_ready b tinect-shb
start_node_ready c tinect-shc
start_node_ready e tinect-she
start_node_ready d tinect-shd
start_node_ready a tinect-sha
wait_paths a,b,c,d d,c,b,a 120
remote_expect_ping tinect-sha tinea 10.65.3.3

# Keep A-B alive while only the second hop changes. The new active path must
# contain E, proving that full ordered identity—not only first-hop instance—
# participates in conditional Circuit commit.
sudo -n ip -n "$NS_C" link set "$CD_C" down
sudo -n ip -n "$NS_D" link set "$CD_D" down
wait_paths a,b,e,d d,e,b,a 90
remote_expect_ping tinect-sha tinea 10.65.3.3

sudo -n ip -n "$NS_C" link set "$CD_C" up
sudo -n ip -n "$NS_D" link set "$CD_D" up
wait_paths a,b,c,d d,c,b,a 120
remote_expect_ping tinect-sha tinea 10.65.3.3
echo "same-first-hop full-path identity switch test passed"
