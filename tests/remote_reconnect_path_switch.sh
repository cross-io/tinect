#!/usr/bin/env bash
# Verifies bidirectional path selection across four nodes after short and
# long relay outages. A-B-D is preferred; A-C-D is the fallback.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"

TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-reconnect-path}"
WORK="${WORK:-/tmp/tinect-reconnect-path-$TINECT_NS_PREFIX}"
NS_A="$(remote_ns tinect-rpa)"
NS_B="$(remote_ns tinect-rpb)"
NS_C="$(remote_ns tinect-rpc)"
NS_D="$(remote_ns tinect-rpd)"
PIDS=()

VETH_TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"
METRICS_PORT=$((19900 + VETH_TOKEN % 1000))
AB_A="rpa${VETH_TOKEN:0:7}a"
AB_B="rpa${VETH_TOKEN:0:7}b"
BD_B="rpa${VETH_TOKEN:0:7}c"
BD_D="rpa${VETH_TOKEN:0:7}d"
AC_A="rpa${VETH_TOKEN:0:7}e"
AC_C="rpa${VETH_TOKEN:0:7}f"
CD_C="rpa${VETH_TOKEN:0:7}g"
CD_D="rpa${VETH_TOKEN:0:7}h"

fail() {
  echo "reconnect/path-switch integration test failed: $*" >&2
  remote_finish 1
}

start_node() {
  local node="$1" fixture="$2" socket="$WORK/$1.sock"
  REMOTE_SOCKETS+=("$socket")
  REMOTE_LOG_NODES+=("$node")
  sudo -n env "TINECT_TEST_TIMING_PROFILE=$TINECT_TEST_TIMING_PROFILE" \
    ip netns exec "$(remote_ns "$fixture")" "$BIN" up "$WORK/$node.yaml" \
    >>"$WORK/$node.log" 2>&1 &
  REMOTE_PIDS+=("$!")
}

stop_node() {
  local node="$1" fixture="$2" ns pid
  ns="$(remote_ns "$fixture")"
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  for _ in $(seq 1 100); do
    if [[ -z "$(sudo -n ip netns pids "$ns" 2>/dev/null || true)" ]]; then
      break
    fi
    sleep 0.1
  done
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  for _ in $(seq 1 50); do
    [[ ! -e "$WORK/$node.sock" ]] && return 0
    sleep 0.1
  done
  fail "socket for stopped node $node did not disappear"
}

status_json() {
  sudo -n "$BIN" status --socket "$WORK/$1.sock" 2>/dev/null
}

link_is_closed() {
  STATUS_JSON="$(status_json a)" python3 -c '
import json
import os

try:
    status = json.loads(os.environ["STATUS_JSON"])
except (KeyError, json.JSONDecodeError):
    raise SystemExit(1)

raise SystemExit(not any(
    link.get("peer") == "b"
    and link.get("last_error") == "QUIC connection closed"
    for link in status.get("links", [])
))
' 2>/dev/null
}

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
  local expected_a="$1" expected_d="$2" timeout_secs="$3"
  for _ in $(seq 1 "$((timeout_secs * 10))"); do
    if path_is a d "$expected_a" && path_is d a "$expected_d"; then
      return 0
    fi
    sleep 0.1
  done
  fail "A path did not become [$expected_a] or D path did not become [$expected_d]"
}

expect_bidirectional_ping() {
  remote_expect_ping tinect-rpa tinea 10.64.3.3
  remote_expect_ping tinect-rpd tund 10.64.0.1
}

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT

[[ -x "$BIN" ]] || fail "build the release binary first: cargo build --release"
sudo -n true || fail "passwordless sudo is required"

for node in a b c d; do
  remote_keygen "$node"
done
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"
CK="$(remote_public_key c)"
DK="$(remote_public_key d)"

remote_namespace tinect-rpa
remote_namespace tinect-rpb
remote_namespace tinect-rpc
remote_namespace tinect-rpd
remote_veth "$AB_A" "$AB_B" tinect-rpa tinect-rpb 10.230.11.1/24 10.230.11.2/24
remote_veth "$BD_B" "$BD_D" tinect-rpb tinect-rpd 10.230.12.1/24 10.230.12.2/24
remote_veth "$AC_A" "$AC_C" tinect-rpa tinect-rpc 10.230.13.1/24 10.230.13.2/24
remote_veth "$CD_C" "$CD_D" tinect-rpc tinect-rpd 10.230.14.1/24 10.230.14.2/24
# A and D are exits for the two directions of the overlay traffic. Keep the
# administrator-owned forwarding precondition explicit in every isolated
# namespace so the test does not depend on the host's global sysctl state.
for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_D"; do
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
done

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock, metrics_listen: 127.0.0.1:$METRICS_PORT, pcap_buffer_packets: 16}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.230.11.2:4434]}
  c: {public_key: $CK, endpoints: [quic://10.230.13.2:4435]}
  d: {public_key: $DK, endpoints: [], routes: [{ip_cidr: 10.64.3.3/32, priority: 100}], paths: [{path: [a, b, d]}, {path: [a, c, d]}]}
allowed_routes:
  - {allow: [10.64.0.1/32], for: [d]}
allowed_local_ports:
  - {allow: [icmp], for: [d]}
connect_to: [b, c]
EOF

cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  d: {public_key: $DK, endpoints: [quic://10.230.12.2:4436], paths: [{path: [b, d]}]}
  a: {public_key: $AK, endpoints: [quic://10.230.11.1:4433], paths: [{path: [b, a]}]}
connect_to: [d]
EOF

cat >"$WORK/c.yaml" <<EOF
id: c
allow_transit: true
identity_key_path: $WORK/c.key
listen: quic://0.0.0.0:4435
tun: {name: tunc, addresses: [10.64.2.1/32]}
runtime: {status_socket: $WORK/c.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  d: {public_key: $DK, endpoints: [quic://10.230.14.2:4436], paths: [{path: [c, d]}]}
  a: {public_key: $AK, endpoints: [quic://10.230.13.1:4433], paths: [{path: [c, a]}]}
connect_to: [d]
EOF

cat >"$WORK/d.yaml" <<EOF
id: d
identity_key_path: $WORK/d.key
listen: quic://0.0.0.0:4436
tun: {name: tund, addresses: [10.64.3.3/32]}
runtime: {status_socket: $WORK/d.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [d, c, a]}, {path: [d, b, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.230.12.1:4434]}
  c: {public_key: $CK, endpoints: [quic://10.230.14.1:4435]}
allowed_routes:
  - {allow: [10.64.3.3/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
# B and C already establish the only two physical links D needs.  Letting D
# dial them too races two valid QUIC connections for each edge; the losing
# endpoint is deliberately superseded and can leave the fallback branch
# without a completed topology snapshot.  This test exercises circuit
# failover, not duplicate-link arbitration, so keep the physical topology
# deterministic.
connect_to: []
EOF

start_node b tinect-rpb
start_node c tinect-rpc
start_node d tinect-rpd
start_node a tinect-rpa
remote_assert_timing_profile a

# The resolver must prefer the first ready candidate on both ends before any
# outage is injected. This also proves that both relay branches are ready.
wait_paths a,b,d d,c,a 120
expect_bidirectional_ping

# Exercise the operational surfaces alongside the data plane: metrics must be
# loopback-only but reachable inside the node namespace, and enabled PCAP must
# contain a captured inner packet after the first successful exchange.
sudo -n ip netns exec "$NS_A" python3 - "$METRICS_PORT" <<'PY'
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
sock.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
reply = sock.recv(65535)
if b"200 OK" not in reply or b"tinect_links_healthy" not in reply or b"tinect_flows" not in reply:
    raise SystemExit("metrics response did not contain expected gauges")
PY
sudo -n "$BIN" pcap --socket "$WORK/a.sock" --output "$WORK/a.pcap" >/dev/null
[[ "$(sudo -n stat -c %s "$WORK/a.pcap")" -gt 24 ]] || fail "enabled PCAP did not capture an inner packet"

# LSA refreshes and proof renewals must not rebuild a semantically unchanged
# circuit. Cross multiple advertisement intervals and compare
# source-side OPEN acknowledgements before and after the quiet period.
INITIAL_OPEN_ACKS="$(grep -c 'circuit OPEN acknowledged dst=d' "$WORK/a.log" || true)"
if [[ "${TINECT_TEST_TIMING_PROFILE:-}" == "topology-fast" ]]; then
  sleep 8
else
  sleep 20
fi
wait_paths a,b,d d,c,a 10
[[ "$(grep -c 'circuit OPEN acknowledged dst=d' "$WORK/a.log" || true)" == "$INITIAL_OPEN_ACKS" ]] \
  || fail "LSA refresh caused an unnecessary source circuit OPEN"

# Short outage: stop only the preferred relay, wait for both directions to
# switch to A-C-D, then reconnect it immediately after fallback converges.
stop_node b tinect-rpb
remote_wait_deadline "A status reports B closed" 30 link_is_closed \
  || fail "A did not observe B closing"
wait_paths a,c,d d,c,a 60
expect_bidirectional_ping
start_node b tinect-rpb
wait_paths a,b,d d,c,a 120
expect_bidirectional_ping

# Repeat the short outage to catch stale Link-instance/lease state and
# duplicate active circuits after a successful migration has already occurred.
stop_node b tinect-rpb
remote_wait_deadline "A status reports repeated B close" 30 link_is_closed \
  || fail "A did not observe the repeated B close"
wait_paths a,c,d d,c,a 60
expect_bidirectional_ping
start_node b tinect-rpb
wait_paths a,b,d d,c,a 120
expect_bidirectional_ping

# Long outage: keep the same relay absent beyond its five-second idle timeout.
# The fallback must remain active and usable while the preferred branch is
# unavailable; after restart the source and destination must migrate back.
stop_node b tinect-rpb
remote_wait_deadline "A status reports B closed during long outage" 30 link_is_closed \
  || fail "A did not observe B closing during long outage"
wait_paths a,c,d d,c,a 60
sleep 8
path_is a d a,c,d || fail "A left the fallback path during the long outage"
path_is d a d,c,a || fail "D left the fallback path during the long outage"
expect_bidirectional_ping
start_node b tinect-rpb
wait_paths a,b,d d,c,a 120
expect_bidirectional_ping

echo "four-node short/long relay reconnect and bidirectional path-switch test passed"
