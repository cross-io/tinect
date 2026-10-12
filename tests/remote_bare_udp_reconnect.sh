#!/usr/bin/env bash
# Reconnect coverage for QUIC's bare-UDP physical carrier. Restarting one
# endpoint must not leave the peer's superseded Link emitting PMTU probes with
# the old Physical session key into the replacement Link.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"

WORK="${WORK:-/tmp/tinect-bare-udp-reconnect-$TINECT_NS_PREFIX}"
NS_A="$(remote_ns tinect-bur-a)"
NS_B="$(remote_ns tinect-bur-b)"
TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"
VETH_A="bu${TOKEN:0:8}a"
VETH_B="bu${TOKEN:0:8}b"

fail() {
  echo "bare-UDP reconnect test failed: $*" >&2
  remote_finish 1
}

start_node() {
  local node="$1" fixture="$2" ns socket
  ns="$(remote_ns "$fixture")"
  socket="$WORK/$node.sock"
  REMOTE_SOCKETS+=("$socket")
  REMOTE_LOG_NODES+=("$node")
  sudo -n ip netns exec "$ns" "$BIN" up "$WORK/$node.yaml" \
    >"$WORK/$node.log" 2>&1 &
  REMOTE_PIDS+=("$!")
}

status_healthy() {
  local node="$1" peer="$2"
  sudo -n "$BIN" status --socket "$WORK/$node.sock" 2>/dev/null |
    python3 -c '
import json
import sys

peer = sys.argv[1]
try:
    status = json.load(sys.stdin)
except (json.JSONDecodeError, OSError):
    raise SystemExit(1)
raise SystemExit(not any(
    link.get("peer") == peer and link.get("healthy") is True
    for link in status.get("links", [])
))
' "$peer"
}

wait_for_socket() {
  local socket="$1" timeout_secs="$2"
  remote_wait_deadline "status socket $socket" "$timeout_secs" "[[ -S '$socket' ]]"
}

wait_for_healthy() {
  local node="$1" peer="$2"
  remote_wait_deadline "healthy $node-$peer link" 45 "status_healthy '$node' '$peer'"
}

stop_node() {
  local fixture="$1" ns pid
  ns="$(remote_ns "$fixture")"
  # Network namespaces do not isolate the PID namespace: a pkill executed
  # through `ip netns exec` would terminate every tinect daemon on the host.
  # Enumerate only processes attached to this namespace and signal those.
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  remote_wait_deadline "$fixture shutdown" 15 \
    "! sudo -n ip netns pids '$ns' 2>/dev/null | grep -q ."
}

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
[[ -x "$BIN" ]] || fail "build the release binary first"
sudo -n true || fail "passwordless sudo is required"

remote_namespace tinect-bur-a
remote_namespace tinect-bur-b
remote_veth "$VETH_A" "$VETH_B" tinect-bur-a tinect-bur-b \
  10.252.0.1/24 10.252.0.2/24
remote_keygen a
remote_keygen b
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.252.0.1:4433
tun: {name: tunea, addresses: [10.90.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.252.0.2:4434], routes: [{ip_cidr: 10.90.0.2/32, priority: 100}]}
connect_to: [b]
EOF

cat >"$WORK/b.yaml" <<EOF
id: b
identity_key_path: $WORK/b.key
listen: quic://10.252.0.2:4434
tun: {name: tunb, addresses: [10.90.0.2/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.252.0.1:4433], routes: [{ip_cidr: 10.90.0.1/32, priority: 100}]}
EOF

start_node b tinect-bur-b
wait_for_socket "$WORK/b.sock" 15
start_node a tinect-bur-a
wait_for_socket "$WORK/a.sock" 15
wait_for_healthy a b
wait_for_healthy b a
remote_expect_ping tinect-bur-a tunea 10.90.0.2

# Replacing B closes A's QUIC control connection while A's old Link still has
# a bare-UDP receiver and PMTU worker. The old implementation leaves those
# workers alive; once B reconnects, its new Link receives stale probes and
# reports repeated physical authentication failures.
stop_node tinect-bur-b
start_node b tinect-bur-b
wait_for_socket "$WORK/b.sock" 15
wait_for_healthy a b
wait_for_healthy b a
remote_expect_ping tinect-bur-a tunea 10.90.0.2

auth_before="$(grep -cF 'physical payload authentication failed' "$WORK/b.log" || true)"
idle_before="$(grep -cF 'physical link received no authenticated payload before idle timeout' "$WORK/b.log" || true)"
sleep 8
auth_after="$(grep -cF 'physical payload authentication failed' "$WORK/b.log" || true)"
idle_after="$(grep -cF 'physical link received no authenticated payload before idle timeout' "$WORK/b.log" || true)"
(( auth_after == auth_before )) || fail "stale physical authentication failures after reconnect: before=$auth_before after=$auth_after"
(( idle_after == idle_before )) || fail "physical idle timeout after reconnect: before=$idle_before after=$idle_after"

echo "bare-UDP reconnect lifecycle test passed"
