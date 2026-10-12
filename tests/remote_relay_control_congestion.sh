#!/usr/bin/env bash
# Verifies that a congested multi-hop fake-TCP Link does not turn control
# writer backpressure or canceled admission waits into a permanently failed
# preferred-path migration.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-relay-control-congestion}"
PREFIX="${TINECT_NS_PREFIX:-tinect-relay-control}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
sudo -n true

for node in a b c; do remote_keygen "$node"; done
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"
CK="$(remote_public_key c)"
for node in a b c; do remote_namespace "$node"; done
remote_veth ab-a ab-b a b 10.230.0.1/24 10.230.0.2/24
remote_veth bc-b bc-c b c 10.231.0.1/24 10.231.0.2/24
remote_veth ac-a ac-c a c 10.232.0.1/24 10.232.0.2/24

# Start with only the direct A<->C path available. The relay Link is then
# restored under a rate limit and delay while B floods D2 traffic over the
# same QUIC+fake-TCP connection.
sudo -n ip -n "$(remote_ns b)" link set bc-b down
sudo -n ip -n "$(remote_ns c)" link set bc-c down
sudo -n ip netns exec "$(remote_ns c)" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns c)" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic-faketcp://0.0.0.0:4433
tun: {name: tinea, addresses: [10.68.0.1/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/a.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
path_migration: {readiness_stability_secs: 1, deadline_secs: 20, drain_timeout_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic-faketcp://10.230.0.2:4434]}
  c: {public_key: $CK, endpoints: [quic-faketcp://10.232.0.2:4435], routes: [{ip_cidr: 10.68.2.2/32, priority: 100}], paths: [{path: [a, b, c]}, {path: [a, c]}]}
connect_to: [b, c]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic-faketcp://0.0.0.0:4434
tun: {name: tunb, addresses: [10.68.1.1/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/b.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic-faketcp://10.230.0.1:4433], paths: [{path: [b, a]}]}
  c: {public_key: $CK, endpoints: [quic-faketcp://10.231.0.2:4435], routes: [{ip_cidr: 10.68.2.2/32, priority: 100}], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic-faketcp://0.0.0.0:4435
tun: {name: tunc, addresses: [10.68.2.2/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/c.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
path_migration: {readiness_stability_secs: 1, deadline_secs: 20, drain_timeout_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic-faketcp://10.232.0.1:4433], routes: [{ip_cidr: 10.68.0.1/32, priority: 100}], paths: [{path: [c, b, a]}, {path: [c, a]}]}
  b: {public_key: $BK, endpoints: [quic-faketcp://10.231.0.1:4434]}
allowed_routes:
  - {allow: [10.68.2.2/32], for: [a, b]}
allowed_local_ports:
  - {allow: [icmp, 'udp(9000)'], for: [a, b]}
EOF

path_is() {
  local node="$1" expected="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" 2>/dev/null)" \
    EXPECTED="$expected" python3 -c '
import json
import os

raw = os.environ["STATUS_JSON"]
if not raw:
    raise SystemExit(1)
try:
    status = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(1)
want = os.environ["EXPECTED"].split(",")
raise SystemExit(not any(
    circuit.get("healthy") and circuit.get("active_path_names") == want
    for circuit in status.get("circuits", [])
))
'
}

link_metrics_are_clean() {
  local node="$1" peer="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" 2>/dev/null)" \
    PEER="$peer" python3 -c '
import json
import os

status = json.loads(os.environ["STATUS_JSON"])
peer = os.environ["PEER"]
links = [link for link in status.get("links", []) if link.get("peer") == peer]
metrics = [link.get("metrics") for link in links if link.get("metrics") is not None]
if not metrics:
    raise SystemExit(1)
raise SystemExit(any(metric.get("stream_admission_rejections", 0) != 0 for metric in metrics))
'
}

remote_start b b
remote_start c c
remote_start a a
remote_assert_timing_profile a
remote_wait_tun a tinea 150
remote_wait_tun c tunc 150

for _ in $(seq 1 300); do
  if path_is a a,c && path_is c c,a; then break; fi
  sleep 0.1
done
path_is a a,c
path_is c c,a
remote_expect_ping a tinea 10.68.2.2

sudo -n ip -n "$(remote_ns b)" link set bc-b up
sudo -n ip -n "$(remote_ns c)" link set bc-c up
remote_wait_deadline "B-C relay Link authenticated" 30 \
  "grep -Eq 'outbound QUIC link authenticated peer_name=b|inbound QUIC link authenticated peer_name=b' '$REMOTE_WORK/c.log' || grep -Eq 'outbound QUIC link authenticated peer_name=c|inbound QUIC link authenticated peer_name=c' '$REMOTE_WORK/b.log'"
# Keep the relay control path congested without turning this fixture into a
# physical-link outage. Link replacement and lossy-path recovery are covered
# by separate fixtures; this scenario targets control-plane backpressure
# during renewal.
sudo -n ip netns exec "$(remote_ns b)" tc qdisc replace dev bc-b root \
  netem rate 1mbit delay 200ms 20ms
sudo -n ip netns exec "$(remote_ns c)" tc qdisc replace dev bc-c root \
  netem rate 1mbit delay 200ms 20ms

FLOOD_PIDS=()
for _ in 1 2 3 4; do
  sudo -n ip netns exec "$(remote_ns b)" python3 - "$WORK/flood.log" <<'PY' &
import socket
import sys
import time

log_path = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"x" * 800
deadline = time.monotonic() + 70
sent = 0
while time.monotonic() < deadline:
    try:
        sock.sendto(payload, ("10.68.2.2", 9000))
        sent += 1
    except OSError:
        # Link replacement can temporarily withdraw the overlay route. Keep
        # the generator alive so the next authenticated Link is exercised.
        time.sleep(0.01)
        continue
    time.sleep(0.02)
with open(log_path, "a", encoding="ascii") as log:
    log.write(f"{sent}\n")
PY
  REMOTE_PIDS+=("$!")
  FLOOD_PIDS+=("$!")
done

# The migration must complete while the relay carries D2 load. In the old
# implementation all eight S0 writer slots could be occupied by slow writes;
# the next relay OPEN was then rejected locally and the preferred candidate
# was quarantined as if the path itself had failed.
for _ in $(seq 1 900); do
  if path_is a a,b,c && path_is c c,b,a; then
    break
  fi
  sleep 0.1
done
path_is a a,b,c
path_is c c,b,a

# Force a bounded burst of severe loss and delay while control writers and D2
# traffic are active. Some admission waits can time out or be canceled here;
# restoring the carrier must also restore the exact queue and byte budgets,
# rather than leaving an invisible waiter that poisons later renewals.
sudo -n ip netns exec "$(remote_ns b)" tc qdisc replace dev bc-b root \
  netem rate 128kbit delay 500ms 100ms loss 35% limit 20
sudo -n ip netns exec "$(remote_ns c)" tc qdisc replace dev bc-c root \
  netem rate 128kbit delay 500ms 100ms loss 35% limit 20
sleep 8
sudo -n ip netns exec "$(remote_ns b)" tc qdisc replace dev bc-b root \
  netem rate 1mbit delay 200ms 20ms
sudo -n ip netns exec "$(remote_ns c)" tc qdisc replace dev bc-c root \
  netem rate 1mbit delay 200ms 20ms

# Keep the flood running across a full configured renewal interval. A saturated
# control stream may make the implementation replace the physical Link; the
# active multi-hop lease must still converge again instead of staying revoked
# merely because one renewal met local admission backpressure.
if [[ "${TINECT_TEST_TIMING_PROFILE:-}" == "circuit-fast" ]]; then
  sleep 4
else
  sleep 32
fi
# The generators continue for 70 seconds.  Do not treat a transiently clean
# Link as final convergence while a later renewal can still be affected by the
# intentionally saturated control path.
for pid in "${FLOOD_PIDS[@]}"; do
  wait "$pid"
done
remote_wait_deadline "multi-hop path and control links recovered after congested renewal" 120 \
  "path_is a a,b,c && path_is c c,b,a && link_metrics_are_clean b c && link_metrics_are_clean c b"
path_is a a,b,c
path_is c c,b,a
link_metrics_are_clean b c
link_metrics_are_clean c b
remote_expect_ping a tinea 10.68.2.2
echo "relay control congestion and renewal test passed"
