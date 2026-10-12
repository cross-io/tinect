#!/usr/bin/env bash
# Verifies runtime OPEN failure on a ready preferred relay path falls back to
# a ready direct path, then migrates back after the relay recovers.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-open-candidate-fallback}"
PREFIX="${TINECT_NS_PREFIX:-tinect-open-fallback}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"

remote_init "$WORK"
trap remote_cleanup EXIT
sudo -n true

for node in a b c; do remote_keygen "$node"; done
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"
CK="$(remote_public_key c)"
for node in a b c; do remote_namespace "$node"; done
remote_veth ab-a ab-b a b 10.220.0.1/24 10.220.0.2/24
remote_veth bc-b bc-c b c 10.221.0.1/24 10.221.0.2/24
remote_veth ac-a ac-c a c 10.222.0.1/24 10.222.0.2/24
sudo -n ip netns exec "$(remote_ns c)" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns c)" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.65.0.1/32]}
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.220.0.2:4434]}
  c: {public_key: $CK, endpoints: [quic://10.222.0.2:4435], routes: [{ip_cidr: 10.65.2.2/32, priority: 100}], paths: [{path: [a, b, c]}, {path: [a, c]}]}
connect_to: [b, c]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.65.1.1/32]}
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.220.0.1:4433], paths: [{path: [b, a]}]}
  c: {public_key: $CK, endpoints: [quic://10.221.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://0.0.0.0:4435
tun: {name: tunc, addresses: [10.65.2.2/32]}
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.222.0.1:4433], routes: [{ip_cidr: 10.65.0.1/32, priority: 100}], paths: [{path: [c, b, a]}, {path: [c, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.221.0.1:4434]}
allowed_routes:
  - {allow: [10.65.2.2/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
connect_to: [b]
EOF

# Establish B<->C and advertise that edge before the source starts. The
# preferred path will therefore pass local readiness checks even though its
# next relay hop is about to lose control traffic.
remote_start b b
remote_start c c
remote_wait_log b "outbound QUIC link authenticated" 150
remote_wait_log c "inbound QUIC link authenticated" 150
sudo -n ip netns exec "$(remote_ns b)" tc qdisc add dev bc-b root netem loss 100%

remote_start a a

path_is() {
  local node="$1" expected="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" 2>/dev/null)" EXPECTED="$expected" python3 -c '
import json, os
raw = os.environ["STATUS_JSON"]
if not raw:
    raise SystemExit(1)
try:
    status = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(1)
want = os.environ["EXPECTED"].split(",")
raise SystemExit(not any(
    circuit.get("destination") in ("c", "a")
    and circuit.get("healthy")
    and circuit.get("active_path_names") == want
    for circuit in status.get("circuits", [])
))
'
}

for _ in $(seq 1 300); do
  if path_is a a,c; then break; fi
  sleep 0.1
done
path_is a a,c
remote_expect_ping a tinea 10.65.2.2

# Restore the underlay without restarting any daemon. The preferred relay
# candidate should become usable again and migration must converge to it.
sudo -n ip netns exec "$(remote_ns b)" tc qdisc del dev bc-b root
for _ in $(seq 1 300); do
  if path_is a a,b,c; then
    echo "OPEN candidate fallback test passed"
    exit 0
  fi
  sleep 0.1
done
echo "OPEN candidate fallback did not migrate back to the preferred path" >&2
remote_report_failure
exit 1
