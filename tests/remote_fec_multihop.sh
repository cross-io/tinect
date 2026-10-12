#!/usr/bin/env bash
# Privileged three-node FEC test. It injects loss/reordering on both physical
# hops, checks that each Link converges independently, and replaces the relay
# to ensure the old decoder and feedback state are not reused.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-fec-multihop}"
WORK="${WORK:-/tmp/tinect-fec-multihop}"
FEC_RATE="${FEC_RATE:-1.5}"
# Keep both loss probes comfortably inside the CI job's bounded runtime while
# still sending enough source symbols to exercise repair and feedback.
FEC_PING_COUNT="${FEC_PING_COUNT:-120}"
FEC_PING_INTERVAL="${FEC_PING_INTERVAL:-0.1}"
FEC_HEALTH_PING_COUNT="${FEC_HEALTH_PING_COUNT:-4000}"
source "$PWD/tests/lib/remote.sh"
remote_init "$WORK"
trap 'remote_finish $?' EXIT

sudo -n true
for node in a r b; do
  remote_namespace "$node"
  remote_keygen "$node"
done
remote_veth ar-a ar-r a r 10.250.0.1/24 10.250.0.2/24
remote_veth rb-r rb-b r b 10.251.0.1/24 10.251.0.2/24
AK="$(remote_public_key a)"
RK="$(remote_public_key r)"
BK="$(remote_public_key b)"
for namespace in "$(remote_ns a)" "$(remote_ns r)" "$(remote_ns b)"; do
  sudo -n ip netns exec "$namespace" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$namespace" sysctl -qw net.ipv6.conf.all.forwarding=1
done

cat >"$REMOTE_WORK/a.yaml" <<EOF
id: a
identity_key_path: $REMOTE_WORK/a.key
listen: quic://10.250.0.1:4433
repair_rate: $FEC_RATE
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
tun: {name: tinea, addresses: [10.70.0.1/32]}
peers:
  r: {public_key: $RK, endpoints: [quic://10.250.0.2:4434]}
  b:
    public_key: $BK
    endpoints: []
    routes: [{ip_cidr: 10.70.0.2/32, priority: 100}]
    paths: [{path: [a, r, b]}]
connect_to:
  - {peer: r, repair_rate: $FEC_RATE}
EOF

cat >"$REMOTE_WORK/r.yaml" <<EOF
id: r
allow_transit: true
identity_key_path: $REMOTE_WORK/r.key
listen: quic://0.0.0.0:4434
repair_rate: $FEC_RATE
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
tun: {name: tunr, addresses: [10.70.1.1/32]}
peers:
  a: {public_key: $AK, endpoints: [quic://10.250.0.1:4433], paths: [{path: [r, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.251.0.2:4435], paths: [{path: [r, b]}]}
connect_to:
  - {peer: b, repair_rate: $FEC_RATE}
EOF

cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
identity_key_path: $REMOTE_WORK/b.key
listen: quic://10.251.0.2:4435
repair_rate: $FEC_RATE
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
tun: {name: tunb, addresses: [10.70.0.2/32]}
peers:
  r: {public_key: $RK, endpoints: [quic://10.251.0.1:4434]}
  a:
    public_key: $AK
    endpoints: []
    routes: [{ip_cidr: 10.70.0.1/32, priority: 100}]
    paths: [{path: [b, r, a]}]
allowed_routes:
  - {allow: [10.70.0.2/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF

remote_start b b
remote_start r r
remote_start a a
remote_wait_tun a tinea
remote_wait_tun b tunb
remote_wait_log a 'circuit OPEN acknowledged' 300
remote_expect_ping a tinea 10.70.0.2

inject_loss() {
  for pair in \
    "$(remote_ns a):ar-a" \
    "$(remote_ns r):ar-r" \
    "$(remote_ns r):rb-r" \
    "$(remote_ns b):rb-b"; do
    local namespace="${pair%%:*}"
    local interface="${pair##*:}"
    sudo -n ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
      delay 10ms loss 20% reorder 10% 50%
  done
}

clear_loss() {
  for pair in \
    "$(remote_ns a):ar-a" \
    "$(remote_ns r):ar-r" \
    "$(remote_ns r):rb-r" \
    "$(remote_ns b):rb-b"; do
    local namespace="${pair%%:*}"
    local interface="${pair##*:}"
    sudo -n ip netns exec "$namespace" tc qdisc del dev "$interface" root 2>/dev/null || true
  done
}

fec_metric() {
  local node="$1" peer="$2" field="$3"
  sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" |
    python3 -c '
import json
import sys

peer, field = sys.argv[1:]
status = json.load(sys.stdin)
for link in status.get("links", []):
    if link.get("peer") == peer:
        print((link.get("metrics") or {}).get(field, 0))
        raise SystemExit(0)
raise SystemExit(1)
' "$peer" "$field"
}

assert_positive() {
  local node="$1" peer="$2" field="$3" value
  value="$(fec_metric "$node" "$peer" "$field")"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    echo "$node->$peer $field did not converge: $value" >&2
    return 1
  }
}

link_is_healthy() {
  local node="$1" peer="$2" expected="$3"
  sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" |
    python3 -c '
import json
import sys

peer, expected = sys.argv[1:]
status = json.load(sys.stdin)
for link in status.get("links", []):
    if link.get("peer") == peer:
        raise SystemExit(0 if link.get("healthy") is (expected == "true") else 1)
raise SystemExit(1)
' "$peer" "$expected"
}

wait_for_link_health() {
  local description="$1" node="$2" peer="$3" expected="$4"
  remote_wait_deadline "$description" 60 "link_is_healthy '$node' '$peer' '$expected'"
}

run_loss_probe() {
  inject_loss
  sudo -n ip netns exec "$(remote_ns a)" ping -I tinea -s 900 \
    -i "$FEC_PING_INTERVAL" -c "$FEC_PING_COUNT" -W 1 10.70.0.2 >/dev/null || true
  clear_loss
}

run_loss_probe
assert_positive r a fec_rx_repairs
assert_positive r a fec_recovered
assert_positive b r fec_rx_repairs
assert_positive b r fec_recovered

# Drop almost all datagrams only on the relay->source hop. The reverse path
# remains available for reliable FEC reports, so this exercises the saturated
# report health edge without turning it into a transport disconnect test.
sudo -n ip netns exec "$(remote_ns r)" tc qdisc replace dev ar-r root netem \
  delay 10ms loss 99%
sudo -n ip netns exec "$(remote_ns b)" ping -I tunb -s 900 \
  -i 0.001 -c "$FEC_HEALTH_PING_COUNT" -W 1 10.70.0.1 >/dev/null || true
clear_loss
wait_for_link_health 'relay-to-source FEC health degradation' r a false

# Do not send ordinary traffic after the loss is removed.  The only packets
# that can produce the two valid recovery windows are Link-local FEC probes;
# this is the regression check for a unique unhealthy first hop.
wait_for_link_health 'relay-to-source FEC health recovery' r a true

# Kill only the relay daemon. The next source packet must use a fresh pair of
# Link instances, with fresh ESI/RID/decoder/report state on both hops.
for pid in $(sudo -n ip netns pids "$(remote_ns r)"); do
  if [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == tinect ]]; then
    sudo -n kill -KILL "$pid" 2>/dev/null || true
  fi
done
remote_wait_for 'relay process shutdown' \
  "[[ -z \"\$(sudo -n ip netns pids '$(remote_ns r)' 2>/dev/null)\" ]]" 100
remote_start r r
remote_wait_log r 'outbound QUIC link authenticated' 300
remote_wait_deadline 'post-replacement circuit recovery' 90 \
  "sudo -n ip netns exec '$(remote_ns a)' ping -I tinea -c 1 -W 1 10.70.0.2"
run_loss_probe
assert_positive r a fec_rx_repairs
assert_positive r a fec_recovered
assert_positive r a fec_feedback_sent
assert_positive b r fec_rx_repairs
assert_positive b r fec_recovered
assert_positive b r fec_feedback_sent

echo "three-node FEC loss/reorder and relay replacement test passed"
