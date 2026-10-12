#!/usr/bin/env bash
# Fault-injects downstream process/link loss while the source first hop stays
# alive.  The source must receive a signed CircuitBroken
# feedback, withdraw the stale lease, and establish a fresh circuit.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-circuit-feedback}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-feedback}"
source "$PWD/tests/lib/remote.sh"

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
[[ -x "$BIN" ]] || { echo "build the release binary first: cargo build --release" >&2; exit 1; }
sudo -n true

# The circuit-fast watchdog case intentionally keeps A-B's Link alive longer
# than the source-side lease grace.  Otherwise a dropped reverse feedback
# frame would be hidden by first-hop Link teardown instead of exercising the
# local renewal fallback.
if [[ "$TINECT_TEST_TIMING_PROFILE" == "circuit-fast" ]]; then
  A_B_IDLE_TIMEOUT=60
  B_A_IDLE_TIMEOUT=60
else
  A_B_IDLE_TIMEOUT=5
  B_A_IDLE_TIMEOUT=5
fi

for node in a b c; do remote_keygen "$node"; done
remote_namespace tinect-fb-a
remote_namespace tinect-fb-b
remote_namespace tinect-fb-c
remote_veth fb-ab-a fb-ab-b tinect-fb-a tinect-fb-b 10.251.0.1/24 10.251.0.2/24
remote_veth fb-bc-b fb-bc-c tinect-fb-b tinect-fb-c 10.252.0.1/24 10.252.0.2/24
sudo -n ip netns exec "$(remote_ns tinect-fb-c)" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns tinect-fb-c)" sysctl -qw net.ipv6.conf.all.forwarding=1

AK="$(remote_public_key a)"
BK="$(remote_public_key b)"
CK="$(remote_public_key c)"
cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.251.0.1:4433
tun: {name: tinea, addresses: [10.67.0.1/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/a.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: $A_B_IDLE_TIMEOUT, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.251.0.2:4434]}
  c: {public_key: $CK, endpoints: [], routes: [{ip_cidr: 10.67.2.2/32, priority: 100}], paths: [{path: [a, b, c]}]}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.67.1.1/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/b.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: $B_A_IDLE_TIMEOUT, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.251.0.1:4433], paths: [{path: [b, a]}]}
  c: {public_key: $CK, endpoints: [quic://10.252.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://10.252.0.2:4435
tun: {name: tunc, addresses: [10.67.2.2/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/c.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.67.0.1/32, priority: 100}], paths: [{path: [c, b, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.252.0.1:4434]}
allowed_routes:
  - {allow: [10.67.2.2/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF

start_c() { remote_start c tinect-fb-c; }
kill_c() {
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$(remote_ns tinect-fb-c)" 2>/dev/null || true)
}
feedback_count() {
  grep -Ec 'downstream circuit failure invalidated source snapshot' "$WORK/a.log" || true
}
ack_count() { grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true; }
wait_feedback_increment() {
  local before="$1"
  remote_wait_deadline 'source circuit feedback' 30 "((\$(feedback_count) > $before))"
}
wait_new_ack() {
  local before="$1"
  remote_wait_deadline 'fresh circuit acknowledgement' 45 "((\$(ack_count) > $before))"
}

start_c
remote_start b tinect-fb-b
remote_start a tinect-fb-a
remote_wait_tun tinect-fb-a tinea
remote_wait_tun tinect-fb-c tunc
remote_wait_log b 'circuit relay installed' 1000
remote_wait_log c 'circuit exit authorization installed' 1000
remote_expect_ping tinect-fb-a tinea 10.67.2.2

# Case 1: abrupt downstream exit restart.  A-B remains connected, so the
# source can recover only if B propagates feedback or the renewal fallback
# notices that C no longer owns the binding.
feedback_before="$(feedback_count)"
ack_before="$(ack_count)"
kill_c
sleep 0.2
start_c
remote_wait_tun tinect-fb-c tunc
wait_feedback_increment "$feedback_before"
wait_new_ack "$ack_before"
remote_expect_ping tinect-fb-a tinea 10.67.2.2

# Case 2: repeat the crash/reconnect quickly.  This covers duplicate and late
# feedback while a replacement C Link is already registered.
for _ in 1 2 3; do
  feedback_before="$(feedback_count)"
  ack_before="$(ack_count)"
  kill_c
  sleep 0.2
  start_c
  remote_wait_tun tinect-fb-c tunc
  wait_feedback_increment "$feedback_before"
  wait_new_ack "$ack_before"
  remote_expect_ping tinect-fb-a tinea 10.67.2.2
done

# Case 3: only the downstream B-C underlay is blackholed.  A-B remains up,
# which specifically exercises removal of an outgoing relay binding and the
# reverse CircuitBroken path instead of first-hop Link teardown.
feedback_before="$(feedback_count)"
sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc replace dev fb-bc-b root netem loss 100%
sudo -n ip netns exec "$(remote_ns tinect-fb-c)" tc qdisc replace dev fb-bc-c root netem loss 100%
wait_feedback_increment "$feedback_before"
sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc del dev fb-bc-b root
sudo -n ip netns exec "$(remote_ns tinect-fb-c)" tc qdisc del dev fb-bc-c root
remote_expect_ping tinect-fb-a tinea 10.67.2.2

# Case 4 (circuit-fast only): remove the downstream binding and blackhole the
# reverse A-B direction at the same time.  B can no longer deliver its signed
# CircuitBroken feedback, while A-B itself stays alive.  A must therefore
# invalidate the active circuit when its long-lease-sized local failure grace
# expires, then rebuild after both underlays are restored.
if [[ "$TINECT_TEST_TIMING_PROFILE" == "circuit-fast" ]]; then
  watchdog_before="$(grep -c 'reason="circuit renewal failure grace expired"' "$WORK/a.log" || true)"
  ack_before="$(ack_count)"
  sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc replace dev fb-ab-b root netem loss 100%
  sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc replace dev fb-bc-b root netem loss 100%
  sudo -n ip netns exec "$(remote_ns tinect-fb-c)" tc qdisc replace dev fb-bc-c root netem loss 100%
  remote_wait_deadline 'source local renewal failure grace expiry' 35 \
    "((\$(grep -c 'reason=\"circuit renewal failure grace expired\"' '$WORK/a.log' || true) > $watchdog_before))"
  sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc del dev fb-bc-b root
  sudo -n ip netns exec "$(remote_ns tinect-fb-c)" tc qdisc del dev fb-bc-c root
  sudo -n ip netns exec "$(remote_ns tinect-fb-b)" tc qdisc del dev fb-ab-b root
  wait_new_ack "$ack_before"
  remote_expect_ping tinect-fb-a tinea 10.67.2.2
fi

echo "circuit feedback fault-injection tests passed"
