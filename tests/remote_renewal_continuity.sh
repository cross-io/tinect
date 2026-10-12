#!/usr/bin/env bash
# Verifies that an idle circuit renews on its absolute protocol deadline even
# while continuous topology deltas keep waking the source worker.
#
# keepalive_secs=1 makes B advertise a fresh LSA every second.  Each accepted
# delta calls request_reconcile, so the source's opens generation is bumped
# continuously.  A relative sleep-based RENEW timer would be restarted by
# every one of those events and starved; the absolute sleep_until deadline
# must still deliver a signed renewal every CIRCUIT_RENEW_INTERVAL and the
# circuit must never be rebuilt while its lease is alive.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-renewal}"
WORK="${WORK:-/tmp/tinect-renewal-$TINECT_NS_PREFIX}"
NS_B="$(remote_ns tinect-rb)"
if [[ "${TINECT_TEST_TIMING_PROFILE:-}" == "circuit-fast" ]]; then
  DEFAULT_RENEW_WINDOW_SECONDS=7
else
  DEFAULT_RENEW_WINDOW_SECONDS=90
fi
RENEW_WINDOW_SECONDS="${RENEW_WINDOW_SECONDS:-$DEFAULT_RENEW_WINDOW_SECONDS}"
MIN_RENEWS="${MIN_RENEWS:-2}"

fail() {
  echo "renewal continuity integration test failed: $*" >&2
  for node in a b; do
    echo "===== $node log =====" >&2
    cat "$WORK/$node.log" >&2 || true
  done
  remote_finish 1
}

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
[[ -x "$BIN" ]] || fail "build the release binary first"
sudo -n true || fail "passwordless sudo is required"
remote_keygen a
remote_keygen b
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"
remote_namespace tinect-ra
remote_namespace tinect-rb
remote_veth rn-a rn-b tinect-ra tinect-rb 10.200.0.1/24 10.200.0.2/24
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.200.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime:
  status_socket: $WORK/a.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.200.0.2:4434], routes: [{ip_cidr: 10.64.0.2/32, priority: 100}], paths: [{path: [a, b]}]}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
identity_key_path: $WORK/b.key
listen: quic://10.200.0.2:4434
tun: {name: tunb, addresses: [10.64.0.2/32]}
runtime:
  status_socket: $WORK/b.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.200.0.1:4433], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [b, a]}]}
allowed_routes: [{allow: [10.64.0.2/32], for: [a]}]
allowed_local_ports: [{allow: [icmp], for: [a]}]
EOF

remote_start b tinect-rb
remote_start a tinect-ra
remote_assert_timing_profile a
remote_wait_tun tinect-ra tinea
remote_wait_tun tinect-rb tunb
remote_wait_log b 'circuit exit authorization installed' 300
remote_expect_ping tinect-ra tinea 10.64.0.2

OPEN_BEFORE="$(grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true)"
RENEW_BEFORE="$(grep -c 'circuit renewal acknowledged' "$WORK/a.log" || true)"

# The peer lease is twelve hours, so a renew outage is not observable through
# circuit expiry inside a test window.  Assert on the signed renewal itself:
# under a continuous topology-event stream the absolute deadline must still
# fire at least MIN_RENEWS times, and the source must not rebuild the circuit
# (no new OPEN) while the lease stays alive.
sleep "$RENEW_WINDOW_SECONDS"

RENEW_AFTER="$(grep -c 'circuit renewal acknowledged' "$WORK/a.log" || true)"
OPEN_AFTER="$(grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true)"
[[ "$RENEW_AFTER" -ge $((RENEW_BEFORE + MIN_RENEWS)) ]] \
  || fail "RENEW not delivered on schedule under continuous topology events ($RENEW_BEFORE -> $RENEW_AFTER)"
[[ "$OPEN_AFTER" == "$OPEN_BEFORE" ]] \
  || fail "idle circuit was rebuilt during the renewal window (OPEN $OPEN_BEFORE -> $OPEN_AFTER)"
remote_expect_ping tinect-ra tinea 10.64.0.2

echo "renewal continuity integration test passed"
