#!/usr/bin/env bash
# Verifies that sustained data traffic keeps a circuit alive through the
# throttled lease-refresh path.  refresh_binding rewrites the 12-hour lease
# deadline at most once per throttle window, but every authenticated packet
# must still keep the circuit usable: no source OPEN (rebuild) may happen
# during a traffic burst that spans several lease-refresh windows.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-active-lease}"
WORK="${WORK:-/tmp/tinect-active-lease-$TINECT_NS_PREFIX}"
NS_A="$(remote_ns tinect-la)"
NS_B="$(remote_ns tinect-lb)"
if [[ "${TINECT_TEST_TIMING_PROFILE:-}" == "circuit-fast" ]]; then
  DEFAULT_TRAFFIC_PINGS=12
else
  DEFAULT_TRAFFIC_PINGS=60
fi
TRAFFIC_PINGS="${TRAFFIC_PINGS:-$DEFAULT_TRAFFIC_PINGS}"
PING_INTERVAL_SECONDS="${PING_INTERVAL_SECONDS:-1}"

fail() {
  echo "active lease continuity integration test failed: $*" >&2
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
remote_namespace tinect-la
remote_namespace tinect-lb
remote_veth al-a al-b tinect-la tinect-lb 10.210.0.1/24 10.210.0.2/24
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.210.0.1:4433
tun: {name: tinea, addresses: [10.67.0.1/32]}
runtime:
  status_socket: $WORK/a.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.210.0.2:4434], routes: [{ip_cidr: 10.67.0.2/32, priority: 100}], paths: [{path: [a, b]}]}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
identity_key_path: $WORK/b.key
listen: quic://10.210.0.2:4434
tun: {name: tunb, addresses: [10.67.0.2/32]}
runtime:
  status_socket: $WORK/b.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [quic://10.210.0.1:4433], routes: [{ip_cidr: 10.67.0.1/32, priority: 100}], paths: [{path: [b, a]}]}
allowed_routes: [{allow: [10.67.0.2/32], for: [a]}]
allowed_local_ports: [{allow: [icmp], for: [a]}]
EOF

remote_start b tinect-lb
remote_start a tinect-la
remote_assert_timing_profile a
remote_wait_tun tinect-la tinea
remote_wait_tun tinect-lb tunb
remote_wait_log b 'circuit exit authorization installed' 300
remote_expect_ping tinect-la tinea 10.67.0.2

OPEN_BEFORE="$(grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true)"

# One ping per second for well over the lease-refresh throttle window. Under
# circuit-fast this also crosses the complete eight-second receiver lease,
# making a missing refresh/renew observable instead of relying on the
# production twelve-hour safety margin. A rebuild would tear down the circuit
# and fail a probe, so every ping must succeed and the OPEN count must stay
# flat.
for i in $(seq 1 "$TRAFFIC_PINGS"); do
  sudo -n ip netns exec "$NS_A" ping -I tinea -c 1 -W 1 10.67.0.2 >/dev/null 2>&1 \
    || fail "ping $i/$TRAFFIC_PINGS failed during the active lease window"
  sleep "$PING_INTERVAL_SECONDS"
done

OPEN_AFTER="$(grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true)"
[[ "$OPEN_AFTER" == "$OPEN_BEFORE" ]] \
  || fail "active circuit was rebuilt during the traffic burst (OPEN $OPEN_BEFORE -> $OPEN_AFTER)"
remote_expect_ping tinect-la tinea 10.67.0.2

echo "active lease continuity integration test passed"
