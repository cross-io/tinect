#!/usr/bin/env bash
# Verifies transactional ownership of underlay escape routes.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-route-ownership}"
PREFIX="${TINECT_NS_PREFIX:-tinect-route-ownership}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
sudo -n true

remote_keygen a
remote_keygen b
BK="$(remote_public_key b)"
remote_namespace a
remote_namespace gateway
remote_veth ag-a ag-gateway a gateway 10.241.0.2/24 10.241.0.1/24

sudo -n ip -n "$(remote_ns a)" route add default via 10.241.0.1 dev ag-a
# This route belongs to the operator. Tinect must use it without replacing it
# or claiming it in the shutdown ownership token.
sudo -n ip -n "$(remote_ns a)" route add 192.0.2.10/32 \
  via 10.241.0.1 dev ag-a metric 77

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.69.0.1/32]}
runtime:
  status_socket: $REMOTE_STATUS_SOCKET_DIR/a.sock
link_health: {keepalive_secs: 1, idle_timeout_secs: 30, reconnect_interval_secs: 1}
peers:
  b:
    public_key: $BK
    endpoints: [quic://192.0.2.10:4433, quic://192.0.2.11:4433]
    routes: [{ip_cidr: 0.0.0.0/1, priority: 100}]
connect_to: [b]
EOF

remote_start a a
remote_wait_tun a tinea 100
remote_wait_deadline "managed overlay and underlay routes installed" 10 \
  "sudo -n ip -n '$(remote_ns a)' route show exact 0.0.0.0/1 | grep -Fq 'dev tinea' && sudo -n ip -n '$(remote_ns a)' route show exact 192.0.2.11/32 | grep -Fq 'via 10.241.0.1'"

operator_route="$(sudo -n ip -n "$(remote_ns a)" route show exact 192.0.2.10/32)"
grep -Fq 'via 10.241.0.1' <<<"$operator_route"
grep -Fq 'metric 77' <<<"$operator_route"

launcher_pid="${REMOTE_PIDS[0]}"
daemon_pid="$(sudo -n ip netns pids "$(remote_ns a)" | head -1)"
[[ -n "$daemon_pid" ]]
sudo -n kill -TERM "$daemon_pid"
remote_wait_deadline "daemon graceful shutdown" 15 \
  "[[ -z \"\$(sudo -n ip netns pids '$(remote_ns a)' 2>/dev/null)\" ]]"
wait "$launcher_pid"
REMOTE_PIDS=()

[[ -z "$(sudo -n ip -n "$(remote_ns a)" route show exact 0.0.0.0/1)" ]]
[[ -z "$(sudo -n ip -n "$(remote_ns a)" route show exact 192.0.2.11/32)" ]]
operator_route="$(sudo -n ip -n "$(remote_ns a)" route show exact 192.0.2.10/32)"
grep -Fq 'via 10.241.0.1' <<<"$operator_route"
grep -Fq 'metric 77' <<<"$operator_route"

echo "underlay route ownership lifecycle test passed"
