#!/usr/bin/env bash
# Verifies that a shared relay failure reconciles each destination independently.
# D prefers B and falls back to C; E prefers C and falls back to B.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-multi-destination}"
WORK="${WORK:-/tmp/tinect-multi-destination-$TINECT_NS_PREFIX}"
NS_A="$(remote_ns tinect-mda)"; NS_B="$(remote_ns tinect-mdb)"; NS_C="$(remote_ns tinect-mdc)"
NS_D="$(remote_ns tinect-mdd)"; NS_E="$(remote_ns tinect-mde)"
TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"

fail() { echo "multi-destination isolation test failed: $*" >&2; remote_finish 1; }
start_node() {
  local node="$1" fixture="$2"
  REMOTE_SOCKETS+=("$WORK/$node.sock"); REMOTE_LOG_NODES+=("$node")
  sudo -n ip netns exec "$(remote_ns "$fixture")" "$BIN" up "$WORK/$node.yaml" >>"$WORK/$node.log" 2>&1 &
  REMOTE_PIDS+=("$!")
}

# Serialize node startup (see remote_same_first_hop_switch.sh for why): the
# fixture verifies per-destination path isolation, not startup convergence,
# and a simultaneous five-node dial burst makes the QUIC accept/dial race
# unreliable.
start_node_ready() {
  local node="$1" fixture="$2"
  start_node "$node" "$fixture"
  for _ in $(seq 1 100); do
    [[ -S "$WORK/$node.sock" ]] && break
    sleep 0.1
  done
  sleep 1
}
stop_node() {
  local fixture="$1" ns pid
  ns="$(remote_ns "$fixture")"
  while read -r pid; do [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true; done \
    < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
}
status_json() { sudo -n "$BIN" status --socket "$WORK/$1.sock" 2>/dev/null; }
paths_are() {
  STATUS_JSON="$(status_json a)" python3 - "$@" <<'PY'
import json, os, sys
try:
    circuits = json.loads(os.environ["STATUS_JSON"])["circuits"]
except (KeyError, json.JSONDecodeError):
    raise SystemExit(1)
want = {sys.argv[i]: sys.argv[i + 1].split(',') for i in range(1, len(sys.argv), 2)}
for destination, path in want.items():
    if not any(c.get("destination") == destination and c.get("healthy")
               and c.get("active_path_names") == path for c in circuits):
        raise SystemExit(1)
PY
}
wait_paths() {
  local d_path="$1" e_path="$2" timeout_secs="$3"
  for _ in $(seq 1 "$((timeout_secs * 10))"); do
    if paths_are d "$d_path" e "$e_path"; then return 0; fi
    sleep 0.1
  done
  fail "expected destination paths D=[$d_path], E=[$e_path]"
}
ping_both() {
  remote_expect_ping tinect-mda tinea 10.67.3.3
  remote_expect_ping tinect-mda tinea 10.67.4.4
}

remote_init "$WORK"
trap 'remote_finish "$?"' EXIT
[[ -x "$BIN" ]] || fail "build the release binary first"
sudo -n true || fail "passwordless sudo is required"
for n in a b c d e; do remote_keygen "$n"; done
AK="$(remote_public_key a)"; BK="$(remote_public_key b)"; CK="$(remote_public_key c)"
DK="$(remote_public_key d)"; EK="$(remote_public_key e)"
for f in tinect-mda tinect-mdb tinect-mdc tinect-mdd tinect-mde; do remote_namespace "$f"; done
remote_veth "md${TOKEN:0:7}a" "md${TOKEN:0:7}b" tinect-mda tinect-mdb 10.232.11.1/24 10.232.11.2/24
remote_veth "md${TOKEN:0:7}c" "md${TOKEN:0:7}d" tinect-mda tinect-mdc 10.232.12.1/24 10.232.12.2/24
remote_veth "md${TOKEN:0:7}e" "md${TOKEN:0:7}f" tinect-mdb tinect-mdd 10.232.13.1/24 10.232.13.2/24
remote_veth "md${TOKEN:0:7}g" "md${TOKEN:0:7}h" tinect-mdc tinect-mdd 10.232.14.1/24 10.232.14.2/24
remote_veth "md${TOKEN:0:7}i" "md${TOKEN:0:7}j" tinect-mdb tinect-mde 10.232.15.1/24 10.232.15.2/24
remote_veth "md${TOKEN:0:7}k" "md${TOKEN:0:7}l" tinect-mdc tinect-mde 10.232.16.1/24 10.232.16.2/24
for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_D" "$NS_E"; do
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
done

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.67.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  b: {public_key: $BK, endpoints: [quic://10.232.11.2:4434]}
  c: {public_key: $CK, endpoints: [quic://10.232.12.2:4435]}
  d: {public_key: $DK, endpoints: [], routes: [{ip_cidr: 10.67.3.3/32, priority: 100}], paths: [{path: [a, b, d]}, {path: [a, c, d]}]}
  e: {public_key: $EK, endpoints: [], routes: [{ip_cidr: 10.67.4.4/32, priority: 100}], paths: [{path: [a, c, e]}, {path: [a, b, e]}]}
connect_to: [b, c]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.67.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  e: {public_key: $EK, endpoints: [quic://10.232.15.2:4437], paths: [{path: [b, e]}]}
  a: {public_key: $AK, endpoints: [quic://10.232.11.1:4433], paths: [{path: [b, a]}]}
  d: {public_key: $DK, endpoints: [quic://10.232.13.2:4436], paths: [{path: [b, d]}]}
connect_to: [d, e]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
allow_transit: true
identity_key_path: $WORK/c.key
listen: quic://0.0.0.0:4435
tun: {name: tunc, addresses: [10.67.2.1/32]}
runtime: {status_socket: $WORK/c.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  e: {public_key: $EK, endpoints: [quic://10.232.16.2:4437], paths: [{path: [c, e]}]}
  a: {public_key: $AK, endpoints: [quic://10.232.12.1:4433], paths: [{path: [c, a]}]}
  d: {public_key: $DK, endpoints: [quic://10.232.14.2:4436], paths: [{path: [c, d]}]}
connect_to: [d, e]
EOF
cat >"$WORK/d.yaml" <<EOF
id: d
identity_key_path: $WORK/d.key
listen: quic://0.0.0.0:4436
tun: {name: tund, addresses: [10.67.3.3/32]}
runtime: {status_socket: $WORK/d.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.67.0.1/32, priority: 100}], paths: [{path: [d, b, a]}, {path: [d, c, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.232.13.1:4434]}
  c: {public_key: $CK, endpoints: [quic://10.232.14.1:4435]}
allowed_routes: [{allow: [10.67.3.3/32], for: [a]}]
allowed_local_ports: [{allow: [icmp], for: [a]}]
connect_to: [b, c]
EOF
cat >"$WORK/e.yaml" <<EOF
id: e
identity_key_path: $WORK/e.key
listen: quic://0.0.0.0:4437
tun: {name: tune, addresses: [10.67.4.4/32]}
runtime: {status_socket: $WORK/e.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5, reconnect_interval_secs: 1}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.67.0.1/32, priority: 100}], paths: [{path: [e, c, a]}, {path: [e, b, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.232.15.1:4434]}
  c: {public_key: $CK, endpoints: [quic://10.232.16.1:4435]}
allowed_routes: [{allow: [10.67.4.4/32], for: [a]}]
allowed_local_ports: [{allow: [icmp], for: [a]}]
connect_to: [b, c]
EOF

start_node_ready b tinect-mdb
start_node_ready c tinect-mdc
start_node_ready d tinect-mdd
start_node_ready e tinect-mde
start_node_ready a tinect-mda
wait_paths a,b,d a,c,e 120
ping_both

# B is primary only for D. E must keep its C path while D migrates to C.
stop_node tinect-mdb
wait_paths a,c,d a,c,e 90
ping_both

# Reconnecting B may restore D's preferred path, but must not move E away from
# its own preferred C path.
start_node b tinect-mdb
wait_paths a,b,d a,c,e 120
ping_both
echo "multi-destination reconcile isolation test passed"
