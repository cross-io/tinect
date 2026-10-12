#!/usr/bin/env bash
# Privileged Linux smoke test for the real TUN + QUIC data plane.
# Run on Linux from the repository root.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-two}"
WORK="${WORK:-/tmp/tinect-two-node-$TINECT_NS_PREFIX}"
STATUS_SOCKET_DIR="${STATUS_SOCKET_DIR:-$WORK/status-sockets}"
CARRIER="${CARRIER:-quic}"
A_LISTEN_ADDRESS="${A_LISTEN_ADDRESS:-10.200.0.1:4433}"
B_LISTEN_ADDRESS="${B_LISTEN_ADDRESS:-10.200.0.2:4434}"
A_UNDERLAY_CIDR="${A_UNDERLAY_CIDR:-10.200.0.1/24}"
B_UNDERLAY_CIDR="${B_UNDERLAY_CIDR:-10.200.0.2/24}"
A_EXTRA_UNDERLAY_CIDR="${A_EXTRA_UNDERLAY_CIDR:-}"
B_EXTRA_UNDERLAY_CIDR="${B_EXTRA_UNDERLAY_CIDR:-}"
A_PEER_ENDPOINT="${A_PEER_ENDPOINT:-10.200.0.1:4433}"
B_PEER_ENDPOINT="${B_PEER_ENDPOINT:-10.200.0.2:4434}"
A_TUN_CIDR="${A_TUN_CIDR:-10.64.0.1/32}"
B_TUN_CIDR="${B_TUN_CIDR:-10.64.0.2/32}"
A_EXTRA_ROUTE_PREFIX="${A_EXTRA_ROUTE_PREFIX:-}"
B_EXTRA_ROUTE_PREFIX="${B_EXTRA_ROUTE_PREFIX:-}"
A_TUN_IP="${A_TUN_CIDR%%/*}"
B_TUN_IP="${B_TUN_CIDR%%/*}"
A_LISTEN_PORT="${A_LISTEN_PORT:-4433}"
B_LISTEN_PORT="${B_LISTEN_PORT:-4434}"
A_FWMARK="${A_FWMARK:-}"
B_FWMARK="${B_FWMARK:-}"
NS_A="$TINECT_NS_PREFIX-a"
NS_B="$TINECT_NS_PREFIX-b"
# Interfaces coexist briefly in the initial namespace before being moved. A
# short derived name keeps them unique across matrix jobs and within Linux's
# 15-character interface-name limit.
VETH_TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"
VETH_A="tn${VETH_TOKEN:0:8}a"
VETH_B="tn${VETH_TOKEN:0:8}b"

PING_ARGS=()
if [[ "$B_TUN_IP" == *:* ]]; then
  PING_ARGS=(-6)
fi
CIRCUIT_READY_TIMEOUT_SECONDS=60
PID_A=""
PID_B=""
FLOOD_PID=""

case "$CARRIER" in
  quic|quicfull|quic-faketcp|quicfull-faketcp) ;;
  *) echo "CARRIER must be quic, quicfull, quic-faketcp, or quicfull-faketcp" >&2; exit 2 ;;
esac

for mark in "$A_FWMARK" "$B_FWMARK"; do
  [[ -z "$mark" || "$mark" =~ ^[0-9]+$ ]] || {
    echo "A_FWMARK and B_FWMARK must be unsigned integers" >&2
    exit 2
  }
done

A_FWMARK_CONFIG=""
B_FWMARK_CONFIG=""
[[ -z "$A_FWMARK" ]] || A_FWMARK_CONFIG="fwmark: $A_FWMARK"
[[ -z "$B_FWMARK" ]] || B_FWMARK_CONFIG="fwmark: $B_FWMARK"
HEALTHY_NFT_TEST="${HEALTHY_NFT_TEST:-0}"
HEALTHY_NFT_EXPLICIT_TARGETS="${HEALTHY_NFT_EXPLICIT_TARGETS:-0}"
HEALTHY_NFT_PRESERVE_TABLE="${HEALTHY_NFT_PRESERVE_TABLE:-0}"
HEALTHY_NFT_TABLE="tinect_test_policy"
HEALTHY_NFT_CONFIG=""
if [[ "$HEALTHY_NFT_TEST" == 1 ]]; then
  if [[ "$HEALTHY_NFT_EXPLICIT_TARGETS" == 1 ]]; then
    HEALTHY_NFT_CONFIG="nft_healthy_set:
  v4: ${HEALTHY_NFT_TABLE}:healthy_v4
  v6: ${HEALTHY_NFT_TABLE}:healthy_v6
  destroy_set: true
  destroy_table: $([[ "$HEALTHY_NFT_PRESERVE_TABLE" == 1 ]] && echo false || echo true)"
  else
    HEALTHY_NFT_CONFIG="nft_healthy_set:
  prefix: ${HEALTHY_NFT_TABLE}:healthy
  destroy_set: true
  destroy_table: true"
  fi
fi
FWMARK_POLICY_TEST="${FWMARK_POLICY_TEST:-0}"
MANAGED_ROUTES_TEST="${MANAGED_ROUTES_TEST:-0}"
MANAGED_ROUTES_CONFIG=""
[[ "$MANAGED_ROUTES_TEST" == 1 ]] && MANAGED_ROUTES_CONFIG="managed_routes: false"
FEC_TEST="${FEC_TEST:-0}"
FEC_RATE="${FEC_RATE:-0.75}"
FEC_PING_COUNT="${FEC_PING_COUNT:-200}"
FEC_PING_WAIT="${FEC_PING_WAIT:-1}"
# Keep the loss probe bounded independently of the six-minute CI job timeout.
# iputils ping defaults to a one-second interval, which makes 200 packets take
# several minutes when netem drops replies.  The explicit interval still
# provides enough source symbols for the FEC estimator while avoiding a
# runner-load-dependent test duration.
FEC_PING_INTERVAL="${FEC_PING_INTERVAL:-0.05}"
FEC_PING_TIMEOUT="${FEC_PING_TIMEOUT:-90}"
REQUIRE_FEC_RECOVERY="${REQUIRE_FEC_RECOVERY:-1}"
FEC_CONFIG="repair_rate: 0"
A_CONNECT_TO_CONFIG="connect_to: [b]"
if [[ "$FEC_TEST" == 1 ]]; then
  FEC_CONFIG="repair_rate: $FEC_RATE"
  A_CONNECT_TO_CONFIG="connect_to:
  - {peer: b, repair_rate: $FEC_RATE}"
fi
A_EXTRA_ROUTE_CONFIG=""
B_EXTRA_ROUTE_CONFIG=""
[[ -z "$A_EXTRA_ROUTE_PREFIX" ]] || A_EXTRA_ROUTE_CONFIG="      - {ip_cidr: $A_EXTRA_ROUTE_PREFIX, priority: 100}"
[[ -z "$B_EXTRA_ROUTE_PREFIX" ]] || B_EXTRA_ROUTE_CONFIG="      - {ip_cidr: $B_EXTRA_ROUTE_PREFIX, priority: 100}"

stop_daemons() {
  [[ -n "$PID_A" ]] && sudo -n kill -TERM "$PID_A" 2>/dev/null || true
  [[ -n "$PID_B" ]] && sudo -n kill -TERM "$PID_B" 2>/dev/null || true
  [[ -n "$FLOOD_PID" ]] && sudo -n kill -TERM "$FLOOD_PID" 2>/dev/null || true
  # `$!` is the host-side `sudo ip netns exec` wrapper. Killing it does not
  # reliably forward SIGTERM to the processes it started in all iproute2
  # versions, so terminate every process attached to these test-owned
  # namespaces. Network namespaces do not isolate the PID view, which is why
  # this uses `ip netns pids` instead of a namespace-local `pkill`.
  for namespace in "$NS_A" "$NS_B"; do
    while read -r pid; do
      [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$namespace" 2>/dev/null || true)
  done
  # Do not wait on `sudo ip netns exec`: on some failures its wrapper can
  # outlive the daemon and wait indefinitely. Namespace deletion below is the
  # final ownership boundary and terminates any remaining children.
  PID_A=""
  PID_B=""
}

assert_fake_tcp_cleanup() {
  [[ "$CARRIER" == *faketcp ]] || return 0
  for pair in "$NS_A:$A_LISTEN_PORT" "$NS_B:$B_LISTEN_PORT"; do
    namespace="${pair%%:*}"
    port="${pair##*:}"
    # Daemon shutdown is asynchronous: wait for its owned guard to disappear
    # before diagnosing a leak, rather than racing the SIGTERM handler.
    # The daemon's configured graceful-shutdown budget defaults to ten
    # seconds.  The guard is owned by the QUICP socket and is released after
    # that budget if a blocked transport task needs aborting, so allow one
    # extra second before calling it a leak.
    for _ in $(seq 1 110); do
      sudo -n ip netns exec "$namespace" nft list table inet "tinect_quicp_rst_$port" \
        >/dev/null 2>&1 || break
      sleep 0.1
    done
    if sudo -n ip netns exec "$namespace" nft list table inet "tinect_quicp_rst_$port" \
      >/dev/null 2>&1; then
      echo "fake-TCP RST guard leaked from $namespace" >&2
      return 1
    fi
  done
}

cleanup() {
  echo "=== nftables ruleset in $NS_A ==="
  sudo -n ip netns exec "$NS_A" nft list ruleset || true
  echo "=== nftables ruleset in $NS_B ==="
  sudo -n ip netns exec "$NS_B" nft list ruleset || true
  stop_daemons
  assert_fake_tcp_cleanup || true
  sudo -n ip netns del "$NS_A" 2>/dev/null || true
  sudo -n ip netns del "$NS_B" 2>/dev/null || true
  sudo -n rm -f "$STATUS_SOCKET_DIR/a.sock" "$STATUS_SOCKET_DIR/b.sock"
}
trap cleanup EXIT

sudo -n true
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$STATUS_SOCKET_DIR"
"$BIN" keygen --output "$WORK/a.key" >"$WORK/a.identity"
"$BIN" keygen --output "$WORK/b.key" >"$WORK/b.identity"
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"

sudo -n ip netns del "$NS_A" 2>/dev/null || true
sudo -n ip netns del "$NS_B" 2>/dev/null || true
sudo -n ip netns add "$NS_A"
sudo -n ip netns add "$NS_B"
sudo -n ip link add "$VETH_A" type veth peer name "$VETH_B"
sudo -n ip link set "$VETH_A" netns "$NS_A"
sudo -n ip link set "$VETH_B" netns "$NS_B"
add_underlay_address() {
  local namespace="$1"
  local address="$2"
  local interface="$3"
  if [[ "$address" == *:* ]]; then
    # Avoid IPv6 duplicate-address-detection delaying the isolated test.
    sudo -n ip -n "$namespace" -6 addr add "$address" nodad dev "$interface"
  else
    sudo -n ip -n "$namespace" addr add "$address" dev "$interface"
  fi
}
add_underlay_address "$NS_A" "$A_UNDERLAY_CIDR" "$VETH_A"
add_underlay_address "$NS_B" "$B_UNDERLAY_CIDR" "$VETH_B"
[[ -z "$A_EXTRA_UNDERLAY_CIDR" ]] || add_underlay_address "$NS_A" "$A_EXTRA_UNDERLAY_CIDR" "$VETH_A"
[[ -z "$B_EXTRA_UNDERLAY_CIDR" ]] || add_underlay_address "$NS_B" "$B_EXTRA_UNDERLAY_CIDR" "$VETH_B"
sudo -n ip -n "$NS_A" link set lo up
sudo -n ip -n "$NS_B" link set lo up
sudo -n ip -n "$NS_A" link set "$VETH_A" up
sudo -n ip -n "$NS_B" link set "$VETH_B" up
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_B" sysctl -qw net.ipv6.conf.all.forwarding=1

if [[ "$HEALTHY_NFT_TEST" == 1 ]]; then
  for namespace in "$NS_A" "$NS_B"; do
    sudo -n ip netns exec "$namespace" nft add table inet "$HEALTHY_NFT_TABLE"
    if [[ "$HEALTHY_NFT_PRESERVE_TABLE" == 1 ]]; then
      sudo -n ip netns exec "$namespace" nft add set inet "$HEALTHY_NFT_TABLE" user_sentinel \
        '{ type ipv4_addr; }'
      sudo -n ip netns exec "$namespace" nft add element inet "$HEALTHY_NFT_TABLE" user_sentinel \
        '{ 198.51.100.1 }'
    fi
    sudo -n ip netns exec "$namespace" nft add set inet "$HEALTHY_NFT_TABLE" healthy_v4 \
      '{ type ipv4_addr; flags interval; }'
    sudo -n ip netns exec "$namespace" nft add set inet "$HEALTHY_NFT_TABLE" healthy_v6 \
      '{ type ipv6_addr; flags interval; }'
    sudo -n ip netns exec "$namespace" nft add element inet "$HEALTHY_NFT_TABLE" healthy_v4 \
      '{ 192.0.2.1/32 }'
    sudo -n ip netns exec "$namespace" nft add element inet "$HEALTHY_NFT_TABLE" healthy_v6 \
      '{ 2001:db8::1/128 }'
  done
fi

configure_fwmark_policy() {
  local namespace="$1" interface="$2" remote="$3" mark="$4"
  sudo -n ip -n "$namespace" route add "$remote/32" dev "$interface" table 100
  sudo -n ip -n "$namespace" rule add priority 100 to "$remote/32" fwmark "$mark" lookup 100
  sudo -n ip -n "$namespace" route get "$remote" mark "$mark" | grep -Fq "dev $interface"
  # The route rule verifies policy selection for marked packets. The output
  # guard makes an unmarked carrier packet fail the real handshake while
  # leaving return traffic and reverse-path validation unaffected.
  sudo -n ip netns exec "$namespace" nft add table ip tinect_test_fwmark
  sudo -n ip netns exec "$namespace" nft \
    'add chain ip tinect_test_fwmark output { type filter hook output priority filter; policy accept; }'
  sudo -n ip netns exec "$namespace" nft add rule ip tinect_test_fwmark output \
    ip daddr "$remote" meta mark '!=' "$mark" drop
}

if [[ "$FWMARK_POLICY_TEST" == 1 ]]; then
  [[ -n "$A_FWMARK" && "$A_FWMARK" == "$B_FWMARK" ]] || {
    echo "FWMARK_POLICY_TEST requires identical non-empty A_FWMARK and B_FWMARK" >&2
    exit 2
  }
  # Constrain only A's active-dial path. B's listener replies through its
  # ordinary connected route, so this proves that A's carrier socket mark is
  # necessary without turning reverse-path validation into a test variable.
  configure_fwmark_policy "$NS_A" "$VETH_A" "${B_UNDERLAY_CIDR%%/*}" "$A_FWMARK"
fi

cat >"$WORK/a.yaml" <<EOF
id: a
accept_connections: true
identity_key_path: $WORK/a.key
listen: $CARRIER://$A_LISTEN_ADDRESS
$A_FWMARK_CONFIG
$HEALTHY_NFT_CONFIG
$MANAGED_ROUTES_CONFIG
$FEC_CONFIG
tun:
  name: tinea
  addresses: [$A_TUN_CIDR]
runtime:
  pcap_buffer_packets: 64
  status_socket: $STATUS_SOCKET_DIR/a.sock
peers:
  b:
    public_key: $BK
    endpoints: ["$CARRIER://$B_PEER_ENDPOINT"]
    routes:
      - {ip_cidr: $B_TUN_CIDR, priority: 100}
$B_EXTRA_ROUTE_CONFIG
    paths:
      - path: [a, b]
$A_CONNECT_TO_CONFIG
EOF

cat >"$WORK/b.yaml" <<EOF
id: b
accept_connections: true
identity_key_path: $WORK/b.key
listen: $CARRIER://$B_LISTEN_ADDRESS
$B_FWMARK_CONFIG
$HEALTHY_NFT_CONFIG
$MANAGED_ROUTES_CONFIG
$FEC_CONFIG
tun:
  name: tunb
  addresses: [$B_TUN_CIDR]
runtime:
  status_socket: $STATUS_SOCKET_DIR/b.sock
peers:
  a:
    public_key: $AK
    endpoints: ["$CARRIER://$A_PEER_ENDPOINT"]
    routes:
      - {ip_cidr: $A_TUN_CIDR, priority: 100}
$A_EXTRA_ROUTE_CONFIG
    paths:
      - path: [b, a]
allowed_routes:
  - allow: [$B_TUN_CIDR]
    for: [a]
allowed_local_ports:
  - {allow: [icmp, tcp(18080)], for: [a]}
EOF

wait_for_status_socket() {
  local socket="$1" timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while ((SECONDS < deadline)); do
    [[ -S "$socket" ]] && return 0
    sleep 0.1
  done
  echo "timed out waiting ${timeout_seconds}s for status socket $socket" >&2
  return 1
}

sudo -n ip netns exec "$NS_B" sh -c 'echo "$$" > "$1"; exec "$2" up "$3"' \
  sh "$WORK/b.pid" "$BIN" "$WORK/b.yaml" >"$WORK/b.log" 2>&1 &
PID_B=$!
wait_for_status_socket "$STATUS_SOCKET_DIR/b.sock" 15

sudo -n ip netns exec "$NS_A" sh -c 'echo "$$" > "$1"; exec "$2" up "$3"' \
  sh "$WORK/a.pid" "$BIN" "$WORK/a.yaml" >"$WORK/a.log" 2>&1 &
PID_A=$!

for _ in $(seq 1 50); do
  if sudo -n ip -n "$NS_A" link show tinea >/dev/null 2>&1 \
    && sudo -n ip -n "$NS_B" link show tunb >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

# `ip netns exec` is a host-side wrapper.  The inner shell records its own
# PID immediately before `exec`, so shutdown targets the daemon rather than
# relying on wrapper signal forwarding or iproute2 PID enumeration.
read -r PID_A <"$WORK/a.pid"
read -r PID_B <"$WORK/b.pid"
wait_for_status_socket "$STATUS_SOCKET_DIR/a.sock" 15

status_has_healthy_circuit() {
  local namespace="$1" node="$2" destination="$3"
  sudo -n ip netns exec "$namespace" "$BIN" status \
    --socket "$STATUS_SOCKET_DIR/$node.sock" 2>/dev/null |
    python3 -c '
import json
import sys

destination = sys.argv[1]
try:
    status = json.load(sys.stdin)
except (json.JSONDecodeError, OSError):
    raise SystemExit(1)

raise SystemExit(
    0
    if any(
        circuit.get("destination") == destination
        and circuit.get("healthy") is True
        and circuit.get("active_path")
        for circuit in status.get("circuits", [])
    )
    else 1
)
' "$destination"
}

wait_for_bidirectional_circuits() {
  local deadline=$((SECONDS + CIRCUIT_READY_TIMEOUT_SECONDS))
  local namespace
  while ((SECONDS < deadline)); do
    if status_has_healthy_circuit "$NS_A" a b \
      && status_has_healthy_circuit "$NS_B" b a; then
      return 0
    fi
    sleep 0.1
  done

  echo "timed out waiting ${CIRCUIT_READY_TIMEOUT_SECONDS}s for healthy bidirectional circuits" >&2
  for node in a b; do
    namespace="$NS_A"
    [[ "$node" == b ]] && namespace="$NS_B"
    echo "=== status for $node ===" >&2
    sudo -n ip netns exec "$namespace" "$BIN" status \
      --socket "$STATUS_SOCKET_DIR/$node.sock" >&2 || true
    echo "=== routes for $node ===" >&2
    sudo -n ip netns exec "$namespace" "$BIN" routes \
      --socket "$STATUS_SOCKET_DIR/$node.sock" >&2 || true
  done
  return 1
}

wait_for_bidirectional_circuits

if [[ "$FEC_TEST" == 1 ]]; then
  sudo -n ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem \
    delay 10ms loss 20% reorder 10% 50%
  sudo -n ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem \
    delay 10ms loss 20% reorder 10% 50%
  fec_ping_status=0
  timeout --signal=TERM --kill-after=5s "$FEC_PING_TIMEOUT" \
    sudo -n ip netns exec "$NS_A" ping "${PING_ARGS[@]}" -I tinea -s 900 \
    -i "$FEC_PING_INTERVAL" -c "$FEC_PING_COUNT" -W "$FEC_PING_WAIT" \
    "$B_TUN_IP" >/dev/null || fec_ping_status=$?
  case "$fec_ping_status" in
    0|1) ;;
    124|137|143)
      echo "FEC loss probe exceeded ${FEC_PING_TIMEOUT}s" >&2
      exit 1
      ;;
    *)
      echo "FEC loss probe failed with exit code $fec_ping_status" >&2
      exit 1
      ;;
  esac
  sudo -n ip netns exec "$NS_A" tc qdisc del dev "$VETH_A" root 2>/dev/null || true
  sudo -n ip netns exec "$NS_B" tc qdisc del dev "$VETH_B" root 2>/dev/null || true
  sudo -n ip netns exec "$NS_A" "$BIN" status "$WORK/a.yaml" |
    python3 -c 'import json, sys; s=json.load(sys.stdin); assert any((l.get("metrics") or {}).get("fec_tx_repairs", 0) > 0 for l in s["links"])'
  sudo -n ip netns exec "$NS_B" "$BIN" status "$WORK/b.yaml" |
    REQUIRE_FEC_RECOVERY="$REQUIRE_FEC_RECOVERY" python3 -c 'import json, os, sys; s=json.load(sys.stdin); require_recovery = os.environ.get("REQUIRE_FEC_RECOVERY", "1") == "1"; assert any((m := (l.get("metrics") or {})).get("fec_enabled") and m.get("fec_rx_sources", 0) > 0 and m.get("fec_rx_repairs", 0) > 0 and (not require_recovery or m.get("fec_recovered", 0) > 0) and m.get("fec_feedback_sent", 0) > 0 for l in s["links"])'
  echo "datagram FEC survived injected loss and reordering"
fi

if [[ "$MANAGED_ROUTES_TEST" == 1 ]]; then
  for pair in "$NS_A:$B_TUN_IP:tinea" "$NS_B:$A_TUN_IP:tunb"; do
    namespace="${pair%%:*}"
    rest="${pair#*:}"
    target="${rest%%:*}"
    interface="${rest##*:}"
    if sudo -n ip -n "$namespace" route show exact "$target/32" | grep -Fq "dev $interface"; then
      echo "managed_routes: false unexpectedly installed $target through $interface" >&2
      exit 1
    fi
    sudo -n ip -n "$namespace" route add "$target/32" dev "$interface"
  done
fi

healthy_nft_set_contains() {
  local namespace="$1" prefix="$2"
  local needle="$prefix"
  local set=healthy_v4
  [[ "$needle" == *:* ]] && set=healthy_v6
  case "$needle" in
    */32|*/128) needle="${needle%/*}" ;;
  esac
  sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" "$set" 2>/dev/null |
    grep -Fq -- "$needle"
}

if [[ "$HEALTHY_NFT_TEST" == 1 ]]; then
  for _ in $(seq 1 300); do
    if healthy_nft_set_contains "$NS_A" "$B_TUN_CIDR" \
      && healthy_nft_set_contains "$NS_B" "$A_TUN_CIDR" \
      && { [[ -z "$B_EXTRA_ROUTE_PREFIX" ]] || healthy_nft_set_contains "$NS_A" "$B_EXTRA_ROUTE_PREFIX"; } \
      && { [[ -z "$A_EXTRA_ROUTE_PREFIX" ]] || healthy_nft_set_contains "$NS_B" "$A_EXTRA_ROUTE_PREFIX"; }; then
      break
    fi
    sleep 0.1
  done
  healthy_nft_set_contains "$NS_A" "$B_TUN_CIDR" || {
    echo "A healthy nft set did not contain the active B prefix" >&2
    exit 1
  }
  healthy_nft_set_contains "$NS_B" "$A_TUN_CIDR" || {
    echo "B healthy nft set did not contain the active A prefix" >&2
    exit 1
  }
  [[ -z "$B_EXTRA_ROUTE_PREFIX" ]] || healthy_nft_set_contains "$NS_A" "$B_EXTRA_ROUTE_PREFIX" || {
    echo "A healthy nft set did not contain the active extra B prefix" >&2
    exit 1
  }
  [[ -z "$A_EXTRA_ROUTE_PREFIX" ]] || healthy_nft_set_contains "$NS_B" "$A_EXTRA_ROUTE_PREFIX" || {
    echo "B healthy nft set did not contain the active extra A prefix" >&2
    exit 1
  }
  for namespace in "$NS_A" "$NS_B"; do
    if healthy_nft_set_contains "$namespace" "192.0.2.1/32"; then
      echo "stale healthy nft set element survived startup in $namespace" >&2
      exit 1
    fi
    if healthy_nft_set_contains "$namespace" "2001:db8::1/128"; then
      echo "stale IPv6 healthy nft set element survived startup in $namespace" >&2
      exit 1
    fi
  done
  echo "healthy nft sets converged after startup cleanup"
fi

# The authenticated physical payload link may need a bidirectional reliable
# session setup on its first forwarded packet. Use bounded probes so this
# smoke test asserts eventual data-plane connectivity rather than timing it
# against a fixed sleep.
for _ in $(seq 1 20); do
  if sudo -n ip netns exec "$NS_A" ping "${PING_ARGS[@]}" -I tinea -c 1 -W 1 "$B_TUN_IP"; then
    break
  fi
  sleep 0.1
done
sudo -n ip netns exec "$NS_A" ping "${PING_ARGS[@]}" -I tinea -c 1 -W 1 "$B_TUN_IP"

if [[ "${FLOOD_QUIC_PACKETS:-0}" =~ ^[1-9][0-9]*$ ]]; then
  sudo -n ip netns exec "$NS_B" python3 - "$A_LISTEN_ADDRESS" "$FLOOD_QUIC_PACKETS" >"$WORK/flood.log" 2>&1 <<'PY' &
import socket
import sys

address = sys.argv[1]
count = int(sys.argv[2])
if address.startswith('['):
    host, port = address[1:].split(']:', 1)
    target = (host, int(port), 0, 0)
    family = socket.AF_INET6
else:
    host, port = address.rsplit(':', 1)
    target = (host, int(port))
    family = socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
packet = b'\x40' + b'\x00' * 1199
for _ in range(count):
    sock.sendto(packet, target)
PY
  FLOOD_PID=$!
  # Allow the sender to fill the demultiplexer queue while the next ping
  # verifies that bare Physical traffic still makes progress.
  sleep 0.2
fi

# Exercises an inner packet near the discovered QUIC DATAGRAM/TUN limit.
sudo -n ip netns exec "$NS_A" ping "${PING_ARGS[@]}" -I tinea -s 1000 -c 2 -W 1 "$B_TUN_IP"

if [[ "${NETEM_SESSION:-0}" == 1 ]]; then
  # Keep a real TCP flow alive while the underlay introduces loss, delay and
  # reordering. This exercises reliable session convergence independently of
  # the ICMP smoke probes above.
  sudo -n ip netns exec "$NS_B" python3 -u - "$B_TUN_IP" <<'PY' >"$WORK/session-server.log" 2>&1 &
import hashlib
import socket
import sys

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((sys.argv[1], 18080))
server.listen(1)
connection, _ = server.accept()
digest = hashlib.sha256()
received = 0
while True:
    chunk = connection.recv(65536)
    if not chunk:
        break
    digest.update(chunk)
    received += len(chunk)
connection.sendall(f"{received}:{digest.hexdigest()}".encode())
connection.close()
server.close()
PY
  for _ in $(seq 1 50); do
    if sudo -n ip netns exec "$NS_B" ss -ltn | grep -q ':18080 '; then break; fi
    sleep 0.1
  done
  sudo -n ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem \
    delay 20ms 10ms loss 5% reorder 15% 50%
  sudo -n ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem \
    delay 20ms 10ms loss 5% reorder 15% 50%
  sudo -n ip netns exec "$NS_A" python3 - "$B_TUN_IP" <<'PY'
import hashlib
import socket
import sys

payload = bytes(index % 251 for index in range(1_500_000))
expected = hashlib.sha256(payload).hexdigest()
client = socket.create_connection((sys.argv[1], 18080), timeout=30)
client.sendall(payload)
client.shutdown(socket.SHUT_WR)
reply = b""
while True:
    chunk = client.recv(1024)
    if not chunk:
        break
    reply += chunk
client.close()
if reply.decode() != f"{len(payload)}:{expected}":
    raise SystemExit(f"unexpected session reply: {reply!r}")
PY
  sudo -n ip netns exec "$NS_A" tc qdisc del dev "$VETH_A" root 2>/dev/null || true
  sudo -n ip netns exec "$NS_B" tc qdisc del dev "$VETH_B" root 2>/dev/null || true
  echo "reliable TCP session survived loss/delay/reordering"
fi

sudo -n ip netns exec "$NS_A" "$BIN" status "$WORK/a.yaml" | grep -q '"fec_loss_ppm"'
sudo -n ip netns exec "$NS_A" "$BIN" pcap "$WORK/a.yaml" --output "$WORK/a.pcap"
test "$(sudo -n stat -c %s "$WORK/a.pcap")" -gt 24
stop_daemons
if [[ "$HEALTHY_NFT_TEST" == 1 ]]; then
  for namespace in "$NS_A" "$NS_B"; do
    if [[ "$HEALTHY_NFT_PRESERVE_TABLE" == 1 ]]; then
      for _ in $(seq 1 120); do
        if sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" user_sentinel \
          >/dev/null 2>&1 \
          && ! sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" healthy_v4 \
            >/dev/null 2>&1 \
          && ! sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" healthy_v6 \
            >/dev/null 2>&1; then
          break
        fi
        sleep 0.1
      done
      sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" user_sentinel \
        >/dev/null 2>&1
      if sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" healthy_v4 \
        >/dev/null 2>&1; then
        echo "healthy IPv4 nft set survived shutdown in $namespace" >&2
        exit 1
      fi
      if sudo -n ip netns exec "$namespace" nft list set inet "$HEALTHY_NFT_TABLE" healthy_v6 \
        >/dev/null 2>&1; then
        echo "healthy IPv6 nft set survived shutdown in $namespace" >&2
        exit 1
      fi
    else
      for _ in $(seq 1 120); do
        if ! sudo -n ip netns exec "$namespace" nft list table inet "$HEALTHY_NFT_TABLE" \
          >/dev/null 2>&1; then
          break
        fi
        sleep 0.1
      done
      if sudo -n ip netns exec "$namespace" nft list table inet "$HEALTHY_NFT_TABLE" \
        >/dev/null 2>&1; then
        echo "healthy nft table survived shutdown in $namespace" >&2
        exit 1
      fi
    fi
  done
  echo "healthy nft resources had the configured shutdown lifecycle"
fi
assert_fake_tcp_cleanup
echo "two-node encrypted TUN test passed"
