#!/usr/bin/env bash
# Verifies RFC-0022 dynamic first-hop budgets: a live MTU drop and recovery
# must update the source send budget without rebuilding the Circuit.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
TINECT_TEST_TIMING_PROFILE="${TINECT_TEST_TIMING_PROFILE:-production}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-rfc22-$$}"
WORK="${WORK:-/tmp/tinect-rfc22-dynamic-budget-$TINECT_NS_PREFIX}"
NS_A="$TINECT_NS_PREFIX-a"
NS_B="$TINECT_NS_PREFIX-b"
NS_C="$TINECT_NS_PREFIX-c"
AB_MTU="${AB_MTU:-1500}"
LOWER_AB_MTU="${LOWER_AB_MTU:-1200}"
BC_MTU="${BC_MTU:-1500}"
PIDS=()

# Derive short host-veth names from the same per-run namespace prefix. This
# follows remote_two_node.sh and prevents host-interface collisions in CI.
VETH_TOKEN="$(printf '%s' "$TINECT_NS_PREFIX" | cksum | awk '{print $1}')"
AB_A="r22${VETH_TOKEN:0:8}a"
AB_B="r22${VETH_TOKEN:0:8}b"
BC_B="r22${VETH_TOKEN:0:8}c"
BC_C="r22${VETH_TOKEN:0:8}d"

cleanup() {
  local pid ns
  for pid in "${PIDS[@]:-}"; do sudo -n kill -TERM "$pid" 2>/dev/null || true; done
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    while read -r pid; do
      [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    sudo -n ip netns del "$ns" 2>/dev/null || true
  done
  sudo -n rm -f "$WORK"/*.sock 2>/dev/null || true
}
trap cleanup EXIT

fail() {
  echo "RFC-0022 dynamic budget integration test failed: $*" >&2
  for node in a b c; do
    echo "===== $node log =====" >&2
    cat "$WORK/$node.log" >&2 || true
    echo "===== $node status =====" >&2
    status_json "$node" >&2 || true
  done
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    echo "===== $ns interfaces =====" >&2
    sudo -n ip -n "$ns" -br link show 2>/dev/null >&2 || true
  done
  exit 1
}

status_json() {
  sudo -n "$BIN" status --socket "$WORK/$1.sock" 2>/dev/null
}

wait_for_status_socket() {
  local socket="$1" timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while ((SECONDS < deadline)); do
    [[ -S "$socket" ]] && return 0
    sleep 0.1
  done
  return 1
}

link_is_healthy() {
  STATUS_JSON="$(status_json "$1")" PEER="$2" python3 -c '
import json, os
status = json.loads(os.environ["STATUS_JSON"])
peer = os.environ["PEER"]
raise SystemExit(not any(
    link.get("peer") == peer and link.get("healthy") is True
    for link in status.get("links", [])
))
'
}

wait_for_healthy_link() {
  local node="$1" peer="$2" timeout_seconds="$3"
  local deadline=$((SECONDS + timeout_seconds))
  while ((SECONDS < deadline)); do
    if link_is_healthy "$node" "$peer" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

active_path_is_abc() {
  STATUS_JSON="$(status_json a)" python3 -c '
import json, os
raw = os.environ.get("STATUS_JSON", "")
if not raw:
    raise SystemExit(1)
status = json.loads(raw)
raise SystemExit(not any(
    circuit.get("destination") == "c"
    and circuit.get("healthy")
    and circuit.get("active_path_names") == ["a", "b", "c"]
    for circuit in status["circuits"]
))
'
}

link_datagram_limit() {
  local node="$1" peer="$2"
  STATUS_JSON="$(status_json "$node")" PEER="$peer" python3 -c '
import json, os
for link in json.loads(os.environ["STATUS_JSON"])["links"]:
    if link["peer"] == os.environ["PEER"] and link["metrics"] is not None:
        print(link["metrics"]["datagram_max_size"])
        break
else:
    raise SystemExit(1)
'
}

open_ack_count() {
  grep -c 'circuit OPEN acknowledged' "$WORK/a.log" || true
}

sudo -n true
[[ -x "$BIN" ]] || { echo "build the release binary first: cargo build --release" >&2; exit 1; }
for value in "$AB_MTU" "$LOWER_AB_MTU" "$BC_MTU"; do
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1200 || value > 9000 )); then
    echo "MTU values must be integers in 1200..=9000" >&2
    exit 2
  fi
done
(( LOWER_AB_MTU < AB_MTU )) || { echo "LOWER_AB_MTU must be smaller than AB_MTU" >&2; exit 2; }

sudo -n rm -rf "$WORK"
mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"
CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"

for ns in "$NS_A" "$NS_B" "$NS_C"; do
  sudo -n ip netns del "$ns" 2>/dev/null || true
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
done
sudo -n ip link add "$AB_A" type veth peer name "$AB_B"
sudo -n ip link add "$BC_B" type veth peer name "$BC_C"
sudo -n ip link set "$AB_A" netns "$NS_A"
sudo -n ip link set "$AB_B" netns "$NS_B"
sudo -n ip link set "$BC_B" netns "$NS_B"
sudo -n ip link set "$BC_C" netns "$NS_C"
sudo -n ip -n "$NS_A" addr add 10.222.0.1/24 dev "$AB_A"
sudo -n ip -n "$NS_B" addr add 10.222.0.2/24 dev "$AB_B"
sudo -n ip -n "$NS_B" addr add 10.223.0.1/24 dev "$BC_B"
sudo -n ip -n "$NS_C" addr add 10.223.0.2/24 dev "$BC_C"
for pair in \
  "$NS_A $AB_A" "$NS_B $AB_B" \
  "$NS_B $BC_B" "$NS_C $BC_C"; do
  sudo -n ip -n "${pair%% *}" link set "${pair##* }" up
done
sudo -n ip -n "$NS_A" link set "$AB_A" mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set "$AB_B" mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set "$BC_B" mtu "$BC_MTU"
sudo -n ip -n "$NS_C" link set "$BC_C" mtu "$BC_MTU"
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.222.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  b: {public_key: $BK, endpoints: [quic://10.222.0.2:4434]}
  c: {public_key: $CK, endpoints: [], routes: [{ip_cidr: 10.64.2.2/32, priority: 100}]}
path_policies:
  c: {max_hops: 3}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  a: {public_key: $AK, endpoints: [quic://10.222.0.1:4433]}
  c: {public_key: $CK, endpoints: [quic://10.223.0.2:4435]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://10.223.0.2:4435
tun: {name: tunc, addresses: [10.64.2.2/32]}
runtime: {status_socket: $WORK/c.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  a: {public_key: $AK, endpoints: []}
  b: {public_key: $BK, endpoints: [quic://10.223.0.1:4434]}
allowed_routes:
  - {allow: [10.64.2.2/32], for: [a]}
  - {allow: [10.64.2.2/32], for: [b]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
  - {allow: [icmp], for: [b]}
EOF

sudo -n env "TINECT_TEST_TIMING_PROFILE=$TINECT_TEST_TIMING_PROFILE" \
  ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PIDS+=("$!")
wait_for_status_socket "$WORK/c.sock" 15 || fail "C status socket did not become ready"

sudo -n env "TINECT_TEST_TIMING_PROFILE=$TINECT_TEST_TIMING_PROFILE" \
  ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PIDS+=("$!")
wait_for_status_socket "$WORK/b.sock" 15 || fail "B status socket did not become ready"
wait_for_healthy_link b c 30 || fail "B-C link did not become healthy"

sudo -n env "TINECT_TEST_TIMING_PROFILE=$TINECT_TEST_TIMING_PROFILE" \
  ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PIDS+=("$!")
if [[ "$TINECT_TEST_TIMING_PROFILE" != "production" ]]; then
  for _ in $(seq 1 300); do
    grep -Fq "integration-test timing profile enabled profile=\"$TINECT_TEST_TIMING_PROFILE\"" "$WORK/a.log" && break
    sleep 0.1
  done
  grep -Fq "integration-test timing profile enabled profile=\"$TINECT_TEST_TIMING_PROFILE\"" "$WORK/a.log" \
    || fail "daemon did not enable timing profile $TINECT_TEST_TIMING_PROFILE"
fi
wait_for_status_socket "$WORK/a.sock" 15 || fail "A status socket did not become ready"

INITIAL_AB_LIMIT=""
for _ in $(seq 1 600); do
  INITIAL_AB_LIMIT="$(link_datagram_limit a b 2>/dev/null || true)"
  if [[ "$INITIAL_AB_LIMIT" =~ ^[0-9]+$ ]] \
    && (( INITIAL_AB_LIMIT > LOWER_AB_MTU )) \
    && active_path_is_abc; then
    break
  fi
  sleep 0.1
done
[[ "$INITIAL_AB_LIMIT" =~ ^[0-9]+$ ]] || fail "A-B DATAGRAM capacity was not published (value=${INITIAL_AB_LIMIT:-missing})"
(( INITIAL_AB_LIMIT > LOWER_AB_MTU )) || fail "initial A-B capacity is not above the lower MTU"
active_path_is_abc || fail "initial A-B-C circuit did not become active"
INITIAL_OPEN_ACKS="$(open_ack_count)"
(( INITIAL_OPEN_ACKS > 0 )) || fail "initial circuit OPEN acknowledgement was not logged"

# A first-hop LinkCapacityChanged event must update A's active budget without
# an LSA round trip or Circuit rebuild.
sudo -n ip -n "$NS_A" link set "$AB_A" mtu "$LOWER_AB_MTU"
sudo -n ip -n "$NS_B" link set "$AB_B" mtu "$LOWER_AB_MTU"
LOWERED_AB_LIMIT=""
for _ in $(seq 1 300); do
  LOWERED_AB_LIMIT="$(link_datagram_limit a b 2>/dev/null || true)"
  if [[ "$LOWERED_AB_LIMIT" =~ ^[0-9]+$ ]] \
    && (( LOWERED_AB_LIMIT < INITIAL_AB_LIMIT )) \
    && active_path_is_abc; then
    break
  fi
  sleep 0.2
done
[[ "$LOWERED_AB_LIMIT" =~ ^[0-9]+$ ]] || fail "A-B capacity disappeared after MTU decrease"
(( LOWERED_AB_LIMIT < INITIAL_AB_LIMIT )) || fail "A-B capacity did not decrease"
active_path_is_abc || fail "Circuit path changed during first-hop MTU decrease"
[[ "$(open_ack_count)" == "$INITIAL_OPEN_ACKS" ]] || fail "MTU decrease rebuilt the Circuit"

# Restore the first hop. Recovery may take several authenticated probes.  The
# contract under test is an in-place increase after the drop; requiring the
# probe loop to rediscover its exact pre-drop ceiling makes this test depend on
# carrier-specific PMTU convergence timing.
sudo -n ip -n "$NS_A" link set "$AB_A" mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set "$AB_B" mtu "$AB_MTU"
RECOVERED_AB_LIMIT=""
for _ in $(seq 1 240); do
  RECOVERED_AB_LIMIT="$(link_datagram_limit a b 2>/dev/null || true)"
  if [[ "$RECOVERED_AB_LIMIT" =~ ^[0-9]+$ ]] \
    && (( RECOVERED_AB_LIMIT >= INITIAL_AB_LIMIT - 64 )); then
    break
  fi
  sleep 0.5
done
[[ "$RECOVERED_AB_LIMIT" =~ ^[0-9]+$ ]] || fail "A-B capacity did not recover"
(( RECOVERED_AB_LIMIT > LOWERED_AB_LIMIT )) || fail "A-B capacity did not increase after recovery"
active_path_is_abc || fail "Circuit path changed during MTU recovery"
[[ "$(open_ack_count)" == "$INITIAL_OPEN_ACKS" ]] || fail "MTU recovery rebuilt the Circuit"

echo "RFC-0022 dynamic budget integration test passed: A-B ${INITIAL_AB_LIMIT}->${LOWERED_AB_LIMIT}->${RECOVERED_AB_LIMIT}, OPEN acknowledgements=${INITIAL_OPEN_ACKS}"
