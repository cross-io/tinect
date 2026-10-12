#!/usr/bin/env bash
# Two same-prefix NAT exits; verifies traffic switches from b to c when b dies.
set -euo pipefail
BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-exit-failover}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-exit}"
source "$PWD/tests/lib/remote.sh"
NS_A="$TINECT_NS_PREFIX-a"; NS_B="$TINECT_NS_PREFIX-b"; NS_C="$TINECT_NS_PREFIX-c"; NS_X="$TINECT_NS_PREFIX-x"
PIDS=()
expect_overlay_ping() {
  local target="$1"
  local attempt
  for attempt in $(seq 1 20); do
    if sudo -n ip netns exec "$NS_A" ping -I tinea -c 1 -W 1 "$target"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}
cleanup() {
  for pid in "${PIDS[@]:-}"; do sudo -n kill "$pid" 2>/dev/null || true; done
  for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_X"; do
    while read -r pid; do
      [[ -n "$pid" ]] && sudo -n kill "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_X"; do sudo -n ip netns del "$ns" 2>/dev/null || true; done
  sudo -n rm -f "$WORK/a.sock" "$WORK/b.sock" "$WORK/c.sock"
}
trap cleanup EXIT
sudo -n true
sudo -n rm -rf "$WORK"
mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"
CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"
for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_X"; do sudo -n ip netns del "$ns" 2>/dev/null || true; sudo -n ip netns add "$ns"; sudo -n ip -n "$ns" link set lo up; done
remote_veth_between ab-a ab-b "$NS_A" "$NS_B" 10.220.0.1/24 10.220.0.2/24
remote_veth_between ac-a ac-c "$NS_A" "$NS_C" 10.223.0.1/24 10.223.0.2/24
remote_veth_between bx-b bx-x "$NS_B" "$NS_X" 10.221.0.1/30 10.221.0.2/30
remote_veth_between cx-c cx-x "$NS_C" "$NS_X" 10.222.0.1/30 10.222.0.2/30
sudo -n ip -n "$NS_X" addr add 10.250.0.2/32 dev lo
sudo -n ip -n "$NS_B" route add 10.250.0.2/32 via 10.221.0.2
sudo -n ip -n "$NS_C" route add 10.250.0.2/32 via 10.222.0.2
# Internet exits require administrator-owned forwarding.  Configure both
# families explicitly in these isolated test namespaces rather than relying
# on Tinect to mutate host-wide sysctls.
for ns in "$NS_B" "$NS_C"; do
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
done
cat >"$WORK/a.yaml" <<EOF
id: a
allow_transit: true
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
link_health: {keepalive_secs: 2, idle_timeout_secs: 15, reconnect_interval_secs: 2}
peers:
  b: {public_key: $BK, endpoints: [quic://10.220.0.2:4434], routes: [{ip_cidr: 10.250.0.0/24, priority: 100}], paths: [{path: [a, b]}]}
  c: {public_key: $CK, endpoints: [quic://10.223.0.2:4435], routes: [{ip_cidr: 10.250.0.0/24, priority: 50}], paths: [{path: [a, c]}]}
connect_to: [b, c]
EOF
for n in b c; do
  if [[ "$n" == b ]]; then key="$BK"; listen=10.220.0.2:4434; endpoint=10.220.0.1:4433; tun=tunb; addr=10.64.1.1/32; else key="$CK"; listen=10.223.0.2:4435; endpoint=10.223.0.1:4433; tun=tunc; addr=10.64.2.1/32; fi
  cat >"$WORK/$n.yaml" <<EOF
id: $n
allow_transit: true
identity_key_path: $WORK/$n.key
listen: quic://$listen
tun: {name: $tun, addresses: [$addr]}
runtime: {status_socket: $WORK/$n.sock}
peers:
  a: {public_key: $AK, endpoints: [quic://$endpoint], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [$n, a]}]}
allowed_routes:
  - allow: [10.250.0.0/24]
    for: [a]
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF
done
sudo -n ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PID_B=$!; PIDS+=("$PID_B")
sudo -n ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PID_C=$!; PIDS+=("$PID_C")
sudo -n ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PID_A=$!; PIDS+=("$PID_A")
for _ in $(seq 1 80); do sudo -n ip -n "$NS_A" link show tinea >/dev/null 2>&1 && break; sleep 0.1; done
sudo -n ip -n "$NS_A" link show tinea >/dev/null
sleep 3
expect_overlay_ping 10.250.0.2
# Network namespaces do not isolate the PID view; kill only processes whose
# network namespace is tinect-b, never a host-wide pkill.
while read -r pid; do
  [[ -n "$pid" ]] && sudo -n kill "$pid" 2>/dev/null || true
done < <(sudo -n ip netns pids "$NS_B" 2>/dev/null || true)
# Wait for the carrier close instead of guessing from a keepalive interval.
# The configured QUIC idle timeout is the actual upper bound; the route
# binding refresher runs independently after the close is observed.
for _ in $(seq 1 250); do
  if grep -q 'control stream closed peer_name=b' "$WORK/a.log"; then
    break
  fi
  sleep 0.1
done
grep -q 'control stream closed peer_name=b' "$WORK/a.log"
sleep 1
expect_overlay_ping 10.250.0.2
echo "same-prefix exit failover test passed"
