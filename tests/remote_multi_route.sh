#!/usr/bin/env bash
# Privileged Linux smoke test for two independently routed Overlay prefixes.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-multi-route}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-multi}"
source "$PWD/tests/lib/remote.sh"
NS_A="$TINECT_NS_PREFIX-a"; NS_B="$TINECT_NS_PREFIX-b"; NS_C="$TINECT_NS_PREFIX-c"
PIDS=()
cleanup() {
  local pid ns
  for pid in "${PIDS[@]:-}"; do sudo -n kill -TERM "$pid" 2>/dev/null || true; done
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    while read -r pid; do
      [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; done
  sudo -n rm -f "$WORK/a.sock" "$WORK/b.sock" "$WORK/c.sock"
}
trap cleanup EXIT

sudo -n true
rm -rf "$WORK" && mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"
CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"

for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; sudo -n ip netns add "$ns"; sudo -n ip -n "$ns" link set lo up; done
remote_veth_between ab-a ab-b "$NS_A" "$NS_B" 10.201.0.1/24 10.201.0.2/24
remote_veth_between ac-a ac-c "$NS_A" "$NS_C" 10.202.0.1/24 10.202.0.2/24
for ns in "$NS_B" "$NS_C"; do
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
done

cat >"$WORK/a.yaml" <<EOF
id: a
accept_connections: true
allow_transit: true
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
peers:
  b: {public_key: $BK, endpoints: [quic://10.201.0.2:4434], routes: [{ip_cidr: 10.64.1.2/32, priority: 100}], paths: [{path: [a, b]}]}
  c: {public_key: $CK, endpoints: [quic://10.202.0.2:4435], routes: [{ip_cidr: 10.64.2.2/32, priority: 100}], paths: [{path: [a, c]}]}
connect_to: [b, c]
EOF
for n in b c; do
  key_var="${n^^}K"; eval "PK=\${$key_var}"
  if [[ "$n" == b ]]; then listen=10.201.0.2:4434; prefix=10.64.1.2/32; tun=tunb; addr=10.64.1.2/32; endpoint=10.201.0.1:4433; else listen=10.202.0.2:4435; prefix=10.64.2.2/32; tun=tunc; addr=10.64.2.2/32; endpoint=10.202.0.1:4433; fi
  cat >"$WORK/$n.yaml" <<EOF
id: $n
accept_connections: true
allow_transit: true
identity_key_path: $WORK/$n.key
listen: quic://$listen
tun: {name: $tun, addresses: [$addr]}
runtime: {status_socket: $WORK/$n.sock}
peers:
  a: {public_key: $AK, endpoints: [quic://$endpoint], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [$n, a]}]}
allowed_routes:
  - allow: [$prefix]
    for: [a]
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF
done

sudo -n ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PIDS+=("$!")
for _ in $(seq 1 50); do sudo -n ip -n "$NS_A" link show tinea >/dev/null 2>&1 && sudo -n ip -n "$NS_B" link show tunb >/dev/null 2>&1 && sudo -n ip -n "$NS_C" link show tunc >/dev/null 2>&1 && break; sleep 0.1; done
# A may create tinea as soon as its first exit is ready. Wait for both
# independently authenticated Links before exercising either prefix.
for _ in $(seq 1 100); do
  [[ "$(grep -c 'outbound QUIC link authenticated' "$WORK/a.log" || true)" -ge 2 ]] && break
  sleep 0.1
done
[[ "$(grep -c 'outbound QUIC link authenticated' "$WORK/a.log" || true)" -ge 2 ]]
expect_ping() {
  local target="$1"
  # The first packet may bootstrap the bidirectional reliable sessions used
  # by the authenticated physical payload protocol. Keep the assertion on
  # the target route, but allow that bounded setup exchange to complete.
  for _ in $(seq 1 20); do
    if sudo -n ip netns exec "$NS_A" ping -I tinea -c 1 -W 1 "$target"; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out reaching $target through tinea" >&2
  return 1
}

expect_ping 10.64.1.2
expect_ping 10.64.2.2
echo "multi-route encrypted TUN test passed"
