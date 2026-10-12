#!/usr/bin/env bash
# Verifies direct fallback -> relay preferred-path migration without restart.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-preferred-path-migration}"
PREFIX="${TINECT_NS_PREFIX:-tinect-migration}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"
NS_A="$PREFIX-a"; NS_B="$PREFIX-b"; NS_C="$PREFIX-c"
PIDS=()
# ShellCheck cannot see that this cleanup function is invoked by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
  local pid ns
  for pid in "${PIDS[@]:-}"; do sudo -n kill -TERM "$pid" 2>/dev/null || true; done
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    while read -r pid; do [[ -n "$pid" ]] && sudo -n kill -TERM "$pid" 2>/dev/null || true; done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; done
  sudo -n rm -f "$WORK/a.sock" "$WORK/b.sock" "$WORK/c.sock"
}
trap cleanup EXIT

sudo -n true
sudo -n rm -rf "$WORK"; mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"; BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"; CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"
for ns in "$NS_A" "$NS_B" "$NS_C"; do sudo -n ip netns del "$ns" 2>/dev/null || true; sudo -n ip netns add "$ns"; sudo -n ip -n "$ns" link set lo up; done
remote_veth_between ab-a ab-b "$NS_A" "$NS_B" 10.210.0.1/24 10.210.0.2/24
remote_veth_between bc-b bc-c "$NS_B" "$NS_C" 10.211.0.1/24 10.211.0.2/24
remote_veth_between ac-a ac-c "$NS_A" "$NS_C" 10.212.0.1/24 10.212.0.2/24
# Start with only the direct A<->C physical path available.
sudo -n ip -n "$NS_B" link set bc-b down; sudo -n ip -n "$NS_C" link set bc-c down
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://0.0.0.0:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock}
peers:
  b: {public_key: $BK, endpoints: [quic://10.210.0.2:4434]}
  c: {public_key: $CK, endpoints: [quic://10.212.0.2:4435, quic://10.210.0.2:4435], routes: [{ip_cidr: 10.64.2.2/32, priority: 100}], paths: [{path: [a, b, c]}, {path: [a, c]}]}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
peers:
  a: {public_key: $AK, endpoints: [quic://10.210.0.1:4433], paths: [{path: [b, a]}]}
  c: {public_key: $CK, endpoints: [quic://10.211.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://0.0.0.0:4435
tun: {name: tunc, addresses: [10.64.2.2/32]}
runtime: {status_socket: $WORK/c.sock}
peers:
  a: {public_key: $AK, endpoints: [quic://10.212.0.1:4433], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [c, b, a]}, {path: [c, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.211.0.1:4434]}
allowed_routes:
  - {allow: [10.64.2.2/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
connect_to: [a]
EOF

sudo -n ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PIDS+=("$!")
sudo -n ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PIDS+=("$!")

path_is() {
  local socket="$1"; local expected="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$socket" 2>/dev/null)" EXPECTED="$expected" python3 -c '
import json, os
if not os.environ["STATUS_JSON"]:
    raise SystemExit(1)
want = os.environ["EXPECTED"].split(",")
raise SystemExit(not any(c.get("destination") in ("c", "a") and c.get("healthy") and c.get("active_path_names") == want for c in json.loads(os.environ["STATUS_JSON"])["circuits"]))
'
}
for _ in $(seq 1 180); do path_is "$WORK/a.sock" a,c && path_is "$WORK/c.sock" c,a && break; sleep 0.1; done
path_is "$WORK/a.sock" a,c; path_is "$WORK/c.sock" c,a

# Restore the higher-priority relay. Both sources must migrate within the
# configured 10-second deadline while their daemons remain running.
sudo -n ip -n "$NS_B" link set bc-b up; sudo -n ip -n "$NS_C" link set bc-c up
for _ in $(seq 1 180); do
  if path_is "$WORK/a.sock" a,b,c && path_is "$WORK/c.sock" c,b,a; then
    echo "preferred path migration test passed"; exit 0
  fi
  sleep 0.1
done
echo "preferred path migration did not complete" >&2
cat "$WORK/a.log" "$WORK/b.log" "$WORK/c.log" >&2
exit 1
