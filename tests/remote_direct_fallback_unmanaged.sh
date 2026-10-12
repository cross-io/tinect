#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-df-unmanaged-$TINECT_NS_PREFIX}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-df-unmanaged}"
source "$SCRIPT_DIR/lib/remote.sh"

remote_init "$WORK"
trap 'remote_finish $?' EXIT
remote_namespace a
remote_namespace x
remote_namespace y
remote_veth ax xa a x 10.240.0.1/24 10.240.0.2/24
remote_veth xy yx x y 10.241.0.1/24 10.241.0.2/24
NS_A="$(remote_ns a)"
NS_X="$(remote_ns x)"
NS_Y="$(remote_ns y)"
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.all.accept_local=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.ax.rp_filter=0
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.ax.accept_local=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.all.accept_local=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xa.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xa.accept_local=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xy.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xy.accept_local=1
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.yx.rp_filter=0
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.yx.accept_local=1
sudo -n ip -n "$NS_A" -6 addr add fd00:240::1/64 dev ax nodad
sudo -n ip -n "$NS_X" -6 addr add fd00:240::2/64 dev xa nodad
sudo -n ip -n "$NS_X" -6 addr add fd00:241::1/64 dev xy nodad
sudo -n ip -n "$NS_Y" -6 addr add fd00:241::2/64 dev yx nodad
AX_MAC="$(sudo -n ip -n "$NS_A" link show ax 2>/dev/null | awk '/link\/ether/ {print $2}')"
XA_MAC="$(sudo -n ip -n "$NS_X" link show xa 2>/dev/null | awk '/link\/ether/ {print $2}')"
XY_MAC="$(sudo -n ip -n "$NS_X" link show xy 2>/dev/null | awk '/link\/ether/ {print $2}')"
YX_MAC="$(sudo -n ip -n "$NS_Y" link show yx 2>/dev/null | awk '/link\/ether/ {print $2}')"
sudo -n ip -n "$NS_A" neigh replace 10.240.0.2 lladdr "$XA_MAC" nud permanent dev ax
sudo -n ip -n "$NS_A" -6 neigh replace fd00:240::2 lladdr "$XA_MAC" nud permanent dev ax
sudo -n ip -n "$NS_X" neigh replace 10.240.0.1 lladdr "$AX_MAC" nud permanent dev xa
sudo -n ip -n "$NS_X" -6 neigh replace fd00:240::1 lladdr "$AX_MAC" nud permanent dev xa
sudo -n ip -n "$NS_X" neigh replace 10.241.0.2 lladdr "$YX_MAC" nud permanent dev xy
sudo -n ip -n "$NS_X" -6 neigh replace fd00:241::2 lladdr "$YX_MAC" nud permanent dev xy
sudo -n ip -n "$NS_Y" neigh replace 10.241.0.1 lladdr "$XY_MAC" nud permanent dev yx
sudo -n ip -n "$NS_Y" -6 neigh replace fd00:241::1 lladdr "$XY_MAC" nud permanent dev yx
sudo -n ip -n "$NS_Y" addr add 10.250.0.2/32 dev lo
sudo -n ip -n "$NS_Y" route add 10.240.0.0/24 via 10.241.0.1 dev yx
sudo -n ip -n "$NS_Y" -6 addr add fd00:250::2/128 dev lo nodad
sudo -n ip -n "$NS_Y" -6 route add fd00:240::/64 via fd00:241::1 dev yx
sudo -n ip -n "$NS_X" route add 10.250.0.2/32 via 10.241.0.2 dev xy
sudo -n ip -n "$NS_X" -6 route add fd00:250::2/128 via fd00:241::2 dev xy

remote_keygen a
cat >"$WORK/a.yaml" <<CONFIG_EOF
id: a
identity_key_path: $WORK/a.key
managed_routes: false
listen: quic://127.0.0.1:0
direct:
  fallback: true
  dscp: 46
  fwmark: 0x100
  conntrack_zone: 32123
tun: {name: tinea, addresses: [10.64.0.1/32, fd00:64::1/128]}
CONFIG_EOF

remote_start a a
remote_wait_tun a tinea 100
direct_table="tinect_direct_74696e6561"
nat_table="tinect_direct_nat_74696e6561"
remote_wait_for "direct fallback nft table" \
  "sudo -n ip netns exec '$NS_A' nft list table inet '$direct_table' >/dev/null 2>&1" 100
# managed_routes=false: the directional-zone table and ctnetlink worker must
# still be active so the operator's own masquerade can bind reinjected flows.
remote_wait_for "direct fallback conntrack zone table" \
  "sudo -n ip netns exec '$NS_A' nft list table inet '$nat_table' >/dev/null 2>&1" 100
sudo -n ip netns exec "$NS_A" nft list table inet "$nat_table" >"$WORK/zone-rules.nft"
grep -Eq 'ct (original )?zone set 32123' "$WORK/zone-rules.nft"
if grep -Fq 'notrack' "$WORK/zone-rules.nft"; then
  echo "direct fallback must not disable conntrack" >&2
  exit 1
fi
grep -Fq 'masquerade' "$WORK/zone-rules.nft" && {
  echo "managed_routes=false must not install the owned masquerade" >&2
  exit 1
}

# Operator-owned routing and NAT (the managed_routes=false contract):
# 1. route overlay-unknown destinations into the TUN,
# 2. policy-route reinjected (fwmark 0x100) packets to the default egress,
# 3. masquerade reinjected packets leaving the egress.
sudo -n ip -n "$NS_A" route add 10.250.0.2/32 dev tinea
sudo -n ip -n "$NS_A" -6 route add fd00:250::2/128 dev tinea
sudo -n ip -n "$NS_A" rule add fwmark 0x100/0xffffffff table 100
sudo -n ip -n "$NS_A" -6 rule add fwmark 0x100/0xffffffff table 100
sudo -n ip -n "$NS_A" route add 10.240.0.0/24 dev ax table 100
sudo -n ip -n "$NS_A" -6 route add fd00:240::/64 dev ax table 100
sudo -n ip -n "$NS_A" route add 10.250.0.2/32 via 10.240.0.2 dev ax table 100
sudo -n ip -n "$NS_A" -6 route add fd00:250::2/128 via fd00:240::2 dev ax table 100
sudo -n ip netns exec "$NS_A" nft add table inet operator_nat
sudo -n ip netns exec "$NS_A" nft add chain inet operator_nat postrouting '{ type nat hook postrouting priority 100; policy accept; }'
sudo -n ip netns exec "$NS_A" nft add rule inet operator_nat postrouting oifname "ax" masquerade

capture_and_ping() {
  local family="$1" target="$2" ping_command capture_filter expected_source
  if [[ "$family" == v4 ]]; then
    ping_command=(ping -I 10.64.0.1 -c 2 -W 2 "$target")
    capture_filter="icmp and host $target"
    expected_source="10.240.0.1 > $target"
  else
    ping_command=(ping -6 -I fd00:64::1 -c 2 -W 2 "$target")
    capture_filter="icmp6 and host $target"
    expected_source="fd00:240::1 > $target"
  fi
  sudo -n ip netns exec "$NS_Y" timeout 5 tcpdump -ni yx -c 1 "$capture_filter" \
    >"$WORK/$family.peer-y.capture" 2>&1 &
  local peer_y_capture_pid=$!
  sleep 0.3
  if ! sudo -n ip netns exec "$NS_A" "${ping_command[@]}"; then
    kill "$peer_y_capture_pid" 2>/dev/null || true
    wait "$peer_y_capture_pid" 2>/dev/null || true
    cat "$WORK/$family.peer-y.capture" >&2 || true
    return 1
  fi
  wait "$peer_y_capture_pid"
  grep -Fq "$expected_source" "$WORK/$family.peer-y.capture"
}

capture_and_ping v4 10.250.0.2
capture_and_ping v6 fd00:250::2
echo "managed_routes=false direct fallback with operator NAT passed"
remote_finish 0
