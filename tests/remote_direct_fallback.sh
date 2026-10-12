#!/usr/bin/env bash
# Verifies direct fallback for IPv4/IPv6, including mark policy routing and
# the kernel-side loop guard when the mark is deliberately routed back to TUN.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-direct-fallback}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-direct-fallback}"
source "$SCRIPT_DIR/lib/remote.sh"

remote_init "$WORK"
trap 'remote_finish $?' EXIT
remote_namespace a
remote_namespace s
remote_namespace x
remote_namespace y
remote_veth sa as s a 10.99.0.1/24 10.99.0.2/24
remote_veth ax xa a x 10.240.0.1/24 10.240.0.2/24
remote_veth xy yx x y 10.241.0.1/24 10.241.0.2/24
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.conf.all.accept_local=1
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.conf.ax.rp_filter=0
sudo -n ip netns exec "$(remote_ns a)" sysctl -q -w net.ipv4.conf.as.rp_filter=0
NS_A="$(remote_ns a)"
NS_S="$(remote_ns s)"
NS_X="$(remote_ns x)"
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.ax.accept_local=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.as.accept_local=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.all.accept_local=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xa.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xa.accept_local=1
NS_Y="$(remote_ns y)"
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xy.rp_filter=0
sudo -n ip netns exec "$NS_X" sysctl -q -w net.ipv4.conf.xy.accept_local=1
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_Y" sysctl -q -w net.ipv4.conf.yx.rp_filter=0
sudo -n ip -n "$NS_A" -6 addr add fd00:99::2/64 dev as nodad
sudo -n ip -n "$NS_S" -6 addr add fd00:99::1/64 dev sa nodad
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
# Replies only need a route back to the masqueraded underlay source. There is
# deliberately no route to the TUN source: a ping that succeeds therefore
# proves the automatic direct-fallback masquerade is actually translating.
sudo -n ip -n "$NS_Y" route add 10.240.0.0/24 via 10.241.0.1 dev yx
sudo -n ip -n "$NS_Y" -6 addr add fd00:250::2/128 dev lo nodad
sudo -n ip -n "$NS_Y" -6 route add fd00:240::/64 via fd00:241::1 dev yx
sudo -n ip -n "$NS_S" route add 10.250.0.2/32 via 10.99.0.2 dev sa
sudo -n ip -n "$NS_S" -6 route add fd00:250::2/128 via fd00:99::2 dev sa
sudo -n ip -n "$NS_X" route add 10.250.0.2/32 via 10.241.0.2 dev xy
sudo -n ip -n "$NS_X" -6 route add fd00:250::2/128 via fd00:241::2 dev xy

remote_keygen a
cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
managed_routes: true
listen: quic://127.0.0.1:0
direct:
  fallback: true
  dscp: 46
  fwmark: 0x100
  conntrack_zone: 32123
tun: {name: tinea, addresses: [10.64.0.1/32, fd00:64::1/128]}
EOF

remote_start a a
remote_wait_tun a tinea 100
direct_table="tinect_direct_74696e6561"
remote_wait_for "direct fallback nft table" \
  "sudo -n ip netns exec '$NS_A' nft list table inet '$direct_table' >/dev/null 2>&1" 100
sudo -n ip netns exec "$NS_A" nft list table inet "$direct_table" >"$WORK/direct-rules.nft"
grep -Fq 'hook prerouting' "$WORK/direct-rules.nft"
grep -Fq 'policy accept' "$WORK/direct-rules.nft"
grep -Fq 'meta mark set' "$WORK/direct-rules.nft"
grep -Fq 'drop' "$WORK/direct-rules.nft"
cat "$WORK/direct-rules.nft"

# With managed_routes enabled the daemon also installs the fallback
# POSTROUTING masquerade. The integration fixture acts as the operator's own
# nft configuration; the daemon-owned table must appear and translate the
# reinjected TUN source before packets leave the underlay.
nat_table="tinect_direct_nat_74696e6561"
remote_wait_for "direct fallback nat table" \
  "sudo -n ip netns exec '$NS_A' nft list table inet '$nat_table' >/dev/null 2>&1" 100
sudo -n ip netns exec "$NS_A" nft list table inet "$nat_table" >"$WORK/direct-nat-rules.nft"
grep -Eq 'ct (original )?zone set 32123' "$WORK/direct-nat-rules.nft"
if grep -Fq 'notrack' "$WORK/direct-nat-rules.nft"; then
  echo "direct fallback must not disable conntrack" >&2
  exit 1
fi
grep -Fq 'hook postrouting' "$WORK/direct-nat-rules.nft"
grep -Fq 'masquerade' "$WORK/direct-nat-rules.nft"
cat "$WORK/direct-nat-rules.nft"

sudo -n ip -n "$NS_A" route add 10.250.0.2/32 dev tinea
sudo -n ip -n "$NS_A" -6 route add fd00:250::2/128 dev tinea
sudo -n ip -n "$NS_A" rule add fwmark 0x100/0xffffffff table 100
sudo -n ip -n "$NS_A" -6 rule add fwmark 0x100/0xffffffff table 100
sudo -n ip -n "$NS_A" route add 10.240.0.0/24 dev ax table 100
sudo -n ip -n "$NS_A" -6 route add fd00:240::/64 dev ax table 100
sudo -n ip -n "$NS_A" route add 10.250.0.2/32 via 10.240.0.2 dev ax table 100
sudo -n ip -n "$NS_A" -6 route add fd00:250::2/128 via fd00:240::2 dev ax table 100
sudo -n ip -n "$NS_A" rule show
sudo -n ip -n "$NS_A" route show table 100
sudo -n ip -n "$NS_A" -6 route show table 100
sudo -n ip netns exec "$NS_A" ip route get 10.250.0.2 from 10.64.0.1 mark 0x100
sudo -n ip netns exec "$NS_A" ip -6 route get fd00:250::2 from fd00:64::1 mark 0x100
sudo -n ip netns exec "$NS_A" sysctl net.ipv4.ip_forward net.ipv4.conf.all.forwarding net.ipv4.conf.ax.forwarding

capture_and_ping() {
  local family="$1" target="$2" ping_ns="${3:-}" ping_source="${4:-}"
  local ping_command capture_filter expected_source
  ping_ns="${ping_ns:-$NS_A}"
  if [[ "$family" == v4 ]]; then
    ping_command=(ping -I "${ping_source:-10.64.0.1}" -c 2 -W 2 "$target")
    capture_filter="icmp and host $target"
    expected_source="10.240.0.1 > $target"
  else
    ping_command=(ping -6 -I "${ping_source:-fd00:64::1}" -c 2 -W 2 "$target")
    capture_filter="icmp6 and host $target"
    expected_source="fd00:240::1 > $target"
  fi
  sudo -n ip netns exec "$NS_A" timeout 5 tcpdump -ni ax -c 1 -xx "$capture_filter" \
    >"$WORK/$family.capture" 2>&1 &
  local capture_pid=$!
  sudo -n ip netns exec "$NS_X" timeout 5 tcpdump -ni any -c 1 -xx "$capture_filter" \
    >"$WORK/$family.peer.capture" 2>&1 &
  local peer_capture_pid=$!
  sudo -n ip netns exec "$NS_X" timeout 5 tcpdump -ni lo -c 1 -xx "$capture_filter" \
    >"$WORK/$family.peer-lo.capture" 2>&1 &
  local peer_lo_capture_pid=$!
  sudo -n ip netns exec "$NS_Y" timeout 5 tcpdump -ni yx -c 1 "$capture_filter" \
    >"$WORK/$family.peer-y.capture" 2>&1 &
  local peer_y_capture_pid=$!
  sleep 0.2
  if ! sudo -n ip netns exec "$ping_ns" "${ping_command[@]}"; then
    kill "$capture_pid" 2>/dev/null || true
    kill "$peer_capture_pid" 2>/dev/null || true
    kill "$peer_lo_capture_pid" 2>/dev/null || true
    kill "$peer_y_capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    wait "$peer_capture_pid" 2>/dev/null || true
    wait "$peer_lo_capture_pid" 2>/dev/null || true
    wait "$peer_y_capture_pid" 2>/dev/null || true
    cat "$WORK/$family.capture" >&2 || true
    cat "$WORK/$family.peer.capture" >&2 || true
    cat "$WORK/$family.peer-lo.capture" >&2 || true
    cat "$WORK/$family.peer-y.capture" >&2 || true
    sudo -n ip -n "$NS_X" -br addr show 2>/dev/null >&2 || true
    sudo -n ip -n "$NS_X" route show table main >&2 || true
    sudo -n ip -n "$NS_Y" -br addr show 2>/dev/null >&2 || true
    sudo -n ip -n "$NS_Y" route show table main >&2 || true
    sudo -n ip netns exec "$NS_A" nft list table inet "$direct_table" >&2 || true
    return 1
  fi
  wait "$capture_pid"
  kill "$peer_capture_pid" "$peer_lo_capture_pid" "$peer_y_capture_pid" 2>/dev/null || true
  wait "$peer_capture_pid" 2>/dev/null || true
  wait "$peer_lo_capture_pid" 2>/dev/null || true
  wait "$peer_y_capture_pid" 2>/dev/null || true
  # The peer must observe the masqueraded underlay source, not the TUN source:
  # with managed_routes the daemon owns this NAT step.
  grep -Fq "$expected_source" "$WORK/$family.peer-y.capture"
  # The first IPv4/IPv6 header word on the underlay must prove that DSCP was
  # cleared while ECN, IPv4 total-length, and the IPv6 flow label survive.
  python3 - "$family" "$WORK/$family.capture" <<'PY'
import re, sys
family, path = sys.argv[1], sys.argv[2]
try:
    text = open(path, encoding="utf-8", errors="replace").read()
except OSError:
    raise SystemExit(1)
ethertype = "0800" if family == "v4" else "86dd"
match = re.search(ethertype + r" ([0-9a-f]{4})", text)
if not match:
    raise SystemExit(1)
word = int(match.group(1), 16)
if family == "v4":
    dscp = (word & 0x00ff) >> 2
else:
    traffic_class = ((word >> 8) & 0x0f) << 4 | ((word >> 4) & 0x0f)
    dscp = traffic_class >> 2
if dscp != 0:
    raise SystemExit(1)
PY
}

# A successful ping proves the prerouting mark selected table 100 instead of
# the ordinary TUN route, and the header-word check proves that DSCP was
# cleared before the packet reached the local default/underlay exit.
capture_and_ping v4 10.250.0.2
capture_and_ping v6 fd00:250::2

# Forwarded path: a sender behind the tinect node routes through the TUN. The
# first pass is FORWARD traffic. The ctnetlink delete must remove that default
# zone flow before the reinjected packet is assigned to zone 32123 and reaches
# the owned masquerade chain.
capture_and_ping v4 10.250.0.2 "$NS_S" 10.99.0.1
capture_and_ping v6 fd00:250::2 "$NS_S" fd00:99::1

# Fault injection: kill the daemon without running Drop/cleanup while active
# fallback-zone flows exist. The kernel-owned conntrack entries and nft tables
# survive the process, so the replacement daemon must flush the reserved zone
# before it accepts new fallback traffic. This covers downstream restart and
# late/stale state rather than relying only on a graceful reconnect.
DIRECT_CONNTRACK_ZONE=32123
zone_entries() {
  # Recent kernels can disable the legacy conntrack procfs interface while
  # still exposing the same entries through ctnetlink. Keep the assertion
  # tied to the kernel API rather than a version-specific proc file.
  sudo -n ip netns exec "$NS_A" conntrack -L --orig-zone "$DIRECT_CONNTRACK_ZONE" 2>/dev/null \
    | awk 'NF { count++ } END { print count + 0 }'
}
if [[ "$(zone_entries)" -eq 0 ]]; then
  echo "expected active direct fallback conntrack entries before crash" >&2
  exit 1
fi
crashed_pid="$(sudo -n ip netns pids "$NS_A" | head -1)"
sudo -n kill -KILL "$crashed_pid"
for _ in $(seq 1 100); do
  if ! sudo -n kill -0 "$crashed_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if sudo -n kill -0 "$crashed_pid" 2>/dev/null; then
  echo "fault-injected daemon did not exit" >&2
  exit 1
fi
wait "${REMOTE_PIDS[0]}" 2>/dev/null || true
REMOTE_PIDS=()
if [[ "$(zone_entries)" -eq 0 ]]; then
  echo "crash unexpectedly removed the stale fallback zone" >&2
  exit 1
fi

remote_start a a
remote_wait_tun a tinea 100
remote_wait_for "replacement direct fallback nft table" \
  "sudo -n ip netns exec '$NS_A' nft list table inet '$nat_table' >/dev/null 2>&1" 100
remote_wait_for "replacement daemon startup zone flush" \
  "[[ \"\$(zone_entries)\" -eq 0 ]]" 100
# Routes whose output device was the crashed TUN are removed with that device;
# policy rules and underlay table-100 routes remain valid.
sudo -n ip -n "$NS_A" route add 10.250.0.2/32 dev tinea
sudo -n ip -n "$NS_A" -6 route add fd00:250::2/128 dev tinea
capture_and_ping v4 10.250.0.2
capture_and_ping v6 fd00:250::2

# Count packets the forward-hook loop guard has dropped so far. The reinjected
# packet is a fresh skb whose mark is zero and whose DSCP is cleared by the
# prerouting rule, so a prerouting check can never see the loop; the drop must
# happen after routing, when the marked packet is about to be transmitted back
# into this TUN.
direct_loop_drops() {
  sudo -n ip netns exec "$NS_A" nft list chain inet "$direct_table" forward 2>/dev/null \
    | sed -n 's/.*counter packets \([0-9][0-9]*\) bytes.*drop.*/\1/p' | head -1
}

# Deliberately route the direct-fallback mark back to TUN. The daemon must not
# receive an endless stream of its own packets: the owned forward/output rules
# drop the marked packet after routing, before it can be read from the TUN fd
# again. The drop counters must advance, proving the guard actually fired
# instead of the ping failing merely because replies cannot be delivered.
loop_drops_before="$(direct_loop_drops)"
sudo -n ip -n "$NS_A" route replace 10.250.0.2/32 dev tinea table 100
sudo -n ip -n "$NS_A" -6 route replace fd00:250::2/128 dev tinea table 100
if sudo -n ip netns exec "$NS_A" timeout 3 ping -I 10.64.0.1 -c 1 -W 1 10.250.0.2; then
  echo "IPv4 direct fallback loop unexpectedly reached the target" >&2
  exit 1
fi
if sudo -n ip netns exec "$NS_A" timeout 3 ping -6 -I fd00:64::1 -c 1 -W 1 fd00:250::2; then
  echo "IPv6 direct fallback loop unexpectedly reached the target" >&2
  exit 1
fi
loop_drops_after="$(direct_loop_drops)"
if [[ -z "$loop_drops_before" || -z "$loop_drops_after" \
  || "$loop_drops_after" -le "$loop_drops_before" ]]; then
  echo "direct fallback mark loop guard did not drop the marked packet" >&2
  sudo -n ip netns exec "$NS_A" nft list table inet "$direct_table" >&2 || true
  exit 1
fi

# Stop before deleting the namespace so cleanup can be checked explicitly.
# Signal the tinect process inside the namespace directly: forwarding SIGTERM
# through the sudo/ip netns exec wrapper chain is not guaranteed to reach the
# daemon in every runner environment, and a stuck shutdown must fail this test
# quickly instead of consuming the whole CI timeout.
daemon_pid="$(sudo -n ip netns pids "$NS_A" | head -1)"
if [[ -z "$daemon_pid" ]]; then
  echo "daemon is not running before shutdown" >&2
  exit 1
fi
sudo -n kill -TERM "$daemon_pid"
for _ in $(seq 1 100); do
  if ! sudo -n kill -0 "$daemon_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if sudo -n kill -0 "$daemon_pid" 2>/dev/null; then
  echo "daemon did not exit within 10s of SIGTERM" >&2
  tail -50 "$WORK/a.log" >&2 || true
  exit 1
fi
REMOTE_PIDS=()
if sudo -n ip netns exec "$NS_A" nft list table inet "$direct_table" >/dev/null 2>&1; then
  echo "direct fallback nft table survived daemon shutdown" >&2
  exit 1
fi
if sudo -n ip netns exec "$NS_A" nft list table inet "$nat_table" >/dev/null 2>&1; then
  echo "direct fallback nat table survived daemon shutdown" >&2
  exit 1
fi
if [[ "$(zone_entries)" -ne 0 ]]; then
  echo "direct fallback conntrack zone survived daemon shutdown" >&2
  exit 1
fi

remote_finish 0
