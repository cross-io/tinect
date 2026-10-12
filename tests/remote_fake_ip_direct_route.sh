#!/usr/bin/env bash
# Privileged FakeIP explicit-direct route test. Fallback stays disabled so a
# success proves that direct.routes participates in domain priority ranking.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-fake-ip-direct-route}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-fake-ip-direct-route}"
source "$PWD/tests/lib/remote.sh"
remote_init "$WORK"
trap 'remote_finish $?' EXIT

sudo -n true
remote_namespace a
remote_namespace x
remote_veth ax-a ax-x a x 10.235.0.1/24 10.235.0.2/24
NS_A="$(remote_ns a)"
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.all.accept_local=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.all.rp_filter=0
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.default.rp_filter=0
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.ax-a.accept_local=1
sudo -n ip netns exec "$NS_A" sysctl -q -w net.ipv4.conf.ax-a.rp_filter=0
sudo -n ip -n "$(remote_ns x)" addr add 10.251.0.2/32 dev lo
sudo -n ip -n "$(remote_ns a)" route add 10.251.0.2/32 via 10.235.0.2 dev ax-a

remote_keygen a
remote_keygen b
BK="$(remote_public_key b)"
printf 'target.test\n' >"$WORK/domains.txt"
printf ' target.test # identical normalized set\n' >"$WORK/domains-copy.txt"

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://127.0.0.1:0
tun: {name: tinea, addresses: [10.64.0.1/32]}
direct:
  fallback: false
  dscp: 46
  fwmark: 0x100
  conntrack_zone: 32125
  routes: [{site_set: ./domains-copy.txt, priority: 120}]
fake_ip:
  listen: 127.0.0.1:5354
  upstream_dns: [10.251.0.2:5353]
  disable_ipv6: true
peers:
  b:
    public_key: $BK
    endpoints: []
    routes: [{site_set: ./domains.txt, priority: 100}]
    paths: [{path: [a, b]}]
EOF

sudo -n ip netns exec "$(remote_ns x)" \
  python3 "$PWD/tests/fake_dns_server.py" 10.251.0.2 5353 10.251.0.2 \
  >"$WORK/dns.log" 2>&1 &
REMOTE_PIDS+=("$!")
sudo -n ip netns exec "$(remote_ns x)" \
  python3 "$PWD/tests/fake_echo_server.py" 8080 >"$WORK/echo.log" 2>&1 &
REMOTE_PIDS+=("$!")

remote_start a a
remote_wait_tun a tinea
direct_table="tinect_direct_74696e6561"
remote_wait_for "direct nft table" \
  "sudo -n ip netns exec '$(remote_ns a)' nft list table inet '$direct_table' >/dev/null 2>&1" 100
direct_nat_table="tinect_direct_nat_74696e6561"
remote_wait_for "direct nat table" \
  "sudo -n ip netns exec '$(remote_ns a)' nft list table inet '$direct_nat_table' >/dev/null 2>&1" 100
sudo -n ip -n "$(remote_ns a)" rule add fwmark 0x100/0xffffffff table 100
sudo -n ip -n "$(remote_ns a)" route add 10.251.0.2/32 via 10.235.0.2 dev ax-a table 100

FAKE_IP="$(sudo -n ip netns exec "$(remote_ns a)" python3 -c '
import socket,struct
q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x06target\x04test\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,("127.0.0.1",5354));print(socket.inet_ntoa(s.recv(4096)[-4:]))
')"
[[ "$FAKE_IP" == 198.18.* ]]
remote_expect_ping a tinea "$FAKE_IP"
sudo -n ip netns exec "$(remote_ns a)" python3 - "$FAKE_IP" <<'PY'
import socket,sys
target=(sys.argv[1],8080)
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
    sock=socket.socket(socket.AF_INET,kind);sock.settimeout(3)
    if kind == socket.SOCK_STREAM: sock.connect(target)
    sock.sendto(b"fake-ip-direct-route",target) if kind == socket.SOCK_DGRAM else sock.sendall(b"fake-ip-direct-route")
    assert sock.recv(64) == b"fake-ip-direct-route"
PY

echo "FakeIP explicit direct route passed with fallback disabled"
