#!/usr/bin/env bash
# Privileged two-node FakeIP test. Also proves a pure-IP site_set works on B without FakeIP.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-fake-ip}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-fake-ip}"
source "$PWD/tests/lib/remote.sh"
remote_init "$WORK"
trap 'remote_finish $?' EXIT

sudo -n true
remote_namespace a
remote_namespace b
remote_veth ab-a ab-b a b 10.231.0.1/24 10.231.0.2/24
sudo -n ip netns exec "$(remote_ns b)" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns b)" sysctl -qw net.ipv6.conf.all.forwarding=1
remote_keygen a
remote_keygen b
AK="$(remote_public_key a)"
BK="$(remote_public_key b)"

printf 'target.test\n' >"$WORK/domains.txt"
printf ' target.test # same normalized content\n' >"$WORK/domains-copy.txt"

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.231.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
fake_ip:
  listen: 127.0.0.1:5354
  upstream_dns: [127.0.0.1:5399]
  disable_ipv6: true
peers:
  b:
    public_key: $BK
    endpoints: [quic://10.231.0.2:4434]
    upstream_dns: [127.0.0.1:5398]
    routes:
      - {site_set: ./domains.txt, priority: 100}
      - {site_set: ./domains-copy.txt, priority: 80}
    paths:
      - path: [a, b]
        override_upstream_dns: [127.0.0.1:5353]
        override_routes: [{site_set: ./domains.txt, priority: 110}]
connect_to: [b]
EOF

cat >"$WORK/b.yaml" <<EOF
id: b
identity_key_path: $WORK/b.key
listen: quic://10.231.0.2:4434
tun: {name: tunb, addresses: [10.64.1.2/32]}
peers:
  a:
    public_key: $AK
    endpoints: [quic://10.231.0.1:4433]
    # Return traffic is addressed to A's node-side TUN identity, never to the
    # source-local FakeIP pool.
    routes: [{ip_cidr: 10.64.0.1/32, priority: 100}]
    paths: [{path: [b, a]}]
allowed_local_ports:
  - {allow: [icmp, 'tcp(8080)', 'udp(8080)'], for: [a]}
allowed_routes:
  - {allow: [127.0.0.1/32], for: [a]}
EOF

sudo -n ip netns exec "$(remote_ns b)" python3 "$PWD/tests/fake_dns_server.py" 127.0.0.1 5353 10.64.1.2 >"$WORK/dns.log" 2>&1 &
REMOTE_PIDS+=("$!")
sudo -n ip netns exec "$(remote_ns b)" python3 "$PWD/tests/fake_echo_server.py" 8080 >"$WORK/echo.log" 2>&1 &
REMOTE_PIDS+=("$!")
remote_start b b
remote_start a a
remote_wait_tun a tinea
remote_wait_tun b tunb
remote_wait_log a "outbound QUIC link authenticated"

resolve_fake_ip() {
  FAKE_IP="$(sudo -n ip netns exec "$(remote_ns a)" python3 -c '
import socket,struct
q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x06target\x04test\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,("127.0.0.1",5354));r=s.recv(4096)
print(socket.inet_ntoa(r[-4:]))
' 2>/dev/null)" || return 1
  [[ "$FAKE_IP" == 198.18.* ]]
}

# Link authentication can complete before the node-local FakeIP listener is
# ready to accept queries. Wait for the actual DNS response before testing the
# data path, while keeping the startup wait bounded.
remote_wait_deadline "FakeIP DNS response" 30 resolve_fake_ip
remote_expect_ping a tinea "$FAKE_IP"
sudo -n ip netns exec "$(remote_ns a)" python3 - "$FAKE_IP" <<'PY'
import socket,sys
target=(sys.argv[1],8080)
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
    sock=socket.socket(socket.AF_INET,kind);sock.settimeout(3)
    if kind == socket.SOCK_STREAM: sock.connect(target)
    sock.sendto(b"fake-ip-return-path",target) if kind == socket.SOCK_DGRAM else sock.sendall(b"fake-ip-return-path")
    data=sock.recv(128)
    assert data == b"fake-ip-return-path", data
PY

# Removing the node-identity route prevents kernel replies from reaching the
# return-flow table and therefore fails closed. The FakeIP pool is not routed
# on B at any point.
sudo -n ip -n "$(remote_ns b)" route del 10.64.0.1/32 dev tunb
remote_expect_no_ping a tinea "$FAKE_IP"

echo "FakeIP path DNS override, port-aware return path, shared site set, and independent pure-IP site-set test passed"
