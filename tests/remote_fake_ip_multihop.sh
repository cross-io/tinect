#!/usr/bin/env bash
# Privileged three-node FakeIP return-path test through an opaque relay.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-fake-ip-multihop}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-fake-ip-multihop}"
source "$PWD/tests/lib/remote.sh"
remote_init "$WORK"
trap 'remote_finish $?' EXIT

sudo -n true
for node in a r b; do remote_namespace "$node"; remote_keygen "$node"; done
remote_veth ar-a ar-r a r 10.232.0.1/24 10.232.0.2/24
remote_veth rb-r rb-b r b 10.233.0.1/24 10.233.0.2/24
sudo -n ip netns exec "$(remote_ns b)" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$(remote_ns b)" sysctl -qw net.ipv6.conf.all.forwarding=1
AK="$(remote_public_key a)"; RK="$(remote_public_key r)"; BK="$(remote_public_key b)"
printf 'target.test\n' >"$WORK/domains.txt"

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.232.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
fake_ip:
  listen: 127.0.0.1:5354
  upstream_dns: [127.0.0.1:5399]
  disable_ipv6: true
peers:
  r: {public_key: $RK, endpoints: [quic://10.232.0.2:4434]}
  b:
    public_key: $BK
    endpoints: []
    upstream_dns: [127.0.0.1:5353]
    routes:
      - {site_set: ./domains.txt, priority: 100}
      - {ip_cidr: 10.64.2.2/32, priority: 100}
    paths: [{path: [a, r, b]}]
connect_to: [r]
EOF

cat >"$WORK/r.yaml" <<EOF
id: r
allow_transit: true
identity_key_path: $WORK/r.key
listen: quic://0.0.0.0:4434
tun: {name: tunr, addresses: [10.64.1.1/32]}
peers:
  a: {public_key: $AK, endpoints: [quic://10.232.0.1:4433], paths: [{path: [r, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.233.0.2:4435], paths: [{path: [r, b]}]}
connect_to: [b]
EOF

cat >"$WORK/b.yaml" <<EOF
id: b
identity_key_path: $WORK/b.key
listen: quic://10.233.0.2:4435
tun: {name: tunb, addresses: [10.64.2.2/32]}
peers:
  a:
    public_key: $AK
    endpoints: []
    routes:
      - {ip_cidr: 10.64.0.1/32, priority: 100, bind: true}
      # Keep the spoof-test return route pointed at A while binding this
      # address to the relay. Binding is independent of route priority.
      - {ip_cidr: 10.64.9.9/32, priority: 100}
    paths: [{path: [b, r, a]}]
  r:
    public_key: $RK
    endpoints: [quic://10.233.0.1:4434]
    routes: [{ip_cidr: 10.64.9.9/32, priority: 90, bind: true}]
allowed_local_ports:
  - {allow: [icmp, 'tcp(8080)', 'udp(8080)'], for: [a]}
allowed_routes:
  - {allow: [127.0.0.1/32], for: [a]}
EOF

sudo -n ip netns exec "$(remote_ns b)" python3 "$PWD/tests/fake_dns_server.py" 127.0.0.1 5353 10.64.2.2 >"$WORK/dns.log" 2>&1 &
REMOTE_PIDS+=("$!")
sudo -n ip netns exec "$(remote_ns b)" python3 "$PWD/tests/fake_echo_server.py" 8080 >"$WORK/echo.log" 2>&1 &
REMOTE_PIDS+=("$!")
remote_start b b; remote_start r r; remote_start a a
remote_wait_tun a tinea; remote_wait_tun b tunb
remote_wait_log a 'circuit OPEN acknowledged' 300

FAKE_IP="$(sudo -n ip netns exec "$(remote_ns a)" python3 -c '
import socket,struct
q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x06target\x04test\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,("127.0.0.1",5354));print(socket.inet_ntoa(s.recv(4096)[-4:]))
')"
remote_expect_ping a tinea "$FAKE_IP"
sudo -n ip netns exec "$(remote_ns a)" python3 - "$FAKE_IP" <<'PY'
import socket,sys
target=(sys.argv[1],8080)
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
    sock=socket.socket(socket.AF_INET,kind);sock.settimeout(3)
    if kind == socket.SOCK_STREAM: sock.connect(target)
    sock.sendto(b"multihop",target) if kind == socket.SOCK_DGRAM else sock.sendall(b"multihop")
    assert sock.recv(64) == b"multihop"
PY

# Verify both sides of the binding at the final decrypting node: A's real TUN
# source is allowed through the opaque relay, while the same path rejects a
# packet whose source range is bound to the relay identity.
remote_expect_ping a tinea 10.64.2.2
sudo -n ip -n "$(remote_ns a)" addr add 10.64.9.9/32 dev tinea
if sudo -n ip netns exec "$(remote_ns a)" ping -I 10.64.9.9 -c 1 -W 1 10.64.2.2; then
  echo "source binding spoof unexpectedly reached B through the relay" >&2
  exit 1
fi

# Replace both relay Links while retaining the source FakeIP mapping. The old
# return flow must be revoked and the next packet must converge on a new
# bidirectional Circuit without accepting a late reverse frame.
relay_daemon_pids() {
  local pid
  for pid in $(sudo -n ip netns pids "$(remote_ns r)"); do
    [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == tinect ]] && printf '%s\n' "$pid"
  done
}
for pid in $(relay_daemon_pids); do
  sudo -n kill -TERM "$pid"
done
remote_wait_for "relay shutdown" \
  "[[ -z \"\$(relay_daemon_pids)\" ]]" 150
remote_start r r
remote_wait_log r 'outbound QUIC link authenticated' 300
# A source Link that reconnects before the relay has both adjacencies can
# consume one bounded topology-snapshot recovery window (30s). Verify the
# following fresh Link/Circuit convergence rather than racing that deadline.
remote_wait_deadline "FakeIP ping after relay Link replacement" 60 \
  "sudo -n ip netns exec '$(remote_ns a)' ping -I tinea -c 1 -W 1 '$FAKE_IP'"

echo "multihop FakeIP peer DNS override and TCP/UDP/ICMP return-path test passed"
