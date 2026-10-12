#!/usr/bin/env bash
# Privileged Linux integration test for tinect-fake-tcp across a stateful SNAT.
# Run explicitly from the repository root; it never runs under cargo test.
set -euo pipefail

ROOT="${ROOT:-$PWD}"
ENDPOINT="${ENDPOINT:-$ROOT/target/release/examples/nat-endpoint}"
PREFIX="${TINECT_NS_PREFIX:-tinect-ft}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"
CLIENT_NS="$PREFIX-client"
NAT_NS="$PREFIX-nat"
SERVER_NS="$PREFIX-server"
CLIENT_PID=""
SERVER_PID=""

cleanup() {
  [[ -n "$CLIENT_PID" ]] && sudo -n kill "$CLIENT_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && sudo -n kill "$SERVER_PID" 2>/dev/null || true
  sudo -n ip netns del "$CLIENT_NS" 2>/dev/null || true
  sudo -n ip netns del "$NAT_NS" 2>/dev/null || true
  sudo -n ip netns del "$SERVER_NS" 2>/dev/null || true
}
trap cleanup EXIT

sudo -n true
if [[ ! -x "$ENDPOINT" ]]; then
  cargo build --release -p tinect-fake-tcp --example nat-endpoint --features raw-test
fi
test -x "$ENDPOINT"

cleanup
for ns in "$CLIENT_NS" "$NAT_NS" "$SERVER_NS"; do
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
done

remote_veth_between ftc0 ftn0 "$CLIENT_NS" "$NAT_NS" 10.250.10.2/24 10.250.10.1/24
remote_veth_between ftn1 fts0 "$NAT_NS" "$SERVER_NS" 10.250.20.1/24 10.250.20.2/24

sudo -n ip -n "$CLIENT_NS" route add default via 10.250.10.1
sudo -n ip -n "$SERVER_NS" route add default via 10.250.20.1

# Keep the host TCP stacks from answering the deliberately userspace TCP flow.
for ns in "$CLIENT_NS" "$SERVER_NS"; do
  sudo -n ip netns exec "$ns" nft add table inet tinect_fake_tcp
  sudo -n ip netns exec "$ns" nft 'add chain inet tinect_fake_tcp output { type filter hook output priority filter; policy accept; }'
  sudo -n ip netns exec "$ns" nft add rule inet tinect_fake_tcp output tcp flags '&' rst == rst meta mark '!=' 0x5443 drop
done
sudo -n ip netns exec "$NAT_NS" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NAT_NS" nft add table ip tinect_fake_tcp_nat
sudo -n ip netns exec "$NAT_NS" nft 'add chain ip tinect_fake_tcp_nat forward { type filter hook forward priority filter; policy drop; }'
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_fake_tcp_nat forward iifname ftn0 oifname ftn1 meta l4proto tcp accept
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_fake_tcp_nat forward iifname ftn1 oifname ftn0 ct state established,related meta l4proto tcp accept
sudo -n ip netns exec "$NAT_NS" nft 'add chain ip tinect_fake_tcp_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_fake_tcp_nat postrouting ip saddr 10.250.10.0/24 oifname ftn1 meta l4proto tcp snat to 10.250.20.1

PAYLOAD='quic-datagram-through-stateful-nat'
# Namespace-local endpoints: client waits for the server pure ACK through SNAT.
sudo -n ip netns exec "$SERVER_NS" "$ENDPOINT" server --local 10.250.20.2:443 --peer 10.250.20.1:40000 --payload "$PAYLOAD" &
SERVER_PID=$!
sleep 0.1
sudo -n ip netns exec "$CLIENT_NS" "$ENDPOINT" client --local 10.250.10.2:40000 --remote 10.250.20.2:443 --payload "$PAYLOAD" &
CLIENT_PID=$!
wait "$CLIENT_PID"; CLIENT_PID=""
wait "$SERVER_PID"; SERVER_PID=""

# The server checked the source is the NAT address (10.250.20.1); receiving its
# pure ACK at the client also verifies conntrack's reverse translation.
echo 'fake TCP NAT integration test passed'

cleanup
trap - EXIT
for ns in "$CLIENT_NS" "$NAT_NS" "$SERVER_NS"; do
  if sudo -n ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "namespace cleanup incomplete: $ns" >&2
    exit 1
  fi
done
echo 'fake TCP NAT resources cleaned up'
