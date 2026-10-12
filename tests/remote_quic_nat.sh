#!/usr/bin/env bash
# Privileged Linux regression test for active client ports through stateful SNAT.
# Run explicitly from the repository root; it never touches production hosts.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
CARRIER="${CARRIER:-quic}"
LISTEN_PORT="${LISTEN_PORT:-4433}"
PREFIX="${TINECT_NS_PREFIX:-tinect-quic-nat}"
TINECT_NS_PREFIX="$PREFIX"
source "$PWD/tests/lib/remote.sh"
WORK="${WORK:-/tmp/$PREFIX}"
CLIENT_NS="$PREFIX-client"
NAT_NS="$PREFIX-nat"
SERVER_NS="$PREFIX-server"
CLIENT_IF=qnc0
NAT_CLIENT_IF=qnn0
NAT_SERVER_IF=qnn1
SERVER_IF=qns0
CLIENT_PID=""
SERVER_PID=""
TCPDUMP_PID=""

case "$CARRIER" in
  quic|quicfull) L4PROTO=udp; BPF_FILTER="udp and dst host 10.251.20.2 and dst port $LISTEN_PORT" ;;
  quic-faketcp|quicfull-faketcp) L4PROTO=tcp; BPF_FILTER="tcp and dst host 10.251.20.2 and dst port $LISTEN_PORT" ;;
  *) echo "CARRIER must be quic, quicfull, quic-faketcp, or quicfull-faketcp" >&2; exit 2 ;;
esac

stop_daemons() {
  [[ -z "$CLIENT_PID" ]] || sudo -n kill -TERM "$CLIENT_PID" 2>/dev/null || true
  [[ -z "$SERVER_PID" ]] || sudo -n kill -TERM "$SERVER_PID" 2>/dev/null || true
  for namespace in "$CLIENT_NS" "$SERVER_NS"; do
    while read -r pid; do
      [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == tinect ]] \
        && sudo -n kill -TERM "$pid" 2>/dev/null || true
    done < <(sudo -n ip netns pids "$namespace" 2>/dev/null || true)
  done
}

assert_fake_tcp_cleanup() {
  [[ "$CARRIER" == *faketcp ]] || return 0
  for namespace in "$CLIENT_NS" "$SERVER_NS"; do
    for _ in $(seq 1 110); do
      sudo -n ip netns exec "$namespace" nft list table inet "tinect_quicp_rst_$LISTEN_PORT" >/dev/null 2>&1 || break
      sleep 0.1
    done
    if sudo -n ip netns exec "$namespace" nft list table inet "tinect_quicp_rst_$LISTEN_PORT" >/dev/null 2>&1; then
      echo "fake-TCP RST guard leaked from $namespace" >&2
      return 1
    fi
  done
}

cleanup() {
  local result=$?
  [[ -z "$TCPDUMP_PID" ]] || sudo -n kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
  stop_daemons
  assert_fake_tcp_cleanup || true
  sudo -n ip netns del "$CLIENT_NS" 2>/dev/null || true
  sudo -n ip netns del "$NAT_NS" 2>/dev/null || true
  sudo -n ip netns del "$SERVER_NS" 2>/dev/null || true
  sudo -n rm -f "$WORK/client.sock" "$WORK/server.sock"
  if [[ "$result" -ne 0 ]]; then
    for log in client.log server.log tcpdump.log; do
      [[ -s "$WORK/$log" ]] || continue
      echo "=== $log ===" >&2
      sed -n '1,160p' "$WORK/$log" >&2 || true
    done
  fi
  return "$result"
}
trap cleanup EXIT

sudo -n true
[[ -x "$BIN" ]] || { echo "build the release binary first: cargo build --release" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump is required" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK"
"$BIN" keygen --output "$WORK/client.key" >"$WORK/client.identity"
"$BIN" keygen --output "$WORK/server.key" >"$WORK/server.identity"
CLIENT_KEY="$(awk '/public_key:/{print $2}' "$WORK/client.identity")"
SERVER_KEY="$(awk '/public_key:/{print $2}' "$WORK/server.identity")"

for namespace in "$CLIENT_NS" "$NAT_NS" "$SERVER_NS"; do
  sudo -n ip netns del "$namespace" 2>/dev/null || true
  sudo -n ip netns add "$namespace"
  sudo -n ip -n "$namespace" link set lo up
done

remote_veth_between "$CLIENT_IF" "$NAT_CLIENT_IF" "$CLIENT_NS" "$NAT_NS" 10.251.10.2/24 10.251.10.1/24
remote_veth_between "$NAT_SERVER_IF" "$SERVER_IF" "$NAT_NS" "$SERVER_NS" 10.251.20.1/24 10.251.20.2/24

sudo -n ip -n "$CLIENT_NS" route add default via 10.251.10.1
sudo -n ip -n "$SERVER_NS" route add default via 10.251.20.1

sudo -n ip netns exec "$NAT_NS" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$CLIENT_NS" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$CLIENT_NS" sysctl -qw net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$SERVER_NS" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$SERVER_NS" sysctl -qw net.ipv6.conf.all.forwarding=1
sudo -n ip netns exec "$NAT_NS" nft add table ip tinect_stateful_nat
sudo -n ip netns exec "$NAT_NS" nft 'add chain ip tinect_stateful_nat forward { type filter hook forward priority filter; policy drop; }'
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_stateful_nat forward iifname "$NAT_CLIENT_IF" oifname "$NAT_SERVER_IF" ct state new,established,related meta l4proto "$L4PROTO" accept
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_stateful_nat forward iifname "$NAT_SERVER_IF" oifname "$NAT_CLIENT_IF" ct state established,related meta l4proto "$L4PROTO" accept
sudo -n ip netns exec "$NAT_NS" nft 'add chain ip tinect_stateful_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo -n ip netns exec "$NAT_NS" nft add rule ip tinect_stateful_nat postrouting ip saddr 10.251.10.0/24 oifname "$NAT_SERVER_IF" meta l4proto "$L4PROTO" snat to 10.251.20.1

cat >"$WORK/server.yaml" <<EOF
id: server
accept_connections: true
identity_key_path: $WORK/server.key
listen: $CARRIER://10.251.20.2:$LISTEN_PORT
tun:
  name: tunsrv
  addresses: [10.64.20.2/32]
runtime:
  status_socket: $WORK/server.sock
peers:
  client:
    public_key: $CLIENT_KEY
    endpoints: ["$CARRIER://10.251.10.2:$LISTEN_PORT"]
    routes:
      - {ip_cidr: 10.64.20.1/32, priority: 100}
allowed_routes:
  - allow: [10.64.20.2/32]
    for: [client]
EOF

cat >"$WORK/client.yaml" <<EOF
id: client
accept_connections: true
identity_key_path: $WORK/client.key
listen: $CARRIER://10.251.10.2:$LISTEN_PORT
tun:
  name: tuncli
  addresses: [10.64.20.1/32]
runtime:
  status_socket: $WORK/client.sock
peers:
  server:
    public_key: $SERVER_KEY
    endpoints: ["$CARRIER://10.251.20.2:$LISTEN_PORT"]
    routes:
      - {ip_cidr: 10.64.20.2/32, priority: 100}
connect_to: [server]
allowed_routes:
  - allow: [10.64.20.1/32]
    for: [server]
EOF

sudo -n ip netns exec "$SERVER_NS" sh -c 'echo "$$" > "$1"; exec "$2" up "$3"' sh "$WORK/server.pid" "$BIN" "$WORK/server.yaml" >"$WORK/server.log" 2>&1 &
for _ in $(seq 1 150); do
  [[ -s "$WORK/server.pid" ]] && break
  sleep 0.1
done
SERVER_PID="$(cat "$WORK/server.pid")"
for _ in $(seq 1 150); do
  [[ -S "$WORK/server.sock" ]] && break
  sleep 0.1
done
[[ -S "$WORK/server.sock" ]] || { echo "server status socket did not appear" >&2; exit 1; }

sudo -n ip netns exec "$SERVER_NS" tcpdump -nn -i "$SERVER_IF" -c 1 -w "$WORK/underlay.pcap" "$BPF_FILTER" >"$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID="$!"

sudo -n ip netns exec "$CLIENT_NS" sh -c 'echo "$$" > "$1"; exec "$2" up "$3"' sh "$WORK/client.pid" "$BIN" "$WORK/client.yaml" >"$WORK/client.log" 2>&1 &
for _ in $(seq 1 150); do
  [[ -s "$WORK/client.pid" ]] && break
  sleep 0.1
done
CLIENT_PID="$(cat "$WORK/client.pid")"
for _ in $(seq 1 150); do
  [[ -S "$WORK/client.sock" ]] && break
  sleep 0.1
done
[[ -S "$WORK/client.sock" ]] || { echo "client status socket did not appear" >&2; exit 1; }

for _ in $(seq 1 200); do
  if [[ -s "$WORK/underlay.pcap" ]] && ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
[[ -s "$WORK/underlay.pcap" ]] || { echo "did not capture an active packet at the server" >&2; exit 1; }

capture_line="$(sudo -n ip netns exec "$SERVER_NS" tcpdump -nn -r "$WORK/underlay.pcap" 2>/dev/null | head -n 1)"
source_port="$(sed -nE 's/.*IP 10\.251\.20\.1\.([0-9]+) >.*/\1/p' <<<"$capture_line")"
[[ "$capture_line" == *"IP 10.251.20.1."* ]] || { echo "unexpected SNAT source in capture: $capture_line" >&2; exit 1; }
[[ "$source_port" =~ ^[0-9]+$ ]] || { echo "could not parse source port from capture: $capture_line" >&2; exit 1; }
[[ "$source_port" -ne "$LISTEN_PORT" ]] || { echo "active connection reused listener port $LISTEN_PORT" >&2; exit 1; }
echo "server observed SNAT source 10.251.20.1:$source_port (listener port $LISTEN_PORT)"

for _ in $(seq 1 200); do
  if sudo -n ip netns exec "$CLIENT_NS" "$BIN" status --socket "$WORK/client.sock" 2>/dev/null | python3 -c 'import json,sys; s=json.load(sys.stdin); raise SystemExit(0 if any(x.get("destination")=="server" and x.get("healthy") and x.get("active_path") for x in s.get("circuits",[])) else 1)' \
    && sudo -n ip netns exec "$SERVER_NS" "$BIN" status --socket "$WORK/server.sock" 2>/dev/null | python3 -c 'import json,sys; s=json.load(sys.stdin); raise SystemExit(0 if any(x.get("destination")=="client" and x.get("healthy") and x.get("active_path") for x in s.get("circuits",[])) else 1)'; then break; fi
  sleep 0.1
done

ping_tun() {
  local namespace="$1" interface="$2" target="$3"
  for _ in $(seq 1 20); do
    if sudo -n ip netns exec "$namespace" ping -I "$interface" -c 1 -W 1 "$target"; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out pinging $target through $interface in $namespace" >&2
  return 1
}

ping_tun "$CLIENT_NS" tuncli 10.64.20.2
ping_tun "$SERVER_NS" tunsrv 10.64.20.1

stop_daemons
assert_fake_tcp_cleanup
echo "stateful SNAT QUIC regression passed for $CARRIER"
