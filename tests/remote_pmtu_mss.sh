#!/usr/bin/env bash
# Verifies physical-link DPLPMTUD, multi-hop PMTU propagation, and TCP MSS
# clamping on the real QUIC/TUN data plane. Run from the repository root.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
WORK="${WORK:-/tmp/tinect-pmtu-mss}"
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-pmtu}"
source "$PWD/tests/lib/remote.sh"
NS_A="$TINECT_NS_PREFIX-a"
NS_B="$TINECT_NS_PREFIX-b"
NS_C="$TINECT_NS_PREFIX-c"
AB_MTU="${AB_MTU:-1500}"
BC_MTU="${BC_MTU:-1280}"
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
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    sudo -n ip netns del "$ns" 2>/dev/null || true
  done
  sudo -n rm -f "$WORK/a.sock" "$WORK/b.sock" "$WORK/c.sock"
}
trap cleanup EXIT

fail() {
  echo "PMTU/MSS integration test failed: $*" >&2
  for node in a b c; do
    echo "===== $node status =====" >&2
    sudo -n "$BIN" status --socket "$WORK/$node.sock" >&2 || true
  done
  for node in a b c; do
    echo "===== $node log =====" >&2
    cat "$WORK/$node.log" >&2 || true
  done
  for ns in "$NS_A" "$NS_B" "$NS_C"; do
    echo "===== $ns interfaces =====" >&2
    sudo -n ip -n "$ns" -br link show 2>/dev/null >&2 || true
  done
  exit 1
}

link_datagram_limit() {
  local node="$1" peer="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$WORK/$node.sock")" \
    PEER="$peer" python3 -c '
import json, os
for link in json.loads(os.environ["STATUS_JSON"])["links"]:
    if link["peer"] == os.environ["PEER"] and link["metrics"] is not None:
        print(link["metrics"]["datagram_max_size"])
        break
else:
    raise SystemExit(1)
'
}

link_pmtu_protocol_errors() {
  local node="$1" peer="$2"
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$WORK/$node.sock")" \
    PEER="$peer" python3 -c '
import json, os
for link in json.loads(os.environ["STATUS_JSON"])["links"]:
    if link["peer"] == os.environ["PEER"] and link["metrics"] is not None:
        print(link["metrics"]["pmtu_protocol_errors"])
        break
else:
    raise SystemExit(1)
'
}

active_circuit_path() {
  STATUS_JSON="$(sudo -n "$BIN" status --socket "$WORK/a.sock" 2>/dev/null)" python3 -c '
import json, os
expected = ["a", "b", "c"]
raise SystemExit(not any(
    circuit.get("destination") == "c"
    and circuit.get("healthy")
    and circuit.get("active_path_names") == expected
    for circuit in json.loads(os.environ["STATUS_JSON"])["circuits"]
))
' 2>/dev/null
}

sudo -n true
[[ -x "$BIN" ]] || { echo "build the release binary first: cargo build --release" >&2; exit 1; }
for value in "$AB_MTU" "$BC_MTU"; do
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1200 || value > 9000 )); then
    echo "AB_MTU and BC_MTU must be integer values in 1200..=9000" >&2
    exit 2
  fi
done
(( BC_MTU < AB_MTU )) || { echo "BC_MTU must be smaller than AB_MTU" >&2; exit 2; }

sudo -n rm -rf "$WORK"
mkdir -p "$WORK"
for n in a b c; do "$BIN" keygen --output "$WORK/$n.key" >"$WORK/$n.identity"; done
AK="$(awk '/public_key:/{print $2}' "$WORK/a.identity")"
BK="$(awk '/public_key:/{print $2}' "$WORK/b.identity")"
CK="$(awk '/public_key:/{print $2}' "$WORK/c.identity")"

for ns in "$NS_A" "$NS_B" "$NS_C"; do
  sudo -n ip netns del "$ns" 2>/dev/null || true
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
done
remote_veth_between pmtu-ab-a pmtu-ab-b "$NS_A" "$NS_B" 10.212.0.1/24 10.212.0.2/24
remote_veth_between pmtu-bc-b pmtu-bc-c "$NS_B" "$NS_C" 10.213.0.1/24 10.213.0.2/24
sudo -n ip -n "$NS_A" link set pmtu-ab-a mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set pmtu-ab-b mtu "$AB_MTU"
sudo -n ip -n "$NS_B" link set pmtu-bc-b mtu "$BC_MTU"
sudo -n ip -n "$NS_C" link set pmtu-bc-c mtu "$BC_MTU"
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$NS_C" sysctl -qw net.ipv6.conf.all.forwarding=1

cat >"$WORK/a.yaml" <<EOF
id: a
identity_key_path: $WORK/a.key
listen: quic://10.212.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
runtime: {status_socket: $WORK/a.sock, pcap_buffer_packets: 16}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  b: {public_key: $BK, endpoints: [quic://10.212.0.2:4434]}
  c: {public_key: $CK, endpoints: [], routes: [{ip_cidr: 10.64.2.2/32, priority: 100}]}
path_policies:
  c: {max_hops: 3}
connect_to: [b]
EOF
cat >"$WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
runtime: {status_socket: $WORK/b.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  a: {public_key: $AK, endpoints: [quic://10.212.0.1:4433]}
  c: {public_key: $CK, endpoints: [quic://10.213.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
cat >"$WORK/c.yaml" <<EOF
id: c
identity_key_path: $WORK/c.key
listen: quic://10.213.0.2:4435
tun: {name: tunc, addresses: [10.64.2.2/32]}
runtime: {status_socket: $WORK/c.sock}
link_health: {keepalive_secs: 1, idle_timeout_secs: 5}
peers:
  a: {public_key: $AK, endpoints: [], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [c, b, a]}]}
  b: {public_key: $BK, endpoints: [quic://10.213.0.1:4434]}
allowed_routes:
  - allow: [10.64.2.2/32]
    for: [a]
allowed_local_ports:
  - {allow: [tcp], for: [a]}
EOF

# The shell intentionally owns these diagnostic log files; only the daemon
# process itself needs the privileged namespace transition.
# shellcheck disable=SC2024
sudo -n ip netns exec "$NS_B" "$BIN" up "$WORK/b.yaml" >"$WORK/b.log" 2>&1 & PIDS+=("$!")
# shellcheck disable=SC2024
sudo -n ip netns exec "$NS_C" "$BIN" up "$WORK/c.yaml" >"$WORK/c.log" 2>&1 & PIDS+=("$!")
# shellcheck disable=SC2024
sudo -n ip netns exec "$NS_A" "$BIN" up "$WORK/a.yaml" >"$WORK/a.log" 2>&1 & PIDS+=("$!")

for _ in $(seq 1 600); do
  if active_circuit_path; then
    AB_LIMIT="$(link_datagram_limit a b 2>/dev/null || true)"
    BC_LIMIT="$(link_datagram_limit b c 2>/dev/null || true)"
    if [[ "$AB_LIMIT" =~ ^[0-9]+$ && "$BC_LIMIT" =~ ^[0-9]+$ ]] \
      && (( AB_LIMIT > BC_LIMIT && BC_LIMIT > 0 )); then
      break
    fi
  fi
  sleep 0.1
done
if [[ ! "${AB_LIMIT:-}" =~ ^[0-9]+$ || ! "${BC_LIMIT:-}" =~ ^[0-9]+$ ]] \
  || (( AB_LIMIT <= BC_LIMIT || BC_LIMIT == 0 )); then
  fail "DPLPMTUD did not expose a smaller B-C DATAGRAM limit (A-B=${AB_LIMIT:-missing}, B-C=${BC_LIMIT:-missing})"
fi

# Route bindings are refreshed independently of Link-State receipt. The test
# advertises every second, so wait for multiple LSA and reconciliation rounds
# after observing the discovered link capacities.
sleep 3

# Read the capacities again after route reconciliation. The first values above
# only establish that the smaller second hop has been discovered; they may be
# from an older LSA generation than the binding used for the injected SYN.
AB_LIMIT="$(link_datagram_limit a b 2>/dev/null || true)"
BC_LIMIT="$(link_datagram_limit b c 2>/dev/null || true)"
if [[ ! "$AB_LIMIT" =~ ^[0-9]+$ || ! "$BC_LIMIT" =~ ^[0-9]+$ ]] \
  || (( AB_LIMIT <= BC_LIMIT )); then
  fail "PMTU capacities did not remain ordered after route convergence (A-B=${AB_LIMIT:-missing}, B-C=${BC_LIMIT:-missing})"
fi
echo "Discovered ordered PMTU capacities: A-B=$AB_LIMIT, B-C=$BC_LIMIT"

# A locally rejected oversized UDP probe is a PMTU result, not a protocol
# failure.  Before this regression fix Linux EMSGSIZE was stringified by the
# shared socket and fell through the protocol-error path, leaving the worker
# retrying the same oversized probe indefinitely.  Keep this assertion close
# to the constrained-link convergence so CI catches that exact regression.
for pair in "a b" "b c"; do
  node="${pair%% *}"
  peer="${pair##* }"
  protocol_errors="$(link_pmtu_protocol_errors "$node" "$peer")"
  (( protocol_errors == 0 )) || fail "PMTU probe reported $protocol_errors protocol errors on $node->$peer"
done

# Keep the three-node circuit idle for several watchdog periods.  Physical
# keepalive is sent every second and idle_timeout_secs is five seconds; a
# healthy implementation must not tear down the links merely because the
# asynchronous keepalive has not yet been dispatched to the receiver task.
declare -A IDLE_TIMEOUTS_BEFORE
for node in a b c; do
  IDLE_TIMEOUTS_BEFORE[$node]="$(grep -c 'physical payload idle timeout' "$WORK/$node.log" || true)"
done
sleep 8
for node in a b c; do
  after="$(grep -c 'physical payload idle timeout' "$WORK/$node.log" || true)"
  if (( after > IDLE_TIMEOUTS_BEFORE[$node] )); then
    fail "idle keepalive watchdog closed $node while the circuit was idle"
  fi
done
active_circuit_path || fail "circuit was not retained across the idle keepalive interval"
echo "Physical keepalive remained stable during an idle watchdog interval"

# DPLPMTUD may still be increasing both links while the circuit is idle.  Take
# the MSS snapshot only after the advertised capacities have stopped changing,
# so the expected value describes the active route at injection time rather
# than an earlier, conservative sample.
stable_count=0
for _ in $(seq 1 100); do
  next_ab="$(link_datagram_limit a b 2>/dev/null || true)"
  next_bc="$(link_datagram_limit b c 2>/dev/null || true)"
  if [[ "$next_ab" == "$AB_LIMIT" && "$next_bc" == "$BC_LIMIT" ]]; then
    stable_count=$((stable_count + 1))
  else
    stable_count=0
    AB_LIMIT="$next_ab"
    BC_LIMIT="$next_bc"
  fi
  if [[ "$AB_LIMIT" =~ ^[0-9]+$ && "$BC_LIMIT" =~ ^[0-9]+$ ]] \
    && (( AB_LIMIT > BC_LIMIT && stable_count >= 10 )); then
    break
  fi
  sleep 0.2
done
if [[ ! "$AB_LIMIT" =~ ^[0-9]+$ || ! "$BC_LIMIT" =~ ^[0-9]+$ ]] \
  || (( AB_LIMIT <= BC_LIMIT || stable_count < 10 )); then
  fail "PMTU capacities did not stabilize before MSS check (A-B=${AB_LIMIT:-missing}, B-C=${BC_LIMIT:-missing})"
fi
echo "Using stable PMTU capacities for MSS check: A-B=$AB_LIMIT, B-C=$BC_LIMIT"

# Inject a small, valid raw IPv4 TCP SYN. Unlike a normal kernel TCP connect,
# its 1460-byte MSS option is not pre-clamped from the TUN device MTU.
sudo -n ip netns exec "$NS_A" python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

source = socket.inet_aton('10.64.0.1')
destination = socket.inet_aton('10.64.2.2')
tcp = struct.pack('!HHLLBBHHH', 40000, 443, 1, 0, 0x60, 0x02, 65535, 0, 0) + b'\x02\x04\x05\xb4'
pseudo = source + destination + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp))
tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, socket.IPPROTO_TCP, 0, source, destination)
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.sendto(ip + tcp, ('10.64.2.2', 0))
PY

for _ in $(seq 1 50); do
  sudo -n "$BIN" pcap --socket "$WORK/a.sock" --output "$WORK/a.pcap" >/dev/null
  [[ "$(sudo -n stat -c %s "$WORK/a.pcap")" -gt 24 ]] && break
  sleep 0.1
done

AB_LIMIT="$AB_LIMIT" BC_LIMIT="$BC_LIMIT" PCAP="$WORK/a.pcap" python3 - <<'PY'
import os, struct

ab = int(os.environ['AB_LIMIT'])
bc = int(os.environ['BC_LIMIT'])
# Current binary framing: 41-byte end-to-end DATA frame and 25-byte physical
# forward envelope, followed by the inner IPv4 and TCP headers.
expected = min(ab, bc) - 41 - 25 - 20 - 24
if expected <= 0 or expected >= 1460:
    raise SystemExit(f'invalid expected MSS {expected} from limits A-B={ab}, B-C={bc}')

data = open(os.environ['PCAP'], 'rb').read()
if len(data) < 24:
    raise SystemExit('PCAP is missing its global header')
offset = 24
observed = []
while offset + 16 <= len(data):
    _, _, included, _ = struct.unpack_from('<IIII', data, offset)
    offset += 16
    packet = data[offset:offset + included]
    offset += included
    if len(packet) < 44 or packet[0] >> 4 != 4 or packet[9] != 6:
        continue
    ihl = (packet[0] & 0x0f) * 4
    if len(packet) < ihl + 24 or packet[16:20] != b'\x0a\x40\x02\x02':
        continue
    tcp = packet[ihl:]
    if struct.unpack_from('!H', tcp, 2)[0] != 443 or not (tcp[13] & 0x02):
        continue
    tcp_len = (tcp[12] >> 4) * 4
    options = tcp[20:tcp_len]
    for index in range(len(options) - 3):
        if options[index:index + 2] == b'\x02\x04':
            observed.append(struct.unpack_from('!H', options, index + 2)[0])

if observed != [expected]:
    raise SystemExit(f'expected one clamped MSS {expected}; captured {observed}')
print(f'PMTU discovery and MSS clamp verified: A-B={ab}, B-C={bc}, MSS={expected}')
PY

echo "PMTU discovery and automatic MSS clamp integration test passed"
