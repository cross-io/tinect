#!/usr/bin/env bash
# Privileged Linux integration coverage for QUIC admission, circuits, relays,
# and exit authorization. Run from the repository root.
set -euo pipefail

BIN="${BIN:-$PWD/target/release/tinect}"
source "$PWD/tests/lib/remote.sh"
WORK="${WORK:-/tmp/tinect-auth-forwarding-$TINECT_NS_PREFIX}"

require_binary() {
  [[ -x "$BIN" ]] || { echo "build the release binary first: cargo build --release" >&2; exit 1; }
  sudo -n true
}

two_nodes() {
  local prefix="$1"
  remote_namespace "$prefix-a"
  remote_namespace "$prefix-b"
  remote_veth a0 b0 "$prefix-a" "$prefix-b" 10.240.0.1/24 10.240.0.2/24
}

configure_exit_forwarding() {
  local ns
  ns="$(remote_ns "$1")"
  # Internet exits require administrator-owned forwarding.  These are isolated
  # test namespaces, so make both family prerequisites explicit here rather
  # than asking Tinect to mutate any host-level sysctl.
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  sudo -n ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
}

case_connect_admission() {
  remote_init "$WORK/connect"
  two_nodes tinect-ca
  remote_keygen a; remote_keygen b
  local ak bk; ak="$(remote_public_key a)"; bk="$(remote_public_key b)"
  cat >"$REMOTE_WORK/a.yaml" <<EOF
id: a
identity_key_path: $REMOTE_WORK/a.key
listen: quic://10.240.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
peers: {b: {public_key: $bk, endpoints: [quic://10.240.0.2:4434]}}
connect_to: [b]
EOF
  cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
identity_key_path: $REMOTE_WORK/b.key
listen: quic://10.240.0.2:4434
tun: {name: tunb, addresses: [10.64.0.2/32]}
peers: {a: {public_key: $ak, endpoints: [quic://10.240.0.1:4433]}}
EOF
  remote_start b tinect-ca-b; remote_start a tinect-ca-a
  remote_wait_log b 'inbound QUIC link authenticated peer_name=a'
  remote_cleanup

  remote_init "$WORK/connect-deny"
  two_nodes tinect-cd
  remote_keygen a; remote_keygen b
  ak="$(remote_public_key a)"; bk="$(remote_public_key b)"
  cat >"$REMOTE_WORK/a.yaml" <<EOF
id: a
identity_key_path: $REMOTE_WORK/a.key
listen: quic://10.240.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
peers: {b: {public_key: $bk, endpoints: [quic://10.240.0.2:4434]}}
connect_to: [b]
EOF
  cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
identity_key_path: $REMOTE_WORK/b.key
listen: quic://10.240.0.2:4434
tun: {name: tunb, addresses: [10.64.0.2/32]}
peers: {a: {public_key: $ak, endpoints: [quic://10.240.0.1:4433], accept_connections: false}}
EOF
  remote_start b tinect-cd-b; remote_start a tinect-cd-a
  remote_wait_log b 'peer is not allowed to connect'
  if grep -Fq 'inbound QUIC link authenticated peer_name=a' "$REMOTE_WORK/b.log"; then
    echo "denied peer unexpectedly authenticated" >&2
    return 1
  fi
  remote_cleanup
}

case_unknown_peer() {
  remote_init "$WORK/unknown"
  two_nodes tinect-cu
  remote_keygen attacker; remote_keygen b
  local bk; bk="$(remote_public_key b)"
  cat >"$REMOTE_WORK/attacker.yaml" <<EOF
id: attacker
identity_key_path: $REMOTE_WORK/attacker.key
listen: quic://10.240.0.1:4433
tun: {name: tuna, addresses: [10.64.0.1/32]}
peers: {b: {public_key: $bk, endpoints: [quic://10.240.0.2:4434]}}
connect_to: [b]
EOF
  cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
identity_key_path: $REMOTE_WORK/b.key
listen: quic://10.240.0.2:4434
tun: {name: tunb, addresses: [10.64.0.2/32]}
peers: {}
EOF
  remote_start b tinect-cu-b; remote_start attacker tinect-cu-a
  remote_wait_log b 'unknown peer cannot establish a link'
  if grep -Fq 'inbound QUIC link authenticated' "$REMOTE_WORK/b.log"; then
    echo "unknown peer unexpectedly authenticated" >&2
    return 1
  fi
  remote_cleanup
}

write_three_node_configs() {
  local relay_transit="$1"
  local ak bk ck; ak="$(remote_public_key a)"; bk="$(remote_public_key b)"; ck="$(remote_public_key c)"
  cat >"$REMOTE_WORK/a.yaml" <<EOF
id: a
identity_key_path: $REMOTE_WORK/a.key
listen: quic://10.241.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
# This scenario repeatedly crashes a peer. Tighten its isolated link-health
# timers so the recovery assertions exercise reconnect logic rather than
# spending most of CI waiting for the production idle timeout.
link_health: {keepalive_secs: 1, idle_timeout_secs: 15}
peers:
  b: {public_key: $bk, endpoints: [quic://10.241.0.2:4434]}
  c: {public_key: $ck, endpoints: [], routes: [{ip_cidr: 10.64.2.0/24, priority: 100}, {ip_cidr: 10.65.0.0/16, priority: 100}], paths: [{path: [a, b, c]}]}
connect_to: [b]
EOF
  cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $REMOTE_WORK/b.key
listen: quic://0.0.0.0:4434
tun: {name: tunb, addresses: [10.64.1.1/32]}
link_health: {keepalive_secs: 1, idle_timeout_secs: 15}
peers:
  a: {public_key: $ak, endpoints: [quic://10.241.0.1:4433], allow_transit: $relay_transit, paths: [{path: [b, a]}]}
  c: {public_key: $ck, endpoints: [quic://10.242.0.2:4435], paths: [{path: [b, c]}]}
connect_to: [c]
EOF
  cat >"$REMOTE_WORK/c.yaml" <<EOF
id: c
identity_key_path: $REMOTE_WORK/c.key
listen: quic://10.242.0.2:4435
tun: {name: tunc, addresses: [10.64.2.2/32]}
link_health: {keepalive_secs: 1, idle_timeout_secs: 15}
peers:
  a: {public_key: $ak, endpoints: [], routes: [{ip_cidr: 10.64.0.1/32, priority: 100}], paths: [{path: [c, b, a]}]}
  b: {public_key: $bk, endpoints: [quic://10.242.0.1:4434]}
allowed_routes:
  - {allow: [10.64.2.0/24], deny: [10.64.2.10/32, 10.64.2.12/32], for: [a]}
allowed_local_ports:
  - {allow: [icmp], for: [a]}
EOF
}

start_three_nodes() {
  remote_namespace tinect-ta; remote_namespace tinect-tb; remote_namespace tinect-tc
  remote_veth ab-a ab-b tinect-ta tinect-tb 10.241.0.1/24 10.241.0.2/24
  remote_veth bc-b bc-c tinect-tb tinect-tc 10.242.0.1/24 10.242.0.2/24
  configure_exit_forwarding tinect-tc
  remote_keygen a; remote_keygen b; remote_keygen c
}

case_transit_and_egress() {
  remote_init "$WORK/transit-deny"
  start_three_nodes; write_three_node_configs false
  remote_start c tinect-tc; remote_start b tinect-tb; remote_start a tinect-ta
  remote_wait_tun tinect-ta tinea; remote_wait_log b 'circuit OPEN rejected'
  remote_expect_no_ping tinect-ta tinea 10.64.2.2
  remote_wait_status b 'transit:'
  remote_cleanup

  remote_init "$WORK/transit-allow"
  start_three_nodes; write_three_node_configs true
  remote_start c tinect-tc; remote_start b tinect-tb; remote_start a tinect-ta
  remote_wait_tun tinect-ta tinea; remote_wait_tun tinect-tc tunc
  # C may install its return circuit first.  Wait for the actual A -> B -> C
  # relay and C's matching authorization before injecting the first packet, so
  # the reliable session setup cannot overtake the circuit OPEN.
  remote_wait_log b 'incoming_peer_name=a'
  remote_wait_log c 'circuit exit authorization installed'
  remote_expect_ping tinect-ta tinea 10.64.2.2
  # A downstream exit restart must propagate a signed CircuitBroken through
  # the relay and converge a fresh source Circuit without waiting for Renew.
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$(remote_ns tinect-tc)" 2>/dev/null || true)
  sleep 0.2
  remote_start c tinect-tc
  remote_wait_tun tinect-tc tunc
  # A crash has no QUIC close frame. Allow the configured peer idle timeout
  # plus one bounded redial/OPEN round trip before declaring recovery failed.
  remote_wait_deadline 'exit restart circuit recovery' 90 \
    "sudo -n ip netns exec '$(remote_ns tinect-ta)' ping -I tinea -c 1 -W 1 10.64.2.2"
  remote_wait_status c '"rx_packets":'
  # A relay restart removes the source's first-hop Link instance directly.
  # Both ends must retract their snapshots and rebuild once B is reachable,
  # without relying on a data packet to wake the renewal worker.
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$(remote_ns tinect-tb)" 2>/dev/null || true)
  sleep 0.2
  remote_start b tinect-tb
  # B is a transit-only relay, so its local-only TUN is not part of the
  # recovery contract. The end-to-end probe below proves that its replacement
  # daemon, links, topology and relay state are all usable.
  remote_wait_deadline 'relay restart circuit recovery' 90 \
    "sudo -n ip netns exec '$(remote_ns tinect-ta)' ping -I tinea -c 1 -W 1 10.64.2.2"
  # Source restart is intentionally stateless: its configured desired route
  # must initiate a new circuit once its replacement first-hop Link exists.
  # Blackhole B<->C temporarily so the first OPEN cannot receive its exit
  # ACK. This verifies that lost control traffic does not strand the desired
  # circuit or cause the data plane to buffer plaintext packets.
  while read -r pid; do
    [[ -n "$pid" ]] && sudo -n kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo -n ip netns pids "$(remote_ns tinect-ta)" 2>/dev/null || true)
  sleep 0.2
  sudo -n ip netns exec "$(remote_ns tinect-tc)" tc qdisc replace dev bc-c root netem loss 100%
  remote_start a tinect-ta
  remote_wait_tun tinect-ta tinea
  remote_wait_log a 'circuit OPEN acknowledgement timed out' 100
  sudo -n ip netns exec "$(remote_ns tinect-tc)" tc qdisc del dev bc-c root
  remote_wait_deadline 'source restart circuit recovery' 30 \
    "sudo -n ip netns exec '$(remote_ns tinect-ta)' ping -I tinea -c 1 -W 1 10.64.2.2"
  remote_expect_no_ping tinect-ta tinea 10.64.2.10
  remote_wait_status c 'egress:allowed_route_denied'
  remote_expect_no_ping tinect-ta tinea 10.64.2.12
  remote_wait_status c 'egress:allowed_route_denied'
  remote_expect_no_ping tinect-ta tinea 10.65.0.1
  remote_wait_status c 'egress:allowed_route_denied'

  remote_cleanup
}

# A source unknown to the downstream relay can be carried only by an explicitly
# permitted known upstream. The destination deliberately has no return route:
# receipt is asserted through its circuit counter without making it known.
case_unknown_relay() {
  local allow_relay="$1"
  remote_init "$WORK/unknown-relay-$allow_relay"
  local n; for n in a g b c; do remote_namespace "tinect-ur-$n"; remote_keygen "$n"; done
  remote_veth ag-a ag-g tinect-ur-a tinect-ur-g 10.243.0.1/24 10.243.0.2/24
  remote_veth gb-g gb-b tinect-ur-g tinect-ur-b 10.244.0.1/24 10.244.0.2/24
  remote_veth bc-b bc-c tinect-ur-b tinect-ur-c 10.245.0.1/24 10.245.0.2/24
  configure_exit_forwarding tinect-ur-c
  local ak gk bk ck; ak="$(remote_public_key a)"; gk="$(remote_public_key g)"; bk="$(remote_public_key b)"; ck="$(remote_public_key c)"
  cat >"$REMOTE_WORK/a.yaml" <<EOF
id: a
identity_key_path: $REMOTE_WORK/a.key
listen: quic://10.243.0.1:4433
tun: {name: tinea, addresses: [10.66.0.1/32]}
peers: {g: {public_key: $gk, endpoints: [quic://10.243.0.2:4434]}, b: {public_key: $bk, endpoints: []}, c: {public_key: $ck, endpoints: [], routes: [{ip_cidr: 10.66.3.2/32, priority: 100}], paths: [{path: [a, g, b, c]}]}}
connect_to: [g]
EOF
  cat >"$REMOTE_WORK/g.yaml" <<EOF
id: g
allow_transit: true
identity_key_path: $REMOTE_WORK/g.key
listen: quic://0.0.0.0:4434
tun: {name: tung, addresses: [10.66.1.1/32]}
peers: {a: {public_key: $ak, endpoints: [quic://10.243.0.1:4433], paths: [{path: [g, a]}]}, b: {public_key: $bk, endpoints: [quic://10.244.0.2:4435]}, c: {public_key: $ck, endpoints: [], paths: [{path: [g, b, c]}]}}
connect_to: [b]
EOF
  cat >"$REMOTE_WORK/b.yaml" <<EOF
id: b
allow_transit: true
identity_key_path: $REMOTE_WORK/b.key
listen: quic://0.0.0.0:4435
tun: {name: tunb, addresses: [10.66.2.1/32]}
peers: {g: {public_key: $gk, endpoints: [quic://10.244.0.1:4434], allow_relay: $allow_relay}, c: {public_key: $ck, endpoints: [quic://10.245.0.2:4436], paths: [{path: [b, c]}]}}
connect_to: [c]
EOF
  cat >"$REMOTE_WORK/c.yaml" <<EOF
id: c
identity_key_path: $REMOTE_WORK/c.key
listen: quic://10.245.0.2:4436
tun: {name: tunc, addresses: [10.66.3.2/32]}
peers: {b: {public_key: $bk, endpoints: [quic://10.245.0.1:4435]}}
allowed_routes: [{allow: [10.66.3.2/32], for: any_inc_unknown}]
allowed_local_ports: [{allow: [icmp], for: any_inc_unknown}]
EOF
  remote_start c tinect-ur-c; remote_start b tinect-ur-b; remote_start g tinect-ur-g; remote_start a tinect-ur-a
  remote_wait_tun tinect-ur-a tinea
  if [[ "$allow_relay" == false ]]; then
    # The source OPEN is delivered only after the relay's topology and
    # downstream circuit have converged; allow the bounded control-plane
    # retries to reach the authorization check before declaring a failure.
    remote_wait_log b 'circuit OPEN rejected' 1000
    remote_expect_no_ping tinect-ur-a tinea 10.66.3.2
    remote_wait_status b 'transit:'
  else
    remote_wait_log a 'circuit OPEN acknowledged dst=c path=a->g->b->c' 1000
    # C intentionally has no return route, so ICMP cannot succeed.  The
    # packet must nevertheless reach C's egress boundary.  Capture that
    # boundary directly instead of treating the eventually-consistent status
    # snapshot as the data-plane assertion.
    remote_start_tun_rx_counter tinect-ur-c tunc 15
    remote_expect_no_ping tinect-ur-a tinea 10.66.3.2
    remote_wait_tun_rx_counter
  fi
  remote_cleanup
}

run_case() {
  case "$1" in
    connect) case_connect_admission ;;
    unknown-peer) case_unknown_peer ;;
    transit-egress) case_transit_and_egress ;;
    unknown-relay-deny) case_unknown_relay false ;;
    unknown-relay-allow) case_unknown_relay true ;;
    *) echo "unknown case: $1" >&2; return 2 ;;
  esac
}

trap 'remote_finish $?' EXIT
require_binary
if (($#)); then
  run_case "$1"
else
  for scenario in connect unknown-peer transit-egress unknown-relay-deny unknown-relay-allow; do
    echo "== $scenario =="
    run_case "$scenario"
  done
fi
echo "authentication and forwarding integration tests passed"
