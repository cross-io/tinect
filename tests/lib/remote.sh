#!/usr/bin/env bash
# Shared helpers for privileged Linux network-namespace integration tests.
# Scripts source this file; do not execute it directly.

REMOTE_PIDS=()
REMOTE_NAMESPACES=()
REMOTE_SOCKETS=()
REMOTE_LOG_NODES=()
REMOTE_CAPTURE_NODE=""
REMOTE_CAPTURE_INTERFACE=""
REMOTE_CAPTURE_BASELINE=""
REMOTE_CAPTURE_TIMEOUT=""
TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect}"
TINECT_TEST_TIMING_PROFILE="${TINECT_TEST_TIMING_PROFILE:-production}"

remote_ns() {
  local name="$1"
  if [[ "$TINECT_NS_PREFIX" == "tinect" ]]; then
    printf '%s' "$name"
  elif [[ "$name" == tinect-* ]]; then
    printf '%s-%s' "$TINECT_NS_PREFIX" "${name#tinect-}"
  else
    printf '%s-%s' "$TINECT_NS_PREFIX" "$name"
  fi
}

remote_init() {
  REMOTE_WORK="$1"
  REMOTE_STATUS_SOCKET_DIR="$REMOTE_WORK/status-sockets"
  REMOTE_PIDS=()
  REMOTE_NAMESPACES=()
  REMOTE_SOCKETS=()
  REMOTE_LOG_NODES=()
  REMOTE_CAPTURE_NODE=""
  REMOTE_CAPTURE_INTERFACE=""
  REMOTE_CAPTURE_BASELINE=""
  REMOTE_CAPTURE_TIMEOUT=""
  rm -rf "$REMOTE_WORK"
  mkdir -p "$REMOTE_WORK" "$REMOTE_STATUS_SOCKET_DIR"
}

remote_cleanup() {
  local pid ns socket cleanup_failed=0
  local -a namespace_pids=()
  for pid in "${REMOTE_PIDS[@]:-}"; do
    sudo -n kill -TERM "$pid" 2>/dev/null || true
  done
  for ns in "${REMOTE_NAMESPACES[@]:-}"; do
    while read -r pid; do
      [[ -n "$pid" ]] && namespace_pids+=("$pid")
    done < <(sudo -n ip netns pids "$ns" 2>/dev/null || true)
  done
  for pid in "${namespace_pids[@]:-}"; do sudo -n kill -TERM "$pid" 2>/dev/null || true; done
  sleep 0.2
  for pid in "${REMOTE_PIDS[@]:-}" "${namespace_pids[@]:-}"; do
    sudo -n kill -KILL "$pid" 2>/dev/null || true
  done
  for ns in "${REMOTE_NAMESPACES[@]:-}"; do
    sudo -n ip netns del "$ns" 2>/dev/null || true
    if sudo -n ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$ns"; then
      echo "warning: namespace cleanup incomplete: $ns" >&2
      cleanup_failed=1
    fi
  done
  for socket in "${REMOTE_SOCKETS[@]:-}"; do sudo -n rm -f "$socket"; done
  for socket in "${REMOTE_SOCKETS[@]:-}"; do
    if [[ -e "$socket" ]]; then
      echo "warning: socket cleanup incomplete: $socket" >&2
      cleanup_failed=1
    fi
  done
  return "$cleanup_failed"
}

remote_namespace() {
  local ns
  ns="$(remote_ns "$1")"
  sudo -n ip netns del "$ns" 2>/dev/null || true
  sudo -n ip netns add "$ns"
  sudo -n ip -n "$ns" link set lo up
  REMOTE_NAMESPACES+=("$ns")
}

remote_veth() {
  local left_ns right_ns
  left_ns="$(remote_ns "$3")"
  right_ns="$(remote_ns "$4")"
  remote_veth_between "$1" "$2" "$left_ns" "$right_ns" "$5" "$6"
}

# Create a veth with temporary unique host-side names, then rename each end
# after moving it into its fixture namespace. This prevents collisions while
# multiple privileged tests share the initial network namespace.
remote_veth_between() {
  local left="$1" right="$2" left_ns="$3" right_ns="$4" left_addr="$5" right_addr="$6"
  local token host_left host_right
  token="$(printf '%s:%s:%s:%s' "$TINECT_NS_PREFIX" "$left_ns" "$left" "$right" | cksum | awk '{print $1}')"
  host_left="rv${token:0:8}a"
  host_right="rv${token:0:8}b"
  sudo -n ip link add "$host_left" type veth peer name "$host_right"
  sudo -n ip link set "$host_left" netns "$left_ns"
  sudo -n ip link set "$host_right" netns "$right_ns"
  sudo -n ip -n "$left_ns" link set "$host_left" name "$left"
  sudo -n ip -n "$right_ns" link set "$host_right" name "$right"
  sudo -n ip -n "$left_ns" addr add "$left_addr" dev "$left"
  sudo -n ip -n "$right_ns" addr add "$right_addr" dev "$right"
  sudo -n ip -n "$left_ns" link set "$left" up
  sudo -n ip -n "$right_ns" link set "$right" up
}

remote_status_socket() { printf '%s/%s.sock' "$REMOTE_STATUS_SOCKET_DIR" "$1"; }

remote_keygen() {
  local node="$1"
  "$BIN" keygen --output "$REMOTE_WORK/$node.key" >"$REMOTE_WORK/$node.identity"
}

remote_public_key() {
  awk '/public_key:/{print $2}' "$REMOTE_WORK/$1.identity"
}

remote_start() {
  local node="$1" ns socket config
  ns="$(remote_ns "$2")"
  socket="$(remote_status_socket "$node")"
  config="$REMOTE_WORK/$node.yaml"
  # Fixture configs that use this generic launcher get an isolated management
  # socket by default. More specialised tests can declare a runtime block and
  # launch the daemon themselves when they need additional runtime settings.
  if ! grep -Eq '^runtime:' "$config"; then
    printf '\nruntime:\n  status_socket: %s\n' "$socket" >>"$config"
  elif ! grep -Eq '^[[:space:]]+status_socket:' "$config"; then
    echo "fixture config $config has runtime settings but no isolated status_socket" >&2
    return 1
  fi
  REMOTE_SOCKETS+=("$socket")
  REMOTE_LOG_NODES+=("$node")
  sudo -n env "TINECT_TEST_TIMING_PROFILE=$TINECT_TEST_TIMING_PROFILE" \
    ip netns exec "$ns" "$BIN" up "$REMOTE_WORK/$node.yaml" >"$REMOTE_WORK/$node.log" 2>&1 &
  REMOTE_PIDS+=("$!")
}

remote_wait_for() {
  local description="$1" command="$2"
  local tries="${3:-100}" i
  for i in $(seq 1 "$tries"); do
    if eval "$command"; then return 0; fi
    sleep 0.1
  done
  echo "timed out waiting for $description" >&2
  return 1
}

remote_wait_deadline() {
  local description="$1" timeout_secs="$2" command="$3"
  local deadline=$((SECONDS + timeout_secs))
  while ((SECONDS < deadline)); do
    if eval "$command"; then return 0; fi
    sleep 0.1
  done
  echo "timed out waiting for $description after ${timeout_secs}s" >&2
  return 1
}

remote_wait_log() {
  local node="$1" text="$2" tries="${3:-100}"
  remote_wait_deadline "log $node: $text" "$(((tries + 9) / 10))" "grep -Fq -- '$text' '$REMOTE_WORK/$node.log'"
}

remote_assert_timing_profile() {
  local node="$1"
  if [[ "$TINECT_TEST_TIMING_PROFILE" != "production" ]]; then
    remote_wait_log "$node" "integration-test timing profile enabled profile=\"$TINECT_TEST_TIMING_PROFILE\"" 300
  fi
}

remote_wait_tun() {
  local ns tun="$2" tries="${3:-100}"
  ns="$(remote_ns "$1")"
  remote_wait_deadline "TUN $tun in $ns" "$(((tries + 9) / 10))" "sudo -n ip -n '$ns' link show '$tun' >/dev/null 2>&1"
}

remote_status_has() {
  local node="$1" text="$2"
  sudo -n "$BIN" status --socket "$(remote_status_socket "$node")" | grep -Fq -- "$text"
}

remote_wait_status() {
  local node="$1" text="$2" tries="${3:-100}"
  remote_wait_deadline "status $node: $text" "$(((tries + 9) / 10))" "remote_status_has '$node' '$text'"
}

remote_expect_ping() {
  local ns tun="$2" target="$3"
  ns="$(remote_ns "$1")"
  # The first packet on a secure circuit may establish reliable sessions in
  # both directions.  Relay installation and the authenticated setup ACK are
  # asynchronous, so allow enough bounded probes for that control-plane round
  # trip instead of assuming that a few immediate probes cover it.
  remote_wait_deadline "ping $target through $tun" 30 \
    "sudo -n ip netns exec '$ns' ping -I '$tun' -c 1 -W 1 '$target'"
}

remote_expect_no_ping() {
  local ns tun="$2" target="$3"
  ns="$(remote_ns "$1")"
  if sudo -n ip netns exec "$ns" ping -I "$tun" -c 1 -W 1 "$target"; then
    echo "unexpectedly reached $target through $tun" >&2
    return 1
  fi
}

# Record the TUN RX counter at an egress boundary.  A packet written by
# tinect into the TUN device is an RX packet from the kernel's perspective;
# using the interface counter avoids depending on tcpdump's TUN direction
# semantics and is separate from the eventually-consistent status API.
remote_tun_rx_packets() {
  local node="$1" interface="$2" ns
  ns="$(remote_ns "$node")"
  sudo -n ip -n "$ns" -s link show dev "$interface" \
    2>/dev/null \
    | awk '$1 == "RX:" {getline; print $2; exit}'
}

remote_start_tun_rx_counter() {
  local node="$1" interface="$2" timeout_secs="${3:-15}"
  REMOTE_CAPTURE_NODE="$node"
  REMOTE_CAPTURE_INTERFACE="$interface"
  REMOTE_CAPTURE_TIMEOUT="$timeout_secs"
  REMOTE_CAPTURE_BASELINE="$(remote_tun_rx_packets "$node" "$interface")" || REMOTE_CAPTURE_BASELINE=""
  if [[ ! "$REMOTE_CAPTURE_BASELINE" =~ ^[0-9]+$ ]]; then
    echo "could not read RX packet counter for $node:$interface" >&2
    return 1
  fi
}

remote_wait_tun_rx_counter() {
  if [[ -z "$REMOTE_CAPTURE_NODE" || -z "$REMOTE_CAPTURE_INTERFACE" ]]; then
    echo "TUN RX counter was not recorded" >&2
    return 1
  fi
  local deadline=$((SECONDS + REMOTE_CAPTURE_TIMEOUT)) current
  while ((SECONDS < deadline)); do
    current="$(remote_tun_rx_packets "$REMOTE_CAPTURE_NODE" "$REMOTE_CAPTURE_INTERFACE")" || current=""
    if [[ "$current" =~ ^[0-9]+$ ]] && ((current > REMOTE_CAPTURE_BASELINE)); then
      return 0
    fi
    sleep 0.1
  done
  echo "TUN RX packet counter did not increase for $REMOTE_CAPTURE_NODE:$REMOTE_CAPTURE_INTERFACE" >&2
  echo "baseline=$REMOTE_CAPTURE_BASELINE current=$current" >&2
  return 1
}

remote_dump_logs() {
  local node
  for node in "$@"; do
    echo "===== $node log =====" >&2
    cat "$REMOTE_WORK/$node.log" >&2 || true
  done
}

remote_report_failure() {
  local ns node
  remote_dump_logs "${REMOTE_LOG_NODES[@]:-}"
  for node in "${REMOTE_LOG_NODES[@]:-}"; do
    echo "===== $node status =====" >&2
    timeout --signal=TERM --kill-after=1 6s sudo -n "$BIN" status \
      --socket "$(remote_status_socket "$node")" >&2 || true
  done
  if [[ -n "${REMOTE_CAPTURE_NODE:-}" ]]; then
    echo "===== TUN RX counter =====" >&2
    echo "node=$REMOTE_CAPTURE_NODE interface=$REMOTE_CAPTURE_INTERFACE baseline=$REMOTE_CAPTURE_BASELINE" >&2
  fi
  for ns in "${REMOTE_NAMESPACES[@]:-}"; do
    echo "===== $ns interfaces =====" >&2
    sudo -n ip -n "$ns" -br link show 2>/dev/null >&2 || true
    echo "===== $ns addresses =====" >&2
    sudo -n ip -n "$ns" -br addr show 2>/dev/null >&2 || true
    echo "===== $ns routes =====" >&2
    sudo -n ip -n "$ns" route show table all >&2 || true
    sudo -n ip -n "$ns" -6 route show table all >&2 || true
    echo "===== $ns rules =====" >&2
    sudo -n ip -n "$ns" rule show >&2 || true
    sudo -n ip -n "$ns" -6 rule show >&2 || true
    echo "===== $ns nftables =====" >&2
    sudo -n ip netns exec "$ns" nft list ruleset >&2 || true
    echo "===== $ns conntrack =====" >&2
    sudo -n ip netns exec "$ns" sh -c 'cat /proc/net/nf_conntrack 2>/dev/null || true' >&2 || true
  done
}

remote_finish() {
  local code="$1"
  trap - EXIT
  if [[ "$code" -ne 0 ]]; then remote_report_failure; fi
  if ! remote_cleanup && [[ "$code" -eq 0 ]]; then
    code=1
  fi
  exit "$code"
}
