#!/usr/bin/env bash
# Exercises full QUIC over fake-TCP on an IPv6-only underlay.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quicfull-faketcp \
  WORK="${WORK:-/tmp/tinect-quicfull-faketcp-ipv6-two-node}" \
  A_UNDERLAY_CIDR='fd00:204::1/64' \
  B_UNDERLAY_CIDR='fd00:204::2/64' \
  A_LISTEN_ADDRESS='[fd00:204::1]:4433' \
  B_LISTEN_ADDRESS='[fd00:204::2]:4434' \
  A_PEER_ENDPOINT='[fd00:204::1]:4433' \
  B_PEER_ENDPOINT='[fd00:204::2]:4434' \
  "$SCRIPT_DIR/remote_two_node.sh"
