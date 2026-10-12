#!/usr/bin/env bash
# Exercises outbound endpoint selection when the listener and peer endpoint
# use opposite address families. Both namespaces have dual-stack underlays.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quic \
  WORK="${WORK:-/tmp/tinect-quic-mixed-address-family-two-node}" \
  A_UNDERLAY_CIDR='10.202.0.1/24' \
  B_UNDERLAY_CIDR='10.202.0.2/24' \
  A_EXTRA_UNDERLAY_CIDR='fd00:202::1/64' \
  B_EXTRA_UNDERLAY_CIDR='fd00:202::2/64' \
  A_LISTEN_ADDRESS='10.202.0.1:4433' \
  B_LISTEN_ADDRESS='[fd00:202::2]:4434' \
  A_PEER_ENDPOINT='10.202.0.1:4433' \
  B_PEER_ENDPOINT='[fd00:202::2]:4434' \
  "$SCRIPT_DIR/remote_two_node.sh"
