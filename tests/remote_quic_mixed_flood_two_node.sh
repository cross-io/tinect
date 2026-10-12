#!/usr/bin/env bash
# Floods the shared UDP port with QUIC-shaped packets and verifies that bare
# Physical traffic remains usable.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quic \
  FLOOD_QUIC_PACKETS=50000 \
  WORK="${WORK:-/tmp/tinect-quic-mixed-flood-two-node}" \
  "$SCRIPT_DIR/remote_two_node.sh"
