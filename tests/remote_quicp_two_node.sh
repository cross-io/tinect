#!/usr/bin/env bash
# Reuses the two-node QUIC test with the fake-TCP Quinn socket.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quic-faketcp WORK="${WORK:-/tmp/tinect-quicp-two-node}" \
  "$SCRIPT_DIR/remote_two_node.sh"
