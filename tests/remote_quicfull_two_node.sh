#!/usr/bin/env bash
# Exercises the full QUIC carrier over an IPv4 underlay.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quicfull \
  WORK="${WORK:-/tmp/tinect-quicfull-two-node}" \
  "$SCRIPT_DIR/remote_two_node.sh"
