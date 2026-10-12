#!/usr/bin/env bash
# Exercises full QUIC over the Fake-TCP carrier over an IPv4 underlay.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CARRIER=quicfull-faketcp \
  WORK="${WORK:-/tmp/tinect-quicfull-faketcp-two-node}" \
  "$SCRIPT_DIR/remote_two_node.sh"
