#!/usr/bin/env bash
# Runs the real TUN two-node test with a long TCP flow under netem.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NETEM_SESSION=1 \
  WORK="${WORK:-/tmp/tinect-loss-reorder-session}" \
  "$SCRIPT_DIR/remote_two_node.sh"
