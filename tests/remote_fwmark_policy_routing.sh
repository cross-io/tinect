#!/usr/bin/env bash
# Makes unmarked underlay traffic prohibited so the carrier must apply SO_MARK.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FWMARK_POLICY_TEST=1 \
  A_FWMARK=4242 \
  B_FWMARK=4242 \
  WORK="${WORK:-/tmp/tinect-fwmark-policy-routing}" \
  "$SCRIPT_DIR/remote_two_node.sh"
