#!/usr/bin/env bash
# Confirms policy-managed overlay routes are left untouched by the daemon.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MANAGED_ROUTES_TEST=1 \
  WORK="${WORK:-/tmp/tinect-unmanaged-routes}" \
  "$SCRIPT_DIR/remote_two_node.sh"
