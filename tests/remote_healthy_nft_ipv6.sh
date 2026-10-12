#!/usr/bin/env bash
# Covers IPv6 healthy-route sets, explicit targets, and user-table retention.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  HEALTHY_NFT_TEST=1 \
  HEALTHY_NFT_EXPLICIT_TARGETS=1 \
  HEALTHY_NFT_PRESERVE_TABLE=1 \
  MANAGED_ROUTES_TEST=1 \
  WORK="${WORK:-/tmp/tinect-healthy-nft-ipv6}" \
  A_EXTRA_ROUTE_PREFIX='fd00:64::1/128' \
  B_EXTRA_ROUTE_PREFIX='fd00:64::2/128' \
  "$SCRIPT_DIR/remote_two_node.sh"
