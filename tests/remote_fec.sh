#!/usr/bin/env bash
set -euo pipefail

TINECT_NS_PREFIX="${TINECT_NS_PREFIX:-tinect-fec}"
FEC_TEST=1
export TINECT_NS_PREFIX FEC_TEST
exec "$(dirname "$0")/remote_two_node.sh" "$@"
