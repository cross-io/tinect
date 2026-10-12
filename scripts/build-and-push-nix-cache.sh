#!/usr/bin/env bash

set -euo pipefail

# Build Tinect on a Linux builder and publish its closure to the Nix HTTP
# binary cache. The cache password is read from the environment and is never
# written to the repository or printed by this script.

cache_url="${NIX_CACHE_URL:-https://nix-cache.ihc.im}"
flake_ref="${NIX_FLAKE_REF:-.}#tinect"
cache_password="${NIX_CACHE_PASSWORD:-}"
secret_key_file="${NIX_CACHE_SECRET_KEY_FILE:-$HOME/.config/nix/cache-signing-key.sec}"
package_name="${NIX_CACHE_PACKAGE_NAME:-tinect}"
version_name="${NIX_CACHE_VERSION:-}"
registration_tags_json="${NIX_CACHE_TAGS_JSON:-}"
cache_upload_command="${NIX_CACHE_UPLOAD_COMMAND:-nix-cache-upload}"

if ! command -v nix >/dev/null 2>&1; then
  echo "nix is required" >&2
  exit 1
fi

if [[ -z "$cache_password" && -n "${NIX_NETRC_FILE:-}" ]]; then
  cache_host="${cache_url#https://}"
  cache_host="${cache_host#http://}"
  cache_host="${cache_host%%/*}"
  cache_password="$(awk -v host="$cache_host" '
    $1 == "machine" && $2 == host {
      for (index = 3; index < NF; index += 1) {
        if ($index == "password") {
          print $(index + 1)
          exit
        }
      }
    }
  ' "$NIX_NETRC_FILE")"
fi

if [[ -z "$cache_password" ]]; then
  echo "set NIX_CACHE_PASSWORD or provide a matching password in NIX_NETRC_FILE" >&2
  exit 1
fi
if ! command -v "$cache_upload_command" >/dev/null 2>&1; then
  echo "nix-cache-upload is required; set NIX_CACHE_UPLOAD_COMMAND or install it in PATH" >&2
  exit 1
fi

echo "Building $flake_ref"
out_path="$(nix build --no-link --print-out-paths "$flake_ref")"
echo "Built $out_path"

if [[ -z "$registration_tags_json" ]]; then
  nix_system="$(nix eval --raw --impure --expr 'builtins.currentSystem')"
  registration_tags_json="$(printf '{"channel":"dev","system":"%s"}' "$nix_system")"
fi

mapfile -t closure_paths < <(nix-store --query --requisites "$out_path")
if [[ -z "$version_name" ]]; then
  output_name="$(basename "$out_path")"
  output_hash="${output_name%%-*}"
  version_name="${output_hash:0:12}"
fi

if [[ -s "$secret_key_file" ]]; then
  nix store sign --key-file "$secret_key_file" "${closure_paths[@]}"
else
  echo "warning: signing key not found at $secret_key_file; published narinfo files will be unsigned" >&2
fi

echo "Publishing the closure to $cache_url"
cache_tag_args=()
while IFS=$'\t' read -r tag_key tag_value; do
  cache_tag_args+=(--tag "$tag_key=$tag_value")
done < <(jq -r 'if type != "object" then error("NIX_CACHE_TAGS_JSON must be an object") else to_entries[] | [.key, (.value | tostring)] | @tsv end' <<<"$registration_tags_json")

NIX_CACHE_WRITE_TOKEN="$cache_password" \
  "$cache_upload_command" \
    --to "$cache_url" \
    --package "$package_name" \
    --version "$version_name" \
    "${cache_tag_args[@]}" \
    "$out_path"
