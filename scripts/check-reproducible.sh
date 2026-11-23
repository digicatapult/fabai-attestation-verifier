#!/usr/bin/env bash
# Checks that the WASM bundle rebuilds bit for bit: two builds from the same
# commit, the second with an empty build cache and from another directory,
# must have the same SHA-256 (seal-check "Rebuild matches").
set -euo pipefail

work=""
cleanup() { [[ -z "$work" ]] || rm -rf "$work"; }

main() {
  local root first second
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  work="$(mktemp -d)"
  trap cleanup EXIT

  "$root/scripts/build-wasm.sh" "$work/first" > /dev/null
  cp -R "$root" "$work/copy"
  GOCACHE="$work/cache" "$work/copy/scripts/build-wasm.sh" "$work/second" > /dev/null

  first="$(sha256sum < "$work/first/fabai-seal.wasm")"
  second="$(sha256sum < "$work/second/fabai-seal.wasm")"
  if [[ "$first" != "$second" ]]; then
    printf 'check-reproducible: rebuild differs\n  %s\n  %s\n' "$first" "$second" >&2
    return 1
  fi
  printf 'reproducible: fabai-seal.wasm %s\n' "${first%% *}"
}

main "$@"
