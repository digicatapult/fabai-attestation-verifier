#!/usr/bin/env bash
# Builds the seal check's WASM bundle reproducibly, and copies wasm_exec.js
# and the JS wrapper beside it.
#
#   scripts/build-wasm.sh <out-dir> [<allowlist.json> <bundle.json>]
#
# With an allowlist, the list's Sigstore bundle is verified natively first
# (fabai-seal allowlist verify) and the list is embedded, so the bundle's
# SHA-256 covers it (design D9 fallback). Without one, the bundle embeds no
# list and every check fails with allowlist_unverified.
set -euo pipefail

readonly GO_TOOLCHAIN="go1.27.4"
embedded=""

# empty_embedded restores the committed, empty allowlist.json.
empty_embedded() { [[ -z "$embedded" ]] || : > "$embedded"; }

main() {
  local out="${1:?usage: build-wasm.sh <out-dir> [<allowlist.json> <bundle.json>]}"
  local allowlist="${2:-}" bundle="${3:-}"
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  embedded="$root/cmd/fabai-seal-wasm/allowlist.json"

  export GOTOOLCHAIN="$GO_TOOLCHAIN" CGO_ENABLED=0 GOFLAGS=-mod=readonly
  if [[ "$(go env GOVERSION)" != "$GO_TOOLCHAIN" ]]; then
    printf 'build-wasm: need %s, have %s\n' "$GO_TOOLCHAIN" "$(go env GOVERSION)" >&2
    return 1
  fi

  if [[ -n "$allowlist" ]]; then
    [[ -n "$bundle" ]] || { printf 'build-wasm: an allowlist needs its Sigstore bundle\n' >&2; return 2; }
    [[ ! -s "$embedded" ]] || { printf 'build-wasm: %s is not empty\n' "$embedded" >&2; return 1; }
    allowlist="$(realpath "$allowlist")" bundle="$(realpath "$bundle")"
    trap empty_embedded EXIT
    (cd "$root" && go run ./cmd/fabai-seal allowlist verify --allowlist "$allowlist" --bundle "$bundle" --out "$embedded")
  fi

  mkdir -p "$out"
  out="$(cd "$out" && pwd)"
  (cd "$root" && GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$out/fabai-seal.wasm" ./cmd/fabai-seal-wasm)
  cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/wasm_exec.js"
  cp "$root/js/seal.mjs" "$out/seal.mjs"
  (cd "$out" && sha256sum fabai-seal.wasm wasm_exec.js seal.mjs > SHA256SUMS && cat SHA256SUMS)
}

main "$@"
