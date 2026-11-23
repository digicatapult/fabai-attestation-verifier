# Notice

fabai-attestation-verifier, copyright 2026 Digital Catapult

This repository is licensed under the GNU Affero General Public License,
version 3 (see [`LICENSE`](LICENSE)). It imports `tinfoil-go`'s
`verify/document` package, which is AGPL-3.0, so the verifier, and the WASM
bundle the kiosk loads, are too.

## Go dependencies

These dependencies are linked into the library, the `fabai-seal` CLI, and the
WASM bundle, at the versions pinned in [`go.mod`](go.mod) and [`go.sum`](go.sum):

| Module | Source | Version | Licence | Used for |
|--------|--------|---------|---------|----------|
| `github.com/tinfoilsh/tinfoil-go` | [tinfoilsh/tinfoil-go](https://github.com/tinfoilsh/tinfoil-go) | v0.17.0-rc.12 ([`05ca0ef`](https://github.com/tinfoilsh/tinfoil-go/commit/05ca0ef060def7b9aa12f1a00ddae6cc6a236571)) | `verify/` (including `verify/document`): AGPL-3.0. The rest of the repository, including the `internal/canonical` and `endorsement/config` packages `verify/document` imports: Apache-2.0 | Strict v3 document parsing and the `REPORT_DATA` recomputation. Only `verify/document` and its imports are linked |
| `github.com/tinfoilsh/go-sev-guest` | [tinfoilsh/go-sev-guest](https://github.com/tinfoilsh/go-sev-guest), Tinfoil's fork of [google/go-sev-guest](https://github.com/google/go-sev-guest) | `v0.0.0-20261118213236-e9f4702918d3`, the pin `tinfoil-go` v0.17.0-rc.12 uses | Apache-2.0 | Report parsing, handling of VCEK, ASK, and ARK, the report signature, CRL checks, Turin TCB layout |
| `github.com/sigstore/sigstore-go` | [sigstore/sigstore-go](https://github.com/sigstore/sigstore-go) | v1.4.1 | Apache-2.0 | Offline check of the allowlist's Sigstore bundle (native builds only: it doesn't build for `js/wasm`) |

Their own dependencies are listed in `go.sum`.

## Data

| Path | Source | Retrieved | Licence or terms |
|------|--------|-----------|------------------|
| [`internal/amd/roots/`](internal/amd/roots) | AMD Key Distribution Service, `https://kdsintf.amd.com/vcek/v1/{Milan,Genoa,Turin}/cert_chain` (the ARK of each chain). Byte-equal to the copies `go-sev-guest` embeds | 2026-11-23 | AMD's published root certificates |
| [`internal/allowlist/trusted_root.json`](internal/allowlist/trusted_root.json) | Sigstore public-good `trusted_root.json`, through its TUF repository ([sigstore/root-signing](https://github.com/sigstore/root-signing)) | 2026-11-23 | Apache-2.0 |
| [`vectors/captured-*.json`](vectors) | v3 attestation documents served by Tinfoil's public `inference.tinfoil.sh` (`tinfoilsh/confidential-model-router` v0.0.179 on [`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage) 0.14.19, AGPL-3.0). Each file records its URL, nonce and capture time | 2026-11-23 | Service output, committed as test data |

## Release artefacts

The release's `wasm_exec.js` is copied unmodified from the Go 1.27.4
toolchain (`lib/wasm/wasm_exec.js`, BSD-3-Clause, copyright The Go Authors).
