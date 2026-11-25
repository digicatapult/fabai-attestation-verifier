//go:build js

package allowlist

import "errors"

// ErrNoSigstoreInWASM is returned by Verify in the WASM build: sigstore-go
// doesn't build for js/wasm, so the kiosk's bundle build verifies the list
// natively and embeds it.
var ErrNoSigstoreInWASM = errors.New("the WASM build can't check a Sigstore bundle; it uses the allowlist embedded at build time")

// Verify always fails in the WASM build.
func Verify(_, _ []byte) (*List, error) {
	return nil, ErrNoSigstoreInWASM
}
