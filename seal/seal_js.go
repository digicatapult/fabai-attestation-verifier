//go:build js

package seal

import (
	"errors"

	"github.com/digicatapult/fabai-attestation-verifier/internal/allowlist"
)

// ErrNoEmbeddedAllowlist means the WASM bundle was built without an
// allowlist, so every check fails with allowlist_unverified.
var ErrNoEmbeddedAllowlist = errors.New("this WASM build embeds no allowlist")

// NewBuildVerified returns a Checker for an allowlist that the kiosk's
// bundle build verified natively (fabai-seal allowlist verify) and embedded
// in the WASM bundle. The pinned bundle digest covers the list. Only affects
// the WASM build.
func NewBuildVerified(listJSON []byte, opts Options) *Checker {
	if len(listJSON) == 0 {
		return newChecker(nil, ErrNoEmbeddedAllowlist, opts)
	}
	list, err := allowlist.Decode(listJSON)
	return newChecker(list, err, opts)
}
