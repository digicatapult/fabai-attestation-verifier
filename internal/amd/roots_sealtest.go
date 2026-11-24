//go:build sealtest

package amd

import "crypto/x509"

// SealtestSetRoots replaces the pinned AMD roots for the synthetic
// conformance vectors and returns a function that restores them. It exists
// only in builds with the sealtest tag; release builds and the WASM bundle
// are built without it, and a test checks that they don't contain this
// symbol. Not safe for concurrent use.
func SealtestSetRoots(roots map[string]*x509.Certificate) (restore func()) {
	saved := pinnedRoots
	pinnedRoots = roots
	return func() { pinnedRoots = saved }
}
