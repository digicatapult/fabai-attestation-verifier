//go:build sealtest && !js

package vectors_test

import (
	"testing"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
)

// TestGeneratedVectors runs freshly generated synthetic vectors, so the
// generator and the committed files can't drift apart unnoticed. The
// generator needs go-sev-guest's test package, which doesn't build for
// js/wasm.
func TestGeneratedVectors(t *testing.T) {
	vectors, err := synth.Synthetic()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) { checkVector(t, v) })
	}
}
