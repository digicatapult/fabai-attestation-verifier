//go:build sealtest

package vectors_test

import (
	"context"
	"testing"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
)

// TestVectors runs every committed vector: the Go side of the conformance
// suite. The same test, built for js/wasm, runs under Node.js.
func TestVectors(t *testing.T) {
	vectors, err := sealtest.Load(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) { checkVector(t, v) })
	}
}

func checkVector(t *testing.T, v *sealtest.Vector) {
	t.Helper()
	result, err := v.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := sealtest.OutcomeOf(result); got != v.Expect {
		t.Errorf("got %+v\nwant %+v\nerrors: %v", got, v.Expect, result.Detail.Errors)
	}
	key, ok := result.SendKey()
	if ok != v.Expect.Permitted || (ok && len(key) != 32) {
		t.Errorf("SendKey() = %d bytes, %v; permitted %v", len(key), ok, v.Expect.Permitted)
	}
	if result.Detail.Report == nil && v.Expect.Hardware.Reason != "parse_failed" && v.Expect.Hardware.Reason != "nonce_mismatch" && v.Expect.Hardware.Reason != "report_data_mismatch" {
		t.Errorf("experts detail has no report fields")
	}
}
