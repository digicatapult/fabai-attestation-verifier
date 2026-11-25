//go:build sealtest && !js

package vectors_test

import (
	"bytes"
	"encoding/json/jsontext"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
)

// TestGeneratedVectors runs freshly generated synthetic vectors, so a
// generator change that breaks a scenario fails here even before the files
// are regenerated. The generator needs go-sev-guest's test package, which
// doesn't build for js/wasm.
func TestGeneratedVectors(t *testing.T) {
	vectors, err := synth.Synthetic()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) { checkVector(t, v) })
	}
}

// TestCommittedVectorsMatchGenerator checks that the committed synthetic
// vectors are exactly the generator's scenarios, with the same inputs and
// expectations, so the two can't drift apart unnoticed. Every generator run
// re-signs the documents and roots, so it doesn't compare those bytes.
func TestCommittedVectorsMatchGenerator(t *testing.T) {
	loaded, err := sealtest.Load(".")
	if err != nil {
		t.Fatal(err)
	}
	committed := make(map[string]*sealtest.Vector)
	for _, v := range loaded {
		if v.Source == "synthetic" {
			committed[v.Name] = v
		}
	}
	generated, err := synth.Synthetic()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range generated {
		got, ok := committed[want.Name]
		delete(committed, want.Name)
		if !ok {
			t.Errorf("%s: generated but not committed; rerun gen", want.Name)
			continue
		}
		if _, err := os.Stat(want.Name + ".json"); err != nil {
			t.Errorf("%s: %v", want.Name, err)
		}
		t.Run(want.Name, func(t *testing.T) { compareVector(t, got, want) })
	}
	for _, name := range slices.Sorted(maps.Keys(committed)) {
		t.Errorf("%s: committed but not generated; remove it or rerun gen", name)
	}
}

func compareVector(t *testing.T, got, want *sealtest.Vector) {
	t.Helper()
	if got.Description != want.Description {
		t.Errorf("description %q, want %q", got.Description, want.Description)
	}
	if got.Nonce != want.Nonce {
		t.Errorf("nonce %s, want %s", got.Nonce, want.Nonce)
	}
	if got.Channel != want.Channel {
		t.Errorf("channel %q, want %q", got.Channel, want.Channel)
	}
	if got.AllowlistVerified != want.AllowlistVerified {
		t.Errorf("allowlistVerified %v, want %v", got.AllowlistVerified, want.AllowlistVerified)
	}
	if !got.CheckTime.Equal(want.CheckTime) {
		t.Errorf("checkTime %v, want %v", got.CheckTime, want.CheckTime)
	}
	if got.Expect != want.Expect {
		t.Errorf("expect %+v, want %+v", got.Expect, want.Expect)
	}
	if got.Capture != nil {
		t.Errorf("synthetic vector has capture %+v", got.Capture)
	}
	if gotProducts, wantProducts := slices.Sorted(maps.Keys(got.Roots)), slices.Sorted(maps.Keys(want.Roots)); !slices.Equal(gotProducts, wantProducts) {
		t.Errorf("roots for %v, want %v", gotProducts, wantProducts)
	}
	if !bytes.Equal(compact(t, got.Allowlist), compact(t, want.Allowlist)) {
		t.Errorf("allowlist differs from the generator's")
	}
}

func compact(t *testing.T, v jsontext.Value) jsontext.Value {
	t.Helper()
	c := v.Clone()
	if err := c.Compact(); err != nil {
		t.Fatal(err)
	}
	return c
}
