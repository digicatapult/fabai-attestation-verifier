//go:build !js

package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const releaseIdentity = "https://github.com/digicatapult/fabai-allowlist/.github/workflows/release.yml@refs/tags/v1.2.3"

func statement(t *testing.T, list []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(list)
	data, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "allowlist.json", "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSigstore(t *testing.T) {
	list := loadList(t)
	tampered := append([]byte(nil), list...)
	tampered[len(tampered)-2] ^= 0x20

	tests := []struct {
		name     string
		identity string
		issuer   string
		checked  []byte
		ok       bool
	}{
		{"signed by the release workflow", releaseIdentity, SignerIssuer, list, true},
		{"tampered list", releaseIdentity, SignerIssuer, tampered, false},
		{"another workflow", "https://github.com/digicatapult/fabai-allowlist/.github/workflows/test.yml@refs/tags/v1.2.3", SignerIssuer, list, false},
		{"another repository", "https://github.com/someone/fabai-allowlist/.github/workflows/release.yml@refs/tags/v1.2.3", SignerIssuer, list, false},
		{"a branch, not a release tag", "https://github.com/digicatapult/fabai-allowlist/.github/workflows/release.yml@refs/heads/main", SignerIssuer, list, false},
		{"another issuer", releaseIdentity, "https://accounts.example.com", list, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore, err := ca.NewVirtualSigstore()
			if err != nil {
				t.Fatal(err)
			}
			entity, err := sigstore.Attest(tt.identity, tt.issuer, statement(t, list))
			if err != nil {
				t.Fatal(err)
			}
			// The virtual instance issues no SCTs; every other requirement holds.
			err = verifySigned(entity, sigstore, tt.checked, []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)})
			if (err == nil) != tt.ok {
				t.Errorf("verifySigned() = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestVerifyRefusesBundleFromAnotherRoot(t *testing.T) {
	if _, err := Verify(loadList(t), []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)); err == nil {
		t.Error("an empty bundle was accepted")
	}
}
