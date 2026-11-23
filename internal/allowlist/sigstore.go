//go:build !js

package allowlist

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// trustedRootJSON is Sigstore's public-good trusted root, fetched through
// its TUF repository on 2026-11-23 and refreshed with each verifier release.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

// Verify checks the list's Sigstore bundle offline against the pinned
// trusted root and the compiled-in signer, then decodes and schema-checks
// the list.
func Verify(listJSON, bundleJSON []byte) (*List, error) {
	trusted, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("pinned Sigstore trusted root: %w", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("allowlist Sigstore bundle: %w", err)
	}
	if err := verifySigned(&b, trusted, listJSON, publicGoodOptions()); err != nil {
		return nil, err
	}
	return Decode(listJSON)
}

// publicGoodOptions are the requirements for a bundle from Sigstore's
// public-good instance, as GitHub's actions/attest makes for a public
// repository: a Fulcio certificate with an SCT, a transparency-log entry, and
// a timestamp from the log or a timestamp authority.
func publicGoodOptions() []verify.VerifierOption {
	return []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
}

// verifySigned checks that entity signs listJSON under options and comes
// from the compiled-in signer. It makes no network requests.
func verifySigned(entity verify.SignedEntity, trusted root.TrustedMaterial, listJSON []byte, options []verify.VerifierOption) error {
	verifier, err := verify.NewVerifier(trusted, options...)
	if err != nil {
		return fmt.Errorf("sigstore verifier: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(SignerIssuer, "", "", SignerSANPattern)
	if err != nil {
		return fmt.Errorf("allowlist signer identity: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(listJSON)), verify.WithCertificateIdentity(identity))
	if _, err := verifier.Verify(entity, policy); err != nil {
		return fmt.Errorf("allowlist signature: %w", err)
	}
	return nil
}
