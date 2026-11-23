package amd

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// The AMD root keys (ARK), fetched from KDS /vcek/v1/<product>/cert_chain
// on 2026-11-23 and byte-equal to go-sev-guest's embedded copies. They are
// the only roots the verifier trusts (design D2); nothing at run time can add
// or replace one.
var (
	//go:embed roots/ark_milan.pem
	arkMilanPEM []byte
	//go:embed roots/ark_genoa.pem
	arkGenoaPEM []byte
	//go:embed roots/ark_turin.pem
	arkTurinPEM []byte
)

// Product lines, as go-sev-guest names them.
const (
	Milan = "Milan"
	Genoa = "Genoa"
	Turin = "Turin"
)

// pinnedARKSHA256 holds the SHA-256 of each ARK's DER encoding.
var pinnedARKSHA256 = map[string]string{
	Milan: "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
	Genoa: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
	Turin: "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
}

// pinnedRoots maps product line to its ARK. It is replaced only by the
// sealtest build's test hook.
var pinnedRoots = mustLoadRoots()

func mustLoadRoots() map[string]*x509.Certificate {
	roots := make(map[string]*x509.Certificate, 3)
	for product, pemBytes := range map[string][]byte{Milan: arkMilanPEM, Genoa: arkGenoaPEM, Turin: arkTurinPEM} {
		cert, err := parsePinnedARK(product, pemBytes)
		if err != nil {
			panic(err)
		}
		roots[product] = cert
	}
	return roots
}

func parsePinnedARK(product string, pemBytes []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("pinned ARK for %s isn't one PEM certificate", product)
	}
	digest := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(digest[:]) != pinnedARKSHA256[product] {
		return nil, fmt.Errorf("pinned ARK for %s has SHA-256 %x, want %s", product, digest, pinnedARKSHA256[product])
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pinned ARK for %s: %w", product, err)
	}
	if cert.Subject.CommonName != "ARK-"+product {
		return nil, fmt.Errorf("pinned ARK for %s has subject %q", product, cert.Subject.CommonName)
	}
	return cert, nil
}

// PinnedARK returns the pinned root for product, if there is one.
func PinnedARK(product string) (*x509.Certificate, bool) {
	cert, ok := pinnedRoots[product]
	return cert, ok
}
