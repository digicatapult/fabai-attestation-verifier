package amd

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/tinfoilsh/go-sev-guest/kds"
	"github.com/tinfoilsh/go-sev-guest/verify"
	"github.com/tinfoilsh/go-sev-guest/verify/trust"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// ErrOffline is returned by OfflineGetter for every URL it doesn't serve.
var ErrOffline = errors.New("the seal check makes no network requests")

// OfflineGetter answers go-sev-guest's HTTPS requests without a network: the
// product's KDS CRL URL gets the CRL from the document's collateral, and
// every other request fails (design D1).
type OfflineGetter struct {
	CRLURL string
	CRLDER []byte
}

// Get implements trust.HTTPSGetter.
func (g OfflineGetter) Get(url string) ([]byte, error) {
	if url == g.CRLURL && len(g.CRLDER) > 0 {
		return bytes.Clone(g.CRLDER), nil
	}
	return nil, fmt.Errorf("%w: refused %s", ErrOffline, url)
}

// GetContext implements trust.ContextHTTPSGetter.
func (g OfflineGetter) GetContext(_ context.Context, url string) ([]byte, error) {
	return g.Get(url)
}

// CRLURL returns the KDS CRL URL for the VCEK chain of product.
func CRLURL(product string) string {
	return kds.CrlLinkByRole(product, "ASK")
}

// checkCRL authenticates the collateral's CRL against the pinned ARK, checks
// that it's current at now, and that it lists neither the ASK nor the VCEK.
// It then hands the CRL to go-sev-guest through OfflineGetter, so the
// library's own ARK-signature and ASK-revocation checks run too.
func checkCRL(ctx context.Context, product string, crlDER []byte, ark, ask, vcek *x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	if len(crlDER) == 0 {
		return nil, reason.Errorf(reason.CRLMissing, "collateral has no amd-crl/v1 entry for subject cpu")
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, reason.Errorf(reason.CRLMissing, "collateral CRL doesn't parse: %v", err)
	}
	if !bytes.Equal(crl.RawIssuer, ark.RawSubject) {
		return nil, reason.Errorf(reason.ChainInvalid, "CRL issuer isn't the pinned %s ARK", product)
	}
	if err := crl.CheckSignatureFrom(ark); err != nil {
		return nil, reason.Errorf(reason.ChainInvalid, "CRL isn't signed by the pinned %s ARK: %v", product, err)
	}
	if crl.NextUpdate.IsZero() {
		return nil, reason.Errorf(reason.CRLExpired, "CRL has no nextUpdate")
	}
	if now.Before(crl.ThisUpdate) {
		return nil, reason.Errorf(reason.CRLExpired, "CRL thisUpdate %s is after the check time", crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if !now.Before(crl.NextUpdate) {
		return nil, reason.Errorf(reason.CRLExpired, "CRL expired at its nextUpdate %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(ask.SerialNumber) == 0 {
			return nil, reason.Errorf(reason.Revoked, "CRL revokes the ASK (serial %x)", ask.SerialNumber)
		}
		if entry.SerialNumber.Cmp(vcek.SerialNumber) == 0 {
			return nil, reason.Errorf(reason.Revoked, "CRL revokes the VCEK (serial %x)", vcek.SerialNumber)
		}
	}

	roots := &trust.AMDRootCerts{ProductLine: product, ProductCerts: &trust.ProductCerts{Ask: ask, Ark: ark}}
	getter := OfflineGetter{CRLURL: CRLURL(product), CRLDER: crlDER}
	if _, err := verify.GetCrlAndCheckRootContext(ctx, roots, &verify.Options{Getter: getter, Now: now}); err != nil {
		var unavailable verify.CRLUnavailableErr
		if errors.As(err, &unavailable) {
			return nil, reason.Errorf(reason.ChainInvalid, "ASK's CRL distribution point isn't %s: %v", getter.CRLURL, err)
		}
		return nil, reason.Errorf(reason.ChainInvalid, "go-sev-guest CRL check: %v", err)
	}
	return crl, nil
}
