// Package amd authenticates an SEV-SNP report offline: the report signature,
// VCEK → ASK → pinned ARK, the CRL from the collateral, the VCEK's
// extensions against the report, and the REPORT_DATA binding
// (seal-check "Hardware tick").
package amd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	spb "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"github.com/tinfoilsh/go-sev-guest/verify"
	"github.com/tinfoilsh/go-sev-guest/verify/trust"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// signatureAlgoECDSAP384SHA384 is SIGNATURE_ALGO for ECDSA P-384 with SHA-384.
const signatureAlgoECDSAP384SHA384 = 1

// minReportVersion is the first report version that carries the CPUID
// family, model and stepping, which name the product and its TCB layout.
const minReportVersion = 3

// Input is what Authenticate needs from a parsed document.
type Input struct {
	// Report is the raw 1184-byte report.
	Report []byte
	// ReportData is the REPORT_DATA the document's sections bind.
	ReportData [64]byte
	// VCEKDER, ChainPEM and CRLDER come from the untrusted collateral.
	VCEKDER  []byte
	ChainPEM []byte
	CRLDER   []byte
}

// Report is the parsed report, available whether or not it authenticated.
type Report struct {
	Proto *spb.Report
	// Product is the product line, or "" if the report doesn't name one.
	Product string
	// ReportedTCB is nil if the product's TCB layout is unknown.
	ReportedTCB *TCB
}

// Chain describes the certificates for the experts view.
type Chain struct {
	VCEK, ASK, ARK *x509.Certificate
	CRL            *x509.RevocationList
}

// ParseReport parses a raw report. Errors carry parse_failed.
func ParseReport(raw []byte) (*Report, error) {
	proto, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, reason.Errorf(reason.ParseFailed, "SNP report: %v", err)
	}
	r := &Report{Proto: proto}
	if proto.GetVersion() >= minReportVersion && proto.GetCpuid1EaxFms() != 0 {
		r.Product = kds.ProductLineFromFms(proto.GetCpuid1EaxFms())
		if tcb, err := DecodeTCB(r.Product, proto.GetReportedTcb()); err == nil {
			r.ReportedTCB = &tcb
		}
	}
	return r, nil
}

// Authenticate checks that r was signed by a genuine AMD VCEK that chains to
// a pinned ARK, isn't revoked, matches the report's chip and TCB, and that
// the report binds in.ReportData. The chain is returned as far as it was
// parsed, for the experts view, even on failure.
func Authenticate(ctx context.Context, r *Report, in Input, now time.Time) (*Chain, error) {
	chain := &Chain{}
	proto := r.Proto

	signer, err := abi.ParseSignerInfo(proto.GetSignerInfo())
	if err != nil {
		return chain, reason.Errorf(reason.SignatureInvalid, "SIGNER_INFO: %v", err)
	}
	switch signer.SigningKey {
	case abi.VcekReportSigner:
	case abi.VlekReportSigner:
		return chain, reason.Errorf(reason.VLEKRefused, "the report is signed with a VLEK; only VCEK-signed reports are accepted")
	default:
		return chain, reason.Errorf(reason.SignatureInvalid, "the report's signing key is %v, not the VCEK", signer.SigningKey)
	}
	if proto.GetSignatureAlgo() != signatureAlgoECDSAP384SHA384 {
		return chain, reason.Errorf(reason.SignatureInvalid, "SIGNATURE_ALGO is %d, not ECDSA P-384 with SHA-384", proto.GetSignatureAlgo())
	}
	if r.Product == "" {
		return chain, reason.Errorf(reason.ChainInvalid, "report version %d doesn't name its product", proto.GetVersion())
	}
	ark, ok := PinnedARK(r.Product)
	if !ok {
		return chain, reason.Errorf(reason.ChainInvalid, "no pinned AMD root for product %q", r.Product)
	}
	chain.ARK = ark

	vcek, ask, err := parseCollateralCerts(in)
	chain.VCEK, chain.ASK = vcek, ask
	if err != nil {
		return chain, err
	}
	roots := &trust.AMDRootCerts{ProductLine: r.Product, ProductCerts: &trust.ProductCerts{Ask: ask, Ark: ark}}
	if _, err := vcek.Verify(*roots.X509Options(now, abi.VcekReportSigner)); err != nil {
		return chain, reason.Errorf(reason.ChainInvalid, "VCEK doesn't chain through the ASK to the pinned %s ARK: %v", r.Product, err)
	}
	if err := verify.SnpReportSignature(in.Report, vcek); err != nil {
		return chain, reason.Errorf(reason.SignatureInvalid, "report signature: %v", err)
	}
	attestation := &spb.Attestation{
		Report:           proto,
		CertificateChain: &spb.CertificateChain{VcekCert: vcek.Raw, AskCert: ask.Raw, ArkCert: ark.Raw},
	}
	options := &verify.Options{
		TrustedRoots:        map[string][]*trust.AMDRootCerts{r.Product: {roots}},
		DisableCertFetching: true,
		Getter:              OfflineGetter{},
		Now:                 now,
	}
	if err := verify.SnpAttestationContext(ctx, attestation, options); err != nil {
		return chain, reason.Errorf(reason.ChainInvalid, "go-sev-guest: %v", err)
	}

	crl, err := checkCRL(ctx, r.Product, in.CRLDER, ark, ask, vcek, now)
	chain.CRL = crl
	if err != nil {
		return chain, err
	}
	if err := matchVCEK(r, vcek); err != nil {
		return chain, err
	}
	return chain, checkReportData(proto.GetReportData(), in.ReportData)
}

func parseCollateralCerts(in Input) (vcek, ask *x509.Certificate, err error) {
	if len(in.VCEKDER) == 0 {
		return nil, nil, reason.Errorf(reason.CollateralMissing, "collateral has no VCEK")
	}
	vcek, err = x509.ParseCertificate(in.VCEKDER)
	if err != nil {
		return nil, nil, reason.Errorf(reason.ChainInvalid, "VCEK: %v", err)
	}
	askDER, _, err := kds.ParseProductCertChain(in.ChainPEM)
	if err != nil {
		return vcek, nil, reason.Errorf(reason.CollateralMissing, "collateral cert_chain_pem: %v", err)
	}
	ask, err = x509.ParseCertificate(askDER)
	if err != nil {
		return vcek, nil, reason.Errorf(reason.ChainInvalid, "ASK: %v", err)
	}
	return vcek, ask, nil
}

// matchVCEK requires the VCEK's HWID to equal the report's CHIP_ID (its
// first 8 bytes on Turin) and its TCB to equal REPORTED_TCB exactly. A
// masked (all-zero) CHIP_ID is refused.
func matchVCEK(r *Report, vcek *x509.Certificate) error {
	exts, err := kds.VcekCertificateExtensions(vcek)
	if err != nil {
		return reason.Errorf(reason.VCEKMismatch, "VCEK extensions: %v", err)
	}
	chipID := r.Proto.GetChipId()
	if len(chipID) != abi.ChipIDSize || bytes.Equal(chipID, make([]byte, abi.ChipIDSize)) {
		return reason.Errorf(reason.VCEKMismatch, "the report's CHIP_ID is masked or malformed")
	}
	want := chipID
	if len(exts.HWID) == abi.TurinSiliconIDSize && r.Product == Turin {
		want = chipID[:abi.TurinSiliconIDSize]
	}
	if !bytes.Equal(exts.HWID, want) {
		return reason.Errorf(reason.VCEKMismatch, "VCEK hardware ID %s isn't the report's CHIP_ID %s", hex.EncodeToString(exts.HWID), hex.EncodeToString(want))
	}
	structVersion, err := kds.StructVersionForProductLine(r.Product)
	if err != nil {
		return reason.Errorf(reason.VCEKMismatch, "%v", err)
	}
	if exts.TCBVersion == nil || exts.TCBVersion.StructVersion() != structVersion {
		return reason.Errorf(reason.VCEKMismatch, "VCEK TCB layout doesn't match product %s", r.Product)
	}
	if exts.TCBVersion.Uint64() != r.Proto.GetReportedTcb() {
		return reason.Errorf(reason.VCEKMismatch, "VCEK TCB %#016x isn't the report's REPORTED_TCB %#016x", exts.TCBVersion.Uint64(), r.Proto.GetReportedTcb())
	}
	return nil
}

func checkReportData(got []byte, want [64]byte) error {
	if len(got) != 64 {
		return reason.Errorf(reason.ReportDataMismatch, "REPORT_DATA is %d bytes", len(got))
	}
	if !bytes.Equal(got[32:], make([]byte, 32)) {
		return reason.Errorf(reason.ReportDataMismatch, "REPORT_DATA bytes 32-63 aren't zero")
	}
	if !bytes.Equal(got, want[:]) {
		return reason.Errorf(reason.ReportDataMismatch, "the report's REPORT_DATA isn't the one the document binds")
	}
	return nil
}

// AtLeast checks every REPORTED_TCB component against minimum. Errors carry
// code and name the first component below it.
func (r *Report) AtLeast(minimum TCB, code reason.Code, what string) error {
	if r.ReportedTCB == nil {
		return reason.Errorf(code, "REPORTED_TCB layout unknown for product %q", r.Product)
	}
	if ok, component := r.ReportedTCB.AtLeast(minimum); !ok {
		return reason.Errorf(code, "REPORTED_TCB %s component is below the %s", component, what)
	}
	return nil
}
