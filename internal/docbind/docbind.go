// Package docbind is the one adapter over tinfoil-go's verify/document
// (design D1). It parses a v3 document strictly, checks the challenge
// against the caller's nonce, recomputes REPORT_DATA, and selects the
// channel keys and the AMD collateral. Nothing it returns is authenticated:
// the SNP report must still prove that the hardware bound ReportData.
package docbind

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// SNPReportSize is the size of a raw SEV-SNP attestation report.
const SNPReportSize = 1184

// Format URIs the verifier accepts or uses.
const (
	AttestationV3Format       = document.AttestationV3Format
	SEVSNPReportV1Format      = document.SEVSNPReportV1Format
	NvidiaGPUEvidenceV1Format = document.NvidiaGPUEvidenceV1Format
	KeyX25519HPKEV1Format     = document.KeyX25519HPKEV1Format
	KeySPKIFPSHA256V1Format   = document.KeySPKIFPSHA256V1Format
	CollateralFormatV2        = collateral.FormatV2
)

// Channel key ids.
const (
	KeyIDHPKE = document.CryptoMaterialIDHPKE
	KeyIDTLS  = document.CryptoMaterialIDTLS
)

// Bound is a parsed document whose challenge matched the caller's nonce.
type Bound struct {
	doc *document.Document
	// Nonce is the caller's nonce.
	Nonce []byte
	// Report is the raw 1184-byte SNP report, not yet authenticated.
	Report []byte
	// ReportData is the REPORT_DATA the report must carry.
	ReportData [64]byte
}

// DeviceItem is one device_evidence item.
type DeviceItem struct {
	ID       string
	Kind     string
	Vendor   string
	Format   string
	Evidence []byte
}

// Parse parses docBytes strictly against nonce and requires SEV-SNP evidence
// and v2 (or absent) collateral. Errors carry parse_failed, nonce_mismatch or
// report_data_mismatch.
func Parse(docBytes, nonce []byte) (*Bound, error) {
	if len(nonce) != document.NonceSize {
		return nil, reason.Errorf(reason.InternalError, "nonce must be %d bytes, got %d", document.NonceSize, len(nonce))
	}
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, reason.Wrap(classifyParseFailure(docBytes, nonce), err)
	}
	evidence := doc.CPUEvidence()
	if evidence.Format != document.SEVSNPReportV1Format {
		return nil, reason.Errorf(reason.ParseFailed, "cpu_evidence.format %q isn't SEV-SNP", evidence.Format)
	}
	if len(evidence.Report) != SNPReportSize {
		return nil, reason.Errorf(reason.ParseFailed, "SNP report is %d bytes, want %d", len(evidence.Report), SNPReportSize)
	}
	if doc.CollateralFormat() != collateral.FormatV2 {
		return nil, reason.Errorf(reason.ParseFailed, "collateral_format %q isn't v2", doc.CollateralFormat())
	}
	reportData, ok := doc.ExpectedReportData()
	if !ok {
		return nil, reason.Errorf(reason.InternalError, "parsed document has no REPORT_DATA")
	}
	return &Bound{doc: doc, Nonce: bytes.Clone(nonce), Report: evidence.Report, ReportData: reportData}, nil
}

// wireShape is a lenient view of the fields the challenge binds, used only to
// name the reason after document.Parse has already refused the document.
type wireShape struct {
	Challenge struct {
		Nonce      string `json:"nonce"`
		ReportData string `json:"report_data"`
	} `json:"challenge"`
	CPUEvidence struct {
		Endorsed struct {
			CryptoMaterialHash string `json:"crypto_material_hash"`
			DeviceEvidenceHash string `json:"device_evidence_hash"`
		} `json:"endorsed"`
	} `json:"cpu_evidence"`
	CryptoMaterial string `json:"crypto_material"`
	DeviceEvidence string `json:"device_evidence"`
}

// classifyParseFailure names why document.Parse refused docBytes. It never
// accepts anything: a document is accepted only when document.Parse succeeds.
// A different nonce is nonce_mismatch, sections or REPORT_DATA that disagree
// with their declared hashes are report_data_mismatch, and anything else is
// parse_failed.
func classifyParseFailure(docBytes, nonce []byte) reason.Code {
	var w wireShape
	if err := json.Unmarshal(docBytes, &w); err != nil {
		return reason.ParseFailed
	}
	if isLowerHex(w.Challenge.Nonce, 32) && w.Challenge.Nonce != hex.EncodeToString(nonce) {
		return reason.NonceMismatch
	}
	cryptoBytes, err1 := base64.StdEncoding.DecodeString(w.CryptoMaterial)
	deviceBytes, err2 := base64.StdEncoding.DecodeString(w.DeviceEvidence)
	if err1 != nil || err2 != nil {
		return reason.ParseFailed
	}
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	if isLowerHex(w.CPUEvidence.Endorsed.CryptoMaterialHash, 32) && w.CPUEvidence.Endorsed.CryptoMaterialHash != hex.EncodeToString(cryptoHash[:]) {
		return reason.ReportDataMismatch
	}
	if isLowerHex(w.CPUEvidence.Endorsed.DeviceEvidenceHash, 32) && w.CPUEvidence.Endorsed.DeviceEvidenceHash != hex.EncodeToString(deviceHash[:]) {
		return reason.ReportDataMismatch
	}
	reportData, err := document.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	if err == nil && isLowerHex(w.Challenge.ReportData, 64) && w.Challenge.ReportData != hex.EncodeToString(reportData[:]) {
		return reason.ReportDataMismatch
	}
	return reason.ParseFailed
}

func isLowerHex(s string, size int) bool {
	if len(s) != 2*size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ChannelKey returns the decoded crypto_material item with both id and
// format, or an error carrying channel_key_missing.
func (b *Bound) ChannelKey(id, format string) ([]byte, error) {
	item, ok := b.doc.CryptoMaterialItem(id)
	if !ok {
		return nil, reason.Errorf(reason.ChannelKeyMissing, "crypto_material has no %q item", id)
	}
	if item.Format != format {
		return nil, reason.Errorf(reason.ChannelKeyMissing, "crypto_material item %q has format %q, want %q", id, item.Format, format)
	}
	key, err := hex.DecodeString(item.Data)
	if err != nil {
		return nil, reason.Errorf(reason.ChannelKeyMissing, "crypto_material item %q: %v", id, err)
	}
	return key, nil
}

// HPKEKey returns the attested 32-byte X25519 HPKE key.
func (b *Bound) HPKEKey() ([]byte, error) {
	return b.ChannelKey(KeyIDHPKE, KeyX25519HPKEV1Format)
}

// TLSPin returns the attested SHA-256 of the TLS leaf's SubjectPublicKeyInfo.
func (b *Bound) TLSPin() ([]byte, error) {
	return b.ChannelKey(KeyIDTLS, KeySPKIFPSHA256V1Format)
}

// KeyIDs returns the crypto_material item ids, for the experts view.
func (b *Bound) KeyIDs() []string {
	items := b.doc.CryptoMaterialItems()
	ids := make([]string, len(items))
	for i, item := range items {
		ids[i] = item.ID
	}
	return ids
}

// DeviceItems returns the device_evidence items.
func (b *Bound) DeviceItems() []DeviceItem {
	items := b.doc.DeviceEvidenceItems()
	out := make([]DeviceItem, len(items))
	for i, item := range items {
		out[i] = DeviceItem{ID: item.ID, Kind: item.Kind, Vendor: item.Vendor, Format: item.Format, Evidence: []byte(item.Evidence)}
	}
	return out
}

// AMDCollateral is the untrusted AMD material from the document.
type AMDCollateral struct {
	// VCEKDER is the VCEK certificate, DER.
	VCEKDER []byte
	// ChainPEM holds the ASK, then the ARK.
	ChainPEM []byte
	// CRLDER is the product CRL, DER. Nil if the document carries none.
	CRLDER []byte
}

// AMDCollateral returns the amd-vcek/v1 entry for subject "cpu" and the
// amd-crl/v1 entry. Every other entry is ignored. A missing VCEK entry is
// collateral_missing; a missing CRL is reported by the caller as crl_missing.
func (b *Bound) AMDCollateral() (AMDCollateral, error) {
	en := b.doc.CPUEndorsements()
	if en.AMDVCEK == nil {
		return AMDCollateral{}, reason.Errorf(reason.CollateralMissing, "collateral has no %s entry for subject %q", collateral.AMDVCEKV1Format, collateral.SubjectCPU)
	}
	out := AMDCollateral{VCEKDER: en.AMDVCEK.VCEKDER, ChainPEM: []byte(en.AMDVCEK.CertChainPEM)}
	if en.AMDCRL != nil {
		out.CRLDER = en.AMDCRL.CRLDER
	}
	return out, nil
}
