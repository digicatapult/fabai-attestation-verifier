package seal

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/internal/gpu"
)

// GPUNote says what the first-version GPU tick does and doesn't prove
// (design D5).
const GPUNote = "GPU evidence is bound to this report and checked for count, architecture and nonce. The GPU's own signature isn't checked yet."

// Detail is the experts view. Fields are filled as far as the check got.
type Detail struct {
	// Nonce is the challenge, lowercase hex.
	Nonce string `json:"nonce,omitempty"`
	// URL is the document request, empty for an offline check.
	URL    string        `json:"url,omitempty"`
	Report *ReportDetail `json:"report,omitempty"`
	Chain  []CertDetail  `json:"chain,omitempty"`
	CRL    *CRLDetail    `json:"crl,omitempty"`
	// Entry is the matched allowlist entry, or the nearest one on failure.
	Entry        string `json:"entry,omitempty"`
	EntryMatched bool   `json:"entryMatched"`
	// KeyIDs are the crypto_material item ids.
	KeyIDs  []string      `json:"keyIds,omitempty"`
	GPU     []gpu.Summary `json:"gpu,omitempty"`
	GPUNote string        `json:"gpuNote"`
	// Errors holds the technical cause of each failed tick.
	Errors []string `json:"errors,omitempty"`
}

// ReportDetail is the SNP report's fields, whether or not it authenticated.
type ReportDetail struct {
	Version     uint32       `json:"version"`
	Product     string       `json:"product,omitempty"`
	Measurement string       `json:"measurement"`
	Policy      PolicyDetail `json:"policy"`
	ReportedTCB string       `json:"reportedTcb"`
	TCB         *amd.TCB     `json:"tcb,omitempty"`
	ChipID      string       `json:"chipId"`
	HostData    string       `json:"hostData"`
	ReportData  string       `json:"reportData"`
	VMPL        uint32       `json:"vmpl"`
}

// PolicyDetail is the guest policy, raw and decoded.
type PolicyDetail struct {
	Raw          string `json:"raw"`
	DebugAccess  string `json:"debugAccess"`
	Debug        bool   `json:"debug"`
	MigrateMA    bool   `json:"migrateMA"`
	SMT          bool   `json:"smt"`
	SingleSocket bool   `json:"singleSocket"`
	ABI          string `json:"abi"`
}

// CertDetail is one certificate of the AMD chain.
type CertDetail struct {
	Role      string    `json:"role"`
	Subject   string    `json:"subject"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

// CRLDetail is the AMD CRL from the collateral.
type CRLDetail struct {
	Issuer     string    `json:"issuer"`
	ThisUpdate time.Time `json:"thisUpdate"`
	NextUpdate time.Time `json:"nextUpdate"`
	Revoked    int       `json:"revoked"`
}

func reportDetail(r *amd.Report) *ReportDetail {
	p := r.Proto
	d := &ReportDetail{
		Version:     p.GetVersion(),
		Product:     r.Product,
		Measurement: hex.EncodeToString(p.GetMeasurement()),
		ReportedTCB: fmt.Sprintf("%#016x", p.GetReportedTcb()),
		TCB:         r.ReportedTCB,
		ChipID:      hex.EncodeToString(p.GetChipId()),
		HostData:    hex.EncodeToString(p.GetHostData()),
		ReportData:  hex.EncodeToString(p.GetReportData()),
		VMPL:        p.GetVmpl(),
		Policy:      PolicyDetail{Raw: fmt.Sprintf("%#x", p.GetPolicy())},
	}
	if policy, err := abi.ParseSnpPolicy(p.GetPolicy()); err == nil {
		d.Policy.Debug = policy.Debug
		d.Policy.MigrateMA = policy.MigrateMA
		d.Policy.SMT = policy.SMT
		d.Policy.SingleSocket = policy.SingleSocket
		d.Policy.ABI = fmt.Sprintf("%d.%d", policy.ABIMajor, policy.ABIMinor)
	}
	d.Policy.DebugAccess = "Administrator debug access: off"
	if d.Policy.Debug {
		d.Policy.DebugAccess = "Administrator debug access: on"
	}
	return d
}

func chainDetail(chain *amd.Chain) ([]CertDetail, *CRLDetail) {
	var certs []CertDetail
	for _, c := range []struct {
		role string
		cert *x509.Certificate
	}{{"VCEK", chain.VCEK}, {"ASK", chain.ASK}, {"ARK", chain.ARK}} {
		if c.cert == nil {
			continue
		}
		certs = append(certs, CertDetail{
			Role:      c.role,
			Subject:   c.cert.Subject.String(),
			Serial:    c.cert.SerialNumber.Text(16),
			NotBefore: c.cert.NotBefore.UTC(),
			NotAfter:  c.cert.NotAfter.UTC(),
		})
	}
	var crl *CRLDetail
	if chain.CRL != nil {
		crl = &CRLDetail{
			Issuer:     chain.CRL.Issuer.String(),
			ThisUpdate: chain.CRL.ThisUpdate.UTC(),
			NextUpdate: chain.CRL.NextUpdate.UTC(),
			Revoked:    len(chain.CRL.RevokedCertificateEntries),
		}
	}
	return certs, crl
}
