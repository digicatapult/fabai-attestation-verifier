//go:build sealtest && !js

// Package synth builds synthetic conformance vectors: a fake ARK, ASK and
// VCEK, SNP reports signed by the fake VCEK, and v3 documents assembled by
// tinfoil-go's document.Build with a quote callback that signs. It exists
// only in builds with the sealtest tag.
package synth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	spb "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	sevtest "github.com/tinfoilsh/go-sev-guest/testing"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Product is the synthetic product line: Turin, the demo CPU.
const Product = "Turin"

// ChainOptions vary the synthetic chain.
type ChainOptions struct {
	// TCB is the VCEK's TCB, which a report must carry as REPORTED_TCB.
	TCB kds.TCBVersionV1
	// HWID is the chip the VCEK is for; its first 8 bytes are the Turin
	// silicon ID.
	HWID [abi.ChipIDSize]byte
	// Keys overrides go-sev-guest's default test keys.
	Keys *sevtest.AmdKeys
	// Created is the chain's creation time.
	Created time.Time
}

// Chain is a synthetic AMD certificate chain and its keys.
type Chain struct {
	signer *sevtest.AmdSigner
	opts   ChainOptions
}

// NewChain builds a Turin ARK, ASK and VCEK (and a VLEK, for the refusal
// vector).
func NewChain(opts ChainOptions) (*Chain, error) {
	keys := opts.Keys
	if keys == nil {
		keys = sevtest.DefaultAmdKeys()
	}
	b := &sevtest.AmdSignerBuilder{
		Keys:             keys,
		ProductName:      "Turin-B0",
		ArkCreationTime:  opts.Created,
		AskCreationTime:  opts.Created,
		AsvkCreationTime: opts.Created,
		VcekCreationTime: opts.Created,
		VlekCreationTime: opts.Created,
		CSPID:            "fabai-sealtest",
		HWID:             opts.HWID,
		TCB:              opts.TCB,
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		return nil, err
	}
	return &Chain{signer: signer, opts: opts}, nil
}

// NewARKKeys returns default test keys with a freshly generated ARK key, for
// a chain to an unknown root.
func NewARKKeys() (*sevtest.AmdKeys, error) {
	ark, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keys := sevtest.DefaultAmdKeys()
	keys.Ark = ark
	return keys, nil
}

// ARK returns the chain's root.
func (c *Chain) ARK() *x509.Certificate { return c.signer.Ark }

// ARKPEM returns the chain's root, PEM-encoded.
func (c *Chain) ARKPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.signer.Ark.Raw}))
}

// ASKSerial is the ASK's serial number.
func (c *Chain) ASKSerial() *big.Int { return c.signer.Ask.SerialNumber }

// VCEKSerial is the VCEK's serial number.
func (c *Chain) VCEKSerial() *big.Int { return c.signer.Vcek.SerialNumber }

// CRL returns a CRL signed by the chain's ARK that lists revoked.
func (c *Chain) CRL(thisUpdate, nextUpdate time.Time, revoked ...*big.Int) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, serial := range revoked {
		entries[i] = x509.RevocationListEntry{SerialNumber: serial, RevocationTime: thisUpdate}
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        x509.SHA384WithRSAPSS,
	}, c.signer.Ark, c.signer.Keys.Ark)
}

// VCEKEntry is the amd-vcek/v1 collateral entry for subject cpu, carrying
// the VCEK and the ASK-then-ARK chain.
func (c *Chain) VCEKEntry() collateral.Entry {
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.signer.Ask.Raw})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.signer.Ark.Raw})...)
	return entry("amd-vcek", collateral.AMDVCEKV1Format, []string{collateral.SubjectCPU}, map[string]string{
		"vcek_der_base64": base64.StdEncoding.EncodeToString(c.signer.Vcek.Raw),
		"cert_chain_pem":  string(chain),
	})
}

// CRLEntry is the amd-crl/v1 collateral entry for subject cpu.
func CRLEntry(crlDER []byte) collateral.Entry {
	return entry("amd-crl", collateral.AMDCRLV1Format, []string{collateral.SubjectCPU}, map[string]string{
		"crl_der_base64": base64.StdEncoding.EncodeToString(crlDER),
	})
}

// SigstoreEntries are Tinfoil's code and platform reference-values entries,
// which the verifier must ignore.
func SigstoreEntries() []collateral.Entry {
	data := map[string]any{"repo": "tinfoilsh/confidential-model-router", "tag": "v0.0.178", "digest": "00", "sigstore_bundle": map[string]string{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}}
	return []collateral.Entry{
		entry("sigstore-code", collateral.SigstoreCodeV1Format, nil, data),
		entry("sigstore-platform", collateral.SigstorePlatformV1Format, nil, data),
	}
}

func entry(id, format string, subjects []string, data any) collateral.Entry {
	raw, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	role := collateral.RoleEndorsement
	if format == collateral.SigstoreCodeV1Format || format == collateral.SigstorePlatformV1Format {
		role = collateral.RoleReferenceValues
	}
	return collateral.Entry{ID: id, Role: role, Format: format, Subjects: subjects, Data: jsontext.Value(raw)}
}

// Report is the content of a synthetic SNP report.
type Report struct {
	Measurement [48]byte
	HostData    [32]byte
	Policy      abi.SnpPolicy
	ReportedTCB uint64
	ChipID      [abi.ChipIDSize]byte
	// VLEK signs with the VLEK instead of the VCEK.
	VLEK bool
}

// Sign builds a version-5 Turin report carrying reportData and signs it.
func (c *Chain) Sign(r Report, reportData [64]byte) ([]byte, error) {
	product := &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN, MachineStepping: wrapperspb.UInt32(0)}
	signerInfo := abi.SignerInfo{SigningKey: abi.VcekReportSigner}
	if r.VLEK {
		signerInfo.SigningKey = abi.VlekReportSigner
	}
	proto := &spb.Report{
		Version:         abi.ReportVersion5,
		GuestSvn:        1,
		Policy:          abi.SnpPolicyToBytes(r.Policy),
		FamilyId:        make([]byte, abi.FamilyIDSize),
		ImageId:         make([]byte, abi.ImageIDSize),
		SignatureAlgo:   abi.SignEcdsaP384Sha384,
		CurrentTcb:      r.ReportedTCB,
		SignerInfo:      abi.ComposeSignerInfo(signerInfo),
		ReportData:      reportData[:],
		Measurement:     r.Measurement[:],
		HostData:        r.HostData[:],
		IdKeyDigest:     make([]byte, abi.IDKeyDigestSize),
		AuthorKeyDigest: make([]byte, abi.AuthorKeyDigestSize),
		ReportId:        make([]byte, abi.ReportIDSize),
		ReportIdMa:      make([]byte, abi.ReportIDMASize),
		ReportedTcb:     r.ReportedTCB,
		Cpuid1EaxFms:    abi.MaskedCpuid1EaxFromSevProduct(product),
		ChipId:          r.ChipID[:],
		CommittedTcb:    r.ReportedTCB,
		LaunchTcb:       r.ReportedTCB,
		CurrentMajor:    1,
		CurrentMinor:    58,
		CommittedMajor:  1,
		CommittedMinor:  58,
		Signature:       make([]byte, abi.SignatureSize),
	}
	raw, err := abi.ReportToAbiBytes(proto)
	if err != nil {
		return nil, err
	}
	rs, ss, err := c.signer.Sign(abi.SignedComponent(raw))
	if err != nil {
		return nil, err
	}
	if err := abi.SetSignature(rs, ss, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// QuoteOptions vary what the quote callback signs.
type QuoteOptions struct {
	// Format overrides the evidence format (for the TDX vector).
	Format string
	// ReportData, if set, is signed instead of the REPORT_DATA Build derived.
	ReportData func([64]byte) [64]byte
	// AfterSigning mutates the signed report (for the corrupted vector).
	AfterSigning func([]byte)
}

// Document builds a v3 document with document.Build, signing the derived
// REPORT_DATA with the chain.
func (c *Chain) Document(in document.BuildInput, r Report, q QuoteOptions) ([]byte, error) {
	return document.Build(in, func(reportData [64]byte) (string, []byte, error) {
		if q.ReportData != nil {
			reportData = q.ReportData(reportData)
		}
		raw, err := c.Sign(r, reportData)
		if err != nil {
			return "", nil, fmt.Errorf("signing synthetic report: %w", err)
		}
		if q.AfterSigning != nil {
			q.AfterSigning(raw)
		}
		format := document.SEVSNPReportV1Format
		if q.Format != "" {
			format = q.Format
		}
		return format, raw, nil
	})
}
