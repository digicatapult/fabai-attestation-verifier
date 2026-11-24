//go:build sealtest && !js

package synth

import (
	"crypto/x509"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// Live builds documents for any nonce, with a CRL current at the real
// clock, for tests of live checks.
type Live struct {
	chain *Chain
	crl   []byte
	hpke  [32]byte
}

// NewLive builds the good synthetic chain and a CRL valid for a day, with
// documents carrying the synthetic HPKE key.
func NewLive() (*Live, error) { return NewLiveWithHPKEKey(hpkeKey) }

// NewLiveWithHPKEKey is NewLive with documents carrying hpke, for a test
// server that holds the matching private key.
func NewLiveWithHPKEKey(hpke [32]byte) (*Live, error) {
	chain, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(1), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	crl, err := chain.CRL(now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		return nil, err
	}
	return &Live{chain: chain, crl: crl, hpke: hpke}, nil
}

// Roots are the roots to install with amd.SealtestSetRoots.
func (l *Live) Roots() map[string]*x509.Certificate {
	return map[string]*x509.Certificate{Product: l.chain.ARK()}
}

// HPKEKey is the hpke key the documents carry.
func (l *Live) HPKEKey() []byte { return l.hpke[:] }

// ChipID is the chip the VCEK is for, as a report's CHIP_ID.
func (l *Live) ChipID() []byte {
	id := hwid(1)
	return id[:]
}

// ReportedTCB is the TCB the VCEK is for, as a report's REPORTED_TCB.
func (l *Live) ReportedTCB() uint64 { return goodTCB.Uint64() }

// VCEKDER is the chain's VCEK, DER-encoded.
func (l *Live) VCEKDER() []byte { return l.chain.VCEKDER() }

// CertChainPEM is the ASK and then the ARK, PEM-encoded.
func (l *Live) CertChainPEM() []byte { return l.chain.CertChainPEM() }

// ARKPEM is the chain's root, PEM-encoded.
func (l *Live) ARKPEM() []byte { return []byte(l.chain.ARKPEM()) }

// CRLDER is the CRL the documents carry, DER-encoded.
func (l *Live) CRLDER() []byte { return l.crl }

// Approved is the Protected VM's document for nonce.
func (l *Live) Approved(nonce []byte) ([]byte, error) {
	return l.ApprovedWithCollateral(nonce, l.collateral())
}

// ApprovedWithCollateral is Approved with the given collateral in place of
// the chain's own VCEK and CRL entries.
func (l *Live) ApprovedWithCollateral(nonce []byte, entries []collateral.Entry) ([]byte, error) {
	return l.chain.Document(l.input(nonce, true, entries), l.report(protectedMeasurement), QuoteOptions{})
}

// Modified is the Modified VM's document for nonce: genuine hardware, a
// measurement on no entry, and no GPU.
func (l *Live) Modified(nonce []byte) ([]byte, error) {
	return l.chain.Document(l.input(nonce, false, l.collateral()), l.report(modifiedMeasurement), QuoteOptions{})
}

func (l *Live) collateral() []collateral.Entry {
	return []collateral.Entry{l.chain.VCEKEntry(), CRLEntry(l.crl)}
}

func (l *Live) report(measurement [48]byte) Report {
	return Report{Measurement: measurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)}
}

func (l *Live) input(nonce []byte, withGPU bool, entries []collateral.Entry) document.BuildInput {
	in := document.BuildInput{
		Nonce:          nonce,
		CryptoMaterial: keysWith(l.hpke),
		DeviceEvidence: []document.DeviceEvidenceItem{},
		Collateral:     entries,
	}
	if withGPU {
		in.DeviceEvidence = []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonce)}
	}
	return in
}
