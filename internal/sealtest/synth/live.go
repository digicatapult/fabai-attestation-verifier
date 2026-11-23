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
}

// NewLive builds the good synthetic chain and a CRL valid for a day.
func NewLive() (*Live, error) {
	chain, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(1), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	crl, err := chain.CRL(now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		return nil, err
	}
	return &Live{chain: chain, crl: crl}, nil
}

// Roots are the roots to install with amd.SealtestSetRoots.
func (l *Live) Roots() map[string]*x509.Certificate {
	return map[string]*x509.Certificate{Product: l.chain.ARK()}
}

// HPKEKey is the hpke key the documents carry.
func (l *Live) HPKEKey() []byte { return hpkeKey[:] }

// Approved is the Protected VM's document for nonce.
func (l *Live) Approved(nonce []byte) ([]byte, error) {
	return l.chain.Document(l.input(nonce, true), Report{
		Measurement: protectedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1),
	}, QuoteOptions{})
}

// Modified is the Modified VM's document for nonce: genuine hardware, a
// measurement on no entry, and no GPU.
func (l *Live) Modified(nonce []byte) ([]byte, error) {
	return l.chain.Document(l.input(nonce, false), Report{
		Measurement: modifiedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1),
	}, QuoteOptions{})
}

func (l *Live) input(nonce []byte, withGPU bool) document.BuildInput {
	in := document.BuildInput{
		Nonce:          nonce,
		CryptoMaterial: keys(),
		DeviceEvidence: []document.DeviceEvidenceItem{},
		Collateral:     []collateral.Entry{l.chain.VCEKEntry(), CRLEntry(l.crl)},
	}
	if withGPU {
		in.DeviceEvidence = []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonce)}
	}
	return in
}
