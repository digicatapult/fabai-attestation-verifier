//go:build sealtest && !js

// Package sealtest serves synthetic attestation documents, for testing a
// gateway, a client that seals requests, or a collateral service against the
// seal check without SEV-SNP hardware.
//
// The documents chain to a synthetic AMD root, not one of AMD's, and match a
// synthetic allowlist. The package exists only in builds with the sealtest
// tag, so release builds can't import it.
package sealtest

import (
	"encoding/json/v2"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
	"github.com/digicatapult/fabai-attestation-verifier/seal"
)

// Replica builds v3 attestation documents for any nonce, as a stand-in for
// a cvmimage replica's attestation endpoint. Its CRL is valid for a day from
// NewReplica.
type Replica struct {
	live *synth.Live
}

// NewReplica returns a Replica whose documents carry hpkeKey, a 32-byte
// X25519 public key, as their HPKE key. A test server that holds the matching
// private key can then open requests sealed to it.
func NewReplica(hpkeKey []byte) (*Replica, error) {
	if len(hpkeKey) != 32 {
		return nil, fmt.Errorf("HPKE key is %d bytes, want 32", len(hpkeKey))
	}
	live, err := synth.NewLiveWithHPKEKey([32]byte(hpkeKey))
	if err != nil {
		return nil, err
	}
	return &Replica{live: live}, nil
}

// Approved returns a document that passes all three ticks: the Protected VM.
func (r *Replica) Approved(nonce []byte) ([]byte, error) { return r.live.Approved(nonce) }

// Modified returns a document from genuine hardware whose measurement is on
// no allowlist entry and which has no GPU: the Modified VM. Its hardware tick
// passes, its software tick fails, and its GPU tick isn't checked.
func (r *Replica) Modified(nonce []byte) ([]byte, error) { return r.live.Modified(nonce) }

// ApprovedWithCollateral is Approved, with collateralJSON, a JSON array of
// collateral entries such as a collateral service returns, in place of the
// replica's own VCEK and CRL entries.
func (r *Replica) ApprovedWithCollateral(nonce, collateralJSON []byte) ([]byte, error) {
	var entries []collateral.Entry
	if err := json.Unmarshal(collateralJSON, &entries); err != nil {
		return nil, fmt.Errorf("collateral entries: %w", err)
	}
	return r.live.ApprovedWithCollateral(nonce, entries)
}

// TrustRoots makes the seal check trust the replica's synthetic root in place
// of the pinned AMD roots, in the whole process, until restore is called. It
// isn't safe to call while a check is running.
func (r *Replica) TrustRoots() (restore func()) { return amd.SealtestSetRoots(r.live.Roots()) }

// Checker returns a Checker for the synthetic allowlist, without its Sigstore
// check. Its checks pass only while TrustRoots is in effect.
func Checker(opts seal.Options) *seal.Checker {
	return seal.SealtestNewChecker(synth.Allowlist(), true, opts)
}

// ChipID is the CHIP_ID the replica's reports carry, and its VCEK is for.
func (r *Replica) ChipID() []byte { return r.live.ChipID() }

// ReportedTCB is the REPORTED_TCB the replica's reports carry, and its VCEK
// is for.
func (r *Replica) ReportedTCB() uint64 { return r.live.ReportedTCB() }

// VCEK is the VCEK that signs the replica's reports, DER-encoded.
func (r *Replica) VCEK() []byte { return r.live.VCEKDER() }

// CertChainPEM is the synthetic ASK and then ARK, PEM-encoded, as AMD KDS
// serves a product's cert_chain.
func (r *Replica) CertChainPEM() []byte { return r.live.CertChainPEM() }

// ARKPEM is the synthetic root, PEM-encoded.
func (r *Replica) ARKPEM() []byte { return r.live.ARKPEM() }

// CRL is the synthetic root's CRL, DER-encoded.
func (r *Replica) CRL() []byte { return r.live.CRLDER() }
