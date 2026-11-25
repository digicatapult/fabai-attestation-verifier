//go:build sealtest && !js

package sealtest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"github.com/digicatapult/fabai-attestation-verifier/internal/fetch"
	"github.com/digicatapult/fabai-attestation-verifier/seal"
	"github.com/digicatapult/fabai-attestation-verifier/sealtest"
)

var hpkeKey = bytes.Repeat([]byte{0x42}, 32)

func newReplica(t *testing.T) *sealtest.Replica {
	t.Helper()
	r, err := sealtest.NewReplica(hpkeKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.TrustRoots())
	return r
}

// serve answers document requests with build's document for the request's
// nonce.
func serve(t *testing.T, build func(nonce []byte) ([]byte, error)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		nonce, err := hex.DecodeString(req.URL.Query().Get("nonce"))
		if err != nil || req.URL.Path != fetch.WellKnownPath {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		doc, err := build(nonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func check(t *testing.T, build func(nonce []byte) ([]byte, error)) *seal.Result {
	t.Helper()
	return sealtest.Checker(seal.Options{}).Check(context.Background(), seal.Target{BaseURL: serve(t, build)})
}

func TestApproved(t *testing.T) {
	r := newReplica(t)
	result := check(t, r.Approved)
	key, ok := result.SendKey()
	if !result.Permitted || !ok || !bytes.Equal(key, hpkeKey) {
		t.Fatalf("permitted %v, key %x: %+v", result.Permitted, key, result.Ticks)
	}
}

func TestModified(t *testing.T) {
	r := newReplica(t)
	result := check(t, r.Modified)
	if result.Permitted || result.Ticks.Hardware.Status != seal.Pass || result.Ticks.Software.Status != seal.Fail {
		t.Fatalf("permitted %v: %+v", result.Permitted, result.Ticks)
	}
}

func TestApprovedWithCollateral(t *testing.T) {
	r := newReplica(t)
	entry := func(id, format string, data map[string]string) collateral.Entry {
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		return collateral.Entry{ID: id, Role: collateral.RoleEndorsement, Format: format, Subjects: []string{collateral.SubjectCPU}, Data: raw}
	}
	vcek := entry("amd-vcek", collateral.AMDVCEKV1Format, map[string]string{
		"vcek_der_base64": base64.StdEncoding.EncodeToString(r.VCEK()),
		"cert_chain_pem":  string(r.CertChainPEM()),
	})
	crl := entry("amd-crl", collateral.AMDCRLV1Format, map[string]string{
		"crl_der_base64": base64.StdEncoding.EncodeToString(r.CRL()),
	})
	for _, tc := range []struct {
		name    string
		entries []collateral.Entry
		want    seal.Status
	}{
		{"VCEK and CRL", []collateral.Entry{vcek, crl}, seal.Pass},
		{"no CRL", []collateral.Entry{vcek}, seal.Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := json.Marshal(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			result := check(t, func(nonce []byte) ([]byte, error) { return r.ApprovedWithCollateral(nonce, entries) })
			if result.Ticks.Hardware.Status != tc.want {
				t.Fatalf("hardware tick %+v, want %s", result.Ticks.Hardware, tc.want)
			}
		})
	}
}

func TestUntrustedRoot(t *testing.T) {
	r, err := sealtest.NewReplica(hpkeKey)
	if err != nil {
		t.Fatal(err)
	}
	result := check(t, r.Approved)
	if result.Permitted || result.Ticks.Hardware.Status != seal.Fail {
		t.Fatalf("permitted %v without TrustRoots: %+v", result.Permitted, result.Ticks)
	}
}

func TestHPKEKeyLength(t *testing.T) {
	if _, err := sealtest.NewReplica(hpkeKey[:31]); err == nil {
		t.Error("NewReplica accepted a 31-byte HPKE key")
	}
}
