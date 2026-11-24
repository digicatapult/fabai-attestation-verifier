// Package gpu applies the first-version GPU evidence checks
// (attestation-binding "GPU evidence, first version". It doesn't
// verify the GPU's SPDM signature, its NVIDIA certificate chain or its
// measurements: it trusts the measured guest to have collected the evidence.
package gpu

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"

	"github.com/digicatapult/fabai-attestation-verifier/internal/docbind"
	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// Item kinds and vendors the GPU tick accepts.
const (
	KindGPU      = "gpu"
	VendorNVIDIA = "nvidia"
)

// Expectation is what the matched allowlist entry requires.
type Expectation struct {
	Count        int
	Architecture string
}

// Summary describes one GPU item for the experts view.
type Summary struct {
	ID               string `json:"id"`
	Architecture     string `json:"arch,omitempty"`
	CertificateBytes int    `json:"certificateBytes"`
	EvidenceBytes    int    `json:"evidenceBytes"`
}

// evidence is the strict shape of an nvidia-gpu-evidence/v1 payload.
type evidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

// Summarize describes every device item, as far as it decodes, whatever the
// outcome of Check.
func Summarize(items []docbind.DeviceItem) []Summary {
	out := make([]Summary, 0, len(items))
	for _, item := range items {
		s := Summary{ID: item.ID}
		var ev evidence
		if json.Unmarshal(item.Evidence, &ev) == nil {
			s.Architecture = ev.Arch
			if raw, err := base64.StdEncoding.DecodeString(ev.Certificate); err == nil {
				s.CertificateBytes = len(raw)
			}
			if raw, err := base64.StdEncoding.DecodeString(ev.Evidence); err == nil {
				s.EvidenceBytes = len(raw)
			}
		}
		out = append(out, s)
	}
	return out
}

// Check requires exactly want.Count items, every one a gpu from nvidia in
// the v1 evidence format, with non-empty canonical base64 certificate and
// evidence, the expected architecture, and the document's nonce.
func Check(items []docbind.DeviceItem, nonce []byte, want Expectation) error {
	for _, item := range items {
		if item.Kind != KindGPU {
			return reason.Errorf(reason.GPUItem, "device item %q has kind %q; only %q items are allowed", item.ID, item.Kind, KindGPU)
		}
	}
	if len(items) != want.Count {
		return reason.Errorf(reason.GPUCount, "the document has %d GPU items, the entry expects %d", len(items), want.Count)
	}
	wantNonce := hex.EncodeToString(nonce)
	for _, item := range items {
		if item.Vendor != VendorNVIDIA || item.Format != docbind.NvidiaGPUEvidenceV1Format {
			return reason.Errorf(reason.GPUItem, "GPU item %q is vendor %q, format %q", item.ID, item.Vendor, item.Format)
		}
		var ev evidence
		if err := json.Unmarshal(item.Evidence, &ev, json.RejectUnknownMembers(true)); err != nil {
			return reason.Errorf(reason.GPUItem, "GPU item %q evidence: %v", item.ID, err)
		}
		if err := canonicalBase64(ev.Certificate); err != nil {
			return reason.Errorf(reason.GPUItem, "GPU item %q certificate: %v", item.ID, err)
		}
		if err := canonicalBase64(ev.Evidence); err != nil {
			return reason.Errorf(reason.GPUItem, "GPU item %q evidence: %v", item.ID, err)
		}
		if ev.Arch != want.Architecture {
			return reason.Errorf(reason.GPUArch, "GPU item %q architecture is %q, the entry expects %q", item.ID, ev.Arch, want.Architecture)
		}
		if ev.Nonce != wantNonce {
			return reason.Errorf(reason.GPUNonce, "GPU item %q nonce isn't the document's nonce", item.ID)
		}
	}
	return nil
}

func canonicalBase64(s string) error {
	if s == "" {
		return fmt.Errorf("is empty")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return err
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return fmt.Errorf("isn't canonical base64")
	}
	return nil
}
