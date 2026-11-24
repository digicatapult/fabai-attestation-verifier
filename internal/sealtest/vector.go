//go:build sealtest

package sealtest

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/seal"
)

// Vector is one conformance vector. The Go and WASM builds read the same files.
type Vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Scenario names the spec scenario it covers, as "<spec>: <scenario>".
	Scenario []string `json:"scenario,omitempty"`
	// Source is "synthetic" or "captured".
	Source string `json:"source"`
	// Capture records where a captured document came from.
	Capture *Capture `json:"capture,omitempty"`
	// Roots, if set, replace the pinned AMD roots (product line to ARK PEM).
	// Absent for captured vectors, which use the pinned roots.
	Roots map[string]string `json:"roots,omitempty"`
	// Document holds the exact document bytes, base64 in the file.
	Document []byte `json:"document"`
	// Nonce is the nonce the check uses, lowercase hex.
	Nonce string `json:"nonce"`
	// Allowlist is the list the check uses; AllowlistVerified says whether
	// it counts as having passed its signature check.
	Allowlist         jsontext.Value `json:"allowlist"`
	AllowlistVerified bool           `json:"allowlistVerified"`
	// CheckTime is the fixed check time.
	CheckTime time.Time `json:"checkTime"`
	// Channel is "hpke" (default) or "tls".
	Channel string  `json:"channel,omitempty"`
	Expect  Outcome `json:"expect"`
}

// Capture is a captured document's provenance.
type Capture struct {
	URL             string    `json:"url"`
	CapturedAt      time.Time `json:"capturedAt"`
	CVMImageVersion string    `json:"cvmimageVersion"`
	CRLAppended     bool      `json:"crlAppended"`
	Notes           string    `json:"notes,omitempty"`
}

// Outcome is what a vector expects, and what a run gave.
type Outcome struct {
	Hardware  TickOutcome `json:"hardware"`
	Software  TickOutcome `json:"software"`
	GPU       TickOutcome `json:"gpu"`
	Permitted bool        `json:"permitted"`
	EntryID   string      `json:"entryId,omitempty"`
}

// TickOutcome is one tick's status and reason.
type TickOutcome struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// OutcomeOf reduces a result to what vectors compare.
func OutcomeOf(r *seal.Result) Outcome {
	tick := func(t seal.Tick) TickOutcome { return TickOutcome{Status: string(t.Status), Reason: string(t.Reason)} }
	return Outcome{
		Hardware:  tick(r.Ticks.Hardware),
		Software:  tick(r.Ticks.Software),
		GPU:       tick(r.Ticks.GPU),
		Permitted: r.Permitted,
		EntryID:   r.EntryID,
	}
}

// Load reads every *.json vector in dir, sorted by file name.
func Load(dir string) ([]*Vector, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	vectors := make([]*Vector, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		v, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		vectors = append(vectors, v)
	}
	return vectors, nil
}

// Parse decodes one vector strictly.
func Parse(data []byte) (*Vector, error) {
	var v Vector
	if err := json.Unmarshal(data, &v, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return &v, nil
}

// Marshal encodes a vector for its file.
func (v *Vector) Marshal() ([]byte, error) {
	data, err := json.Marshal(v, jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Run checks the vector's document with its roots, allowlist and clock, and
// returns the full result.
func (v *Vector) Run(ctx context.Context) (*seal.Result, error) {
	nonce, err := hex.DecodeString(v.Nonce)
	if err != nil {
		return nil, fmt.Errorf("vector nonce: %w", err)
	}
	if v.Roots != nil {
		roots := make(map[string]*x509.Certificate, len(v.Roots))
		for product, pemText := range v.Roots {
			block, _ := pem.Decode([]byte(pemText))
			if block == nil {
				return nil, fmt.Errorf("vector root for %s isn't PEM", product)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("vector root for %s: %w", product, err)
			}
			roots[product] = cert
		}
		defer amd.SealtestSetRoots(roots)()
	}
	opts := seal.Options{}
	switch v.Channel {
	case "", "hpke":
	case "tls":
		opts.Channel = seal.ChannelTLS
	default:
		return nil, fmt.Errorf("vector channel %q", v.Channel)
	}
	checker := seal.SealtestNewChecker(v.Allowlist, v.AllowlistVerified, opts)
	return checker.SealtestCheckDocumentAt(ctx, v.Document, nonce, v.CheckTime), nil
}
