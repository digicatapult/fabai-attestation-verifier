// Package fetch requests a v3 attestation document for a fresh nonce
// (attestation-binding: "Fresh nonce for every check", "Document request").
package fetch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

const (
	// NonceSize is the challenge nonce size in bytes.
	NonceSize = 32
	// WellKnownPath is the v3 document endpoint on a replica, and on the
	// gateway's attestation relay.
	WellKnownPath = "/.well-known/tinfoil-attestation/v3"
	// MaxDocumentBytes caps the response body. A v3 document with one GPU's
	// evidence and the AMD collateral is tens of kilobytes.
	MaxDocumentBytes = 1 << 20
)

// NewNonce returns 32 bytes from the operating system's CSPRNG.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, nil
}

// Target is where the document is requested from.
type Target struct {
	// BaseURL is the replica's or gateway's origin, http or https, with an
	// optional path prefix and no query, fragment or user info.
	BaseURL string
	// Enclave is the replica host the gateway relays to. Empty when talking
	// to a replica directly.
	Enclave string
}

// URL returns the document URL for nonce.
func (t Target) URL(nonce []byte) (string, error) {
	if len(nonce) != NonceSize {
		return "", fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	base, err := url.Parse(t.BaseURL)
	if err != nil {
		return "", fmt.Errorf("base URL: %w", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return "", fmt.Errorf("base URL scheme %q isn't http or https", base.Scheme)
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" {
		return "", errors.New("base URL must be an origin with an optional path, and no user info, query or fragment")
	}
	if t.Enclave != "" && !validHost(t.Enclave) {
		return "", fmt.Errorf("enclave %q isn't a host name", t.Enclave)
	}
	query := url.Values{"nonce": {hex.EncodeToString(nonce)}}
	if t.Enclave != "" {
		query.Set("enclave", t.Enclave)
	}
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + WellKnownPath
	u.RawPath = ""
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// validHost accepts a DNS name, optionally with a port: letters, digits,
// hyphens and dots only.
func validHost(host string) bool {
	if len(host) > 253+6 {
		return false
	}
	name := host
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		port := host[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return false
		}
		name = host[:i]
	}
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// NewClient returns an HTTP client that never follows redirects. Its
// deadline comes from the request context.
func NewClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Document requests the v3 document for nonce. It accepts only a 200 with
// Content-Type application/json and a body within MaxDocumentBytes. Errors
// carry a fetch reason code.
func Document(ctx context.Context, client *http.Client, target Target, nonce []byte) ([]byte, error) {
	docURL, err := target.URL(nonce)
	if err != nil {
		return nil, reason.Wrap(reason.FetchFailed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, reason.Wrap(reason.FetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")
	setPlatformHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, classify(ctx, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, reason.Errorf(reason.BadStatus, "document request answered %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, reason.Errorf(reason.BadStatus, "document Content-Type is %q, want application/json", resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > MaxDocumentBytes {
		return nil, reason.Errorf(reason.TooLarge, "document is %d bytes, over the %d-byte cap", resp.ContentLength, MaxDocumentBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, classify(ctx, err)
	}
	if len(body) > MaxDocumentBytes {
		return nil, reason.Errorf(reason.TooLarge, "document is over the %d-byte cap", MaxDocumentBytes)
	}
	return body, nil
}

func classify(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return reason.Wrap(reason.Timeout, err)
	}
	return reason.Wrap(reason.FetchFailed, err)
}
