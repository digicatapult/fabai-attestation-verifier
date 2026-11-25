// Package seal is the client-side seal check. Before every send, a Checker
// fetches a v3 attestation document for a fresh nonce, authenticates its
// SEV-SNP report offline against pinned AMD roots, matches it against
// FabAI's signed allowlist, checks the GPU evidence, and returns three
// ticks and, only if all three pass, the attested key to seal that one
// request to. Any failure, error, panic or timeout means nothing is sent.
package seal

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/allowlist"
	"github.com/digicatapult/fabai-attestation-verifier/internal/fetch"
	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// DefaultDeadline bounds a whole check: the document request and the local
// verification. Provisional until a check against the Protected VM has been
// timed on the demo host.
const DefaultDeadline = 15 * time.Second

// Channel selects which attested key a result carries.
type Channel int

const (
	// ChannelHPKE is EHBP: the X25519 HPKE key (crypto_material item "hpke").
	ChannelHPKE Channel = iota
	// ChannelTLS is SPKI pinning for native clients connecting directly: the
	// SHA-256 of the TLS leaf's SubjectPublicKeyInfo (item "tls").
	ChannelTLS
)

// Options configures a Checker. None of them can add or replace an AMD root,
// the allowlist signer, or the clock.
type Options struct {
	// Deadline bounds each check. Zero means DefaultDeadline.
	Deadline time.Duration
	// Channel selects the key SendKey returns. Zero means ChannelHPKE.
	Channel Channel
	// Transport carries the document request. Nil means
	// http.DefaultTransport. Redirects are never followed.
	Transport http.RoundTripper
}

// Target is the replica, or the gateway relaying to one.
type Target struct {
	// BaseURL is the origin, http or https, with an optional path prefix.
	BaseURL string
	// Enclave is the replica host the gateway relays to; empty when talking
	// to a replica directly.
	Enclave string
}

// Checker runs seal checks. It keeps no state between checks and is safe for
// concurrent use: each check has its own nonce, document and result.
type Checker struct {
	list    *allowlist.List
	listErr error
	opts    Options
	client  *http.Client
	now     func() time.Time
}

// New returns a Checker for the allowlist listJSON and its Sigstore bundle.
// If the list fails its signature or schema check, every check fails with
// allowlist_unverified; AllowlistError says why. In the WASM build, which
// can't check a Sigstore bundle, use the allowlist embedded at build time.
func New(listJSON, bundleJSON []byte, opts Options) *Checker {
	list, err := allowlist.Verify(listJSON, bundleJSON)
	return newChecker(list, err, opts)
}

func newChecker(list *allowlist.List, listErr error, opts Options) *Checker {
	if opts.Deadline <= 0 {
		opts.Deadline = DefaultDeadline
	}
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if list == nil && listErr == nil {
		listErr = errors.New("no allowlist")
	}
	return &Checker{list: list, listErr: listErr, opts: opts, client: fetch.NewClient(transport), now: time.Now}
}

// AllowlistError is nil if the Checker holds a verified allowlist.
func (c *Checker) AllowlistError() error { return c.listErr }

// Check runs one live check against target with a fresh nonce.
func (c *Checker) Check(ctx context.Context, target Target) (result *Result) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Deadline)
	defer cancel()
	defer recoverInto(&result)

	nonce, err := fetch.NewNonce()
	if err != nil {
		return failed(reason.Wrap(reason.InternalError, err))
	}
	ft := fetch.Target{BaseURL: target.BaseURL, Enclave: target.Enclave}
	docURL, _ := ft.URL(nonce)
	doc, err := fetch.Document(ctx, c.client, ft, nonce)
	if err != nil {
		r := failed(err)
		r.Detail.Nonce, r.Detail.URL = hex.EncodeToString(nonce), docURL
		return r
	}
	r := c.evaluate(ctx, doc, nonce, c.now())
	r.Detail.URL = docURL
	return withDeadline(ctx, r)
}

// CheckDocument checks a saved document against the nonce it was requested
// with, at the current time. It makes no network request.
func (c *Checker) CheckDocument(ctx context.Context, doc, nonce []byte) (result *Result) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Deadline)
	defer cancel()
	defer recoverInto(&result)
	return withDeadline(ctx, c.evaluate(ctx, doc, nonce, c.now()))
}

// failed is a result whose hardware tick failed with err before a document
// was parsed.
func failed(err error) *Result {
	r := newResult()
	r.Detail.GPUNote = GPUNote
	r.fail(Hardware, err)
	r.finish(nil)
	return r
}

// withDeadline refuses a result if the deadline passed while it was made.
func withDeadline(ctx context.Context, r *Result) *Result {
	if err := ctx.Err(); err != nil {
		timedOut := failed(reason.Wrap(reason.Timeout, err))
		timedOut.Detail = r.Detail
		timedOut.Detail.Errors = append(timedOut.Detail.Errors, "hardware: "+reason.Wrap(reason.Timeout, err).Error())
		return timedOut
	}
	return r
}

// recoverInto turns a panic into an internal_error result with no key.
func recoverInto(result **Result) {
	if p := recover(); p != nil {
		*result = failed(reason.Errorf(reason.InternalError, "panic: %v", p))
	}
}
