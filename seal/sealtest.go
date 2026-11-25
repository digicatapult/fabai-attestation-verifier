//go:build sealtest

package seal

import (
	"context"
	"errors"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/allowlist"
)

// SealtestNewChecker returns a Checker for a vector's allowlist without its
// Sigstore check. If verified is false, the Checker behaves as if the list
// failed its signature check. Only in builds with the sealtest tag.
func SealtestNewChecker(listJSON []byte, verified bool, opts Options) *Checker {
	if !verified {
		return newChecker(nil, errors.New("vector marks the allowlist as unverified"), opts)
	}
	list, err := allowlist.Decode(listJSON)
	return newChecker(list, err, opts)
}

// SealtestCheckDocumentAt checks a document at a fixed time, because CRLs
// and certificates expire. Only in builds with the sealtest tag.
func (c *Checker) SealtestCheckDocumentAt(ctx context.Context, doc, nonce []byte, now time.Time) (result *Result) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Deadline)
	defer cancel()
	defer recoverInto(&result)
	return withDeadline(ctx, c.evaluate(ctx, doc, nonce, now))
}
