package seal

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/allowlist"
	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/internal/docbind"
	"github.com/digicatapult/fabai-attestation-verifier/internal/gpu"
	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// evaluate runs steps 2-6 of design D3 on a fetched document:
//
//  2. parse and bind; 3. authenticate the report. A failure in either
//     fails the hardware tick and leaves software and GPU not checked.
//  4. platform: a verified allowlist, and REPORTED_TCB at least its
//     platform minimum. A failure fails the hardware tick, but a low TCB
//     doesn't stop step 5.
//  5. software: the allowlist match and the channel key.
//  6. GPU, only if the software tick passed.
func (c *Checker) evaluate(ctx context.Context, doc, nonce []byte, now time.Time) *Result {
	r := newResult()
	r.Detail.Nonce = hex.EncodeToString(nonce)
	r.Detail.GPUNote = GPUNote
	defer func() { r.finish(r.pendingKey) }()

	bound, err := docbind.Parse(doc, nonce)
	if err != nil {
		r.fail(Hardware, err)
		return r
	}
	r.Detail.KeyIDs = bound.KeyIDs()
	items := bound.DeviceItems()
	r.Detail.GPU = gpu.Summarize(items)

	report, err := amd.ParseReport(bound.Report)
	if err != nil {
		r.fail(Hardware, err)
		return r
	}
	r.Detail.Report = reportDetail(report)

	collateral, err := bound.AMDCollateral()
	if err != nil {
		r.fail(Hardware, err)
		return r
	}
	chain, err := amd.Authenticate(ctx, report, amd.Input{
		Report:     bound.Report,
		ReportData: bound.ReportData,
		VCEKDER:    collateral.VCEKDER,
		ChainPEM:   collateral.ChainPEM,
		CRLDER:     collateral.CRLDER,
	}, now)
	r.Detail.Chain, r.Detail.CRL = chainDetail(chain)
	if err != nil {
		r.fail(Hardware, err)
		return r
	}

	if c.list == nil {
		r.fail(Hardware, reason.Wrap(reason.AllowlistUnverified, c.listErr))
		return r
	}
	if err := report.AtLeast(c.list.PlatformMinimum(), reason.TCBBelowPlatform, "platform minimum"); err != nil {
		r.fail(Hardware, err)
	} else {
		r.pass(Hardware)
	}

	entry, key, err := c.software(report, bound)
	if entry != nil {
		r.Detail.Entry = entry.ID
	}
	if err != nil {
		r.fail(Software, err)
		return r
	}
	r.pass(Software)
	r.Detail.EntryMatched = true
	r.EntryID = entry.ID

	if err := gpu.Check(items, nonce, gpuExpectation(entry)); err != nil {
		r.fail(GPU, err)
		return r
	}
	r.pass(GPU)
	r.pendingKey = key
	return r
}

// software matches the report against the allowlist and takes the channel
// key from the verified document.
func (c *Checker) software(report *amd.Report, bound *docbind.Bound) (*allowlist.Entry, []byte, error) {
	entry, err := c.list.Match(report)
	if err != nil {
		return entry, nil, err
	}
	var key []byte
	switch c.opts.Channel {
	case ChannelTLS:
		key, err = bound.TLSPin()
	default:
		key, err = bound.HPKEKey()
	}
	return entry, key, err
}

func gpuExpectation(entry *allowlist.Entry) gpu.Expectation {
	want := gpu.Expectation{Architecture: entry.VMShape.GPUArchitecture}
	if entry.VMShape.GPUs != nil {
		want.Count = *entry.VMShape.GPUs
	}
	return want
}
