package allowlist

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/tinfoilsh/go-sev-guest/abi"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/reason"
)

// Match finds the entry an authenticated report satisfies (Verifier match):
// an active entry with the report's MEASUREMENT, HOST_DATA, a guest policy
// within the entry's constraints, and REPORTED_TCB at least the entry's
// minimum. On failure, nearest is the entry that came closest, or nil.
func (l *List) Match(r *amd.Report) (matched *Entry, err error) {
	measurement := r.Proto.GetMeasurement()
	var nearest *Entry
	var firstErr error
	revoked := false
	for i := range l.Entries {
		e := &l.Entries[i]
		want, decodeErr := hex.DecodeString(e.Measurement)
		if decodeErr != nil || !bytes.Equal(want, measurement) {
			continue
		}
		if e.Status != StatusActive {
			revoked = true
			if nearest == nil {
				nearest = e
			}
			continue
		}
		if err := e.satisfiedBy(r); err != nil {
			if firstErr == nil {
				nearest, firstErr = e, err
			}
			continue
		}
		return e, nil
	}
	switch {
	case firstErr != nil:
		return nearest, firstErr
	case revoked:
		return nearest, reason.Errorf(reason.MeasurementRevoked, "the report's measurement is only on revoked entry %q", nearest.ID)
	default:
		return nil, reason.Errorf(reason.MeasurementUnknown, "no entry has the report's measurement")
	}
}

func (e *Entry) satisfiedBy(r *amd.Report) error {
	hostData, err := hex.DecodeString(e.HostData)
	if err != nil || !bytes.Equal(hostData, r.Proto.GetHostData()) {
		return reason.Errorf(reason.HostDataMismatch, "HOST_DATA isn't entry %q's", e.ID)
	}
	if err := e.GuestPolicy.check(r.Proto.GetPolicy()); err != nil {
		return reason.Errorf(reason.PolicyRejected, "entry %q: %v", e.ID, err)
	}
	return r.AtLeast(e.minimum, reason.TCBBelowEntry, fmt.Sprintf("entry %q minimum", e.ID))
}

// check applies the constraint to a report's GUEST_POLICY, as go-sev-guest's
// validate package does, with debugging and migration agents always refused.
func (c *PolicyConstraint) check(reportPolicy uint64) error {
	policy, err := abi.ParseSnpPolicy(reportPolicy)
	if err != nil {
		return fmt.Errorf("guest policy: %v", err)
	}
	switch {
	case policy.Debug:
		return fmt.Errorf("guest policy allows debugging")
	case policy.MigrateMA:
		return fmt.Errorf("guest policy allows a migration agent")
	case uint16(policy.ABIMajor)<<8|uint16(policy.ABIMinor) < uint16(c.ABIMajor)<<8|uint16(c.ABIMinor):
		return fmt.Errorf("guest policy ABI %d.%d is below %d.%d", policy.ABIMajor, policy.ABIMinor, c.ABIMajor, c.ABIMinor)
	case policy.SMT && !c.SMT:
		return fmt.Errorf("guest policy allows SMT")
	case policy.CXLAllowed && !c.CXLAllowed:
		return fmt.Errorf("guest policy allows CXL")
	case c.SingleSocket && !policy.SingleSocket:
		return fmt.Errorf("guest policy doesn't require a single socket")
	case c.MemAES256XTS && !policy.MemAES256XTS:
		return fmt.Errorf("guest policy doesn't require AES-256-XTS")
	case c.RAPLDisabled && !policy.RAPLDis:
		return fmt.Errorf("guest policy doesn't disable RAPL")
	case c.CiphertextHidingDRAM && !policy.CipherTextHidingDRAM:
		return fmt.Errorf("guest policy doesn't require ciphertext hiding")
	case c.PageSwapDisabled && !policy.PageSwapDisable:
		return fmt.Errorf("guest policy doesn't disable page swap")
	}
	return nil
}
