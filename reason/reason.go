// Package reason defines the stable reason codes a seal check reports, and an
// error type that carries one (design D3).
package reason

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable reason for a failed tick.
type Code string

// Fetch (step 1).
const (
	FetchFailed Code = "fetch_failed"
	Timeout     Code = "timeout"
	BadStatus   Code = "bad_status"
	TooLarge    Code = "too_large"
)

// Parse and bind (step 2).
const (
	ParseFailed        Code = "parse_failed"
	NonceMismatch      Code = "nonce_mismatch"
	ReportDataMismatch Code = "report_data_mismatch"
)

// Authenticate (step 3).
const (
	CollateralMissing Code = "collateral_missing"
	ChainInvalid      Code = "chain_invalid"
	CRLMissing        Code = "crl_missing"
	CRLExpired        Code = "crl_expired"
	Revoked           Code = "revoked"
	SignatureInvalid  Code = "signature_invalid"
	VCEKMismatch      Code = "vcek_mismatch"
	VLEKRefused       Code = "vlek_refused"
)

// Platform (step 4).
const (
	TCBBelowPlatform    Code = "tcb_below_platform"
	AllowlistUnverified Code = "allowlist_unverified"
)

// Software (step 5).
const (
	MeasurementUnknown Code = "measurement_unknown"
	MeasurementRevoked Code = "measurement_revoked"
	HostDataMismatch   Code = "host_data_mismatch"
	PolicyRejected     Code = "policy_rejected"
	TCBBelowEntry      Code = "tcb_below_entry"
	ChannelKeyMissing  Code = "channel_key_missing"
)

// GPU (step 6).
const (
	GPUCount Code = "gpu_count"
	GPUItem  Code = "gpu_item"
	GPUArch  Code = "gpu_arch"
	GPUNonce Code = "gpu_nonce"
)

// InternalError marks a panic or an error no step expected.
const InternalError Code = "internal_error"

// Error is a failure with its reason code.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Errorf returns an *Error with code and a formatted cause.
func Errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// Wrap returns err with code attached, or nil if err is nil.
func Wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Code: code, Err: err}
}

// CodeOf returns the code carried by err, or InternalError if it carries
// none, so an unclassified error can never pass as a known outcome.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return InternalError
}
