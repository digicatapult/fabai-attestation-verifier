package amd

import (
	"fmt"

	"github.com/tinfoilsh/go-sev-guest/kds"
)

// TCB is a reported TCB's security patch levels. FMC exists only on Turin.
type TCB struct {
	Bootloader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
	// FMC is nil for products without an FMC component (Milan, Genoa).
	FMC *uint8 `json:"fmc,omitempty"`
}

// DecodeTCB splits a raw 64-bit TCB_VERSION using product's layout. Turin
// uses the layout with FMC in byte 0 (TCB struct version 1).
func DecodeTCB(product string, raw uint64) (TCB, error) {
	version, err := kds.DecomposeProductTCB(product, raw)
	if err != nil {
		return TCB{}, err
	}
	switch v := version.(type) {
	case kds.TCBVersionV0:
		return TCB{Bootloader: v.BlSpl, TEE: v.TeeSpl, SNP: v.SnpSpl, Microcode: v.UcodeSpl}, nil
	case kds.TCBVersionV1:
		fmc := v.FmcSpl
		return TCB{Bootloader: v.BlSpl, TEE: v.TeeSpl, SNP: v.SnpSpl, Microcode: v.UcodeSpl, FMC: &fmc}, nil
	default:
		return TCB{}, fmt.Errorf("unknown TCB layout %T for %s", version, product)
	}
}

// AtLeast reports whether every component of t is at least the matching
// component of minimum, and names the first component that isn't. A minimum
// FMC applies only to a TCB that has an FMC component.
func (t TCB) AtLeast(minimum TCB) (ok bool, component string) {
	switch {
	case t.Bootloader < minimum.Bootloader:
		return false, "bootloader"
	case t.TEE < minimum.TEE:
		return false, "tee"
	case t.SNP < minimum.SNP:
		return false, "snp"
	case t.Microcode < minimum.Microcode:
		return false, "microcode"
	case t.FMC != nil && minimum.FMC != nil && *t.FMC < *minimum.FMC:
		return false, "fmc"
	}
	return true, ""
}

// String formats the components for the experts view.
func (t TCB) String() string {
	s := fmt.Sprintf("bootloader %d, TEE %d, SNP %d, microcode %d", t.Bootloader, t.TEE, t.SNP, t.Microcode)
	if t.FMC != nil {
		s += fmt.Sprintf(", FMC %d", *t.FMC)
	}
	return s
}
