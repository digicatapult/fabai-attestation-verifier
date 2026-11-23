// Package allowlist decodes and schema-checks FabAI's measurement allowlist,
// checks its Sigstore attestation, and matches authenticated reports against
// it (measurement-allowlist spec).
package allowlist

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
)

// SchemaVersion is the only list version this verifier reads.
const SchemaVersion = 1

// Entry statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// GPUArchBlackwell is the architecture name the GPU evidence carries.
const GPUArchBlackwell = "BLACKWELL"

// List is a schema-checked allowlist.
type List struct {
	Version            int     `json:"version"`
	PlatformMinimumTCB *TCB    `json:"platformMinimumTcb"`
	Entries            []Entry `json:"entries"`

	platformMinimum amd.TCB
}

// Entry is one approved VM shape. The measured fields mirror the
// fabai-boot-chain measure-snp action's allowlist-entry.json fragment.
type Entry struct {
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	Measurement   string            `json:"measurement"`
	Firmware      Firmware          `json:"firmware"`
	RuntimeImage  RuntimeImage      `json:"runtimeImage"`
	Cmdline       string            `json:"cmdline"`
	ConfigSHA256  string            `json:"configSha256"`
	VMShape       VMShape           `json:"vmShape"`
	GuestFeatures string            `json:"guestFeatures"`
	HostData      string            `json:"hostData"`
	GuestPolicy   *PolicyConstraint `json:"guestPolicy"`
	MinimumTCB    *TCB              `json:"minimumTcb"`
	Provenance    Provenance        `json:"provenance"`

	minimum amd.TCB
}

// Firmware is the stable fabai-boot-chain release the entry was measured with.
type Firmware struct {
	Tag    string `json:"tag"`
	SHA256 string `json:"sha256"`
}

// RuntimeImage is the cvmimage release.
type RuntimeImage struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifestSha256"`
	KernelSHA256   string `json:"kernelSha256"`
	InitrdSHA256   string `json:"initrdSha256"`
}

// VMShape is the launched shape. GPUs and GPUArchitecture are checked
// against the document's GPU evidence; Memory is for information only.
type VMShape struct {
	CPUs            int    `json:"cpus"`
	VCPUSignature   string `json:"vcpuSignature"`
	Memory          *int   `json:"memory"`
	GPUs            *int   `json:"gpus"`
	GPUArchitecture string `json:"gpuArchitecture,omitempty"`
}

// PolicyConstraint bounds the report's guest policy. ABIMajor and ABIMinor
// are minimums; SMT and CXLAllowed permit the bit; SingleSocket, MemAES256XTS,
// RAPLDisabled, CiphertextHidingDRAM and PageSwapDisabled require it. Debug
// and MigrateMA must be false.
type PolicyConstraint struct {
	ABIMajor             uint8 `json:"abiMajor"`
	ABIMinor             uint8 `json:"abiMinor"`
	SMT                  bool  `json:"smt"`
	MigrateMA            bool  `json:"migrateMA"`
	Debug                bool  `json:"debug"`
	SingleSocket         bool  `json:"singleSocket"`
	CXLAllowed           bool  `json:"cxlAllowed"`
	MemAES256XTS         bool  `json:"memAes256Xts"`
	RAPLDisabled         bool  `json:"raplDisabled"`
	CiphertextHidingDRAM bool  `json:"ciphertextHidingDram"`
	PageSwapDisabled     bool  `json:"pageSwapDisabled"`
}

// Provenance records where the entry's measurement came from.
type Provenance struct {
	SignerWorkflow string         `json:"signerWorkflow"`
	SourceRef      string         `json:"sourceRef"`
	Bundle         jsontext.Value `json:"bundle"`
}

// TCB is a minimum reported TCB. Bootloader, TEE, SNP and microcode are
// required; FMC applies to Turin reports only.
type TCB struct {
	Bootloader *uint8 `json:"bootloader"`
	TEE        *uint8 `json:"tee"`
	SNP        *uint8 `json:"snp"`
	Microcode  *uint8 `json:"microcode"`
	FMC        *uint8 `json:"fmc,omitempty"`
}

func (t *TCB) toAMD() (amd.TCB, error) {
	if t == nil {
		return amd.TCB{}, errors.New("is missing")
	}
	if t.Bootloader == nil || t.TEE == nil || t.SNP == nil || t.Microcode == nil {
		return amd.TCB{}, errors.New("needs bootloader, tee, snp and microcode")
	}
	return amd.TCB{Bootloader: *t.Bootloader, TEE: *t.TEE, SNP: *t.SNP, Microcode: *t.Microcode, FMC: t.FMC}, nil
}

// PlatformMinimum returns the checked platform minimum TCB.
func (l *List) PlatformMinimum() amd.TCB { return l.platformMinimum }

// Minimum returns the entry's checked minimum TCB.
func (e *Entry) Minimum() amd.TCB { return e.minimum }

// Decode strictly decodes and schema-checks an allowlist: unknown or
// duplicate members are refused.
func Decode(data []byte) (*List, error) {
	var list List
	if err := json.Unmarshal(data, &list, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	if err := list.Validate(); err != nil {
		return nil, err
	}
	return &list, nil
}

var (
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex96       = regexp.MustCompile(`^[0-9a-f]{96}$`)
	hexNumber   = regexp.MustCompile(`^0x[0-9a-f]+$`)
	headRelease = regexp.MustCompile(`^ovmf-head-`)
)

// Validate applies the schema check. Entry errors name the entry id.
func (l *List) Validate() error {
	if l.Version != SchemaVersion {
		return fmt.Errorf("allowlist: version %d, want %d", l.Version, SchemaVersion)
	}
	platformMinimum, err := l.PlatformMinimumTCB.toAMD()
	if err != nil {
		return fmt.Errorf("allowlist: platform minimum TCB %w", err)
	}
	l.platformMinimum = platformMinimum
	seen := make(map[string]bool, len(l.Entries))
	for i := range l.Entries {
		e := &l.Entries[i]
		if e.ID == "" {
			return fmt.Errorf("allowlist: entry %d has no id", i)
		}
		if seen[e.ID] {
			return fmt.Errorf("allowlist: duplicate entry id %q", e.ID)
		}
		seen[e.ID] = true
		if err := e.validate(platformMinimum); err != nil {
			return fmt.Errorf("allowlist: entry %q: %w", e.ID, err)
		}
	}
	return nil
}

func (e *Entry) validate(platformMinimum amd.TCB) error {
	var problems []string
	check := func(ok bool, problem string) {
		if !ok {
			problems = append(problems, problem)
		}
	}
	check(e.Status == StatusActive || e.Status == StatusRevoked, fmt.Sprintf("status %q isn't active or revoked", e.Status))
	check(hex96.MatchString(e.Measurement), "measurement isn't 96 lowercase hex characters")
	check(e.Firmware.Tag != "" && !headRelease.MatchString(e.Firmware.Tag), "firmware tag is missing or a HEAD prerelease")
	check(hex64.MatchString(e.Firmware.SHA256), "firmware sha256 isn't 64 lowercase hex characters")
	check(e.RuntimeImage.Version != "", "runtime image version is missing")
	check(hex64.MatchString(e.RuntimeImage.ManifestSHA256), "runtime image manifestSha256 isn't 64 lowercase hex characters")
	check(hex64.MatchString(e.RuntimeImage.KernelSHA256), "runtime image kernelSha256 isn't 64 lowercase hex characters")
	check(hex64.MatchString(e.RuntimeImage.InitrdSHA256), "runtime image initrdSha256 isn't 64 lowercase hex characters")
	check(e.Cmdline != "", "cmdline is missing")
	check(hex64.MatchString(e.ConfigSHA256), "configSha256 isn't 64 lowercase hex characters")
	check(e.VMShape.CPUs > 0, "vmShape cpus must be at least 1")
	check(hexNumber.MatchString(e.VMShape.VCPUSignature), "vmShape vcpuSignature isn't lowercase 0x hex")
	switch {
	case e.VMShape.GPUs == nil:
		problems = append(problems, "vmShape gpus is missing")
	case *e.VMShape.GPUs < 0:
		problems = append(problems, "vmShape gpus is negative")
	case *e.VMShape.GPUs > 0:
		check(e.VMShape.GPUArchitecture != "", "GPU architecture is missing")
	default:
		check(e.VMShape.GPUArchitecture == "", "GPU architecture is set, but gpus is 0")
	}
	check(hexNumber.MatchString(e.GuestFeatures), "guestFeatures isn't lowercase 0x hex")
	check(hex64.MatchString(e.HostData), "hostData isn't 64 lowercase hex characters")
	if e.GuestPolicy == nil {
		problems = append(problems, "guestPolicy is missing")
	} else {
		check(!e.GuestPolicy.Debug, "guestPolicy allows debugging")
		check(!e.GuestPolicy.MigrateMA, "guestPolicy allows a migration agent")
	}
	if minimum, err := e.MinimumTCB.toAMD(); err != nil {
		problems = append(problems, "minimumTcb "+err.Error())
	} else {
		e.minimum = minimum
		check(entryMinimumCoversPlatform(minimum, platformMinimum), "minimumTcb is below the platform minimum")
	}
	check(e.Provenance.SignerWorkflow != "", "provenance signerWorkflow is missing")
	check(e.Provenance.SourceRef != "", "provenance sourceRef is missing")
	check(e.Provenance.Bundle.Kind() == '{', "provenance bundle isn't a JSON object")
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// entryMinimumCoversPlatform requires every component of the entry minimum
// to be at least the platform minimum's. A platform FMC minimum needs an
// entry FMC minimum.
func entryMinimumCoversPlatform(entry, platform amd.TCB) bool {
	if platform.FMC != nil && entry.FMC == nil {
		return false
	}
	ok, _ := entry.AtLeast(platform)
	return ok
}
