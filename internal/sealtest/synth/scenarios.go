//go:build sealtest && !js

package synth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	sevtest "github.com/tinfoilsh/go-sev-guest/testing"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
)

// Fixed inputs, so a regenerated vector expects the same outcome.
var (
	CheckTime    = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	chainCreated = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	crlThis      = CheckTime.Add(-24 * time.Hour)
	crlNext      = CheckTime.Add(6 * 24 * time.Hour)

	// goodTCB is the synthetic platform's TCB: at the entry minimum.
	goodTCB = kds.TCBVersionV1{FmcSpl: 1, BlSpl: 1, TeeSpl: 1, SnpSpl: 4, UcodeSpl: 72}
	// betweenTCB meets the platform minimum but not the entry's.
	betweenTCB = kds.TCBVersionV1{FmcSpl: 1, BlSpl: 1, TeeSpl: 1, SnpSpl: 3, UcodeSpl: 72}
	// lowTCB is below the platform minimum.
	lowTCB = kds.TCBVersionV1{FmcSpl: 1, BlSpl: 1, TeeSpl: 1, SnpSpl: 2, UcodeSpl: 72}

	protectedMeasurement = sha512.Sum384([]byte("fabai sealtest: protected image"))
	modifiedMeasurement  = sha512.Sum384([]byte("fabai sealtest: modified image"))
	revokedMeasurement   = sha512.Sum384([]byte("fabai sealtest: revoked image"))
	hostData             = sha256.Sum256([]byte("fabai sealtest: host data"))
	tlsFingerprint       = sha256.Sum256([]byte("fabai sealtest: tls spki"))
	hpkeKey              = sha256.Sum256([]byte("fabai sealtest: hpke key"))
	approvedPolicy       = abi.SnpPolicy{SMT: true}
)

// EntryID is the synthetic allowlist's active entry.
const EntryID = "protected-turin-8cpu"

func hwid(first byte) [abi.ChipIDSize]byte {
	var id [abi.ChipIDSize]byte
	for i := range abi.TurinSiliconIDSize {
		id[i] = first + byte(i)
	}
	return id
}

func nonceFor(name string) []byte {
	sum := sha256.Sum256([]byte("fabai sealtest nonce: " + name))
	return sum[:]
}

func u8(v uint8) *uint8 { return &v }

func tcbJSON(bl, tee, snp, ucode, fmc uint8) map[string]*uint8 {
	return map[string]*uint8{"bootloader": u8(bl), "tee": u8(tee), "snp": u8(snp), "microcode": u8(ucode), "fmc": u8(fmc)}
}

// Allowlist is the synthetic allowlist: one active entry for the protected
// measurement, one revoked entry, a platform minimum at SNP 3 and an entry
// minimum at SNP 4.
func Allowlist() jsontext.Value {
	entry := func(id, status string, measurement [48]byte) map[string]any {
		gpus := 1
		return map[string]any{
			"id":          id,
			"status":      status,
			"measurement": hex.EncodeToString(measurement[:]),
			"firmware":    map[string]string{"tag": "ovmf-edk2-stable202608-r1", "sha256": strings.Repeat("a", 64)},
			"runtimeImage": map[string]string{
				"version": "0.14.19", "manifestSha256": strings.Repeat("b", 64),
				"kernelSha256": strings.Repeat("c", 64), "initrdSha256": strings.Repeat("d", 64),
			},
			"cmdline":       "console=ttyS0 roothash=" + strings.Repeat("e", 64),
			"configSha256":  strings.Repeat("f", 64),
			"vmShape":       map[string]any{"cpus": 8, "vcpuSignature": "0x800f12", "memory": 65536, "gpus": gpus, "gpuArchitecture": "BLACKWELL"},
			"guestFeatures": "0x1",
			"hostData":      hex.EncodeToString(hostData[:]),
			"guestPolicy":   map[string]any{"abiMajor": 0, "abiMinor": 0, "smt": true, "migrateMA": false, "debug": false, "singleSocket": false, "cxlAllowed": false, "memAes256Xts": false, "raplDisabled": false, "ciphertextHidingDram": false, "pageSwapDisabled": false},
			"minimumTcb":    tcbJSON(1, 1, 4, 72, 1),
			"provenance":    map[string]any{"signerWorkflow": "https://github.com/digicatapult/fabai-deploy/.github/workflows/release.yml", "sourceRef": "refs/tags/v1.0.0", "bundle": map[string]string{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}},
		}
	}
	list := map[string]any{
		"version":            1,
		"platformMinimumTcb": tcbJSON(1, 1, 3, 70, 1),
		"entries": []any{
			entry(EntryID, "active", protectedMeasurement),
			entry("old-turin-8cpu", "revoked", revokedMeasurement),
		},
	}
	raw, err := json.Marshal(list, json.Deterministic(true))
	if err != nil {
		panic(err)
	}
	return raw
}

func gpuItem(id, arch string, nonce []byte) document.DeviceEvidenceItem {
	evidence, err := json.Marshal(map[string]string{
		"arch":        arch,
		"certificate": base64.StdEncoding.EncodeToString([]byte("synthetic NVIDIA certificate chain")),
		"evidence":    base64.StdEncoding.EncodeToString([]byte("synthetic SPDM measurement report")),
		"nonce":       hex.EncodeToString(nonce),
	}, json.Deterministic(true))
	if err != nil {
		panic(err)
	}
	return document.DeviceEvidenceItem{ID: id, Kind: "gpu", Vendor: "nvidia", Format: document.NvidiaGPUEvidenceV1Format, Evidence: evidence}
}

func keys() []document.CryptoMaterialItem {
	return []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(tlsFingerprint[:])},
		{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hex.EncodeToString(hpkeKey[:])},
	}
}

// scenario describes one synthetic vector.
type scenario struct {
	name, description string
	specs             []string
	// chain signs the report (default: the good chain). The VCEK entry
	// comes from input.
	chain  *Chain
	report Report
	input  func(nonce []byte) document.BuildInput
	quote  QuoteOptions
	// docNonce, if set, is the nonce the document was built for.
	docNonce []byte
	// edit rewrites the finished document.
	edit       func([]byte) ([]byte, error)
	pinnedOnly bool
	unverified bool
	channel    string
	expect     sealtest.Outcome
}

func pass() sealtest.TickOutcome { return sealtest.TickOutcome{Status: "pass"} }
func fail(reason string) sealtest.TickOutcome {
	return sealtest.TickOutcome{Status: "fail", Reason: reason}
}
func notChecked() sealtest.TickOutcome { return sealtest.TickOutcome{Status: "not_checked"} }
func hardwareFail(reason string) sealtest.Outcome {
	return sealtest.Outcome{Hardware: fail(reason), Software: notChecked(), GPU: notChecked()}
}

var approved = sealtest.Outcome{Hardware: pass(), Software: pass(), GPU: pass(), Permitted: true, EntryID: EntryID}

// Synthetic builds every synthetic vector.
func Synthetic() ([]*sealtest.Vector, error) {
	good, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(1), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	between, err := NewChain(ChainOptions{TCB: betweenTCB, HWID: hwid(1), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	low, err := NewChain(ChainOptions{TCB: lowTCB, HWID: hwid(1), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	otherChip, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(0x41), Created: chainCreated})
	if err != nil {
		return nil, err
	}
	otherVCEKKeys := sevtest.DefaultAmdKeys()
	if otherVCEKKeys.Vcek, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		return nil, err
	}
	otherVCEK, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(1), Created: chainCreated, Keys: otherVCEKKeys})
	if err != nil {
		return nil, err
	}
	unknownRootKeys, err := NewARKKeys()
	if err != nil {
		return nil, err
	}
	unknownRoot, err := NewChain(ChainOptions{TCB: goodTCB, HWID: hwid(1), Created: chainCreated, Keys: unknownRootKeys})
	if err != nil {
		return nil, err
	}

	report := func(tcb kds.TCBVersionV1) Report {
		return Report{Measurement: protectedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: tcb.Uint64(), ChipID: hwid(1)}
	}
	crl, err := good.CRL(crlThis, crlNext)
	if err != nil {
		return nil, err
	}
	expiredCRL, err := good.CRL(crlThis.Add(-30*24*time.Hour), CheckTime.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	askRevokedCRL, err := good.CRL(crlThis, crlNext, good.ASKSerial())
	if err != nil {
		return nil, err
	}
	collateralWith := func(c *Chain, crlDER []byte) []collateral.Entry {
		entries := []collateral.Entry{c.VCEKEntry()}
		if crlDER != nil {
			entries = append(entries, CRLEntry(crlDER))
		}
		return entries
	}
	input := func(c *Chain, crlDER []byte, items func([]byte) []document.DeviceEvidenceItem, material []document.CryptoMaterialItem) func([]byte) document.BuildInput {
		return func(nonce []byte) document.BuildInput {
			return document.BuildInput{Nonce: nonce, CryptoMaterial: material, DeviceEvidence: items(nonce), Collateral: collateralWith(c, crlDER)}
		}
	}
	oneGPU := func(nonce []byte) []document.DeviceEvidenceItem {
		return []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonce)}
	}
	noGPU := func([]byte) []document.DeviceEvidenceItem { return []document.DeviceEvidenceItem{} }
	standard := input(good, crl, oneGPU, keys())

	scenarios := []scenario{
		{name: "approved", description: "The Protected VM on an active entry, with one BLACKWELL GPU",
			specs:  []string{"seal-check: Approved server", "attestation-binding: Matching GPU evidence", "measurement-allowlist: Matching report"},
			report: report(goodTCB), input: standard, expect: approved},
		{name: "approved-tls-channel", description: "A native client asking for the TLS pin gets it from the same document",
			specs:  []string{"attestation-binding: Channel keys come only from the verified document"},
			report: report(goodTCB), input: standard, channel: "tls", expect: approved},
		{name: "approved-with-tinfoil-sigstore", description: "Tinfoil's Sigstore reference-values entries are ignored",
			specs:  []string{"attestation-binding: Tinfoil Sigstore entries present"},
			report: report(goodTCB),
			input: func(nonce []byte) document.BuildInput {
				in := standard(nonce)
				in.Collateral = append(in.Collateral, SigstoreEntries()...)
				return in
			},
			expect: approved},
		{name: "modified-server", description: "A genuine SNP VM whose measurement is on no entry, with no GPU",
			specs:  []string{"seal-check: Modified server", "seal-check: Modified server has no GPU", "seal-check: Beat 5 result", "measurement-allowlist: Unknown measurement"},
			report: Report{Measurement: modifiedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)},
			input:  input(good, crl, noGPU, keys()),
			expect: sealtest.Outcome{Hardware: pass(), Software: fail("measurement_unknown"), GPU: notChecked()}},
		{name: "revoked-entry", description: "The measurement is only on a revoked entry",
			specs:  []string{"measurement-allowlist: Revocation"},
			report: Report{Measurement: revokedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)},
			input:  standard, expect: sealtest.Outcome{Hardware: pass(), Software: fail("measurement_revoked"), GPU: notChecked()}},
		{name: "host-data-mismatch", description: "HOST_DATA isn't the entry's",
			specs:  []string{"measurement-allowlist: Verifier match"},
			report: Report{Measurement: protectedMeasurement, HostData: sha256.Sum256([]byte("other")), Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)},
			input:  standard, expect: sealtest.Outcome{Hardware: pass(), Software: fail("host_data_mismatch"), GPU: notChecked()}},
		{name: "debug-policy", description: "The Protected image launched with DEBUG=1",
			specs:  []string{"seal-check: Debug policy", "measurement-allowlist: Debug policy"},
			report: Report{Measurement: protectedMeasurement, HostData: hostData, Policy: abi.SnpPolicy{SMT: true, Debug: true}, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)},
			input:  standard, expect: sealtest.Outcome{Hardware: pass(), Software: fail("policy_rejected"), GPU: notChecked()}},
		{name: "migration-agent-policy", description: "The guest policy allows a migration agent",
			specs:  []string{"measurement-allowlist: Verifier match"},
			report: Report{Measurement: protectedMeasurement, HostData: hostData, Policy: abi.SnpPolicy{SMT: true, MigrateMA: true}, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1)},
			input:  standard, expect: sealtest.Outcome{Hardware: pass(), Software: fail("policy_rejected"), GPU: notChecked()}},
		{name: "tcb-below-platform", description: "REPORTED_TCB's SNP component is below the platform minimum, on an active entry",
			specs: []string{"seal-check: TCB below the platform minimum", "measurement-allowlist: TCB below minimum", "measurement-allowlist: Out-of-date platform, unknown software"},
			chain: low, report: report(lowTCB), input: input(low, mustCRL(low), oneGPU, keys()),
			expect: sealtest.Outcome{Hardware: fail("tcb_below_platform"), Software: fail("tcb_below_entry"), GPU: notChecked()}},
		{name: "tcb-between-minimums", description: "REPORTED_TCB meets the platform minimum but not the entry's",
			specs: []string{"seal-check: TCB between the two minimums"},
			chain: between, report: report(betweenTCB), input: input(between, mustCRL(between), oneGPU, keys()),
			expect: sealtest.Outcome{Hardware: pass(), Software: fail("tcb_below_entry"), GPU: notChecked()}},
		{name: "allowlist-unverified", description: "The allowlist failed its signature check",
			specs:  []string{"seal-check: Tampered allowlist"},
			report: report(goodTCB), input: standard, unverified: true, expect: hardwareFail("allowlist_unverified")},

		{name: "corrupted-report", description: "One measurement byte of the signed report is flipped",
			specs:  []string{"seal-check: Corrupted report", "seal-check: Report not authenticated", "seal-check: Gate fails"},
			report: report(goodTCB), input: standard,
			quote:  QuoteOptions{AfterSigning: func(raw []byte) { raw[0x90] ^= 0x01 }},
			expect: hardwareFail("signature_invalid")},
		{name: "unknown-root", description: "VCEK and ASK chain to a self-made root, and the report is validly signed by that VCEK",
			specs: []string{"seal-check: Chain to an unknown root"},
			chain: unknownRoot, report: report(goodTCB), input: input(unknownRoot, mustCRL(unknownRoot), oneGPU, keys()),
			pinnedOnly: true, expect: hardwareFail("chain_invalid")},
		{name: "wrong-vcek", description: "The collateral's VCEK chains to the root but didn't sign the report",
			specs:  []string{"attestation-binding: Stub returns a wrong VCEK"},
			report: report(goodTCB), input: input(otherVCEK, crl, oneGPU, keys()),
			expect: hardwareFail("signature_invalid")},
		{name: "vcek-other-chip", description: "The VCEK's hardware ID differs from the report's CHIP_ID",
			specs:  []string{"seal-check: VCEK for another chip"},
			report: report(goodTCB), input: input(otherChip, crl, oneGPU, keys()),
			expect: hardwareFail("vcek_mismatch")},
		{name: "vlek-signed", description: "The report is signed by a VLEK",
			specs:  []string{"seal-check: Hardware tick"},
			report: Report{Measurement: protectedMeasurement, HostData: hostData, Policy: approvedPolicy, ReportedTCB: goodTCB.Uint64(), ChipID: hwid(1), VLEK: true},
			input:  standard, expect: hardwareFail("vlek_refused")},
		{name: "missing-vcek", description: "The collateral has no amd-vcek/v1 entry",
			specs:  []string{"seal-check: Hardware tick"},
			report: report(goodTCB),
			input: func(nonce []byte) document.BuildInput {
				in := standard(nonce)
				in.Collateral = []collateral.Entry{CRLEntry(crl)}
				return in
			},
			expect: hardwareFail("collateral_missing")},
		{name: "missing-crl", description: "The collateral has no amd-crl/v1 entry",
			specs:  []string{"seal-check: Missing CRL"},
			report: report(goodTCB), input: input(good, nil, oneGPU, keys()), expect: hardwareFail("crl_missing")},
		{name: "expired-crl", description: "The check time is after the CRL's nextUpdate",
			specs:  []string{"seal-check: Expired CRL"},
			report: report(goodTCB), input: input(good, expiredCRL, oneGPU, keys()), expect: hardwareFail("crl_expired")},
		{name: "revoked-ask", description: "The CRL lists the ASK's serial number",
			specs:  []string{"seal-check: Revoked ASK"},
			report: report(goodTCB), input: input(good, askRevokedCRL, oneGPU, keys()), expect: hardwareFail("revoked")},

		{name: "replayed-document", description: "A document valid for an earlier check's nonce",
			specs:  []string{"attestation-binding: Replayed document"},
			report: report(goodTCB), input: standard, docNonce: nonceFor("an earlier check"), expect: hardwareFail("nonce_mismatch")},
		{name: "tdx-evidence", description: "cpu_evidence.format is the TDX quote format",
			specs:  []string{"attestation-binding: TDX evidence"},
			report: report(goodTCB), input: standard, quote: QuoteOptions{Format: document.TDXQuoteV1Format}, expect: hardwareFail("parse_failed")},
		{name: "unknown-member", description: "The document has a member the format doesn't define",
			specs:  []string{"attestation-binding: Unknown member"},
			report: report(goodTCB), input: standard, edit: addUnknownMember, expect: hardwareFail("parse_failed")},
		{name: "uppercase-hex", description: "challenge.report_data is valid but written in uppercase hex",
			specs:  []string{"attestation-binding: Uppercase hex"},
			report: report(goodTCB), input: standard, edit: uppercaseReportData, expect: hardwareFail("parse_failed")},
		{name: "collateral-format-v3", description: "collateral_format is v3, which this verifier doesn't accept",
			specs:  []string{"attestation-binding: Strict document parsing"},
			report: report(goodTCB),
			input: func(nonce []byte) document.BuildInput {
				in := standard(nonce)
				in.CollateralFormat = collateral.FormatV3
				return in
			},
			expect: hardwareFail("parse_failed")},
		{name: "tampered-crypto-material", description: "One byte of the decoded crypto_material differs from what the report was built over",
			specs:  []string{"attestation-binding: Tampered crypto material"},
			report: report(goodTCB), input: standard, edit: tamperCryptoMaterial, expect: hardwareFail("report_data_mismatch")},
		{name: "different-report-data", description: "The document is self-consistent, but the report carries a different REPORT_DATA",
			specs:  []string{"attestation-binding: Consistent document, different report"},
			report: report(goodTCB), input: standard,
			quote:  QuoteOptions{ReportData: func([64]byte) [64]byte { var rd [64]byte; copy(rd[:], hpkeKey[:]); return rd }},
			expect: hardwareFail("report_data_mismatch")},
		{name: "nonzero-upper-report-data", description: "REPORT_DATA bytes 32-63 aren't all zero",
			specs:  []string{"attestation-binding: Non-zero upper half"},
			report: report(goodTCB), input: standard,
			quote:  QuoteOptions{ReportData: func(rd [64]byte) [64]byte { rd[40] = 1; return rd }},
			expect: hardwareFail("report_data_mismatch")},

		{name: "hpke-key-missing", description: "The verified document has no hpke item",
			specs:  []string{"attestation-binding: HPKE key missing"},
			report: report(goodTCB), input: input(good, crl, oneGPU, keys()[:1]),
			expect: sealtest.Outcome{Hardware: pass(), Software: fail("channel_key_missing"), GPU: notChecked()}},
		{name: "hpke-key-wrong-format", description: "The hpke item has the SPKI fingerprint format",
			specs:  []string{"attestation-binding: Channel keys come only from the verified document"},
			report: report(goodTCB),
			input: input(good, crl, oneGPU, []document.CryptoMaterialItem{
				keys()[0], {ID: document.CryptoMaterialIDHPKE, Format: document.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(hpkeKey[:])},
			}),
			expect: sealtest.Outcome{Hardware: pass(), Software: fail("channel_key_missing"), GPU: notChecked()}},
		{name: "tls-key-missing", description: "A native client needs the tls item, and the document has none",
			specs:  []string{"attestation-binding: Channel keys come only from the verified document"},
			report: report(goodTCB), input: input(good, crl, oneGPU, keys()[1:]), channel: "tls",
			expect: sealtest.Outcome{Hardware: pass(), Software: fail("channel_key_missing"), GPU: notChecked()}},

		{name: "gpu-hopper", description: "The GPU item's arch is HOPPER; the entry expects BLACKWELL",
			specs:  []string{"attestation-binding: Mismatched GPU evidence"},
			report: report(goodTCB),
			input: input(good, crl, func(nonce []byte) []document.DeviceEvidenceItem {
				return []document.DeviceEvidenceItem{gpuItem("gpu0", "HOPPER", nonce)}
			}, keys()),
			expect: gpuFail("gpu_arch")},
		{name: "gpu-nonce-differs", description: "The GPU item's nonce differs from challenge.nonce",
			specs:  []string{"attestation-binding: GPU nonce differs from the document's"},
			report: report(goodTCB),
			input: input(good, crl, func([]byte) []document.DeviceEvidenceItem {
				return []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonceFor("another nonce"))}
			}, keys()),
			expect: gpuFail("gpu_nonce")},
		{name: "gpu-none", description: "The entry expects 1 GPU and the document has none",
			specs:  []string{"attestation-binding: Wrong number of GPU items"},
			report: report(goodTCB), input: input(good, crl, noGPU, keys()), expect: gpuFail("gpu_count")},
		{name: "gpu-two", description: "The entry expects 1 GPU and the document has 2",
			specs:  []string{"attestation-binding: Wrong number of GPU items"},
			report: report(goodTCB),
			input: input(good, crl, func(nonce []byte) []document.DeviceEvidenceItem {
				return []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonce), gpuItem("gpu1", "BLACKWELL", nonce)}
			}, keys()),
			expect: gpuFail("gpu_count")},
		{name: "gpu-nvswitch", description: "The document carries an NVSwitch item besides the GPU",
			specs:  []string{"attestation-binding: Unexpected NVSwitch item"},
			report: report(goodTCB),
			input: input(good, crl, func(nonce []byte) []document.DeviceEvidenceItem {
				nvswitch := gpuItem("nvswitch0", "BLACKWELL", nonce)
				nvswitch.Kind, nvswitch.Format = "nvswitch", "https://tinfoil.sh/format/nvidia-nvswitch-evidence/v1"
				return []document.DeviceEvidenceItem{gpuItem("gpu0", "BLACKWELL", nonce), nvswitch}
			}, keys()),
			expect: gpuFail("gpu_item")},
		{name: "gpu-empty-certificate", description: "The GPU item's certificate is empty",
			specs:  []string{"attestation-binding: GPU evidence, first version"},
			report: report(goodTCB),
			input: input(good, crl, func(nonce []byte) []document.DeviceEvidenceItem {
				item := gpuItem("gpu0", "BLACKWELL", nonce)
				item.Evidence = []byte(`{"arch":"BLACKWELL","certificate":"","evidence":"c3BkbQ==","nonce":"` + hex.EncodeToString(nonce) + `"}`)
				return []document.DeviceEvidenceItem{item}
			}, keys()),
			expect: gpuFail("gpu_item")},
	}

	roots := map[string]string{Product: good.ARKPEM()}
	vectors := make([]*sealtest.Vector, 0, len(scenarios))
	for _, s := range scenarios {
		v, err := s.build(good, roots)
		if err != nil {
			return nil, fmt.Errorf("scenario %s: %w", s.name, err)
		}
		vectors = append(vectors, v)
	}
	return vectors, nil
}

func gpuFail(reason string) sealtest.Outcome {
	return sealtest.Outcome{Hardware: pass(), Software: pass(), GPU: fail(reason), EntryID: EntryID}
}

func mustCRL(c *Chain) []byte {
	crl, err := c.CRL(crlThis, crlNext)
	if err != nil {
		panic(err)
	}
	return crl
}

func (s scenario) build(good *Chain, roots map[string]string) (*sealtest.Vector, error) {
	signer := s.chain
	if signer == nil {
		signer = good
	}
	nonce := nonceFor(s.name)
	docNonce := nonce
	if s.docNonce != nil {
		docNonce = s.docNonce
	}
	doc, err := signer.Document(s.input(docNonce), s.report, s.quote)
	if err != nil {
		return nil, err
	}
	if s.edit != nil {
		if doc, err = s.edit(doc); err != nil {
			return nil, err
		}
	}
	v := &sealtest.Vector{
		Name:              "synthetic-" + s.name,
		Description:       s.description,
		Scenario:          s.specs,
		Source:            "synthetic",
		Roots:             roots,
		Document:          doc,
		Nonce:             hex.EncodeToString(nonce),
		Allowlist:         Allowlist(),
		AllowlistVerified: !s.unverified,
		CheckTime:         CheckTime,
		Channel:           s.channel,
		Expect:            s.expect,
	}
	if s.pinnedOnly {
		v.Roots = nil
	}
	return v, nil
}

// editDocument decodes doc as a JSON object, applies edit, and re-encodes it.
func editDocument(doc []byte, edit func(map[string]jsontext.Value) error) ([]byte, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(doc, &fields); err != nil {
		return nil, err
	}
	if err := edit(fields); err != nil {
		return nil, err
	}
	return json.Marshal(fields, json.Deterministic(true))
}

func addUnknownMember(doc []byte) ([]byte, error) {
	return editDocument(doc, func(f map[string]jsontext.Value) error {
		f["comment"] = jsontext.Value(`"not part of the v3 format"`)
		return nil
	})
}

func uppercaseReportData(doc []byte) ([]byte, error) {
	return editDocument(doc, func(f map[string]jsontext.Value) error {
		var challenge map[string]string
		if err := json.Unmarshal(f["challenge"], &challenge); err != nil {
			return err
		}
		challenge["report_data"] = strings.ToUpper(challenge["report_data"])
		raw, err := json.Marshal(challenge, json.Deterministic(true))
		f["challenge"] = raw
		return err
	})
}

func tamperCryptoMaterial(doc []byte) ([]byte, error) {
	return editDocument(doc, func(f map[string]jsontext.Value) error {
		var encoded string
		if err := json.Unmarshal(f["crypto_material"], &encoded); err != nil {
			return err
		}
		section, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return err
		}
		// Change one hex digit of the hpke key: the section stays valid JSON.
		i := strings.Index(string(section), hex.EncodeToString(hpkeKey[:]))
		if i < 0 {
			return fmt.Errorf("hpke key not found in crypto_material")
		}
		if section[i] == '0' {
			section[i] = '1'
		} else {
			section[i] = '0'
		}
		raw, err := json.Marshal(base64.StdEncoding.EncodeToString(section))
		f["crypto_material"] = raw
		return err
	})
}
