//go:build sealtest && !js

// Command capture fetches a v3 document from a live cvmimage deployment for
// a fresh nonce and writes two conformance vectors: the capture with an
// allowlist written for its measurement (expected to pass), and the same
// capture with one report byte flipped (the "Seal: corrupted" gate).
//
//	go run -tags sealtest ./internal/sealtest/capture \
//	  -url https://inference.tinfoil.sh -cvmimage 0.14.19 -name tinfoil-router -out vectors
//
// Each fetch has a new nonce, so a capture can't be re-made; the vector
// records where and when it was taken.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tinfoilsh/go-sev-guest/abi"

	"github.com/digicatapult/fabai-attestation-verifier/internal/amd"
	"github.com/digicatapult/fabai-attestation-verifier/internal/docbind"
	"github.com/digicatapult/fabai-attestation-verifier/internal/fetch"
	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
)

func main() {
	baseURL := flag.String("url", "", "deployment base URL")
	cvmimage := flag.String("cvmimage", "", "the deployment's cvmimage version, from its config")
	name := flag.String("name", "", "vector name stem")
	notes := flag.String("notes", "", "notes to record with the capture")
	out := flag.String("out", "vectors", "directory to write the vectors to")
	flag.Parse()
	if *baseURL == "" || *cvmimage == "" || *name == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*baseURL, *cvmimage, *name, *notes, *out); err != nil {
		fmt.Fprintln(os.Stderr, "capture:", err)
		os.Exit(1)
	}
}

func run(baseURL, cvmimage, name, notes, out string) error {
	nonce, err := fetch.NewNonce()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	target := fetch.Target{BaseURL: baseURL}
	docURL, err := target.URL(nonce)
	if err != nil {
		return err
	}
	capturedAt := time.Now().UTC().Truncate(time.Second)
	doc, err := fetch.Document(ctx, fetch.NewClient(http.DefaultTransport), target, nonce)
	if err != nil {
		return err
	}
	bound, err := docbind.Parse(doc, nonce)
	if err != nil {
		return err
	}
	collateral, err := bound.AMDCollateral()
	if err != nil {
		return err
	}
	if collateral.CRLDER == nil {
		return errors.New("the deployment's collateral has no amd-crl/v1 entry; append the product CRL before using this capture")
	}
	report, err := amd.ParseReport(bound.Report)
	if err != nil {
		return err
	}
	allowlist, entryID, err := allowlistFor(report, name)
	if err != nil {
		return err
	}
	capture := &sealtest.Capture{URL: docURL, CapturedAt: capturedAt, CVMImageVersion: cvmimage, Notes: notes}
	stem := fmt.Sprintf("captured-%s-%s", name, strings.ToLower(report.Product))
	approved := &sealtest.Vector{
		Name:              stem,
		Description:       fmt.Sprintf("A v3 document from a public cvmimage %s deployment, with an allowlist written for its measurement", cvmimage),
		Source:            "captured",
		Capture:           capture,
		Document:          doc,
		Nonce:             hex.EncodeToString(nonce),
		Allowlist:         allowlist,
		AllowlistVerified: true,
		CheckTime:         capturedAt,
		Expect: sealtest.Outcome{
			Hardware: sealtest.TickOutcome{Status: "pass"}, Software: sealtest.TickOutcome{Status: "pass"}, GPU: sealtest.TickOutcome{Status: "pass"},
			Permitted: true, EntryID: entryID,
		},
	}
	corruptedDoc, err := flipReportByte(doc)
	if err != nil {
		return err
	}
	corrupted := *approved
	corrupted.Name = stem + "-corrupted"
	corrupted.Description = "The same capture with one MEASUREMENT byte of the report flipped"
	corrupted.Document = corruptedDoc
	corrupted.Expect = sealtest.Outcome{
		Hardware: sealtest.TickOutcome{Status: "fail", Reason: "signature_invalid"},
		Software: sealtest.TickOutcome{Status: "not_checked"}, GPU: sealtest.TickOutcome{Status: "not_checked"},
	}
	for _, v := range []*sealtest.Vector{approved, &corrupted} {
		data, err := v.Marshal()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, v.Name+".json"), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("%s: product %s, MEASUREMENT %x, collateral CRL present\n", stem, report.Product, report.Proto.GetMeasurement())
	return nil
}

// allowlistFor writes an allowlist whose one entry describes the captured
// report: its measurement, HOST_DATA, guest policy, REPORTED_TCB as both
// minimums, and no GPUs. Fields the report can't tell are marked unknown.
func allowlistFor(report *amd.Report, name string) (jsontext.Value, string, error) {
	if report.ReportedTCB == nil {
		return nil, "", fmt.Errorf("unknown TCB layout for %q", report.Product)
	}
	policy, err := abi.ParseSnpPolicy(report.Proto.GetPolicy())
	if err != nil {
		return nil, "", err
	}
	tcb := *report.ReportedTCB
	minimum := map[string]any{"bootloader": tcb.Bootloader, "tee": tcb.TEE, "snp": tcb.SNP, "microcode": tcb.Microcode}
	if tcb.FMC != nil {
		minimum["fmc"] = *tcb.FMC
	}
	unknown := strings.Repeat("0", 64)
	entryID := name + "-" + strings.ToLower(report.Product)
	list := map[string]any{
		"version":            1,
		"platformMinimumTcb": minimum,
		"entries": []any{map[string]any{
			"id":            entryID,
			"status":        "active",
			"measurement":   hex.EncodeToString(report.Proto.GetMeasurement()),
			"firmware":      map[string]string{"tag": "unknown-tinfoil-firmware", "sha256": unknown},
			"runtimeImage":  map[string]string{"version": "unknown", "manifestSha256": unknown, "kernelSha256": unknown, "initrdSha256": unknown},
			"cmdline":       "unknown: written from a captured report",
			"configSha256":  unknown,
			"vmShape":       map[string]any{"cpus": 8, "vcpuSignature": "0x0", "memory": nil, "gpus": 0},
			"guestFeatures": "0x0",
			"hostData":      hex.EncodeToString(report.Proto.GetHostData()),
			"guestPolicy": map[string]any{
				"abiMajor": policy.ABIMajor, "abiMinor": policy.ABIMinor, "smt": policy.SMT, "migrateMA": false, "debug": false,
				"singleSocket": false, "cxlAllowed": false, "memAes256Xts": false, "raplDisabled": false,
				"ciphertextHidingDram": false, "pageSwapDisabled": false,
			},
			"minimumTcb": minimum,
			"provenance": map[string]any{"signerWorkflow": "none: written from a captured report", "sourceRef": "none", "bundle": map[string]any{}},
		}},
	}
	raw, err := json.Marshal(list, json.Deterministic(true))
	return raw, entryID, err
}

// flipReportByte flips one MEASUREMENT byte of the document's report. The
// report isn't covered by REPORT_DATA, so the document still parses.
func flipReportByte(doc []byte) ([]byte, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(doc, &fields); err != nil {
		return nil, err
	}
	var evidence map[string]jsontext.Value
	if err := json.Unmarshal(fields["cpu_evidence"], &evidence); err != nil {
		return nil, err
	}
	var encoded string
	if err := json.Unmarshal(evidence["report_base64"], &encoded); err != nil {
		return nil, err
	}
	report, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	report[0x90] ^= 0x01
	if evidence["report_base64"], err = json.Marshal(base64.StdEncoding.EncodeToString(report)); err != nil {
		return nil, err
	}
	if fields["cpu_evidence"], err = json.Marshal(evidence, json.Deterministic(true)); err != nil {
		return nil, err
	}
	return json.Marshal(fields, json.Deterministic(true))
}
