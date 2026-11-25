//go:build !js

// Command fabai-seal runs the seal check from the command line, for the
// release gates, and verifies an allowlist for the kiosk's WASM build.
//
//	fabai-seal check --allowlist L --bundle B --url <base> [--enclave <host>] [--json]
//	fabai-seal check --allowlist L --bundle B --document <file> --nonce <hex> [--json]
//	fabai-seal allowlist verify --allowlist L --bundle B [--out <file>]
//
// check exits 0 only if sending would be permitted, 1 if not, and 2 on a
// usage error. No flag sets the clock or the AMD roots.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/digicatapult/fabai-attestation-verifier/internal/allowlist"
	"github.com/digicatapult/fabai-attestation-verifier/seal"
)

const (
	exitPermitted = 0
	exitRefused   = 1
	exitUsage     = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) >= 1 && args[0] == "check":
		return check(ctx, args[1:], stdout, stderr)
	case len(args) >= 2 && args[0] == "allowlist" && args[1] == "verify":
		return verifyAllowlist(args[2:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: fabai-seal check ... | fabai-seal allowlist verify ...")
		return exitUsage
	}
}

// checkFlags returns the check subcommand's flag set. The set is fixed:
// a test checks that no flag can carry a root or a clock.
func checkFlags(stderr io.Writer) (*flag.FlagSet, *checkArgs) {
	a := &checkArgs{}
	fs := flag.NewFlagSet("fabai-seal check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.allowlist, "allowlist", "", "allowlist JSON file")
	fs.StringVar(&a.bundle, "bundle", "", "the allowlist's Sigstore bundle")
	fs.StringVar(&a.url, "url", "", "live: replica or gateway base URL")
	fs.StringVar(&a.enclave, "enclave", "", "live, through the gateway: the replica host")
	fs.StringVar(&a.document, "document", "", "offline: a saved v3 document")
	fs.StringVar(&a.nonce, "nonce", "", "offline: the nonce the document was requested with, hex")
	fs.DurationVar(&a.deadline, "deadline", seal.DefaultDeadline, "deadline for the whole check")
	fs.BoolVar(&a.json, "json", false, "print the result as JSON")
	return fs, a
}

type checkArgs struct {
	allowlist, bundle, url, enclave, document, nonce string
	deadline                                         time.Duration
	json                                             bool
}

func check(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, a := checkFlags(stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	live, offline := a.url != "", a.document != "" || a.nonce != ""
	if fs.NArg() != 0 || a.allowlist == "" || a.bundle == "" || live == offline || (offline && (a.document == "" || a.nonce == "")) || (offline && a.enclave != "") {
		fmt.Fprintln(stderr, "fabai-seal check: give --allowlist and --bundle, and either --url (live) or --document and --nonce (offline)")
		return exitUsage
	}
	list, err := os.ReadFile(a.allowlist)
	if err != nil {
		fmt.Fprintln(stderr, "fabai-seal check:", err)
		return exitUsage
	}
	bundle, err := os.ReadFile(a.bundle)
	if err != nil {
		fmt.Fprintln(stderr, "fabai-seal check:", err)
		return exitUsage
	}
	checker := seal.New(list, bundle, seal.Options{Deadline: a.deadline})

	var result *seal.Result
	if live {
		result = checker.Check(ctx, seal.Target{BaseURL: a.url, Enclave: a.enclave})
	} else {
		doc, err := os.ReadFile(a.document)
		if err != nil {
			fmt.Fprintln(stderr, "fabai-seal check:", err)
			return exitUsage
		}
		nonce, err := hex.DecodeString(a.nonce)
		if err != nil || len(nonce) != 32 {
			fmt.Fprintln(stderr, "fabai-seal check: --nonce must be 64 hex characters")
			return exitUsage
		}
		result = checker.CheckDocument(ctx, doc, nonce)
	}
	if err := report(stdout, result, a.json); err != nil {
		fmt.Fprintln(stderr, "fabai-seal check:", err)
		return exitRefused
	}
	if !result.Permitted {
		return exitRefused
	}
	return exitPermitted
}

func report(w io.Writer, r *seal.Result, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	for _, t := range []struct {
		name string
		tick seal.Tick
	}{{"hardware", r.Ticks.Hardware}, {"software", r.Ticks.Software}, {"gpu", r.Ticks.GPU}} {
		line := fmt.Sprintf("%-9s %-12s %s", t.name, t.tick.Status, t.tick.Text)
		if t.tick.Reason != "" {
			line += fmt.Sprintf(" (%s)", t.tick.Reason)
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if r.EntryID != "" {
		fmt.Fprintf(w, "entry     %s\n", r.EntryID)
	}
	for _, e := range r.Detail.Errors {
		fmt.Fprintf(w, "error     %s\n", e)
	}
	_, err := fmt.Fprintln(w, r.Message)
	return err
}

// verifyAllowlist checks an allowlist's Sigstore bundle and schema natively,
// and optionally writes the verified list for the kiosk's WASM build to embed.
func verifyAllowlist(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fabai-seal allowlist verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listPath := fs.String("allowlist", "", "allowlist JSON file")
	bundlePath := fs.String("bundle", "", "the allowlist's Sigstore bundle")
	out := fs.String("out", "", "write the verified list here")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *listPath == "" || *bundlePath == "" {
		fmt.Fprintln(stderr, "fabai-seal allowlist verify: give --allowlist and --bundle")
		return exitUsage
	}
	list, err1 := os.ReadFile(*listPath)
	bundle, err2 := os.ReadFile(*bundlePath)
	if err := errors.Join(err1, err2); err != nil {
		fmt.Fprintln(stderr, "fabai-seal allowlist verify:", err)
		return exitUsage
	}
	verified, err := allowlist.Verify(list, bundle)
	if err != nil {
		fmt.Fprintln(stderr, "fabai-seal allowlist verify:", err)
		return exitRefused
	}
	if *out != "" {
		if err := os.WriteFile(*out, list, 0o644); err != nil {
			fmt.Fprintln(stderr, "fabai-seal allowlist verify:", err)
			return exitRefused
		}
	}
	fmt.Fprintf(stdout, "allowlist verified: %d entries, signed by %s\n", len(verified.Entries), allowlist.SignerWorkflow)
	return exitPermitted
}
