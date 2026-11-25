//go:build sealtest && !js

// Command gen writes the synthetic conformance vectors to a directory:
//
//	go run -tags sealtest ./internal/sealtest/gen -out vectors
//
// The vectors share one allowlist, written once under fixtures/ and named by
// each vector's allowlistFile. Every run re-signs every document.
package main

import (
	"bytes"
	"encoding/json/jsontext"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
)

// allowlistFile is the shared allowlist, relative to the output directory.
// It sits in a subdirectory so that loaders globbing *.json skip it.
const allowlistFile = "fixtures/synthetic-allowlist.json"

func main() {
	out := flag.String("out", "vectors", "directory to write the vectors to")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	vectors, err := synth.Synthetic()
	if err != nil {
		return err
	}
	allowlist := synth.Allowlist()
	if err := writeAllowlist(filepath.Join(out, filepath.FromSlash(allowlistFile)), allowlist); err != nil {
		return err
	}
	for _, v := range vectors {
		if !bytes.Equal(v.Allowlist, allowlist) {
			return fmt.Errorf("%s: allowlist isn't the shared synthetic allowlist", v.Name)
		}
		v.Allowlist, v.AllowlistFile = nil, allowlistFile
		data, err := v.Marshal()
		if err != nil {
			return fmt.Errorf("%s: %w", v.Name, err)
		}
		if err := os.WriteFile(filepath.Join(out, v.Name+".json"), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeAllowlist(path string, allowlist jsontext.Value) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	indented := allowlist.Clone()
	if err := indented.Indent(jsontext.WithIndent("  ")); err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	return os.WriteFile(path, append(indented, '\n'), 0o644)
}
