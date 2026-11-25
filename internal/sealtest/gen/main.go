//go:build sealtest && !js

// Command gen writes the synthetic conformance vectors to a directory:
//
//	go run -tags sealtest ./internal/sealtest/gen -out vectors
//
// The vectors share one allowlist and one set of roots, each written once
// under fixtures/ and named by each vector's allowlistFile and rootsFile.
// Every run re-signs every document; the ARK keeps go-sev-guest's fixed
// test key.
package main

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest"
	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
)

// The shared fixtures, relative to the output directory. They sit in a
// subdirectory so that loaders globbing *.json skip them.
const (
	allowlistFile = "fixtures/synthetic-allowlist.json"
	rootsFile     = "fixtures/synthetic-roots.json"
)

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
	roots, err := sharedRoots(vectors)
	if err != nil {
		return err
	}
	if err := writeFixture(out, allowlistFile, allowlist); err != nil {
		return err
	}
	if err := writeFixture(out, rootsFile, roots); err != nil {
		return err
	}
	for _, v := range vectors {
		if !bytes.Equal(v.Allowlist, allowlist) {
			return fmt.Errorf("%s: allowlist isn't the shared synthetic allowlist", v.Name)
		}
		v.Allowlist, v.AllowlistFile = nil, allowlistFile
		// A vector without roots uses the pinned AMD roots, and keeps none.
		if v.Roots != nil {
			v.Roots, v.RootsFile = nil, rootsFile
		}
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

// sharedRoots returns the roots every vector that has roots carries, and
// fails if they differ.
func sharedRoots(vectors []*sealtest.Vector) (map[string]string, error) {
	var roots map[string]string
	for _, v := range vectors {
		switch {
		case v.Roots == nil:
		case roots == nil:
			roots = v.Roots
		case !maps.Equal(v.Roots, roots):
			return nil, fmt.Errorf("%s: roots aren't the shared synthetic roots", v.Name)
		}
	}
	if roots == nil {
		return nil, errors.New("no synthetic vector has roots")
	}
	return roots, nil
}

// writeFixture writes value as indented JSON to name, relative to out.
func writeFixture(out, name string, value any) error {
	path := filepath.Join(out, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(value, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
