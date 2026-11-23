//go:build sealtest && !js

// Command gen writes the synthetic conformance vectors to a directory:
//
//	go run -tags sealtest ./internal/sealtest/gen -out vectors
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digicatapult/fabai-attestation-verifier/internal/sealtest/synth"
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
	for _, v := range vectors {
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
