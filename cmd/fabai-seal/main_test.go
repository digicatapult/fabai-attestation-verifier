//go:build !js

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheckFlagsCarryNoRootOrClock(t *testing.T) {
	fs, _ := checkFlags(io.Discard)
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	want := []string{"allowlist", "bundle", "deadline", "document", "enclave", "json", "nonce", "url"}
	if !slices.Equal(names, want) {
		t.Errorf("check flags are %v, want %v; review any new flag against seal-check \"Pinned AMD roots\"", names, want)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"check"},
		{"check", "--allowlist", "l", "--bundle", "b"},
		{"check", "--allowlist", "l", "--bundle", "b", "--url", "https://x", "--document", "d", "--nonce", "00"},
		{"check", "--allowlist", "l", "--bundle", "b", "--document", "d"},
		{"allowlist", "verify"},
	} {
		if got := run(context.Background(), args, io.Discard, io.Discard); got != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, got, exitUsage)
		}
	}
}

// TestGateFails is seal-check "Gate fails": an offline check of a captured
// document with one report byte flipped exits non-zero with a failing
// hardware tick.
func TestGateFails(t *testing.T) {
	data, err := os.ReadFile("../../vectors/captured-tinfoil-router-genoa-corrupted.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Document []byte `json:"document"`
		Nonce    string `json:"nonce"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	list, err := os.ReadFile("../../internal/allowlist/testdata/allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code := run(context.Background(), []string{
		"check", "--allowlist", write("allowlist.json", list), "--bundle", write("bundle.json", []byte(`{}`)),
		"--document", write("document.json", v.Document), "--nonce", v.Nonce,
	}, &stdout, io.Discard)
	if code != exitRefused {
		t.Errorf("exit %d, want %d", code, exitRefused)
	}
	if !strings.Contains(stdout.String(), "hardware  fail") || !strings.Contains(stdout.String(), "signature_invalid") {
		t.Errorf("output:\n%s", stdout.String())
	}
}
