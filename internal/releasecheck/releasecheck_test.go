//go:build !js

// Package releasecheck holds tests of the release artefacts themselves.
package releasecheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// marker is in the name of every function the sealtest build adds
// (amd.SealtestSetRoots, seal.SealtestNewChecker, ...). Function names stay
// in a Go binary's pclntab even with -ldflags=-s.
var marker = []byte("Sealtest")

func build(t *testing.T, goos, goarch, pkg string, tags ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "artefact")
	args := []string{"build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", out}
	if len(tags) > 0 {
		args = append(args, "-tags", tags[0])
	}
	cmd := exec.Command("go", append(args, pkg)...)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReleaseBuildsHaveNoSealtestHook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the release artefacts")
	}
	for _, artefact := range []struct{ goos, goarch, pkg string }{
		{"linux", "amd64", "./cmd/fabai-seal"},
		{"js", "wasm", "./cmd/fabai-seal-wasm"},
	} {
		if bytes.Contains(build(t, artefact.goos, artefact.goarch, artefact.pkg), marker) {
			t.Errorf("%s for %s/%s contains the sealtest hook", artefact.pkg, artefact.goos, artefact.goarch)
		}
	}
	// Positive control: the search finds the hook when it is there.
	if !bytes.Contains(build(t, "js", "wasm", "./cmd/fabai-seal-wasm", "sealtest"), marker) {
		t.Error("the sealtest WASM build doesn't contain the marker; the check above proves nothing")
	}
}
