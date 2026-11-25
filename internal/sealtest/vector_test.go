//go:build sealtest && !js

package sealtest

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testList  = `{"version": 1}`
	testRoots = `{"Turin": "PEM"}`
)

// loadOne writes a vector with the given members, beside fixtures/list.json,
// fixtures/roots.json and fixtures/empty.json, and loads the directory.
func loadOne(t *testing.T, members string) ([]*Vector, error) {
	t.Helper()
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.Mkdir(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"list.json": testList, "roots.json": testRoots, "empty.json": `{}`} {
		if err := os.WriteFile(filepath.Join(fixtures, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	doc := `{"name": "v"`
	if members != "" {
		doc += ", " + members
	}
	if err := os.WriteFile(filepath.Join(dir, "v.json"), []byte(doc+"}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(dir)
}

func wantLoadError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Load error %v, want one containing %q", err, want)
	}
}

func loadedOne(t *testing.T, vectors []*Vector, err error) *Vector {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 {
		t.Fatalf("loaded %d vectors, want 1 (fixtures/ isn't a vector)", len(vectors))
	}
	return vectors[0]
}

func TestLoadResolvesAllowlistFile(t *testing.T) {
	for _, tc := range []struct {
		name, members, wantErr string
	}{
		{name: "file", members: `"allowlistFile": "fixtures/list.json"`},
		{name: "inline", members: `"allowlist": ` + testList},
		{name: "both", members: `"allowlistFile": "fixtures/list.json", "allowlist": ` + testList, wantErr: "both allowlist and allowlistFile"},
		{name: "neither", wantErr: "neither allowlist nor allowlistFile"},
		{name: "parent", members: `"allowlistFile": "../list.json"`, wantErr: "isn't a local path"},
		{name: "absolute", members: `"allowlistFile": "/fixtures/list.json"`, wantErr: "isn't a local path"},
		{name: "missing", members: `"allowlistFile": "fixtures/none.json"`, wantErr: "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := loadOne(t, tc.members)
			if tc.wantErr != "" {
				wantLoadError(t, err, tc.wantErr)
				return
			}
			v := loadedOne(t, vectors, err)
			got := v.Allowlist.Clone()
			if err := got.Compact(); err != nil {
				t.Fatal(err)
			}
			if string(got) != `{"version":1}` || v.AllowlistFile != "" {
				t.Errorf("allowlist %s, allowlistFile %q; want the file's list inlined", got, v.AllowlistFile)
			}
		})
	}
}

func TestLoadResolvesRootsFile(t *testing.T) {
	const list = `"allowlistFile": "fixtures/list.json", `
	turin := map[string]string{"Turin": "PEM"}
	for _, tc := range []struct {
		name, members, wantErr string
		want                   map[string]string
	}{
		{name: "file", members: list + `"rootsFile": "fixtures/roots.json"`, want: turin},
		{name: "inline", members: list + `"roots": ` + testRoots, want: turin},
		{name: "pinned", members: `"allowlistFile": "fixtures/list.json"`},
		{name: "both", members: list + `"rootsFile": "fixtures/roots.json", "roots": ` + testRoots, wantErr: "both roots and rootsFile"},
		{name: "empty", members: list + `"rootsFile": "fixtures/empty.json"`, wantErr: "has no roots"},
		{name: "parent", members: list + `"rootsFile": "../roots.json"`, wantErr: "isn't a local path"},
		{name: "absolute", members: list + `"rootsFile": "/fixtures/roots.json"`, wantErr: "isn't a local path"},
		{name: "missing", members: list + `"rootsFile": "fixtures/none.json"`, wantErr: "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vectors, err := loadOne(t, tc.members)
			if tc.wantErr != "" {
				wantLoadError(t, err, tc.wantErr)
				return
			}
			v := loadedOne(t, vectors, err)
			if !maps.Equal(v.Roots, tc.want) || (v.Roots == nil) != (tc.want == nil) || v.RootsFile != "" {
				t.Errorf("roots %v, rootsFile %q; want %v", v.Roots, v.RootsFile, tc.want)
			}
		})
	}
}

func TestRunRefusesUnresolvedFiles(t *testing.T) {
	for name, vector := range map[string]string{
		"allowlist": `{"name": "v", "allowlistFile": "fixtures/list.json", "nonce": "00"}`,
		"roots":     `{"name": "v", "allowlist": {}, "rootsFile": "fixtures/roots.json", "nonce": "00"}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := Parse([]byte(vector))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "resolved") {
				t.Errorf("Run error %v, want an unresolved %s error", err, name)
			}
		})
	}
}
