//go:build sealtest && !js

package sealtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadResolvesAllowlistFile(t *testing.T) {
	const list = `{"version": 1}`
	for _, tc := range []struct {
		name, members, wantErr string
	}{
		{name: "file", members: `"allowlistFile": "fixtures/list.json"`},
		{name: "inline", members: `"allowlist": ` + list},
		{name: "both", members: `"allowlistFile": "fixtures/list.json", "allowlist": ` + list, wantErr: "both allowlist and allowlistFile"},
		{name: "neither", wantErr: "neither allowlist nor allowlistFile"},
		{name: "parent", members: `"allowlistFile": "../list.json"`, wantErr: "isn't a local path"},
		{name: "absolute", members: `"allowlistFile": "/fixtures/list.json"`, wantErr: "isn't a local path"},
		{name: "missing", members: `"allowlistFile": "fixtures/none.json"`, wantErr: "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "fixtures"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "fixtures", "list.json"), []byte(list), 0o644); err != nil {
				t.Fatal(err)
			}
			doc := `{"name": "v"`
			if tc.members != "" {
				doc += ", " + tc.members
			}
			if err := os.WriteFile(filepath.Join(dir, "v.json"), []byte(doc+"}"), 0o644); err != nil {
				t.Fatal(err)
			}

			vectors, err := Load(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(vectors) != 1 {
				t.Fatalf("loaded %d vectors, want 1 (fixtures/ isn't a vector)", len(vectors))
			}
			got := vectors[0].Allowlist.Clone()
			if err := got.Compact(); err != nil {
				t.Fatal(err)
			}
			if string(got) != `{"version":1}` || vectors[0].AllowlistFile != "" {
				t.Errorf("allowlist %s, allowlistFile %q; want the file's list inlined", got, vectors[0].AllowlistFile)
			}
		})
	}
}

func TestRunRefusesUnresolvedAllowlist(t *testing.T) {
	v, err := Parse([]byte(`{"name": "v", "allowlistFile": "fixtures/list.json", "nonce": "00"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "isn't resolved") {
		t.Errorf("Run error %v, want an unresolved allowlist error", err)
	}
}
