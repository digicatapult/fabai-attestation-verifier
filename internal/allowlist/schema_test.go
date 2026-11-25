package allowlist

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
)

func loadList(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// edit decodes the test list into generic JSON, applies change to its first
// entry (or to the list when entry is false), and re-encodes it.
func edit(t *testing.T, data []byte, change func(list, entry map[string]any)) []byte {
	t.Helper()
	var list map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	entry := list["entries"].([]any)[0].(map[string]any)
	change(list, entry)
	out, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecodeValid(t *testing.T) {
	list, err := Decode(loadList(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) != 2 || list.PlatformMinimum().SNP != 3 || list.Entries[0].Minimum().SNP != 4 {
		t.Errorf("unexpected list %+v", list)
	}
}

func TestSchemaFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(list, entry map[string]any)
		want   string
	}{
		{"malformed measurement", func(_, e map[string]any) { e["measurement"] = strings.ToUpper(e["measurement"].(string)) }, `entry "protected-turin-8cpu": measurement`},
		{"short measurement", func(_, e map[string]any) { e["measurement"] = "00" }, `entry "protected-turin-8cpu": measurement`},
		{"GPU architecture missing", func(_, e map[string]any) { delete(e["vmShape"].(map[string]any), "gpuArchitecture") }, `entry "protected-turin-8cpu": GPU architecture is missing`},
		{"GPU count missing", func(_, e map[string]any) { delete(e["vmShape"].(map[string]any), "gpus") }, `entry "protected-turin-8cpu": vmShape gpus is missing`},
		{"entry minimum below platform", func(_, e map[string]any) { e["minimumTcb"].(map[string]any)["snp"] = 2 }, `entry "protected-turin-8cpu": minimumTcb is below the platform minimum`},
		{"entry minimum missing a component", func(_, e map[string]any) { delete(e["minimumTcb"].(map[string]any), "microcode") }, `entry "protected-turin-8cpu": minimumTcb needs`},
		{"platform minimum missing", func(l, _ map[string]any) { delete(l, "platformMinimumTcb") }, "platform minimum TCB is missing"},
		{"HEAD firmware", func(_, e map[string]any) { e["firmware"].(map[string]any)["tag"] = "ovmf-head-20261101" }, "HEAD prerelease"},
		{"debug allowed", func(_, e map[string]any) { e["guestPolicy"].(map[string]any)["debug"] = true }, "allows debugging"},
		{"migration agent allowed", func(_, e map[string]any) { e["guestPolicy"].(map[string]any)["migrateMA"] = true }, "allows a migration agent"},
		{"unknown status", func(_, e map[string]any) { e["status"] = "pending" }, "isn't active or revoked"},
		{"unknown member", func(_, e map[string]any) { e["notes"] = "x" }, "unknown object member"},
		{"duplicate id", func(l, e map[string]any) { l["entries"].([]any)[1].(map[string]any)["id"] = e["id"] }, "duplicate entry id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(edit(t, loadList(t), tt.change))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestDuplicateMemberRefused(t *testing.T) {
	data := loadList(t)
	dup := strings.Replace(string(data), `"version": 1`, `"version": 1, "version": 1`, 1)
	if _, err := Decode([]byte(dup)); err == nil {
		t.Error("a duplicate member was accepted")
	}
	if !jsontext.Value(data).IsValid() {
		t.Fatal("test list isn't valid JSON")
	}
}
