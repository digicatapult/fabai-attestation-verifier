package seal

import (
	"reflect"
	"slices"
	"testing"
)

// TestNoRootOverride checks seal-check "No root override" for the library:
// the only configuration is Options, and none of its fields can carry a
// root, a signer identity or a clock.
func TestNoRootOverride(t *testing.T) {
	var fields []string
	for f := range reflect.TypeFor[Options]().Fields() {
		fields = append(fields, f.Name)
	}
	if want := []string{"Deadline", "Channel", "Transport"}; !slices.Equal(fields, want) {
		t.Errorf("Options fields are %v, want %v; review any new field against seal-check \"Pinned AMD roots\"", fields, want)
	}
}
