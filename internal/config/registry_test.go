package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// stringSliceFieldPaths walks the Config struct and returns the dotted yaml-key
// path of every []string field. These are exactly the scalar-list fields whose
// environment value would have to be comma-split, so the result must equal the
// listEnvKeys registry. Slices of structs (tenants) and maps (collectors,
// profiling.pyroscope.tags) are file-only and deliberately excluded.
func stringSliceFieldPaths(t reflect.Type, prefix string, out map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported — not a config key
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		switch f.Type.Kind() {
		case reflect.Struct:
			stringSliceFieldPaths(f.Type, path, out)
		case reflect.Slice:
			if f.Type.Elem().Kind() == reflect.String {
				out[path] = true
			}
		}
	}
}

// TestListEnvKeysMatchesStringSliceFields guards that listEnvKeys (the registry
// the env-var-reference generator consults to decide which sequence keys are
// comma-separated env vars rather than file-only) stays in sync with the actual
// []string fields on Config. graph2otel has none today, so both sides are empty.
// Add a []string config field without registering it here and this fails with
// the exact offending key — the reminder to both register it AND teach
// envTransform to comma-split its value; register a key that matches no []string
// field and the entry is dead.
func TestListEnvKeysMatchesStringSliceFields(t *testing.T) {
	fields := map[string]bool{}
	stringSliceFieldPaths(reflect.TypeOf(Config{}), "", fields)

	var unregistered, stale []string
	for k := range fields {
		if !listEnvKeys[k] {
			unregistered = append(unregistered, k)
		}
	}
	for k := range listEnvKeys {
		if !fields[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("[]string config field(s) missing from listEnvKeys (their env value won't be comma-split, and the generated doc won't mark them as lists):\n  %s",
			strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("listEnvKeys entries that match no []string field (dead/renamed):\n  %s",
			strings.Join(stale, "\n  "))
	}
}
