package config_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
	"go.yaml.in/yaml/v3"
)

// defaultKeySet is the canonical set of every leaf configuration key, derived by
// flattening the YAML encoding of Default(). Because the config structs carry no
// `omitempty`, every field — including zero-valued ones — appears, so this is the
// authoritative "every key" list that the example file and the Helm values are
// checked against. A leaf is a scalar, a list, or an empty map (e.g. collectors
// or profiling.pyroscope.tags); non-empty nested maps are recursed into.
func defaultKeySet(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := yaml.Marshal(config.Default())
	if err != nil {
		t.Fatalf("marshal defaults: %v", err)
	}
	return flattenYAMLKeys(t, raw)
}

func flattenYAMLKeys(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	return flattenMap(root)
}

func flattenMap(root map[string]any) map[string]bool {
	out := map[string]bool{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		m, ok := v.(map[string]any)
		if !ok || len(m) == 0 {
			if prefix != "" {
				out[prefix] = true
			}
			return
		}
		for k, child := range m {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			walk(path, child)
		}
	}
	walk("", root)
	return out
}

func diffKeys(want, got map[string]bool) (missing, extra []string) {
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// TestExampleConfigCoversEveryKey guards that config.example.yaml explicitly
// shows EVERY configuration key, not just that it loads and validates.
// TestConfigExampleLoadsAndValidates compares only the loaded result, which
// silently passes when a key is omitted (it falls back to the default), so it
// cannot catch a field that was added to the struct but never written into the
// example. This test compares the set of keys literally present in the file
// against the canonical key set from Default(): a missing key means the example
// is stale (add it, then regenerate docs/env-vars.md), an extra key means a
// typo/rename in the example. This is the "new config key forces a registry/doc
// update" gate — the analog of tailscale2otel's TestExampleConfigCoversEveryKey
// and opnsense-exporter's TestCollectorFlagsCoverAllSwitchFlags.
func TestExampleConfigCoversEveryKey(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	want := defaultKeySet(t)
	got := flattenYAMLKeys(t, data)

	missing, extra := diffKeys(want, got)
	if len(missing) > 0 {
		t.Errorf("config.example.yaml is missing %d key(s) defined by config.Default() — add them (and regenerate docs/env-vars.md) so the example documents every field:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("config.example.yaml has %d key(s) not in config.Default() — likely a typo or stale rename:\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
}

// TestHelmValuesConfigCoversEveryKey guards that the Helm chart's values.yaml
// `config:` block — rendered verbatim into the ConfigMap as config.yaml — covers
// EVERY configuration key, so the chart cannot silently drift from the config
// struct as fields are added. The comparison is key-set only (value-agnostic):
// the chart deliberately overrides some VALUES (e.g. admin.enabled defaults to
// true in the chart so the Deployment can wire probes, and checkpoint_dir points
// at the mounted volume), which is fine — only a missing/extra KEY is drift.
func TestHelmValuesConfigCoversEveryKey(t *testing.T) {
	path := filepath.Join("..", "..", "charts", "graph2otel", "values.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("chart values.yaml not found (%v) — Helm sync gate skipped", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("unmarshal values.yaml: %v", err)
	}
	cfg, ok := values["config"].(map[string]any)
	if !ok {
		t.Fatalf("values.yaml has no top-level `config:` mapping")
	}

	want := defaultKeySet(t)
	got := flattenMap(cfg)

	missing, extra := diffKeys(want, got)
	if len(missing) > 0 {
		t.Errorf("charts/graph2otel/values.yaml `config:` block is missing %d key(s) defined by config.Default() — add them so the chart documents every field:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("charts/graph2otel/values.yaml `config:` block has %d key(s) not in config.Default() — likely a typo or stale rename:\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
}
