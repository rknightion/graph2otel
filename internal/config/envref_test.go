package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateEnvDoc regenerates the committed docs/env-vars.md golden file instead of
// asserting it. Run: go test ./internal/config -run TestEnvReferenceDocInSync -update
var updateEnvDoc = flag.Bool("update", false, "rewrite generated golden files (docs/env-vars.md)")

func TestEnvVarName(t *testing.T) {
	cases := map[string]string{
		"log_level":                           "G2O_LOG_LEVEL",
		"checkpoint_dir":                      "G2O_CHECKPOINT_DIR",
		"otlp.endpoint":                       "G2O_OTLP__ENDPOINT",
		"otlp.grafana_cloud.instance_id":      "G2O_OTLP__GRAFANA_CLOUD__INSTANCE_ID",
		"otlp.grafana_cloud.token":            "G2O_OTLP__GRAFANA_CLOUD__TOKEN",
		"cardinality.metric_limit":            "G2O_CARDINALITY__METRIC_LIMIT",
		"profiling.pyroscope.basic_auth_user": "G2O_PROFILING__PYROSCOPE__BASIC_AUTH_USER",
		"profiling.mutex_profile_fraction":    "G2O_PROFILING__MUTEX_PROFILE_FRACTION",
	}
	for key, want := range cases {
		if got := envVarName(key); got != want {
			t.Errorf("envVarName(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestEnvVarNameRoundTripsEnvKey pins the two directions of the transform
// against each other: envKey (used by Load) and envVarName (used by the doc
// generator) must be exact inverses, so the documented variable is the one Load
// actually reads.
func TestEnvVarNameRoundTripsEnvKey(t *testing.T) {
	for _, key := range []string{
		"log_level", "checkpoint_dir", "otlp.endpoint",
		"otlp.grafana_cloud.token", "cardinality.metric_limit",
		"profiling.pyroscope.basic_auth_password", "profiling.block_profile_rate",
	} {
		if got := envKey(envVarName(key)); got != key {
			t.Errorf("envKey(envVarName(%q)) = %q, want round-trip to %q", key, got, key)
		}
	}
}

func TestEnvReferenceRowsClassification(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	rows, err := envReferenceRows(example)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	byKey := map[string]envRow{}
	for _, r := range rows {
		byKey[r.Key] = r
	}

	// A plain scalar: env-settable, default + description carried from the file.
	ep, ok := byKey["otlp.endpoint"]
	if !ok {
		t.Fatal("otlp.endpoint row missing")
	}
	if ep.FileOnly || ep.List {
		t.Errorf("otlp.endpoint should be a plain scalar, got %+v", ep)
	}
	if ep.EnvVar != "G2O_OTLP__ENDPOINT" {
		t.Errorf("otlp.endpoint env = %q", ep.EnvVar)
	}
	if ep.Desc == "" {
		t.Error("otlp.endpoint description not carried from the example comment")
	}

	// Structured values are file-only (no env var): the tenants list-of-structs
	// and the collectors / profiling.pyroscope.tags maps.
	for _, k := range []string{"tenants", "collectors", "profiling.pyroscope.tags"} {
		if r := byKey[k]; !r.FileOnly || r.EnvVar != "" {
			t.Errorf("%s should be file-only with no env var, got %+v", k, r)
		}
	}
}

func TestRenderEnvReferenceEscapesAndLists(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	block, err := renderEnvReference(example)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// log_level's comment contains pipes ("debug | info | …") — they must be
	// escaped so they don't break the markdown table.
	if strings.Contains(block, "debug | info") {
		t.Error("unescaped pipe in a table cell would break the markdown table")
	}
	if !strings.Contains(block, "G2O_LOG_LEVEL") {
		t.Error("expected log_level env var in the rendered table")
	}
	// File-only fields appear only in the trailing note, never as a row.
	if strings.Contains(block, "| `` |") {
		t.Error("a file-only field leaked into the table with an empty env var")
	}
	if !strings.Contains(block, "**File-only**") || !strings.Contains(block, "`tenants`") {
		t.Error("file-only note missing")
	}
}

// TestEnvReferenceDocInSync is the drift gate: docs/env-vars.md must equal the
// table generated from config.example.yaml. It rides the normal `go test` run
// (no separate tool/module), so it is already part of `make check`. Regenerate
// with `scripts/regen-generated.sh envref` or
// `go test ./internal/config -run TestEnvReferenceDocInSync -update`.
func TestEnvReferenceDocInSync(t *testing.T) {
	exPath := filepath.Join("..", "..", "config.example.yaml")
	docPath := filepath.Join("..", "..", "docs", "env-vars.md")

	example, err := os.ReadFile(exPath)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	block, err := renderEnvReference(example)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	current, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read docs/env-vars.md: %v", err)
	}
	want, err := spliceEnvReference(string(current), block)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}

	if *updateEnvDoc {
		if err := os.WriteFile(docPath, []byte(want), 0o644); err != nil { //nolint:gosec // G306: generated docs file is intentionally world-readable
			t.Fatalf("write docs/env-vars.md: %v", err)
		}
		t.Logf("regenerated %s", docPath)
		return
	}
	if want != string(current) {
		t.Errorf("docs/env-vars.md is out of date with config.example.yaml — regenerate with " +
			"`scripts/regen-generated.sh envref` (or `go test ./internal/config -run TestEnvReferenceDocInSync -update`) and commit the result")
	}
}
