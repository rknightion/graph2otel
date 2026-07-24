package signalcatalog

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite spec/signal-catalog.json from the collector signal goldens")

// repoRoot is this package's directory two levels up: internal/signalcatalog.
const repoRoot = "../.."

// TestPrometheusName pins the OTLP -> Prometheus name derivation against the
// cases this repo has already shipped queries for. The [live] entries were
// verified against a live Grafana Cloud Mimir (alerts/README.md) or appear in a
// shipped dashboard; the rest exercise the algorithm's branches.
func TestPrometheusName(t *testing.T) {
	cases := []struct {
		name, unit, kind, want string
	}{
		// Annotation units carry no suffix at all.
		{"intune.device_encryption.devices", "{device}", "gauge", "intune_device_encryption_devices"},
		{"entra.credentials.expiring.total", "{credential}", "gauge", "entra_credentials_expiring_total"}, // [live]
		{"entra.secure_score.current", "{score}", "gauge", "entra_secure_score_current"},
		// Dimensionless gauges gain _ratio; dimensionless SUMS gain _total instead.
		{"intune.compliance.policy.version", "1", "gauge", "intune_compliance_policy_version_ratio"},
		{"mdca.discovery.parse.tasks", "1", "sum", "mdca_discovery_parse_tasks_total"}, // [live]
		{"graph2otel.api.unexpected", "1", "sum", "graph2otel_api_unexpected_total"},
		// Percent and time units.
		{"entra.secure_score.percentage", "%", "gauge", "entra_secure_score_percentage_percent"},
		{"mdca.discovery.parse.last_success.age", "s", "gauge", "mdca_discovery_parse_last_success_age_seconds"}, // [live]
		// A unit word already present in the name is NOT appended twice.
		{"intune.connector.heartbeat_age_seconds", "s", "gauge", "intune_connector_heartbeat_age_seconds"},
		{"intune.apple_token.days_until_expiry", "d", "gauge", "intune_apple_token_days_until_expiry"},                               // [live]
		{"intune.uxa.app_health.mean_time_to_failure_minutes", "min", "gauge", "intune_uxa_app_health_mean_time_to_failure_minutes"}, // [live]
		// Bytes.
		{"m365.onedrive.storage_used", "By", "gauge", "m365_onedrive_storage_used_bytes"},
		// Histograms keep their base name; the _bucket/_sum/_count series hang
		// off it at query time.
		{"intune.uxa.boot_time_ms", "ms", "histogram", "intune_uxa_boot_time_ms_milliseconds"},
	}
	for _, c := range cases {
		if got := PrometheusName(c.name, c.unit, c.kind); got != c.want {
			t.Errorf("PrometheusName(%q, %q, %q) = %q, want %q", c.name, c.unit, c.kind, got, c.want)
		}
	}
}

// TestLoadAggregatesEveryGolden proves the catalog is an aggregation of the
// committed goldens rather than a hand-kept list: every package's golden must
// contribute, and every cataloged metric must name at least one package.
func TestLoadAggregatesEveryGolden(t *testing.T) {
	cat, err := Load(repoRoot)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat.Metrics) == 0 || len(cat.Logs) == 0 {
		t.Fatalf("catalog is empty: %d metrics, %d logs", len(cat.Metrics), len(cat.Logs))
	}
	golden, err := filepath.Glob(filepath.Join(repoRoot, "internal", "collectors", "*", "*", "testdata", "signals.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(golden) != cat.PackageCount {
		t.Errorf("PackageCount = %d, want %d (one per committed golden)", cat.PackageCount, len(golden))
	}
	for _, m := range cat.Metrics {
		if len(m.Packages) == 0 {
			t.Errorf("metric %q names no package", m.Name)
		}
		if m.Domain == "" || !strings.HasPrefix(m.Name, m.Domain+".") {
			t.Errorf("metric %q has domain %q", m.Name, m.Domain)
		}
		if m.PrometheusName == "" {
			t.Errorf("metric %q has no prometheus_name", m.Name)
		}
	}
	for _, l := range cat.Logs {
		if len(l.Packages) == 0 {
			t.Errorf("log %q names no package", l.EventName)
		}
	}
}

// TestSignalCatalogInSync is the staleness gate: spec/signal-catalog.json is
// a pure function of the committed signal goldens, so it can never be stale
// without failing a plain `go test`. Regenerate with
// `scripts/regen-generated.sh catalog`.
func TestSignalCatalogInSync(t *testing.T) {
	cat, err := Load(repoRoot)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, err := Render(cat)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	path := filepath.Join(repoRoot, CatalogPath)
	if *update {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: fixed in-repo path
	if err != nil {
		t.Fatalf("reading %s (regenerate with `scripts/regen-generated.sh catalog`): %v", path, err)
	}
	if string(want) != string(body) {
		t.Errorf("%s is stale — the collector signal goldens changed.\n"+
			"Regenerate with: scripts/regen-generated.sh catalog", CatalogPath)
	}
}
