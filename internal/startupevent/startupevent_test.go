package startupevent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/startupevent"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/version"
)

// processStart is a fixed, non-zero event time standing in for the real
// process start. Every test that emits uses it, so a record stamped with
// arrival time instead is immediately visible.
var processStart = time.Date(2026, 7, 27, 9, 15, 30, 0, time.UTC)

func twoTenantConfig() *config.Config {
	cfg := config.Default()
	cfg.Tenants = []config.TenantConfig{
		{TenantID: "11111111-1111-1111-1111-111111111111"},
		{TenantID: "22222222-2222-2222-2222-222222222222"},
	}
	return cfg
}

// TestEmitCarriesVersionFingerprintAndTenantCount pins the whole emitted
// contract for the no-tenant (stdout) shape: one log record, the canonical
// build version, the Go runtime version, a config fingerprint, and the
// configured tenant count.
func TestEmitCarriesVersionFingerprintAndTenantCount(t *testing.T) {
	rec := telemetrytest.New()
	cfg := config.Default()

	if err := startupevent.Emit(rec.Emitter(), cfg, processStart); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want exactly 1 for a no-tenant config", len(logs))
	}
	got := logs[0]
	if got.EventName != startupevent.EventName {
		t.Errorf("event name = %q, want %q", got.EventName, startupevent.EventName)
	}
	if got.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO", got.SeverityText)
	}
	if got.Attrs[semconv.AttrVersion] != version.String() {
		t.Errorf("%s = %q, want %q (internal/version is the one build-version source)",
			semconv.AttrVersion, got.Attrs[semconv.AttrVersion], version.String())
	}
	if got.Attrs[semconv.AttrGoVersion] != runtime.Version() {
		t.Errorf("%s = %q, want %q", semconv.AttrGoVersion, got.Attrs[semconv.AttrGoVersion], runtime.Version())
	}
	if got.Attrs[semconv.AttrConfigTenantCount] != "0" {
		t.Errorf("%s = %q, want 0", semconv.AttrConfigTenantCount, got.Attrs[semconv.AttrConfigTenantCount])
	}
	fp, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got.Attrs[semconv.AttrConfigFingerprint] != fp {
		t.Errorf("%s = %q, want %q", semconv.AttrConfigFingerprint, got.Attrs[semconv.AttrConfigFingerprint], fp)
	}
	if !strings.Contains(got.Body, version.String()) || !strings.Contains(got.Body, fp) {
		t.Errorf("body = %q, want it to name the version and the fingerprint", got.Body)
	}
	// A record with no tenant configured must NOT claim a tenant.
	if v, present := got.Attrs[semconv.AttrTenantID]; present {
		t.Errorf("%s = %q on a no-tenant config; an empty tenant must stamp nothing", semconv.AttrTenantID, v)
	}
}

// TestEmitStampsTheProcessStartTimeNotArrival is the #226 invariant: an event
// time this process genuinely knows must be stamped, and never left for the
// emitter to fill in with arrival time.
func TestEmitStampsTheProcessStartTimeNotArrival(t *testing.T) {
	rec := telemetrytest.New()
	if err := startupevent.Emit(rec.Emitter(), config.Default(), processStart); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	if !logs[0].Timestamp.Equal(processStart) {
		t.Errorf("record timestamp = %s, want the supplied process start %s",
			logs[0].Timestamp, processStart)
	}
}

// TestEmitRejectsAZeroStartTime: a zero Timestamp means "stamp me on arrival"
// to telemetry.Emitter, which for a startup marker would silently claim the
// process started when the record was exported. Unknown time => no record.
func TestEmitRejectsAZeroStartTime(t *testing.T) {
	rec := telemetrytest.New()
	err := startupevent.Emit(rec.Emitter(), config.Default(), time.Time{})
	if err == nil {
		t.Fatal("Emit with a zero start time returned nil; want an error")
	}
	if got := len(rec.LogRecords()); got != 0 {
		t.Errorf("emitted %d records with an unknown event time, want 0 (dropped, never stamped on arrival)", got)
	}

	// Same rule for a missing configuration: no fingerprint means no marker, not
	// a marker with a blank or invented one.
	if err := startupevent.Emit(rec.Emitter(), nil, processStart); err == nil {
		t.Error("Emit with a nil config returned nil; want an error")
	}
	if got := len(rec.LogRecords()); got != 0 {
		t.Errorf("emitted %d records with no configuration, want 0", got)
	}
}

// TestEmitOncePerConfiguredTenant pins the scope decision: the facts are
// process-wide but delivery is tenant-stamped, because every dashboard panel
// and annotation query filters on tenant_id and an unstamped marker is
// invisible on all of them.
func TestEmitOncePerConfiguredTenant(t *testing.T) {
	rec := telemetrytest.New()
	cfg := twoTenantConfig()

	if err := startupevent.Emit(rec.Emitter(), cfg, processStart); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != len(cfg.Tenants) {
		t.Fatalf("emitted %d records, want one per configured tenant (%d)", len(logs), len(cfg.Tenants))
	}
	fp, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	seen := map[string]bool{}
	inspected := 0
	for _, l := range logs {
		inspected++
		tenant := l.Attrs[semconv.AttrTenantID]
		if tenant == "" {
			t.Errorf("record %q carries no %s", l.Body, semconv.AttrTenantID)
		}
		if seen[tenant] {
			t.Errorf("tenant %q got two startup records", tenant)
		}
		seen[tenant] = true
		if l.Attrs[semconv.AttrConfigFingerprint] != fp {
			t.Errorf("tenant %q fingerprint = %q, want the process-wide %q",
				tenant, l.Attrs[semconv.AttrConfigFingerprint], fp)
		}
		if l.Attrs[semconv.AttrConfigTenantCount] != "2" {
			t.Errorf("tenant %q tenant_count = %q, want 2", tenant, l.Attrs[semconv.AttrConfigTenantCount])
		}
	}
	if inspected != len(cfg.Tenants) {
		t.Fatalf("inspected %d records, want %d", inspected, len(cfg.Tenants))
	}
	for _, tenant := range cfg.Tenants {
		if !seen[tenant.TenantID] {
			t.Errorf("no startup record for configured tenant %q", tenant.TenantID)
		}
	}
}

// TestEmittedVersionMatchesBuildInfo is the cross-check the version-source
// defect asks for: the startup marker and graph2otel.build_info must report the
// same string, from the same source, or a deploy annotation and the build_info
// gauge can disagree about which version is running.
func TestEmittedVersionMatchesBuildInfo(t *testing.T) {
	// Override the ldflags-stamped version away from its "dev" default. Without
	// this the assertion is satisfied by a hardcoded literal that happens to
	// equal the default — which is exactly the second-version-source defect this
	// test exists to catch. (Found by deliberately sabotaging the emit site.)
	old := version.Version
	version.Version = "42.0.0-crosscheck"
	t.Cleanup(func() { version.Version = old })

	buildRec := telemetrytest.New()
	collector.EmitBuildInfo(buildRec.Emitter())
	points := buildRec.MetricPoints(collector.MetricBuildInfo)
	if len(points) != 1 {
		t.Fatalf("build_info points = %d, want 1", len(points))
	}

	startRec := telemetrytest.New()
	if err := startupevent.Emit(startRec.Emitter(), config.Default(), processStart); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	logs := startRec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("startup records = %d, want 1", len(logs))
	}

	for _, key := range []string{semconv.AttrVersion, semconv.AttrGoVersion} {
		if got, want := logs[0].Attrs[key], points[0].Attrs[key]; got != want {
			t.Errorf("%s: startup marker = %q, build_info = %q — they must share one source", key, got, want)
		}
	}
}

// TestFingerprintIsStableAndOneWayShaped pins the emitted form: 16 lowercase
// hex characters, deterministic across repeated calls on an equal config.
func TestFingerprintIsStableAndOneWayShaped(t *testing.T) {
	cfg := twoTenantConfig()
	first, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	second, err := startupevent.Fingerprint(twoTenantConfig())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if first != second {
		t.Errorf("fingerprint is not deterministic: %q then %q", first, second)
	}
	if len(first) != 16 {
		t.Errorf("fingerprint %q is %d characters, want 16", first, len(first))
	}
	for _, r := range first {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("fingerprint %q contains non-lowercase-hex %q", first, r)
		}
	}
}

// TestFingerprintMovesForEveryOperationallyMeaningfulChange is the sensitivity
// half of the contract. Each mutation is a change an operator would expect a
// "configuration changed" marker to report.
func TestFingerprintMovesForEveryOperationallyMeaningfulChange(t *testing.T) {
	base := config.Default()
	baseFP, err := startupevent.Fingerprint(base)
	if err != nil {
		t.Fatalf("Fingerprint(base): %v", err)
	}

	enabled := false
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"log_level", func(c *config.Config) { c.LogLevel = "debug" }},
		{"otlp.endpoint", func(c *config.Config) { c.OTLP.Endpoint = "https://otlp.example.invalid:443" }},
		{"otlp.protocol", func(c *config.Config) { c.OTLP.Protocol = "stdout" }},
		{"otlp.grafana_cloud.instance_id", func(c *config.Config) { c.OTLP.GrafanaCloud.InstanceID = "123456" }},
		{"checkpoint_dir", func(c *config.Config) { c.CheckpointDir = "/var/lib/graph2otel-new" }},
		{"cardinality.per_metric_limit", func(c *config.Config) { c.Cardinality.PerMetricLimit = 1234 }},
		{"cardinality.global_limit", func(c *config.Config) { c.Cardinality.GlobalLimit = 12345 }},
		{"admin.enabled", func(c *config.Config) { c.Admin.Enabled = !c.Admin.Enabled }},
		{"admin.addr", func(c *config.Config) { c.Admin.Addr = "127.0.0.1:9999" }},
		{"backfill.initial_lookback", func(c *config.Config) { c.Backfill.InitialLookback = 72 * time.Hour }},
		{"cost.enabled", func(c *config.Config) { c.Cost.Enabled = !c.Cost.Enabled }},
		{"profiling.pyroscope.enabled", func(c *config.Config) { c.Profiling.Pyroscope.Enabled = true }},
		{"profiling.pyroscope.server_address", func(c *config.Config) {
			c.Profiling.Pyroscope.ServerAddress = "https://pyroscope.example.invalid"
		}},
		{"collector disabled", func(c *config.Config) {
			c.Collectors = map[string]config.CollectorConfig{"entra.signins": {Enabled: &enabled}}
		}},
		{"collector interval", func(c *config.Config) {
			c.Collectors = map[string]config.CollectorConfig{"entra.signins": {Interval: 7 * time.Minute}}
		}},
		{"collector transport", func(c *config.Config) {
			c.Collectors = map[string]config.CollectorConfig{"entra.signins": {Source: "blob"}}
		}},
		{"tenant added", func(c *config.Config) {
			c.Tenants = append(c.Tenants, config.TenantConfig{TenantID: "33333333-3333-3333-3333-333333333333"})
		}},
		{"tenant blob ingest enabled", func(c *config.Config) {
			c.Tenants = []config.TenantConfig{{
				TenantID:   "11111111-1111-1111-1111-111111111111",
				BlobIngest: config.BlobIngestConfig{AccountURL: "https://example.blob.core.windows.net"},
			}}
		}},
		{"secret becomes set", func(c *config.Config) { c.OTLP.GrafanaCloud.Token = config.Secret("a-token") }},
	}

	inspected := 0
	for _, tc := range cases {
		cfg := config.Default()
		tc.mutate(cfg)
		got, ferr := startupevent.Fingerprint(cfg)
		if ferr != nil {
			t.Errorf("%s: Fingerprint: %v", tc.name, ferr)
			continue
		}
		inspected++
		if got == baseFP {
			t.Errorf("%s: fingerprint did not move (%q) — the marker would report no change", tc.name, got)
		}
	}
	if inspected != len(cases) {
		t.Fatalf("inspected %d mutations, want %d", inspected, len(cases))
	}
}

// TestFingerprintDoesNotMoveWhenNothingChanges is the specificity half: a
// restart with an unchanged config must produce an unchanged fingerprint, or
// every restart looks like a configuration change.
func TestFingerprintDoesNotMoveWhenNothingChanges(t *testing.T) {
	before, err := startupevent.Fingerprint(twoTenantConfig())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	// A different Config VALUE with identical content — the shape a restart
	// produces.
	after, err := startupevent.Fingerprint(twoTenantConfig())
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if before != after {
		t.Errorf("fingerprint moved with no configuration change: %q -> %q", before, after)
	}

	// And the same through the REAL loader, twice over one unchanged file. This is
	// the path production takes, and it is the one that exercises map-valued keys
	// (collectors, pyroscope tags) whose iteration order is unspecified in Go — a
	// canonicalizer that leaked that order would make every restart look like a
	// configuration change, on the multi-collector configs where it matters most.
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "otlp:\n  protocol: stdout\ncollectors:\n" +
		"  \"entra.signins.interactive\":\n    interval: 9m\n" +
		"  \"entra.directory_audits\":\n    enabled: false\n" +
		"  \"intune.devices\":\n    interval: 11m\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var loaded []string
	for range 2 {
		cfg, lerr := config.Load(path)
		if lerr != nil {
			t.Fatalf("load config: %v", lerr)
		}
		fp, ferr := startupevent.Fingerprint(cfg)
		if ferr != nil {
			t.Fatalf("Fingerprint: %v", ferr)
		}
		loaded = append(loaded, fp)
	}
	if len(loaded) != 2 {
		t.Fatalf("computed %d fingerprints, want 2", len(loaded))
	}
	if loaded[0] != loaded[1] {
		t.Errorf("fingerprint of one unchanged config file is not stable across loads: %q -> %q",
			loaded[0], loaded[1])
	}
}

// TestFingerprintIgnoresARotatedSecretValue: rotating a credential is not an
// operationally-meaningful CONFIGURATION change, and more importantly the
// fingerprint must not be a function of secret bytes at all.
func TestFingerprintIgnoresARotatedSecretValue(t *testing.T) {
	first := config.Default()
	first.OTLP.GrafanaCloud.Token = config.Secret("glc_the-first-token")
	first.Profiling.Pyroscope.BasicAuthPassword = config.Secret("first-password")
	second := config.Default()
	second.OTLP.GrafanaCloud.Token = config.Secret("glc_a-completely-different-token")
	second.Profiling.Pyroscope.BasicAuthPassword = config.Secret("second-password")

	a, err := startupevent.Fingerprint(first)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	b, err := startupevent.Fingerprint(second)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if a != b {
		t.Errorf("fingerprint is a function of secret bytes: %q vs %q", a, b)
	}
}

// TestNoEmittedFieldCarriesASecret sweeps the body and every attribute value of
// every emitted record for the sentinel credential values. This is the whole
// privacy contract of #310 and it is checked over the RECORD, not the hash
// input, so a future attribute cannot leak one either.
func TestNoEmittedFieldCarriesASecret(t *testing.T) {
	const (
		tokenSentinel    = "SECRET-OTLP-TOKEN-b7f2"
		passwordSentinel = "SECRET-PYROSCOPE-PASSWORD-91ac"
	)
	cfg := twoTenantConfig()
	cfg.OTLP.GrafanaCloud.Token = config.Secret(tokenSentinel)
	cfg.Profiling.Pyroscope.BasicAuthPassword = config.Secret(passwordSentinel)

	rec := telemetrytest.New()
	if err := startupevent.Emit(rec.Emitter(), cfg, processStart); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) == 0 {
		t.Fatal("no records emitted; the sweep would pass vacuously")
	}
	inspected := 0
	for _, l := range logs {
		fields := map[string]string{"<body>": l.Body}
		for k, v := range l.Attrs {
			fields[k] = v
		}
		for name, value := range fields {
			inspected++
			for _, secret := range []string{tokenSentinel, passwordSentinel} {
				if strings.Contains(value, secret) {
					t.Errorf("field %q leaks a credential: %q contains %q", name, value, secret)
				}
			}
		}
	}
	if inspected == 0 {
		t.Fatal("inspected no fields; the sweep would pass vacuously")
	}
}
