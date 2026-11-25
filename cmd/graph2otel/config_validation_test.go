package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestCollectorOverrideInventoryHas177LogicalNamesAcrossAllSevenPaths(t *testing.T) {
	known, _ := collectorOverrideInventory()

	if got, want := len(known), 179; got != want {
		t.Fatalf("logical collector names = %d, want %d", got, want)
	}
	for path, name := range map[string]string{
		"snapshot": "entra.users",
		"window":   "intune.audit_events",
		"blob":     "defender.alert_info",
		"o365":     "m365.activity",
		"mdca":     "mdca.discovery_parse",
		"exo":      "m365.exchange_org_config",
		"hunt":     "defender.vulnerabilities",
	} {
		if !known[name] {
			t.Errorf("%s registration-path collector %q is missing from the override inventory", path, name)
		}
	}
}

func TestCollectorOverrideInventoryDerivesSwitchableNamesFromPolledBlobIntersection(t *testing.T) {
	_, got := collectorOverrideInventory()
	wantNames := map[string]bool{
		"entra.directory_audits": true,
		"entra.provisioning":     true,
		"entra.risk_detections":  true,
	}
	if !maps.Equal(got, wantNames) {
		t.Errorf("source-switchable inventory = %v, want %v", got, wantNames)
	}

	snapshot, window, blob, _, _, _, _ := registrySnapshot()
	polled := namesOfCollectors(t, snapshot, window)
	blobNames := namesOfCollectors(t, blob)
	want := make(map[string]bool)
	for name := range blobNames {
		if polled[name] {
			want[name] = true
		}
	}

	if !maps.Equal(got, want) {
		t.Errorf("source-switchable inventory = %v, want Graph snapshot/window ∩ blob candidates %v", got, want)
	}
}

func TestShippedCollectorOverrideExamplesUseRuntimeName(t *testing.T) {
	const collectorName = "entra.signins.interactive"

	known, _ := collectorOverrideInventory()
	if !known[collectorName] {
		t.Fatalf("shipped example collector %q is absent from the runtime inventory", collectorName)
	}

	envName := "G2O_COLLECTORS__" + strings.ToUpper(collectorName) + "__ENABLED"
	examples := []struct {
		path     string
		required []string
	}{
		{
			path: "../../README.md",
			required: []string{
				`#   "` + collectorName + `":`,
				envName + "=false",
			},
		},
		{
			path: "../../charts/graph2otel/values.yaml",
			required: []string{
				`#   "` + collectorName + `":`,
				`--set 'config.collectors.entra\.signins\.interactive.enabled=false'`,
			},
		},
		{
			path: "../../charts/graph2otel/README.md",
			required: []string{
				`"` + collectorName + `":`,
			},
		},
	}

	for _, example := range examples {
		t.Run(example.path, func(t *testing.T) {
			raw, err := os.ReadFile(example.path)
			if err != nil {
				t.Fatalf("read shipped example: %v", err)
			}
			for _, required := range example.required {
				if !strings.Contains(string(raw), required) {
					t.Errorf("shipped example does not contain runtime-valid override %q", required)
				}
			}
			for _, stale := range []string{"sign_ins", "G2O_COLLECTORS__SIGN_INS__ENABLED"} {
				if strings.Contains(string(raw), stale) {
					t.Errorf("shipped example still contains invalid collector override %q", stale)
				}
			}
		})
	}
}

func namesOfCollectors(t *testing.T, groups ...[]any) map[string]bool {
	t.Helper()
	names := make(map[string]bool)
	for _, group := range groups {
		for _, candidate := range group {
			named, ok := candidate.(interface{ Name() string })
			if !ok {
				t.Fatalf("%T has no Name()", candidate)
			}
			names[named.Name()] = true
		}
	}
	return names
}

func TestHelmCollectorSchemaMatchesRuntimeInventory(t *testing.T) {
	raw, err := os.ReadFile("../../charts/graph2otel/values.schema.json")
	if err != nil {
		t.Fatalf("read Helm values schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode Helm values schema: %v", err)
	}

	known, sourceSwitchable := collectorOverrideInventory()
	definitions := schemaObjectAt(t, schema, "definitions")
	collectorNames := schemaStringSet(t, schemaObjectAt(t, definitions, "collectorName"), "enum")
	assertSameStringSet(t, "Helm collector-name enum", collectorNames, known)

	collectorOverrides := schemaObjectAt(t, definitions, "collectorOverrides")
	switchableProperties := schemaObjectAt(t, collectorOverrides, "properties")
	schemaSwitchable := make(map[string]bool, len(switchableProperties))
	for name, rawProperty := range switchableProperties {
		schemaSwitchable[name] = true
		property, ok := rawProperty.(map[string]any)
		if !ok {
			t.Errorf("definitions.collectorOverrides.properties[%q] = %T, want object", name, rawProperty)
			continue
		}
		if got := schemaRefAt(t, property); got != "#/definitions/sourceSwitchableCollectorOverride" {
			t.Errorf("definitions.collectorOverrides.properties[%q].$ref = %q, want source-switchable override", name, got)
		}
	}
	assertSameStringSet(t, "Helm source-switchable property names", schemaSwitchable, sourceSwitchable)

	additional := schemaObjectAt(t, collectorOverrides, "additionalProperties")
	if got := schemaRefAt(t, additional); got != "#/definitions/collectorOverride" {
		t.Errorf("definitions.collectorOverrides.additionalProperties.$ref = %q, want #/definitions/collectorOverride", got)
	}

	globalCollectors := schemaObjectAt(t, schema, "properties", "config", "properties", "collectors")
	if got := schemaRefAt(t, globalCollectors); got != "#/definitions/collectorOverrides" {
		t.Errorf("config.collectors.$ref = %q, want #/definitions/collectorOverrides", got)
	}
	tenantCollectors := schemaObjectAt(t, schema, "properties", "config", "properties", "tenants", "items", "properties", "collectors")
	if got := schemaRefAt(t, tenantCollectors); got != "#/definitions/collectorOverrides" {
		t.Errorf("config.tenants[].collectors.$ref = %q, want #/definitions/collectorOverrides", got)
	}
}

func schemaObjectAt(t *testing.T, root map[string]any, path ...string) map[string]any {
	t.Helper()
	current := root
	for _, segment := range path {
		next, ok := current[segment].(map[string]any)
		if !ok {
			t.Fatalf("Helm schema path %q = %T, want object", strings.Join(path, "."), current[segment])
		}
		current = next
	}
	return current
}

func schemaStringSet(t *testing.T, object map[string]any, key string) map[string]bool {
	t.Helper()
	values, ok := object[key].([]any)
	if !ok {
		t.Fatalf("Helm schema key %q = %T, want array", key, object[key])
	}
	set := make(map[string]bool, len(values))
	for i, value := range values {
		name, ok := value.(string)
		if !ok {
			t.Fatalf("Helm schema %s[%d] = %T, want string", key, i, value)
		}
		if set[name] {
			t.Errorf("Helm schema %s contains duplicate %q", key, name)
		}
		set[name] = true
	}
	return set
}

func schemaRefAt(t *testing.T, object map[string]any) string {
	t.Helper()
	ref, ok := object["$ref"].(string)
	if !ok {
		t.Errorf("Helm schema object has no string $ref: %v", object)
		return ""
	}
	return ref
}

func assertSameStringSet(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	if maps.Equal(got, want) {
		return
	}
	missing := make([]string, 0)
	extra := make([]string, 0)
	for name := range want {
		if !got[name] {
			missing = append(missing, name)
		}
	}
	for name := range got {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	t.Errorf("%s differs from runtime inventory: missing=%v extra=%v", label, missing, extra)
}

func TestLoadValidatedConfigRejectsUnknownCollectorNames(t *testing.T) {
	tests := []struct {
		name           string
		collector      string
		wantSuggestion string
	}{
		{
			name:           "unambiguous typo suggests known name",
			collector:      "entra.directory_audit",
			wantSuggestion: `did you mean "entra.directory_audits"`,
		},
		{
			name:      "distant name has no suggestion",
			collector: "totally.not_a_collector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, "otlp:\n  protocol: stdout\ncollectors:\n  "+tt.collector+":\n    enabled: false\n")
			_, err := loadValidatedConfig(path)
			if err == nil {
				t.Fatalf("loadValidatedConfig accepted unknown collector %q", tt.collector)
			}
			if !strings.Contains(err.Error(), `collectors["`+tt.collector+`"]`) {
				t.Errorf("error %q does not name collector path", err)
			}
			if tt.wantSuggestion != "" && !strings.Contains(err.Error(), tt.wantSuggestion) {
				t.Errorf("error %q does not contain suggestion %q", err, tt.wantSuggestion)
			}
			if tt.wantSuggestion == "" && strings.Contains(err.Error(), "did you mean") {
				t.Errorf("error %q contains a suggestion for a distant name", err)
			}
		})
	}
}

func TestLoadValidatedConfigReportsUnknownEnvironmentCollectorBeforeInvalidInterval(t *testing.T) {
	const variable = "G2O_COLLECTORS__ENTRA.DIRECTORY_AUDIT__INTERVAL"
	t.Setenv(variable, "500ms")

	path := writeTempConfig(t, "otlp:\n  protocol: stdout\n")
	_, err := loadValidatedConfig(path)
	if err == nil {
		t.Fatal("loadValidatedConfig accepted an unknown environment collector with an invalid interval")
	}
	if !strings.Contains(err.Error(), variable) {
		t.Errorf("error %q does not name exact environment variable %q", err, variable)
	}
	if !strings.Contains(err.Error(), "unknown collector") {
		t.Errorf("error %q does not prioritize the unknown collector diagnostic", err)
	}
	if strings.Contains(err.Error(), ".interval:") {
		t.Errorf("error %q validated the interval before the unknown collector name", err)
	}
}

func TestRunAndCheckRejectCollectorSourcesBeforeConstructors(t *testing.T) {
	tests := []struct {
		name      string
		collector string
		source    string
	}{
		{
			name:      "invalid source spelling",
			collector: "entra.directory_audits",
			source:    "bolb",
		},
		{
			name:      "source on non-switchable collector",
			collector: "entra.users",
			source:    "blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, "otlp:\n  protocol: stdout\ntenants:\n  - tenant_id: tenant-a\ncollectors:\n  "+tt.collector+":\n    source: "+tt.source+"\n")

			t.Run("startup", func(t *testing.T) {
				constructorCalls := 0
				original := buildTelemetryProvider
				buildTelemetryProvider = func(context.Context, *config.Config, io.Writer) (*telemetry.Provider, error) {
					constructorCalls++
					return nil, errors.New("telemetry constructor sentinel")
				}
				t.Cleanup(func() { buildTelemetryProvider = original })

				var stdout, stderr bytes.Buffer
				code := run(context.Background(), []string{"-config", path}, &stdout, &stderr)
				if code != 1 {
					t.Fatalf("run() = %d, want 1; stderr=%s", code, stderr.String())
				}
				if constructorCalls != 0 {
					t.Fatalf("telemetry constructor calls = %d, want zero", constructorCalls)
				}
				assertSourceValidationDiagnostic(t, stderr.String(), tt.collector)
			})

			t.Run("check", func(t *testing.T) {
				constructorCalls := 0
				original := buildTenantAuths
				buildTenantAuths = func([]config.TenantConfig) ([]*auth.TenantAuth, error) {
					constructorCalls++
					return nil, errors.New("credential constructor sentinel")
				}
				t.Cleanup(func() { buildTenantAuths = original })

				var stdout, stderr bytes.Buffer
				code := dispatch(context.Background(), []string{"check", "-config", path}, &stdout, &stderr)
				if code != 1 {
					t.Fatalf("dispatch(check) = %d, want 1; stderr=%s", code, stderr.String())
				}
				if constructorCalls != 0 {
					t.Fatalf("credential constructor calls = %d, want zero", constructorCalls)
				}
				assertSourceValidationDiagnostic(t, stderr.String(), tt.collector)
			})
		})
	}
}

func TestRunAndCheckValidateTenantTeamsConfigBeforeConstructors(t *testing.T) {
	const base = "otlp:\n  protocol: stdout\ntenants:\n  - tenant_id: 00000000-0000-0000-0000-000000000000\n"
	csv := filepath.Join(t.TempDir(), "sites.csv")
	if err := os.WriteFile(csv, []byte("wrong,header\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalTelemetry, originalAuth := buildTelemetryProvider, buildTenantAuths
	var receivedConfig *config.Config
	buildTelemetryProvider = func(_ context.Context, cfg *config.Config, _ io.Writer) (*telemetry.Provider, error) {
		receivedConfig = cfg
		return nil, errors.New("unexpected telemetry constructor")
	}
	buildTenantAuths = func([]config.TenantConfig) ([]*auth.TenantAuth, error) {
		return nil, errors.New("unexpected credential constructor")
	}
	t.Cleanup(func() { buildTelemetryProvider, buildTenantAuths = originalTelemetry, originalAuth })

	for _, tc := range []struct {
		name, yaml, field, reason string
	}{
		{"missing CSV", fmt.Sprintf("sites_file: %q", csv+".missing"), "sites_file", "read Teams sites file"},
		{"invalid CSV", fmt.Sprintf("sites_file: %q", csv), "sites_file", "expected CSV header"},
		{"invalid domain", `internal_domains: ["*example.test"]`, "internal_domains", "expected a DNS domain"},
		{"scalar domains", `internal_domains: example.test`, "internal_domains", "expected a list"},
		{"numeric domain", `internal_domains: [123]`, "internal_domains[0]", "expected a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, base+"    teams:\n      "+tc.yaml+"\n")
			for _, prefix := range [][]string{nil, {"check"}} {
				var stdout, stderr bytes.Buffer
				code := dispatch(context.Background(), append(prefix, "-config", path), &stdout, &stderr)
				diagnostic := stderr.String()
				if code != 1 || !strings.Contains(diagnostic, "tenants[0].teams."+tc.field) ||
					!strings.Contains(diagnostic, tc.reason) || strings.Contains(diagnostic, "unexpected") {
					t.Errorf("dispatch(%v) = %d, stderr=%q; want tenant field and %q before constructors", prefix, code, diagnostic, tc.reason)
				}
			}
		})
	}

	t.Run("singleton mapping validates before constructors", func(t *testing.T) {
		singleton := strings.Replace(base, "  - tenant_id:", "  tenant_id:", 1)
		path := writeTempConfig(t, singleton+"  teams:\n    internal_domains: 123\n")
		for _, prefix := range [][]string{nil, {"check"}} {
			var stdout, stderr bytes.Buffer
			code := dispatch(context.Background(), append(prefix, "-config", path), &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "tenants[0].teams.internal_domains: expected a list") {
				t.Errorf("dispatch(%v) = %d, stderr=%q; want singleton tenant field validation", prefix, code, stderr.String())
			}
		}
		valid := writeTempConfig(t, singleton+"  teams:\n    internal_domains: [example.com]\n")
		cfg, err := config.Load(valid)
		if err != nil {
			t.Fatal(err)
		}
		_, domains := cfg.TeamsSiteInputs("00000000-0000-0000-0000-000000000000")
		if !domains.IsInternal("user@example.com") {
			t.Fatal("valid singleton form did not supply its site's domain rules")
		}
	})

	t.Run("valid config reaches startup", func(t *testing.T) {
		if err := os.WriteFile(csv, []byte("subnet,location,country,latitude,longitude\n192.0.2.0/24,Test site,ZZ,0,0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		const otherTenant = "11111111-1111-1111-1111-111111111111"
		path := writeTempConfig(t, base+fmt.Sprintf(`    teams:
      sites_file: %q
      internal_domains: [example.com, '*.example.com']
      vaac:
        enabled: true
        username_file: /synthetic/no-such-username
        password_file: /synthetic/no-such-password
  - tenant_id: %s
`, csv, otherTenant))
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"-config", path}, &stdout, &stderr)
		// Reaching the injected constructor proves the config was accepted; it
		// stops the CLI before any side effects or tenant credential use.
		if code != 1 || !strings.Contains(stderr.String(), "unexpected telemetry constructor") || receivedConfig == nil {
			t.Fatalf("run() = %d, stderr=%q; want valid config to reach the constructor", code, stderr.String())
		}
		if err := os.Remove(csv); err != nil {
			t.Fatal(err)
		}
		file, domains := receivedConfig.TeamsSiteInputs("00000000-0000-0000-0000-000000000000")
		if file == nil {
			t.Fatal("configured tenant has no prepared site file")
		}
		if got, _ := file.Snapshot().Lookup("", "192.0.2.5", ""); got.Name != "Test site" || got.Country != "ZZ" {
			t.Errorf("prepared lookup = %+v, want Test site in ZZ", got)
		}
		if !domains.IsInternal("user@sub.example.com") {
			t.Error("configured tenant's wildcard did not match")
		}
		if !receivedConfig.TenantVAAC("00000000-0000-0000-0000-000000000000").Enabled || receivedConfig.TenantVAAC(otherTenant).Enabled {
			t.Fatal("VAAC opt-in was lost or inherited by an unconfigured tenant")
		}
		if file, domains := receivedConfig.TeamsSiteInputs(otherTenant); file != nil || domains.IsInternal("user@sub.example.com") {
			t.Error("unconfigured tenant inherited another tenant's Teams enrichment")
		}
	})
}

func TestRunAndCheckValidateTeamsQualityThresholds(t *testing.T) {
	const base = "otlp:\n  protocol: stdout\nteams:\n  quality_thresholds:\n"
	for _, tc := range []struct{ yaml, diagnostic string }{
		{"    min_packets: 500.5\n", "teams.quality_thresholds.min_packets: expected an integer"},
		{"    min_packets: 9223372036854775808\n", "teams.quality_thresholds.min_packets: expected an integer"},
		{"    video_frame_loss_percent: 101\n", "teams.quality_thresholds.video_frame_loss_percent: expected a percentage"},
		{"    audio_jitter_ms: .nan\n", "teams.quality_thresholds.audio_jitter_ms: expected a finite non-negative number"},
		{"    audio_packet_loss_ratio: 1.1\n", "teams.quality_thresholds.audio_packet_loss_ratio: expected a ratio between 0 and 1"},
		{"    audio_rtt_ms: \"500\"\n", "teams.quality_thresholds.audio_rtt_ms: expected a number"},
		{"    vid_frame_rate_fps: 7\n", "unknown configuration key teams.quality_thresholds.vid_frame_rate_fps"},
	} {
		t.Run(strings.TrimSpace(tc.yaml), func(t *testing.T) {
			path := writeTempConfig(t, base+tc.yaml)
			for _, prefix := range [][]string{nil, {"check"}} {
				var stdout, stderr bytes.Buffer
				code := dispatch(t.Context(), append(prefix, "-config", path), &stdout, &stderr)
				if code != 1 || !strings.Contains(stderr.String(), tc.diagnostic) {
					t.Errorf("dispatch(%v) = %d, stderr=%q; want %q", prefix, code, stderr.String(), tc.diagnostic)
				}
			}
		})
	}
	t.Run("YAML and environment overrides reach startup", func(t *testing.T) {
		t.Setenv("G2O_TEAMS__QUALITY_THRESHOLDS__AUDIO_JITTER_MS", "0")
		path := writeTempConfig(t, base+"    audio_jitter_ms: 25\n    video_post_fec_loss_ratio: 0.05\n")
		original := buildTelemetryProvider
		var got *config.Config
		buildTelemetryProvider = func(_ context.Context, cfg *config.Config, _ io.Writer) (*telemetry.Provider, error) {
			got = cfg
			return nil, errors.New("constructor sentinel")
		}
		t.Cleanup(func() { buildTelemetryProvider = original })
		var stdout, stderr bytes.Buffer
		if code := dispatch(t.Context(), []string{"-config", path}, &stdout, &stderr); code != 1 || got == nil || !strings.Contains(stderr.String(), "constructor sentinel") {
			t.Fatalf("dispatch = %d, stderr=%q; expected valid settings to reach the constructor", code, stderr.String())
		}
		q := got.Teams.QualityThresholds
		if q.AudioJitterMs != 0 || q.VideoPostFECLoss != 0.05 || q.MinPackets != 500 {
			t.Errorf("quality thresholds = %+v; want environment jitter 0, YAML post-FEC loss 0.05, default packets 500", q)
		}
	})
}

func assertSourceValidationDiagnostic(t *testing.T, diagnostic, collectorName string) {
	t.Helper()
	wantPath := `collectors["` + collectorName + `"].source`
	if !strings.Contains(diagnostic, wantPath) {
		t.Errorf("diagnostic %q does not contain source path %q", diagnostic, wantPath)
	}
	if strings.Contains(diagnostic, "constructor sentinel") {
		t.Errorf("diagnostic %q came from a constructor after override validation", diagnostic)
	}
}
