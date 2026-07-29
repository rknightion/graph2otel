package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestCollectorOverrideInventoryHas170LogicalNamesAcrossAllSevenPaths(t *testing.T) {
	known, _ := collectorOverrideInventory()

	if got, want := len(known), 170; got != want {
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
