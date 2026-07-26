package graph2otel_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

var (
	livenessProbe = regexp.MustCompile(
		`(?m)^ {10}livenessProbe:\n {12}httpGet:\n {14}path: /healthz\n {14}port: admin$`,
	)
	readinessProbe = regexp.MustCompile(
		`(?m)^ {10}readinessProbe:\n {12}httpGet:\n {14}path: /readyz\n {14}port: admin$`,
	)
	adminPort = regexp.MustCompile(
		`(?m)^ {10}ports:\n {12}- name: admin\n {14}containerPort: [0-9]+$`,
	)
)

func TestDeploymentRendersDistinctLivenessAndReadinessEndpoints(t *testing.T) {
	rendered := renderChart(t)

	assertMatchCount(t, rendered, "liveness /healthz probe", livenessProbe, 1)
	assertMatchCount(t, rendered, "readiness /readyz probe", readinessProbe, 1)
	assertMatchCount(t, rendered, "admin port", adminPort, 1)
}

func TestDeploymentOmitsAdminSurfaceWhenDisabled(t *testing.T) {
	rendered := renderChart(t, "--set", "config.admin.enabled=false")

	assertMatchCount(t, rendered, "liveness probe", livenessProbe, 0)
	assertMatchCount(t, rendered, "readiness probe", readinessProbe, 0)
	assertMatchCount(t, rendered, "admin port", adminPort, 0)
}

func TestHelmRejectsTypoHeavyValues(t *testing.T) {
	typos := []string{"ena" + "beld", "log_lee" + "vl", "proto" + "cool", "sor" + "uce"}
	values := writeValues(t, fmt.Sprintf(`persistence:
  %s: true
config:
  %s: debug
  otlp:
    %s: grpc
  collectors:
    entra.users:
      %s: blob
`, typos[0], typos[1], typos[2], typos[3]))

	for _, command := range []string{"lint", "template"} {
		t.Run(command, func(t *testing.T) {
			args := []string{command}
			if command == "template" {
				args = append(args, "test")
			}
			args = append(args, ".", "-f", values)

			output, err := runHelm(t, args...)
			if err == nil {
				t.Fatalf("helm %s accepted typo-heavy values:\n%s", command, output)
			}
			for _, typo := range typos {
				if !strings.Contains(string(output), typo) {
					t.Errorf("helm %s diagnostic does not name %q:\n%s", command, typo, output)
				}
			}
		})
	}
}

func TestHelmAcceptsExtensionMapsAndCollectorOverrides(t *testing.T) {
	values := writeValues(t, `serviceAccount:
  annotations:
    example.net/workload: graph2otel
podAnnotations:
  example.net/restarted-at: now
podLabels:
  example.net/team: security
config:
  profiling:
    pyroscope:
      tags:
        region: eu-west
        cost-center: secops
  collectors:
    entra.directory_audits:
      enabled: true
      interval: 10m
      source: blob
  tenants:
    - tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: ""
      collectors:
        entra.users:
          enabled: false
          interval: 30m
`)

	for _, command := range []string{"lint", "template"} {
		t.Run(command, func(t *testing.T) {
			args := []string{command}
			if command == "template" {
				args = append(args, "test")
			}
			args = append(args, ".", "-f", values)
			if output, err := runHelm(t, args...); err != nil {
				t.Fatalf("helm %s rejected valid extension maps and collector overrides: %v\n%s",
					command, err, output)
			}
		})
	}
}

func TestHelmRejectsUnknownCollectorNameAndSource(t *testing.T) {
	tests := []struct {
		name       string
		values     string
		diagnostic string
	}{
		{
			name: "unknown collector",
			values: `config:
  collectors:
    entra.usres:
      enabled: true
`,
			diagnostic: "entra.usres",
		},
		{
			name: "unknown source",
			values: `config:
  collectors:
    entra.directory_audits:
      source: bolb
`,
			diagnostic: "/config/collectors/entra.directory_audits/source",
		},
		{
			name: "source on non-switchable collector",
			values: `config:
  collectors:
    entra.users:
      source: blob
`,
			diagnostic: "/config/collectors/entra.users",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := writeValues(t, test.values)
			for _, command := range []string{"lint", "template"} {
				t.Run(command, func(t *testing.T) {
					args := []string{command}
					if command == "template" {
						args = append(args, "test")
					}
					args = append(args, ".", "-f", values)
					output, err := runHelm(t, args...)
					if err == nil {
						t.Fatalf("helm %s accepted invalid collector override:\n%s", command, output)
					}
					if !strings.Contains(string(output), test.diagnostic) {
						t.Errorf("helm %s diagnostic does not name %q:\n%s",
							command, test.diagnostic, output)
					}
				})
			}
		})
	}
}

func TestConfigSchemaMatchesApplicationConfigAndClosesFixedObjects(t *testing.T) {
	schema := loadValuesSchema(t)
	configSchema := schemaObject(t, schema, "properties", "config")

	assertConfigSchema(t, configSchema, reflect.TypeOf(config.Config{}), "config")
}

func TestCollectorOverrideSchemaHasBoundedNamesAndSourceEnum(t *testing.T) {
	schema := loadValuesSchema(t)
	definitions := schemaObject(t, schema, "definitions")
	override := schemaObject(t, definitions, "collectorOverride")
	assertCollectorOverrideProperties(t, override, []string{"enabled", "interval"})

	switchableOverride := schemaObject(t, definitions, "sourceSwitchableCollectorOverride")
	assertCollectorOverrideProperties(
		t, switchableOverride, []string{"enabled", "interval", "source"},
	)
	source := schemaObject(t, switchableOverride, "properties", "source")
	gotSources := schemaStrings(t, source, "enum")
	if want := []string{"graph", "blob"}; !slices.Equal(gotSources, want) {
		t.Errorf("collector source enum = %v, want %v", gotSources, want)
	}

	overrides := schemaObject(t, definitions, "collectorOverrides")
	if got := schemaRef(t, overrides, "propertyNames"); got != "#/definitions/collectorName" {
		t.Errorf("collector overrides propertyNames ref = %q, want collectorName", got)
	}
	if got := schemaRef(t, overrides, "additionalProperties"); got != "#/definitions/collectorOverride" {
		t.Errorf("collector overrides additionalProperties ref = %q, want collectorOverride", got)
	}
	switchableProperties := schemaObject(t, overrides, "properties")
	gotSwitchable := make([]string, 0, len(switchableProperties))
	for name, raw := range switchableProperties {
		gotSwitchable = append(gotSwitchable, name)
		property, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("source-switchable collector %q schema is not an object", name)
			continue
		}
		if got, _ := property["$ref"].(string); got != "#/definitions/sourceSwitchableCollectorOverride" {
			t.Errorf("source-switchable collector %q ref = %q", name, got)
		}
	}
	slices.Sort(gotSwitchable)
	if want := []string{
		"entra.directory_audits",
		"entra.provisioning",
		"entra.risk_detections",
	}; !slices.Equal(gotSwitchable, want) {
		t.Errorf("source-switchable collector names = %v, want %v", gotSwitchable, want)
	}

	names := schemaObject(t, definitions, "collectorName")
	gotNames := schemaStrings(t, names, "enum")
	if len(gotNames) != 148 {
		t.Fatalf("collector name inventory has %d entries, want 148", len(gotNames))
	}
	if !slices.IsSorted(gotNames) {
		t.Error("collector name inventory is not sorted")
	}
	for i := 1; i < len(gotNames); i++ {
		if gotNames[i] == gotNames[i-1] {
			t.Errorf("collector name inventory contains duplicate %q", gotNames[i])
		}
	}
	for _, name := range []string{
		"defender.vulnerabilities",
		"entra.users",
		"graph2otel.blob_categories",
		"intune.devices",
		"m365.activity",
		"mdca.discovery_parse",
		"purview.sensitivity_labels",
	} {
		if _, found := slices.BinarySearch(gotNames, name); !found {
			t.Errorf("collector name inventory is missing %q", name)
		}
	}
}

func TestSchemaRequiresHyphenatedTenantDirectoryGUID(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; schema contract is exercised by the Helm CI job")
	}

	validArgs := []string{
		"template", "test", ".",
		"--set-string", "config.tenants[0].tenant_id=4B8C18BD-2F9F-4227-AF55-9F1061CF9C32",
	}
	if rendered, err := exec.Command(helm, validArgs...).CombinedOutput(); err != nil {
		t.Fatalf("helm template rejected an uppercase hyphenated directory GUID: %v\n%s", err, rendered)
	}

	invalidArgs := []string{
		"template", "test", ".",
		"--set-string", "config.tenants[0].tenant_id=contoso.onmicrosoft.com",
	}
	rendered, err := exec.Command(helm, invalidArgs...).CombinedOutput()
	if err == nil {
		t.Fatal("helm template accepted a verified domain as config.tenants[0].tenant_id")
	}
	if !strings.Contains(string(rendered), "tenant_id") {
		t.Fatalf("helm schema error does not identify tenant_id:\n%s", rendered)
	}

	missingArgs := []string{
		"template", "test", ".",
		"--set-json", `config.tenants=[{"client_id":""}]`,
	}
	rendered, err = exec.Command(helm, missingArgs...).CombinedOutput()
	if err == nil {
		t.Fatal("helm template accepted a config.tenants item with no tenant_id")
	}
	if !strings.Contains(string(rendered), "tenant_id") {
		t.Fatalf("helm schema error does not identify missing tenant_id:\n%s", rendered)
	}
}

func renderChart(t *testing.T, args ...string) []byte {
	t.Helper()

	helmArgs := append([]string{"template", "test", "."}, args...)
	rendered, err := runHelm(t, helmArgs...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, rendered)
	}
	return rendered
}

func runHelm(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()

	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; rendered chart contract is exercised by the Helm CI job")
	}
	return exec.Command(helm, args...).CombinedOutput()
}

func writeValues(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write Helm values: %v", err)
	}
	return path
}

func loadValuesSchema(t *testing.T) map[string]any {
	t.Helper()

	raw, err := os.ReadFile("values.schema.json")
	if err != nil {
		t.Fatalf("read values schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode values schema: %v", err)
	}
	return schema
}

func assertConfigSchema(
	t *testing.T,
	node map[string]any,
	goType reflect.Type,
	path string,
) {
	t.Helper()

	for goType.Kind() == reflect.Pointer {
		goType = goType.Elem()
	}
	switch goType.Kind() {
	case reflect.Struct:
		if goType.PkgPath() == "time" && goType.Name() == "Duration" {
			return
		}
		if additional, ok := node["additionalProperties"].(bool); !ok || additional {
			t.Errorf("%s must set additionalProperties=false", path)
		}
		properties := schemaObject(t, node, "properties")
		want := make([]string, 0, goType.NumField())
		for i := 0; i < goType.NumField(); i++ {
			field := goType.Field(i)
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			want = append(want, name)
			child, ok := properties[name].(map[string]any)
			if !ok {
				t.Errorf("%s schema is missing application key %q", path, name)
				continue
			}
			assertConfigSchema(t, child, field.Type, path+"."+name)
		}
		slices.Sort(want)
		got := make([]string, 0, len(properties))
		for name := range properties {
			got = append(got, name)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s properties = %v, want application keys %v", path, got, want)
		}
	case reflect.Slice:
		assertConfigSchema(t, schemaObject(t, node, "items"), goType.Elem(), path+"[]")
	case reflect.Map:
		switch goType.Elem() {
		case reflect.TypeOf(config.CollectorConfig{}):
			if got, _ := node["$ref"].(string); got != "#/definitions/collectorOverrides" {
				t.Errorf("%s ref = %q, want collectorOverrides", path, got)
			}
		default:
			additional := schemaObject(t, node, "additionalProperties")
			if got, _ := additional["type"].(string); got != "string" {
				t.Errorf("%s free-form values type = %q, want string", path, got)
			}
		}
	}
}

func assertCollectorOverrideProperties(t *testing.T, node map[string]any, want []string) {
	t.Helper()

	if additional, ok := node["additionalProperties"].(bool); !ok || additional {
		t.Error("collector override must set additionalProperties=false")
	}
	properties := schemaObject(t, node, "properties")
	got := make([]string, 0, len(properties))
	for name := range properties {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("collector override properties = %v, want %v", got, want)
	}
}

func schemaObject(t *testing.T, node map[string]any, keys ...string) map[string]any {
	t.Helper()

	current := node
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("schema path %q is not an object", strings.Join(keys, "."))
		}
		current = next
	}
	return current
}

func schemaRef(t *testing.T, node map[string]any, key string) string {
	t.Helper()

	ref, ok := schemaObject(t, node, key)["$ref"].(string)
	if !ok {
		t.Fatalf("schema key %q has no $ref", key)
	}
	return ref
}

func schemaStrings(t *testing.T, node map[string]any, key string) []string {
	t.Helper()

	values, ok := node[key].([]any)
	if !ok {
		t.Fatalf("schema key %q is not an array", key)
	}
	result := make([]string, len(values))
	for i, value := range values {
		var ok bool
		result[i], ok = value.(string)
		if !ok {
			t.Fatalf("schema %s[%d] = %T, want string", key, i, value)
		}
	}
	return result
}

func assertMatchCount(
	t *testing.T,
	rendered []byte,
	name string,
	pattern *regexp.Regexp,
	want int,
) {
	t.Helper()

	if got := len(pattern.FindAll(rendered, -1)); got != want {
		t.Errorf("%s count = %d, want %d", name, got, want)
	}
}
