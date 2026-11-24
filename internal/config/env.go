package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const tenantProfilesEnvKey = "tenants.<n>.profiles"

// listEnvKeys registers comma-separated []string values. <n> names a
// zero-based index into the YAML tenant list, not a dotted koanf key.
var listEnvKeys = map[string]bool{"profiles": true, tenantProfilesEnvKey: true}

// envKey maps a G2O_* environment variable name to its dotted config key:
// strip the prefix, lowercase, and turn the "__" nesting delimiter into ".".
// A single underscore inside a level is preserved (e.g. client_id stays
// client_id).
func envKey(name string) string {
	k := strings.ToLower(strings.TrimPrefix(name, EnvPrefix))
	return strings.ReplaceAll(k, envNestDelim, keyDelim)
}

// envTransform maps fixed environment variables into the koanf key tree.
// Dynamic collector keys and indexed tenant overrides are applied after typed decode.
func envTransform(name, value string) (string, any) {
	if _, ok := parseCollectorEnvName(name); ok {
		// Collector names may contain dots, which are koanf's path delimiter.
		// Apply this established dynamic form after typed decode so the name
		// remains one literal map key.
		return "", nil
	}
	if _, ok := parseTenantProfileEnvIndex(name); ok {
		return "", nil // koanf would replace the YAML tenant slice with a map
	}
	if _, ok := parseTenantGeoIPEnvName(name); ok {
		return "", nil // apply after typed decode, preserving the tenant slice
	}
	key := envKey(name)
	if listEnvKeys[key] {
		return key, splitEnvironmentList(value)
	}
	return key, value
}

type collectorEnvOverride struct {
	name     string
	field    string
	variable string
	value    string
}

type tenantProfileEnvOverride struct {
	index    int
	variable string
	value    string
}

type environmentOverrides struct {
	collectors     []collectorEnvOverride
	tenantProfiles []tenantProfileEnvOverride
	teamsGeoIP     []tenantGeoIPEnvOverride
}

func strictEnvironment() (environmentOverrides, error) {
	validFixed := scalarEnvNames(reflect.TypeOf(Config{}), "")
	environ := os.Environ()
	sort.Strings(environ)

	var overrides environmentOverrides
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		if override, ok := parseCollectorEnvName(name); ok {
			override.value = value
			overrides.collectors = append(overrides.collectors, override)
			continue
		}
		if index, ok := parseTenantProfileEnvIndex(name); ok {
			overrides.tenantProfiles = append(overrides.tenantProfiles, tenantProfileEnvOverride{index, name, value})
			continue
		}
		if override, ok := parseTenantGeoIPEnvName(name); ok {
			override.value = value
			overrides.teamsGeoIP = append(overrides.teamsGeoIP, override)
			continue
		}
		if name == envVarName(removedCardinalityMetricLimit) {
			continue // retained for Load's targeted migration diagnostic
		}
		if !validFixed[name] {
			return environmentOverrides{}, fmt.Errorf("unknown configuration environment variable %s", name)
		}
	}
	return overrides, nil
}

func scalarEnvNames(typ reflect.Type, prefix string) map[string]bool {
	out := map[string]bool{}
	collectScalarEnvNames(typ, prefix, out)
	return out
}

func collectScalarEnvNames(typ reflect.Type, prefix string, out map[string]bool) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		if prefix != "" {
			out[envVarName(prefix)] = true
		}
		return
	}

	fields := yamlStructFields(typ)
	if len(fields) == 0 {
		if prefix != "" {
			out[envVarName(prefix)] = true
		}
		return
	}
	for name, fieldType := range fields {
		path := joinConfigPath(prefix, name)
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		switch fieldType.Kind() {
		case reflect.Map, reflect.Slice, reflect.Array:
			if listEnvKeys[path] {
				out[envVarName(path)] = true
			}
		case reflect.Struct:
			collectScalarEnvNames(fieldType, path, out)
		default:
			out[envVarName(path)] = true
		}
	}
}

func parseTenantProfileEnvIndex(name string) (int, bool) {
	parts := strings.Split(name, envNestDelim)
	if len(parts) != 3 || parts[0] != EnvPrefix+"TENANTS" || parts[2] != "PROFILES" {
		return 0, false
	}
	return parseTenantEnvIndex(parts[1])
}

func parseTenantEnvIndex(raw string) (int, bool) {
	index, err := strconv.Atoi(raw)
	return index, err == nil && index >= 0 && strconv.Itoa(index) == raw
}

func splitEnvironmentList(value string) []string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func applyTenantProfileEnvironment(cfg *Config, overrides []tenantProfileEnvOverride) error {
	for _, override := range overrides {
		if override.index >= len(cfg.Tenants) {
			return fmt.Errorf("%s: tenant index out of range (tenants are configured in YAML)", override.variable)
		}
		profiles := splitEnvironmentList(override.value)
		if err := validateProfiles(profiles, override.variable); err != nil {
			return err
		}
		cfg.Tenants[override.index].Profiles = profiles
	}
	return nil
}

func parseCollectorEnvName(name string) (collectorEnvOverride, bool) {
	parts := strings.Split(name, envNestDelim)
	if len(parts) != 3 || parts[0] != EnvPrefix+"COLLECTORS" {
		return collectorEnvOverride{}, false
	}
	collectorName := parts[1]
	if collectorName == "" || collectorName != strings.ToUpper(collectorName) ||
		!validCollectorEnvSegment(collectorName) {
		return collectorEnvOverride{}, false
	}
	switch parts[2] {
	case "ENABLED", "INTERVAL", "SOURCE":
	default:
		return collectorEnvOverride{}, false
	}
	return collectorEnvOverride{
		name:     strings.ToLower(collectorName),
		field:    strings.ToLower(parts[2]),
		variable: name,
	}, true
}

func validCollectorEnvSegment(name string) bool {
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func applyCollectorEnvironment(cfg *Config, overrides []collectorEnvOverride) error {
	if len(overrides) == 0 {
		return nil
	}
	if cfg.Collectors == nil {
		cfg.Collectors = make(map[string]CollectorConfig)
	}
	cfg.collectorEnvOrigins = make(map[string]string, len(overrides)*2)

	for _, override := range overrides {
		collectorConfig := cfg.Collectors[override.name]
		switch override.field {
		case "enabled":
			enabled, err := strconv.ParseBool(override.value)
			if err != nil {
				return fmt.Errorf("decode environment variable %s: expected a boolean", override.variable)
			}
			collectorConfig.Enabled = &enabled
		case "interval":
			interval, err := time.ParseDuration(override.value)
			if err != nil {
				return fmt.Errorf("decode environment variable %s: expected a duration", override.variable)
			}
			collectorConfig.Interval = interval
		case "source":
			collectorConfig.Source = override.value
		}
		cfg.Collectors[override.name] = collectorConfig

		basePath := "collectors[" + strconv.Quote(override.name) + "]"
		fieldPath := basePath + keyDelim + override.field
		if current, ok := cfg.collectorEnvOrigins[basePath]; !ok || override.variable < current {
			cfg.collectorEnvOrigins[basePath] = override.variable
		}
		cfg.collectorEnvOrigins[fieldPath] = override.variable
	}
	return nil
}
