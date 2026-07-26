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

// listEnvKeys are the config keys whose environment value would be a
// comma-separated list (the scalar []string fields). graph2otel's config
// surface currently has NO []string field, so this registry is empty and the
// env-var-reference generator classifies every sequence node (tenants) as
// file-only. It exists so that a future []string field has an obvious home and
// so TestListEnvKeysMatchesStringSliceFields can fail loudly if one is added
// without registering it here — at which point envTransform must also be taught
// to comma-split that variable's value.
var listEnvKeys = map[string]bool{}

// envKey maps a G2O_* environment variable name to its dotted config key:
// strip the prefix, lowercase, and turn the "__" nesting delimiter into ".".
// A single underscore inside a level is preserved (e.g. client_id stays
// client_id).
func envKey(name string) string {
	k := strings.ToLower(strings.TrimPrefix(name, EnvPrefix))
	return strings.ReplaceAll(k, envNestDelim, keyDelim)
}

// envTransform is the koanf env-provider callback: it converts the variable
// name to a config key. graph2otel's scaffold config has no scalar-list
// ([]string) or list-of-struct ([]TenantConfig) fields that are meaningfully
// settable via a single flat env var, so unlike larger donor configs this
// transform does no value splitting — every value passes through as a plain
// string for mapstructure to decode.
func envTransform(name, value string) (string, any) {
	if _, ok := parseCollectorEnvName(name); ok {
		// Collector names may contain dots, which are koanf's path delimiter.
		// Apply this established dynamic form after typed decode so the name
		// remains one literal map key.
		return "", nil
	}
	return envKey(name), value
}

type collectorEnvOverride struct {
	name     string
	field    string
	variable string
	value    string
}

func strictEnvironment() ([]collectorEnvOverride, error) {
	validFixed := scalarEnvNames(reflect.TypeOf(Config{}), "")
	environ := os.Environ()
	sort.Strings(environ)

	var overrides []collectorEnvOverride
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		if override, ok := parseCollectorEnvName(name); ok {
			override.value = value
			overrides = append(overrides, override)
			continue
		}
		if name == envVarName(removedCardinalityMetricLimit) {
			continue // retained for Load's targeted migration diagnostic
		}
		if !validFixed[name] {
			return nil, fmt.Errorf("unknown configuration environment variable %s", name)
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
			// Structured collections are file-only. The sole exception is the
			// dynamic global collector override form handled separately.
			continue
		case reflect.Struct:
			collectScalarEnvNames(fieldType, path, out)
		default:
			out[envVarName(path)] = true
		}
	}
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
