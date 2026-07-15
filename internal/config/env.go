package config

import "strings"

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
	return envKey(name), value
}
