package config

import "strings"

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
	return envKey(name), value
}
