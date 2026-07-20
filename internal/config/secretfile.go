package config

import (
	"fmt"
	"os"
	"strings"
)

// resolveSecretFiles resolves the *_file secret siblings for graph2otel's own
// egress credentials — the OTLP push token (otlp.grafana_cloud.token) and the
// Pyroscope basic-auth password — mirroring mdca.token_file (#145/#212). The
// credential is mounted as a file (the standard Kubernetes/Docker secret
// pattern) and the *_file path points at it, keeping the secret out of both
// YAML and the environment.
//
// Each pair is value-XOR-file: setting both the inline Secret and its _file
// path is a configuration error (which one wins is ambiguous); setting only the
// _file path reads the file into the Secret; setting only the inline value
// leaves it untouched; setting neither is fine. The resolved credential always
// lands in the Secret-typed field, so it redacts in every config dump.
//
// It runs from Load after every layer is merged, so an inline value from any
// layer (YAML or the G2O_* environment) is counted by the XOR check. It does
// NOT touch tenant auth: those credentials are resolved by
// azidentity.DefaultAzureCredential, whose own env/file/managed-identity chain
// is the correct multi-tenant idiom (#212, explicitly out of scope).
func (c *Config) resolveSecretFiles() error {
	if err := resolveSecretFile(
		"otlp.grafana_cloud.token",
		&c.OTLP.GrafanaCloud.Token,
		c.OTLP.GrafanaCloud.TokenFile,
	); err != nil {
		return err
	}
	if err := resolveSecretFile(
		"profiling.pyroscope.basic_auth_password",
		&c.Profiling.Pyroscope.BasicAuthPassword,
		c.Profiling.Pyroscope.BasicAuthPasswordFile,
	); err != nil {
		return err
	}
	return nil
}

// resolveSecretFile applies the value-XOR-file rule for one secret: field is
// the dotted config key (its file sibling is field+"_file"), value points at
// the Secret to populate, and path is the configured _file value. An empty path
// is a no-op (value-only, or neither). A set path with an already-set value is
// an error; otherwise the file is read into value, trimmed like mdca.token_file
// (cmd/graph2otel/tenants.go) so a mounted secret's trailing newline is not
// treated as part of the credential.
func resolveSecretFile(field string, value *Secret, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if value.Reveal() != "" {
		return fmt.Errorf("%s and %s_file are both set: set only one", field, field)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s_file %q: %w", field, path, err)
	}
	*value = Secret(strings.TrimSpace(string(data)))
	return nil
}
