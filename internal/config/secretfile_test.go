package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

// writeSecretFile writes secret content to a fresh temp file and returns its
// path, for exercising the *_file resolution.
func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return p
}

// TestGrafanaCloudTokenFileResolution covers the value-XOR-file rule for the
// OTLP push token (otlp.grafana_cloud.token / token_file), the file-secret
// sibling added for Kubernetes/Docker secret mounts (#212), mirroring
// mdca.token_file.
func TestGrafanaCloudTokenFileResolution(t *testing.T) {
	tokenPath := writeSecretFile(t, "glc_from_file\n")

	for _, tc := range []struct {
		name      string
		yaml      string
		wantToken string // expected revealed token when no error
		wantErr   string // substring; "" = must succeed
	}{
		{
			name:      "value only is unchanged",
			yaml:      "otlp:\n  grafana_cloud:\n    token: \"glc_inline\"\n",
			wantToken: "glc_inline",
		},
		{
			name:      "file only is read and trimmed",
			yaml:      fmt.Sprintf("otlp:\n  grafana_cloud:\n    token_file: %q\n", tokenPath),
			wantToken: "glc_from_file",
		},
		{
			name:    "both set is a clear error naming the field",
			yaml:    fmt.Sprintf("otlp:\n  grafana_cloud:\n    token: \"glc_inline\"\n    token_file: %q\n", tokenPath),
			wantErr: "otlp.grafana_cloud.token and otlp.grafana_cloud.token_file are both set",
		},
		{
			name:      "neither set is fine and empty",
			yaml:      "otlp:\n  grafana_cloud: {}\n",
			wantToken: "",
		},
		{
			name:    "unreadable file errors, naming the field",
			yaml:    "otlp:\n  grafana_cloud:\n    token_file: \"/nonexistent/path/token\"\n",
			wantErr: "read otlp.grafana_cloud.token_file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load(writeTemp(t, tc.yaml))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load() error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if got := cfg.OTLP.GrafanaCloud.Token.Reveal(); got != tc.wantToken {
				t.Errorf("token = %q, want %q", got, tc.wantToken)
			}
		})
	}
}

// TestPyroscopePasswordFileResolution covers the same value-XOR-file rule for
// the Pyroscope basic-auth password.
func TestPyroscopePasswordFileResolution(t *testing.T) {
	pwPath := writeSecretFile(t, "pyro_from_file\n")

	for _, tc := range []struct {
		name    string
		yaml    string
		wantPw  string
		wantErr string
	}{
		{
			name:   "value only is unchanged",
			yaml:   "profiling:\n  pyroscope:\n    basic_auth_password: \"pyro_inline\"\n",
			wantPw: "pyro_inline",
		},
		{
			name:   "file only is read and trimmed",
			yaml:   fmt.Sprintf("profiling:\n  pyroscope:\n    basic_auth_password_file: %q\n", pwPath),
			wantPw: "pyro_from_file",
		},
		{
			name:    "both set is a clear error naming the field",
			yaml:    fmt.Sprintf("profiling:\n  pyroscope:\n    basic_auth_password: \"pyro_inline\"\n    basic_auth_password_file: %q\n", pwPath),
			wantErr: "profiling.pyroscope.basic_auth_password and profiling.pyroscope.basic_auth_password_file are both set",
		},
		{
			name:   "neither set is fine and empty",
			yaml:   "profiling:\n  pyroscope: {}\n",
			wantPw: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load(writeTemp(t, tc.yaml))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load() error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if got := cfg.Profiling.Pyroscope.BasicAuthPassword.Reveal(); got != tc.wantPw {
				t.Errorf("basic_auth_password = %q, want %q", got, tc.wantPw)
			}
		})
	}
}

// TestSecretFileEnvValueParticipatesInXOR proves the inline value from the
// environment layer (not just YAML) is counted by the value-XOR-file check: a
// token set via G2O_OTLP__GRAFANA_CLOUD__TOKEN together with a token_file must
// still error.
func TestSecretFileEnvValueParticipatesInXOR(t *testing.T) {
	tokenPath := writeSecretFile(t, "glc_from_file\n")
	t.Setenv("G2O_OTLP__GRAFANA_CLOUD__TOKEN", "glc_from_env")

	y := fmt.Sprintf("otlp:\n  grafana_cloud:\n    token_file: %q\n", tokenPath)
	_, err := config.Load(writeTemp(t, y))
	if err == nil || !strings.Contains(err.Error(), "otlp.grafana_cloud.token and otlp.grafana_cloud.token_file are both set") {
		t.Fatalf("Load() error = %v, want both-set error", err)
	}
}

// TestSecretFileEnvPathResolves proves the _file path itself can come from the
// environment (G2O_OTLP__GRAFANA_CLOUD__TOKEN_FILE) and still resolves.
func TestSecretFileEnvPathResolves(t *testing.T) {
	tokenPath := writeSecretFile(t, "glc_from_file\n")
	t.Setenv("G2O_OTLP__GRAFANA_CLOUD__TOKEN_FILE", tokenPath)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if got := cfg.OTLP.GrafanaCloud.Token.Reveal(); got != "glc_from_file" {
		t.Errorf("token = %q, want glc_from_file", got)
	}
}

// TestFileResolvedSecretRedacts proves a credential read from a _file lands in
// the Secret-typed field and therefore redacts under fmt/String — it never
// leaks in a config dump — while Reveal still returns the real value.
func TestFileResolvedSecretRedacts(t *testing.T) {
	tokenPath := writeSecretFile(t, "glc_from_file\n")
	y := fmt.Sprintf("otlp:\n  grafana_cloud:\n    token_file: %q\n", tokenPath)

	cfg, err := config.Load(writeTemp(t, y))
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	tok := cfg.OTLP.GrafanaCloud.Token
	if tok.Reveal() != "glc_from_file" {
		t.Fatalf("Reveal() = %q, want glc_from_file", tok.Reveal())
	}
	for _, verb := range []string{"%v", "%s", "%q", "%#v"} {
		if rendered := fmt.Sprintf(verb, tok); strings.Contains(rendered, "glc_from_file") {
			t.Errorf("fmt %s of file-resolved token leaked the value: %s", verb, rendered)
		}
	}
	if s := tok.String(); s != "REDACTED" {
		t.Errorf("String() = %q, want REDACTED", s)
	}
}
