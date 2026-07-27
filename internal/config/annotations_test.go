package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGrafanaAnnotationsUnsetIsACleanNoOp pins the opt-out shape: the whole
// feature is off unless a URL is supplied, and an empty block must validate
// without complaint. A warning storm on the default deployment is exactly what
// #400 forbids.
func TestGrafanaAnnotationsUnsetIsACleanNoOp(t *testing.T) {
	var a GrafanaAnnotationsConfig
	if a.Configured() {
		t.Error("an empty block reports Configured; the URL is the whole opt-in")
	}
	if err := a.validate(); err != nil {
		t.Errorf("empty block must validate: %v", err)
	}
}

func TestGrafanaAnnotationsURLIsTheOptIn(t *testing.T) {
	a := GrafanaAnnotationsConfig{URL: "https://grafana.example.com", Token: Secret("t")}
	if !a.Configured() {
		t.Fatal("a set url must report Configured")
	}
}

// TestGrafanaAnnotationsRequiresACredential is the loud half of "fail fast":
// a URL with no token would otherwise start and 401 on the first event.
func TestGrafanaAnnotationsRequiresACredential(t *testing.T) {
	a := GrafanaAnnotationsConfig{URL: "https://grafana.example.com"}
	err := a.validate()
	if err == nil {
		t.Fatal("url with no token must be rejected")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q does not name the missing credential", err)
	}
}

// TestGrafanaAnnotationsRejectsAStrayCredential mirrors mdca.token_file: a
// credential mounted for a feature that is switched off silently does nothing,
// which reads as "annotations are on" to whoever mounted it.
func TestGrafanaAnnotationsRejectsAStrayCredential(t *testing.T) {
	for name, a := range map[string]GrafanaAnnotationsConfig{
		"inline token": {Token: Secret("t")},
		"token file":   {TokenFile: "/run/secrets/tok"},
	} {
		if err := a.validate(); err == nil {
			t.Errorf("%s with no url must be rejected", name)
		}
	}
}

func TestGrafanaAnnotationsRejectsARelativeURL(t *testing.T) {
	a := GrafanaAnnotationsConfig{URL: "grafana.example.com", Token: Secret("t")}
	if err := a.validate(); err == nil {
		t.Fatal("a scheme-less url must be rejected")
	}
}

func TestGrafanaAnnotationsRejectsNonPositiveTunables(t *testing.T) {
	base := func() GrafanaAnnotationsConfig {
		a := Default().GrafanaAnnotations
		a.URL = "https://grafana.example.com"
		a.Token = Secret("t")
		return a
	}
	cases := map[string]func(*GrafanaAnnotationsConfig){
		"timeout":         func(a *GrafanaAnnotationsConfig) { a.Timeout = 0 },
		"max_per_minute":  func(a *GrafanaAnnotationsConfig) { a.MaxPerMinute = 0 },
		"queue_size":      func(a *GrafanaAnnotationsConfig) { a.QueueSize = 0 },
		"rollup_interval": func(a *GrafanaAnnotationsConfig) { a.RollupInterval = -time.Second },
		"dedupe_retention": func(a *GrafanaAnnotationsConfig) {
			a.DedupeRetention = 0
		},
	}
	for field, mutate := range cases {
		a := base()
		mutate(&a)
		err := a.validate()
		if err == nil {
			t.Errorf("%s: a non-positive value must be rejected", field)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("%s: error %q does not name the field", field, err)
		}
	}
}

// TestGrafanaAnnotationsTokenFileResolvesIntoTheSecret pins that the file form
// lands in the Secret-typed field, so the credential still redacts in every
// dump and never reaches the config fingerprint as bytes.
func TestGrafanaAnnotationsTokenFileResolvesIntoTheSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("glsa-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.GrafanaAnnotations.URL = "https://grafana.example.com"
	cfg.GrafanaAnnotations.TokenFile = path

	if err := cfg.resolveSecretFiles(); err != nil {
		t.Fatalf("resolveSecretFiles: %v", err)
	}
	if got := cfg.GrafanaAnnotations.Token.Reveal(); got != "glsa-secret-value" {
		t.Errorf("token = %q, want the trimmed file contents", got)
	}
	if got := cfg.GrafanaAnnotations.Token.String(); got != "REDACTED" {
		t.Errorf("resolved token renders as %q, want REDACTED", got)
	}
}

func TestGrafanaAnnotationsTokenAndTokenFileAreExclusive(t *testing.T) {
	cfg := Default()
	cfg.GrafanaAnnotations.URL = "https://grafana.example.com"
	cfg.GrafanaAnnotations.Token = Secret("inline")
	cfg.GrafanaAnnotations.TokenFile = "/run/secrets/tok"
	if err := cfg.resolveSecretFiles(); err == nil {
		t.Fatal("setting both token and token_file must be rejected")
	}
}

// TestGrafanaAnnotationsValidateRunsFromConfigValidate proves the block is
// actually reachable from the process-wide gate rather than only unit-tested.
func TestGrafanaAnnotationsValidateRunsFromConfigValidate(t *testing.T) {
	cfg := Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.GrafanaAnnotations.URL = "https://grafana.example.com"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted a url with no token")
	}
	if !strings.Contains(err.Error(), "grafana_annotations") {
		t.Errorf("error %q is not prefixed with the config path", err)
	}
}

// TestGrafanaAnnotationsDefaultsAreTheDocumentedOnes freezes the public
// defaults #400's brief pins: rollup on for the two size-scaling categories,
// off for the two naturally low-volume ones.
func TestGrafanaAnnotationsDefaultsAreTheDocumentedOnes(t *testing.T) {
	a := Default().GrafanaAnnotations
	if a.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", a.Timeout)
	}
	if a.MaxPerMinute != 60 {
		t.Errorf("max_per_minute = %d, want 60", a.MaxPerMinute)
	}
	if a.QueueSize != 512 {
		t.Errorf("queue_size = %d, want 512", a.QueueSize)
	}
	if a.RollupInterval != 5*time.Minute {
		t.Errorf("rollup_interval = %v, want 5m", a.RollupInterval)
	}
	if a.DedupeRetention != 48*time.Hour {
		t.Errorf("dedupe_retention = %v, want 48h", a.DedupeRetention)
	}
	for name, want := range map[string]AnnotationCategoryConfig{
		"config_posture":    {Enabled: true, Rollup: true},
		"security_incident": {Enabled: true, Rollup: false},
		"service_health":    {Enabled: true, Rollup: false},
		"license":           {Enabled: true, Rollup: true},
	} {
		var got AnnotationCategoryConfig
		switch name {
		case "config_posture":
			got = a.Categories.ConfigPosture
		case "security_incident":
			got = a.Categories.SecurityIncident
		case "service_health":
			got = a.Categories.ServiceHealth
		case "license":
			got = a.Categories.License
		}
		if got != want {
			t.Errorf("categories.%s = %+v, want %+v", name, got, want)
		}
	}
}

// TestGrafanaAnnotationsTokenNeverReachesTheFingerprintInput is the privacy
// claim for the new credential, checked at the same place #310 checks the
// others: the bytes that are hashed.
func TestGrafanaAnnotationsTokenNeverReachesAConfigDump(t *testing.T) {
	const sentinel = "SECRET-GRAFANA-SA-TOKEN-4f19"
	cfg := Default()
	cfg.GrafanaAnnotations.Token = Secret(sentinel)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dump := string(raw)
	if strings.Contains(dump, sentinel) {
		t.Errorf("config dump contains the Grafana token:\n%s", dump)
	}
	if !strings.Contains(dump, "REDACTED") {
		t.Errorf("config dump has no REDACTED marker, so the token was not redacted:\n%s", dump)
	}
}
