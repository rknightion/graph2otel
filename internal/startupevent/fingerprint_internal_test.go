package startupevent

import (
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

// TestCanonicalInputNeverContainsSecretBytes is the strongest form of the
// privacy claim: it inspects the exact byte string that is hashed. Testing the
// emitted attribute is not enough — a fingerprint computed over raw secret bytes
// would still be a (weak, brute-forceable) oracle for a short credential.
func TestCanonicalInputNeverContainsSecretBytes(t *testing.T) {
	const (
		tokenSentinel    = "SECRET-OTLP-TOKEN-b7f2"
		passwordSentinel = "SECRET-PYROSCOPE-PASSWORD-91ac"
	)
	cfg := config.Default()
	cfg.OTLP.GrafanaCloud.Token = config.Secret(tokenSentinel)
	cfg.Profiling.Pyroscope.BasicAuthPassword = config.Secret(passwordSentinel)

	canon, err := canonical(cfg)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if len(canon) == 0 {
		t.Fatal("canonical input is empty; every assertion below would pass vacuously")
	}
	inspected := 0
	for _, secret := range []string{tokenSentinel, passwordSentinel} {
		inspected++
		if strings.Contains(string(canon), secret) {
			t.Errorf("fingerprint input contains the credential %q:\n%s", secret, canon)
		}
	}
	if inspected != 2 {
		t.Fatalf("inspected %d secrets, want 2", inspected)
	}
	// The redaction marker proves the field participated and was redacted,
	// rather than silently vanishing from the surface.
	if !strings.Contains(string(canon), "REDACTED") {
		t.Errorf("fingerprint input has no REDACTED marker, so config.Secret redaction is not what excluded the credentials:\n%s", canon)
	}
}

// TestCanonicalInputCoversEveryTopLevelConfigSection proves the input surface is
// a DENY-list (everything except redacted secrets), not an allow-list: a config
// section added later participates automatically instead of being silently
// excluded from the fingerprint.
func TestCanonicalInputCoversEveryTopLevelConfigSection(t *testing.T) {
	canon, err := canonical(config.Default())
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	// Go field names, because encoding/json has no tags to read on Config.
	want := []string{
		"LogLevel", "Tenants", "OTLP", "Collectors", "Admin",
		"Profiling", "Cardinality", "Cost", "Backfill", "CheckpointDir",
	}
	inspected := 0
	for _, section := range want {
		inspected++
		if !strings.Contains(string(canon), section) {
			t.Errorf("fingerprint input does not cover config section %q:\n%s", section, canon)
		}
	}
	if inspected != len(want) {
		t.Fatalf("inspected %d sections, want %d", inspected, len(want))
	}
}

// TestFingerprintIsDomainSeparated pins that the hash is not a bare SHA-256 of
// the canonical bytes, so a fingerprint can never collide with, or be confirmed
// by, a hash of the same bytes computed for another purpose.
func TestFingerprintIsDomainSeparated(t *testing.T) {
	cfg := config.Default()
	canon, err := canonical(cfg)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	fp, err := Fingerprint(cfg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if fp == hashHex(nil, canon) {
		t.Error("fingerprint equals an undomained SHA-256 of the canonical bytes")
	}
	if fp != hashHex([]byte(fingerprintDomain), canon) {
		t.Errorf("fingerprint %q is not the domain-separated hash of the canonical bytes", fp)
	}
}
