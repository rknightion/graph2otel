package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestBlobIngestAccountURLLoadsPerTenant(t *testing.T) {
	path := writeConfig(t, `
otlp:
  protocol: stdout
tenants:
  - tenant_id: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
    blob_ingest:
      account_url: "https://graph2otelm7kni.blob.core.windows.net"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Tenants[0].BlobIngest.AccountURL; got != "https://graph2otelm7kni.blob.core.windows.net" {
		t.Errorf("blob_ingest.account_url = %q, want the configured account URL", got)
	}
}

// Blob ingest is opt-in infra: a deployment that has provisioned no storage
// account must be completely unaffected, so an absent block is not an error and
// leaves the URL empty (which the composition root reads as "register no blob
// collectors").
func TestBlobIngestDefaultsToOff(t *testing.T) {
	path := writeConfig(t, `
otlp:
  protocol: stdout
tenants:
  - tenant_id: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Tenants[0].BlobIngest.AccountURL; got != "" {
		t.Errorf("blob_ingest.account_url = %q with no blob_ingest block, want empty (off)", got)
	}
}

// exclude_self is the opt-in self-exhaust filter (#154): it round-trips through
// per-tenant YAML exactly like account_url (a tenant sub-key, so no flat G2O_ env
// var — the whole tenants list is file-only).
// exclude_self is a TENANT-level key (#176), a sibling of client_id — not under
// blob_ingest — because the same "self" spans the blob and Graph transports.
func TestExcludeSelfLoadsPerTenant(t *testing.T) {
	path := writeConfig(t, `
otlp:
  protocol: stdout
tenants:
  - tenant_id: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
    client_id: "c98e5057-edde-4666-b301-186a01b4dc58"
    exclude_self: true
    blob_ingest:
      account_url: "https://graph2otelm7kni.blob.core.windows.net"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Tenants[0].ExcludeSelf {
		t.Error("exclude_self = false, want true when set in YAML")
	}
}

// Default-off: an absent exclude_self (the common case) must leave the filter
// off, so nobody loses ~60% of their MGAL feed without opting in.
func TestExcludeSelfDefaultsToOff(t *testing.T) {
	path := writeConfig(t, `
otlp:
  protocol: stdout
tenants:
  - tenant_id: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
    blob_ingest:
      account_url: "https://graph2otelm7kni.blob.core.windows.net"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tenants[0].ExcludeSelf {
		t.Error("exclude_self = true with no key set, want false (default off)")
	}
}

// A typo'd account URL must fail at startup naming the bad value, not once per
// tick per collector.
func TestValidateRejectsAMalformedBlobAccountURL(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"plaintext", "http://graph2otelm7kni.blob.core.windows.net"},
		{"bare account name", "graph2otelm7kni"},
		{"no host", "https://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.OTLP.Protocol = "stdout"
			cfg.Tenants = []TenantConfig{{
				TenantID:   "t1",
				BlobIngest: BlobIngestConfig{AccountURL: tc.url},
			}}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted blob_ingest.account_url = %q", tc.url)
			}
			if !strings.Contains(err.Error(), "blob_ingest.account_url") {
				t.Errorf("error %q does not name the offending key", err)
			}
		})
	}
}

func TestValidateAcceptsAValidBlobAccountURL(t *testing.T) {
	cfg := Default()
	cfg.OTLP.Protocol = "stdout"
	cfg.Tenants = []TenantConfig{{
		TenantID:   "t1",
		BlobIngest: BlobIngestConfig{AccountURL: "https://graph2otelm7kni.blob.core.windows.net"},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected a valid account URL: %v", err)
	}
}
