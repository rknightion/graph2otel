//go:build live

package livecontract

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
)

// TestLiveContract hits the real Graph v1.0 endpoints the default collectors
// depend on, read-only, through internal/graphclient, and checks the response
// fields the mappers read. Run it with `just test-live`.
//
// Outcomes are reported differently on purpose (see the package comment):
//
//   - credentials absent -> t.Skip with a message. The scheduled workflow treats any
//     "--- SKIP" as a failure, so a lane that checked nothing cannot report clean.
//   - 401/403 -> t.Errorf tagged MISCONFIGURED: the poller identity lacks a scope or
//     licence; the API said nothing about shape.
//   - empty collection -> a NOT-APPLICABLE log line, never a skip or a failure.
//   - shape drift or any other error -> t.Errorf.
//
// Failures name endpoints and fields only, never bodies or values: the workflow log
// is public.
func TestLiveContract(t *testing.T) {
	tenant, client := os.Getenv("AZURE_TENANT_ID"), os.Getenv("AZURE_CLIENT_ID")
	secret, cert := os.Getenv("AZURE_CLIENT_SECRET"), os.Getenv("AZURE_CLIENT_CERTIFICATE_PATH")
	if tenant == "" || client == "" || (secret == "" && cert == "") {
		t.Skip("AZURE_TENANT_ID, AZURE_CLIENT_ID and one of AZURE_CLIENT_SECRET or " +
			"AZURE_CLIENT_CERTIFICATE_PATH are required - live contract skipped")
	}
	redact := func(s string) string {
		for _, v := range []string{tenant, client} {
			s = strings.ReplaceAll(s, v, "<redacted>")
		}
		return s
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ta, err := auth.NewTenantAuth(config.TenantConfig{TenantID: tenant})
	if err != nil {
		t.Fatalf("NewTenantAuth: %s", redact(err.Error()))
	}
	gc, err := graphclient.NewClient(ctx, ta, graphclient.Options{})
	if err != nil {
		t.Fatalf("graphclient.NewClient: %s", redact(err.Error()))
	}

	for _, ep := range Manifest() {
		t.Run(ep.ID, func(t *testing.T) {
			body, err := gc.RawGetWithHeaders(ctx, BaseURL+ep.Path, ep.Headers)
			if err != nil {
				if oc, ok := Classify(err); ok {
					t.Errorf("%s: %s: request refused (401/403); the poller identity lacks a scope or licence for %s",
						ep.ID, strings.ToUpper(string(oc)), ep.UsedBy)
					return
				}
				t.Errorf("%s: request failed: %s", ep.ID, redact(err.Error()))
				return
			}
			oc, err := CheckShape(ep, body)
			if err != nil {
				t.Errorf("%s", redact(err.Error()))
				return
			}
			if oc == OutcomeEmpty {
				t.Logf("NOT-APPLICABLE: %s :: empty collection in this tenant, shape not checked", ep.ID)
			}
		})
	}
}
