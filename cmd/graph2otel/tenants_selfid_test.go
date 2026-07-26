package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type selfIdentityCredential struct {
	token    string
	err      error
	requests int
	scopes   [][]string
}

type selfIdentityPageFetcher struct {
	records []map[string]any
}

func (f selfIdentityPageFetcher) FetchPage(
	context.Context,
	string,
) ([]map[string]any, string, error) {
	return f.records, "", nil
}

func (c *selfIdentityCredential) GetToken(
	_ context.Context,
	opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	c.requests++
	c.scopes = append(c.scopes, append([]string(nil), opts.Scopes...))
	return azcore.AccessToken{Token: c.token}, c.err
}

func selfIdentityToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal token claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func selfIdentityLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func selfIdentityLogEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	entries := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestResolveTenantSelfIdentityUsesProvedAppIDForBothPaths(t *testing.T) {
	const (
		tenantID      = "tenant-a"
		configuredID  = "configured-stale-app"
		environmentID = "environment-stale-app"
		provedID      = "authenticated-poller-app"
	)
	t.Setenv("AZURE_CLIENT_ID", environmentID)
	credential := &selfIdentityCredential{
		token: selfIdentityToken(t, map[string]any{"appid": provedID}),
	}
	ta := &auth.TenantAuth{TenantID: tenantID, Cred: credential}
	cfg := &config.Config{Tenants: []config.TenantConfig{{
		TenantID: tenantID, ClientID: configuredID, ExcludeSelf: true,
	}}}
	var logs bytes.Buffer

	identity := resolveTenantSelfIdentity(
		context.Background(), cfg, ta, selfIdentityLogger(&logs),
	)

	if credential.requests != 1 {
		t.Fatalf("token requests = %d, want 1", credential.requests)
	}
	if len(credential.scopes) != 1 ||
		len(credential.scopes[0]) != 1 ||
		credential.scopes[0][0] != auth.GraphDefaultScope {
		t.Fatalf("token scopes = %v, want [[%q]]", credential.scopes, auth.GraphDefaultScope)
	}

	var window collectors.WindowDeps
	var blob collectors.BlobDeps
	identity.applyWindow(&window)
	identity.applyBlob(&blob)
	if !window.ExcludeSelf || window.SelfClientID != provedID {
		t.Fatalf(
			"WindowDeps self filter = (%v, %q), want (true, %q)",
			window.ExcludeSelf, window.SelfClientID, provedID,
		)
	}
	if blob.ExcludeSelf != window.ExcludeSelf || blob.SelfClientID != window.SelfClientID {
		t.Fatalf(
			"BlobDeps self filter = (%v, %q), WindowDeps = (%v, %q)",
			blob.ExcludeSelf, blob.SelfClientID,
			window.ExcludeSelf, window.SelfClientID,
		)
	}

	// Both filters compare a record appId directly with SelfClientID. A record
	// authored by either stale configured/environment identity therefore stays,
	// while a record from the proved token identity is the only self match.
	for _, thirdPartyID := range []string{configuredID, environmentID} {
		if thirdPartyID == window.SelfClientID {
			t.Errorf("stale third-party app %q would be excluded", thirdPartyID)
		}
	}
	if provedID != window.SelfClientID {
		t.Errorf("proved app %q would not be excluded", provedID)
	}

	from := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	records := []map[string]any{
		{"id": "configured-third-party", "appId": configuredID, "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
		{"id": "environment-third-party", "appId": environmentID, "createdDateTime": from.Add(20 * time.Minute).Format(time.RFC3339)},
		{"id": "proved-self", "appId": provedID, "createdDateTime": from.Add(30 * time.Minute).Format(time.RFC3339)},
	}
	endpoint := logpipeline.EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		OrderByReliable: true,
		ExcludeSelf:     window.ExcludeSelf,
		SelfClientID:    window.SelfClientID,
		SelfAppID: func(record map[string]any) string {
			appID, _ := record["appId"].(string)
			return appID
		},
		CollectorName: "entra.signins.service_principal",
		Map: func(record map[string]any) (string, telemetry.Event) {
			id, _ := record["id"].(string)
			return id, telemetry.Event{Name: "entra.signin", Body: id}
		},
	}
	pipeline := logpipeline.NewLogCollector(
		"entra.signins.service_principal",
		time.Minute,
		0,
		tenantID,
		endpoint,
		selfIdentityPageFetcher{records: records},
		checkpoint.NewStore(t.TempDir()),
	)
	capture := telemetrytest.New()
	if _, err := pipeline.CollectWindow(
		context.Background(), from, from.Add(time.Hour), capture.Emitter(), nil,
	); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	gotBodies := map[string]bool{}
	for _, record := range capture.LogRecords() {
		gotBodies[record.Body] = true
	}
	if !gotBodies["configured-third-party"] ||
		!gotBodies["environment-third-party"] ||
		gotBodies["proved-self"] ||
		len(gotBodies) != 2 {
		t.Fatalf(
			"emitted bodies = %v, want stale config/env records only; proved identity must be excluded",
			gotBodies,
		)
	}

	entries := selfIdentityLogEntries(t, &logs)
	if len(entries) != 1 {
		t.Fatalf("warning count = %d, want one mismatch warning: %s", len(entries), logs.String())
	}
	entry := entries[0]
	if entry["level"] != "WARN" ||
		entry["tenant"] != tenantID ||
		entry["configured_client_id"] != configuredID ||
		entry["authenticated_app_id"] != provedID {
		t.Fatalf("mismatch warning = %#v", entry)
	}
	if strings.Contains(logs.String(), environmentID) {
		t.Fatalf("warning treats AZURE_CLIENT_ID as authority: %s", logs.String())
	}
}

func TestResolveTenantSelfIdentityDisabledSkipsTokenRequestAndWarning(t *testing.T) {
	const tenantID = "tenant-a"
	credential := &selfIdentityCredential{
		token: selfIdentityToken(t, map[string]any{"appid": "proved-app"}),
	}
	ta := &auth.TenantAuth{TenantID: tenantID, Cred: credential}
	cfg := &config.Config{Tenants: []config.TenantConfig{{
		TenantID: tenantID, ClientID: "configured-app", ExcludeSelf: false,
	}}}
	var logs bytes.Buffer

	identity := resolveTenantSelfIdentity(
		context.Background(), cfg, ta, selfIdentityLogger(&logs),
	)

	if credential.requests != 0 {
		t.Fatalf("token requests = %d, want 0 when exclude_self is false", credential.requests)
	}
	var window collectors.WindowDeps
	var blob collectors.BlobDeps
	identity.applyWindow(&window)
	identity.applyBlob(&blob)
	if window.ExcludeSelf || window.SelfClientID != "" ||
		blob.ExcludeSelf || blob.SelfClientID != "" {
		t.Fatalf("disabled identity was wired: window=%+v blob=%+v", window, blob)
	}
	if entries := selfIdentityLogEntries(t, &logs); len(entries) != 0 {
		t.Fatalf("warnings = %#v, want none", entries)
	}
}

func TestResolveTenantSelfIdentityProofFailuresAreBoundedAndRedacted(t *testing.T) {
	const (
		tenantID    = "tenant-a"
		configured  = "configured-app"
		tokenSecret = "token-secret-marker"
		errorSecret = "credential-secret-marker"
	)
	tests := []struct {
		name       string
		credential *selfIdentityCredential
		wantReason string
		secrets    []string
	}{
		{
			name: "token request failed",
			credential: &selfIdentityCredential{
				err: errors.New("token request failed: " + errorSecret),
			},
			wantReason: selfIdentityReasonTokenRequestFailed,
			secrets:    []string{errorSecret},
		},
		{
			name: "malformed token",
			credential: &selfIdentityCredential{
				token: "header." + tokenSecret,
			},
			wantReason: selfIdentityReasonMalformedToken,
			secrets:    []string{tokenSecret},
		},
		{
			name: "missing appid",
			credential: &selfIdentityCredential{
				token: selfIdentityToken(t, map[string]any{"marker": tokenSecret}),
			},
			wantReason: selfIdentityReasonMissingAppID,
			secrets:    []string{tokenSecret},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ta := &auth.TenantAuth{TenantID: tenantID, Cred: tt.credential}
			cfg := &config.Config{Tenants: []config.TenantConfig{{
				TenantID: tenantID, ClientID: configured, ExcludeSelf: true,
			}}}
			var logs bytes.Buffer

			identity := resolveTenantSelfIdentity(
				context.Background(), cfg, ta, selfIdentityLogger(&logs),
			)

			if tt.credential.requests != 1 {
				t.Fatalf("token requests = %d, want 1", tt.credential.requests)
			}
			var window collectors.WindowDeps
			var blob collectors.BlobDeps
			identity.applyWindow(&window)
			identity.applyBlob(&blob)
			if window.ExcludeSelf || window.SelfClientID != "" ||
				blob.ExcludeSelf || blob.SelfClientID != "" {
				t.Fatalf("unproved identity enabled filtering: window=%+v blob=%+v", window, blob)
			}

			entries := selfIdentityLogEntries(t, &logs)
			if len(entries) != 1 {
				t.Fatalf("warning count = %d, want exactly 1: %s", len(entries), logs.String())
			}
			entry := entries[0]
			if entry["level"] != "WARN" ||
				entry["tenant"] != tenantID ||
				entry["reason"] != tt.wantReason {
				t.Fatalf("proof warning = %#v", entry)
			}
			for _, forbidden := range append(tt.secrets, configured) {
				if strings.Contains(logs.String(), forbidden) {
					t.Fatalf("warning exposes %q: %s", forbidden, logs.String())
				}
			}
		})
	}
}

func TestSelfIdentityFailureReasonUsesTypedCodeNotErrorMessage(t *testing.T) {
	tests := []struct {
		name       string
		code       auth.ApplicationIdentityFailureCode
		message    string
		wantReason string
	}{
		{
			name:       "token request code with malformed-token prose",
			code:       auth.ApplicationIdentityTokenRequestFailed,
			message:    "malformed Graph access token",
			wantReason: selfIdentityReasonTokenRequestFailed,
		},
		{
			name:       "malformed-token code with missing-appid prose",
			code:       auth.ApplicationIdentityMalformedToken,
			message:    "graph access token has no appid claim",
			wantReason: selfIdentityReasonMalformedToken,
		},
		{
			name:       "missing-appid code with token-request prose",
			code:       auth.ApplicationIdentityMissingAppID,
			message:    "requesting Graph token for authenticated application identity",
			wantReason: selfIdentityReasonMissingAppID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("outer changed prose: %w", &auth.ApplicationIdentityError{
				Code: tt.code,
				Err:  errors.New(tt.message),
			})
			if got := selfIdentityFailureReason(err); got != tt.wantReason {
				t.Errorf("selfIdentityFailureReason() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}
