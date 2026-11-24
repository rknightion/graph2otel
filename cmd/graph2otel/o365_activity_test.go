package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestO365ActivityRecordTypeAllowList(t *testing.T) {
	// The Teams row uses only keys observed in the poller's TeamsSessionStarted
	// response. Values are synthetic, and ObjectId is intentionally opaque.
	const payload = `[
		{"AppAccessContext":{},"ClientIP":"192.0.2.10","CreationTime":"2026-01-02T03:04:05",
		 "DeviceId":"device-test","Id":"teams-session-test","ObjectId":"opaque-test-object",
		 "Operation":"TeamsSessionStarted","OrganizationId":"org-test","RecordType":25,
		 "UserId":"user@example.com","UserKey":"actor-test","UserType":0,"Version":1,"Workload":"MicrosoftTeams"},
		{"Id":"other-audit-test","RecordType":63,"CreationTime":"2026-01-02T03:04:06"},
		{"Id":"invalid-type-test","RecordType":25.5}
	]`
	for _, tc := range []struct {
		name, filter string
		counts       recordoutcome.Counts
	}{
		{"filtered", "      record_type_allow_list: [25]\n", recordoutcome.Counts{Fetched: 3, Mapped: 1, Emitted: 1, Filtered: 2}},
		{"unset", "", recordoutcome.Counts{Fetched: 3, Mapped: 2, Emitted: 2, Dropped: 1}},
		{"empty", "      record_type_allow_list: []\n", recordoutcome.Counts{Fetched: 3, Mapped: 2, Emitted: 2, Dropped: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const tenantID = "00000000-0000-0000-0000-000000000001"
			path := filepath.Join(t.TempDir(), "config.yaml")
			yaml := "tenants:\n  - tenant_id: " + tenantID + "\n    o365_activity:\n      content_types: [Audit.General]\n" + tc.filter
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}

			now := time.Now().UTC().Truncate(time.Second)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const feed = "/api/v1.0/" + tenantID + "/activity/feed"
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == feed+"/subscriptions/start" && r.Method == http.MethodPost && r.URL.Query().Get("contentType") == "Audit.General":
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, `{"error":{"code":"AF20024","message":"subscription already enabled"}}`)
				case r.URL.Path == feed+"/subscriptions/content" && r.Method == http.MethodGet && r.URL.Query().Get("contentType") == "Audit.General":
					_ = json.NewEncoder(w).Encode([]map[string]string{{
						"contentType": "Audit.General", "contentId": "blob-test",
						"contentUri":        "http://" + r.Host + feed + "/audit/blob-test",
						"contentCreated":    now.Add(-time.Hour).Format(time.RFC3339),
						"contentExpiration": now.Add(time.Hour).Format(time.RFC3339),
					}})
				case r.URL.Path == feed+"/audit/blob-test" && r.Method == http.MethodGet:
					_, _ = io.WriteString(w, payload)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(srv.Close)

			reg, rec := collector.NewRegistry(), telemetrytest.New()
			var failures []availabilityStartupFailure
			reason := registerO365Collectors(
				cfg, startupTenantAuth(tenantID), nil, checkpoint.NewStore(t.TempDir()),
				slog.New(slog.NewTextHandler(io.Discard, nil)), rec.Emitter(), reg,
				map[admin.SkipKey]string{}, collectors.O365All(),
				func(ta *auth.TenantAuth, opts o365activityclient.Options) (*o365activityclient.Client, error) {
					opts.BaseURL = srv.URL
					return o365activityclient.NewClient(ta, opts)
				},
				resolveAvailabilityInventory(cfg, tenantID, nil, true), &failures,
			)
			entries := reg.Entries()
			if reason != "" || len(failures) != 0 || len(entries) != 1 || entries[0].Collector.Name() != "m365.activity" {
				t.Fatalf("register m365.activity: reason=%q, failures=%v, entries=%v", reason, failures, entries)
			}
			outcomes := recordoutcome.NewRecorder()
			if _, err := entries[0].Collector.(collector.WindowCollector).CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes); err != nil {
				t.Fatal(err)
			}
			if got := outcomes.Snapshot(); got.Counts != tc.counts || got.Validate() != nil {
				t.Fatalf("outcomes = %+v, want %+v", got, tc.counts)
			}
			logs := rec.LogRecords()
			if uint64(len(logs)) != tc.counts.Emitted {
				t.Fatalf("emitted %d logs, want %d", len(logs), tc.counts.Emitted)
			}
			got := logs[0]
			if got.EventName != "m365.audit" || got.Timestamp.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
				t.Errorf("log name and event time = %q %s", got.EventName, got.Timestamp)
			}
			for key, want := range map[string]string{
				"ingest_transport": "o365_activity", "id": "teams-session-test", "record_type": "MicrosoftTeams", "record_type_id": "25",
				"operation": "TeamsSessionStarted", "object_id": "opaque-test-object", "user_id": "user@example.com", "user_key": "actor-test",
			} {
				if value := got.Attrs[key]; value != want {
					t.Errorf("%s = %q, want %q", key, value, want)
				}
			}
			for key := range got.Attrs {
				if strings.HasPrefix(key, "team_") || strings.HasPrefix(key, "channel_") || strings.HasPrefix(key, "meeting_") {
					t.Errorf("unexpected Teams entity attribute %q", key)
				}
			}
		})
	}
}
