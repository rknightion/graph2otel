package teamsusage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	collogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestUsageTwinsReachOTLPHTTPWithSourceTime(t *testing.T) {
	for _, suffix := range []string{"HEADERS", "LOGS_HEADERS", "METRICS_HEADERS"} {
		t.Setenv("OTEL_EXPORTER_OTLP_"+suffix, "")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_COMPRESSION", "none")
	const tenant = "example-tenant"
	refresh := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var requests []*collogpb.ExportLogsServiceRequest
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/otlp/v1/metrics":
			return
		case "/otlp/v1/logs":
		default:
			t.Errorf("unexpected OTLP path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, err := io.ReadAll(r.Body)
		var req collogpb.ExportLogsServiceRequest
		if err != nil {
			t.Errorf("read OTLP payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := proto.Unmarshal(raw, &req); err != nil {
			t.Errorf("decode OTLP payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests = append(requests, &req)
		mu.Unlock()
	}))
	defer sink.Close()

	p, err := telemetry.NewProvider(t.Context(), telemetry.Options{
		ServiceName: "graph2otel", Endpoint: sink.URL + "/otlp", Protocol: "http", MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdown := sync.OnceValue(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.Shutdown(ctx)
	})
	defer func() { _ = shutdown() }()

	g := &graphStub{bodies: map[string]string{devicesPath: devicesCSV, teamsPath: teamsCSV, trendPath: trendCSV}}
	r := collector.NewRegistry()
	r.Register(New(g), time.Hour)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s := collector.NewScheduler(p.Emitter(), collector.NewMemoryStore(),
		collector.WithTenant(tenant), collector.WithStaggerWindow(0),
		collector.WithClock(func() time.Time { return refresh.Add(60 * time.Hour) }),
		collector.WithEmitterFactory(p.CollectorEmitter),
		collector.WithSourceRecordRecorder(func(_ telemetry.Attribution, _ uint64) { cancel() }),
	)
	if err := s.Run(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected one completed poll, got %v", err)
	}
	if err := shutdown(); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"m365.teams_device_usage/192.0.2.1": "Teams device usage summary",
		"m365.teams_device_usage/192.0.2.2": "Teams device usage summary",
		"m365.team_activity/192.0.2.11":     "Teams activity summary",
		"m365.team_activity/192.0.2.12":     "Teams activity summary",
	}
	mu.Lock()
	defer mu.Unlock()
	for _, req := range requests {
		for _, rl := range req.GetResourceLogs() {
			attrs := rl.GetResource().GetAttributes()
			if service := wireString(attrs, "service.name"); service != "graph2otel" {
				t.Errorf("wire service = %q, want graph2otel", service)
			}
			if domain := wireString(attrs, "graph2otel.event_domain"); domain != "m365" {
				t.Errorf("wire domain = %q, want m365", domain)
			}
			for _, sl := range rl.GetScopeLogs() {
				for _, log := range sl.GetLogRecords() {
					attrs := log.GetAttributes()
					idKey := "id"
					if log.GetEventName() == "m365.teams_device_usage" {
						idKey = "user_id"
					}
					key := log.GetEventName() + "/" + wireString(attrs, idKey)
					if body, ok := want[key]; !ok || log.GetBody().GetStringValue() != body {
						t.Errorf("unexpected OTLP record key/body %q/%q", key, log.GetBody().GetStringValue())
					}
					delete(want, key)
					if got := time.Unix(0, int64(log.GetTimeUnixNano())).UTC(); !got.Equal(refresh) {
						t.Errorf("%s wire time = %v, want source midnight %v", key, got, refresh)
					}
					if wireString(attrs, "report_refresh_date") != "2026-11-23" || wireString(attrs, "report_period") != "7" ||
						wireString(attrs, "tenant_id") != tenant || wireString(attrs, "ingest_transport") != "graph" {
						t.Errorf("%s missing report or routing metadata on OTLP request", key)
					}
				}
			}
		}
	}
	if len(want) != 0 {
		t.Errorf("missing log twins at actual exporter boundary: %v", want)
	}
	if delivery := p.Delivery().Logs; delivery.ExportSuccesses == 0 || delivery.ExportFailures != 0 {
		t.Errorf("local receiver delivery: %+v", delivery)
	}
}

func wireString(attrs []*commonpb.KeyValue, key string) string {
	for _, attr := range attrs {
		if attr.GetKey() == key {
			return attr.GetValue().GetStringValue()
		}
	}
	return ""
}
