package exportjob

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

// TestSignalGolden drives both terminal outcomes through Export. Removing a
// completed/failed result, duration or poll accounting, or downloaded-byte
// accounting from the real production flow must make this fixture fail.
func TestSignalGolden(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	completed := telemetrytest.New()
	completedZIP := buildZip(t, "export.csv", []byte("name\ndevice1\n"))
	completedClient := New(
		&fakePoster{
			post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
				return []byte(`{"id":"completed-job","status":"notStarted"}`), nil
			},
			get: func(context.Context, string, map[string]string) ([]byte, error) {
				expiry := base.Add(time.Hour).Format(time.RFC3339)
				return []byte(fmt.Sprintf(
					`{"id":"completed-job","status":"completed","url":"https://blob.example/completed","expirationDateTime":%q}`,
					expiry,
				)), nil
			},
		},
		&fakeDownloader{download: func(context.Context, string) ([]byte, error) {
			return completedZIP, nil
		}},
		Options{Now: stepClock(base)},
	)
	completedEmitter := telemetry.WithTenant(
		telemetry.WithTransport(completed.Emitter(), telemetry.TransportReportExport),
		"fixture-tenant",
	)
	if _, err := completedClient.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name"},
	}, completedEmitter); err != nil {
		t.Fatalf("completed Export: %v", err)
	}

	failed := telemetrytest.New()
	failedClient := New(
		&fakePoster{
			post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
				return []byte(`{"id":"failed-job","status":"notStarted"}`), nil
			},
			get: func(context.Context, string, map[string]string) ([]byte, error) {
				return []byte(`{"id":"failed-job","status":"failed"}`), nil
			},
		},
		&fakeDownloader{download: func(context.Context, string) ([]byte, error) {
			t.Fatal("Download called for a failed export")
			return nil, nil
		}},
		Options{Now: stepClock(base)},
	)
	failedEmitter := telemetry.WithTenant(
		telemetry.WithTransport(failed.Emitter(), telemetry.TransportReportExport),
		"fixture-tenant",
	)
	if _, err := failedClient.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name"},
	}, failedEmitter); !errors.Is(err, ErrJobFailed) {
		t.Fatalf("failed Export error = %v, want ErrJobFailed", err)
	}

	assertTerminalFixture(t, completed, "completed", 3, len(completedZIP))
	assertTerminalFixture(t, failed, "failed", 2, 0)

	if err := signalcapture.GoldenAt(
		"testdata/signals.json",
		*updateSignalGolden,
		completed,
		failed,
	); err != nil {
		t.Fatal(err)
	}
}

func assertTerminalFixture(
	t *testing.T,
	rec *telemetrytest.Recorder,
	result string,
	wantDuration float64,
	wantBytes int,
) {
	t.Helper()

	jobs := rec.MetricPoints("graph2otel.export.jobs")
	if len(jobs) != 1 {
		t.Fatalf("%s jobs points = %d, want one", result, len(jobs))
	}
	if got := jobs[0].Attrs["result"]; got != result {
		t.Errorf("%s jobs result = %q, want %q", result, got, result)
	}
	if got := jobs[0].Attrs["tenant_id"]; got != "fixture-tenant" {
		t.Errorf("%s jobs tenant_id = %q, want fixture-tenant", result, got)
	}
	if got := jobs[0].Value; got != 1 {
		t.Errorf("%s jobs value = %v, want 1", result, got)
	}

	polls := rec.MetricPoints("graph2otel.export.poll_count")
	if len(polls) != 1 {
		t.Errorf("%s poll_count points = %d, want one", result, len(polls))
	} else if polls[0].Value != 1 {
		t.Errorf("%s poll_count = %v, want 1", result, polls[0].Value)
	}

	durations := rec.MetricPoints("graph2otel.export.duration_seconds")
	if len(durations) != 1 {
		t.Errorf("%s duration_seconds points = %d, want one", result, len(durations))
	} else if durations[0].Value != wantDuration {
		t.Errorf("%s duration_seconds = %v, want %v", result, durations[0].Value, wantDuration)
	}

	bytesPoints := rec.MetricPoints("graph2otel.export.bytes")
	if wantBytes == 0 {
		if len(bytesPoints) != 0 {
			t.Errorf("%s bytes points = %d, want none", result, len(bytesPoints))
		}
	} else if len(bytesPoints) != 1 {
		t.Errorf("%s bytes points = %d, want one", result, len(bytesPoints))
	} else if bytesPoints[0].Value != float64(wantBytes) {
		t.Errorf("%s bytes = %v, want %d", result, bytesPoints[0].Value, wantBytes)
	}
}
