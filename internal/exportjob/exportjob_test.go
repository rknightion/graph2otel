package exportjob

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakePoster adapts plain functions to Poster, so tests can drive Client
// without a real Graph client or httptest server, mirroring
// logpipeline_test.go's pageFetcherFunc pattern.
type fakePoster struct {
	post func(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error)
	get  func(ctx context.Context, url string, headers map[string]string) ([]byte, error)
}

func (f *fakePoster) RawPost(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error) {
	return f.post(ctx, url, body, headers)
}

func (f *fakePoster) RawGetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	return f.get(ctx, url, headers)
}

// fakeDownloader adapts a plain function to Downloader.
type fakeDownloader struct {
	download func(ctx context.Context, sasURL string) ([]byte, error)
}

func (f *fakeDownloader) Download(ctx context.Context, sasURL string) ([]byte, error) {
	return f.download(ctx, sasURL)
}

// buildZip builds an in-memory single-entry ZIP archive, the shape every
// export job's download payload takes.
func buildZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip.Create: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// noSleep is an Options.Sleep that records the requested delay without
// actually waiting, so backoff tests assert the schedule without taking
// wall-clock time.
func noSleep(delays *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*delays = append(*delays, d)
		return nil
	}
}

// stepClock returns an Options.Now that advances by 1s on every call,
// starting at base — a deterministic stand-in for the wall clock so
// duration_seconds is observable without a real sleep.
func stepClock(base time.Time) func() time.Time {
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

func TestExportSlowCompletionBackoffAndDownload(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var delays []time.Duration

	getCalls := 0
	poster := &fakePoster{
		post: func(_ context.Context, url string, body []byte, _ map[string]string) ([]byte, error) {
			if want := "https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs"; url != want {
				t.Fatalf("create url = %q, want %q", url, want)
			}
			if !bytes.Contains(body, []byte(`"reportName":"DeviceInstallStatusByApp"`)) {
				t.Fatalf("create body missing reportName: %s", body)
			}
			return []byte(`{"id":"job1","status":"notStarted"}`), nil
		},
		get: func(_ context.Context, url string, _ map[string]string) ([]byte, error) {
			if want := "https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs/job1"; url != want {
				t.Fatalf("poll url = %q, want %q", url, want)
			}
			getCalls++
			if getCalls <= 4 {
				return []byte(`{"id":"job1","status":"inProgress"}`), nil
			}
			expiry := base.Add(time.Hour).Format(time.RFC3339)
			return []byte(fmt.Sprintf(`{"id":"job1","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
		},
	}

	zipBytes := buildZip(t, "export.csv", []byte("name,state\ndevice1,compliant\ndevice2,noncompliant\n"))
	downloadCalls := 0
	dl := &fakeDownloader{download: func(_ context.Context, sasURL string) ([]byte, error) {
		downloadCalls++
		if sasURL != "https://blob.example/sas" {
			t.Fatalf("download url = %q", sasURL)
		}
		return zipBytes, nil
	}}

	c := New(poster, dl, Options{
		PollInitial: 2 * time.Millisecond,
		PollMax:     8 * time.Millisecond,
		Now:         stepClock(base),
		Sleep:       noSleep(&delays),
	})

	rec := telemetrytest.New()
	rows, err := c.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name", "state"},
	}, rec.Emitter())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if getCalls != 5 {
		t.Fatalf("getCalls = %d, want 5 (4 inProgress + 1 completed)", getCalls)
	}
	if downloadCalls != 1 {
		t.Fatalf("downloadCalls = %d, want 1", downloadCalls)
	}

	wantDelays := []time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 8 * time.Millisecond, 8 * time.Millisecond}
	if len(delays) != len(wantDelays) {
		t.Fatalf("delays = %v, want %v", delays, wantDelays)
	}
	for i, d := range delays {
		if d != wantDelays[i] {
			t.Fatalf("delays[%d] = %v, want %v (full: %v)", i, d, wantDelays[i], delays)
		}
	}

	want := []Row{
		{"name": "device1", "state": "compliant"},
		{"name": "device2", "state": "noncompliant"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}
	for i := range want {
		for k, v := range want[i] {
			if rows[i][k] != v {
				t.Fatalf("rows[%d][%q] = %q, want %q (full: %+v)", i, k, rows[i][k], v, rows)
			}
		}
	}
}

func TestExportFailedJobNoDownload(t *testing.T) {
	poster := &fakePoster{
		post: func(_ context.Context, _ string, _ []byte, _ map[string]string) ([]byte, error) {
			return []byte(`{"id":"job1","status":"notStarted"}`), nil
		},
		get: func(_ context.Context, _ string, _ map[string]string) ([]byte, error) {
			return []byte(`{"id":"job1","status":"failed"}`), nil
		},
	}
	dl := &fakeDownloader{download: func(_ context.Context, _ string) ([]byte, error) {
		t.Fatal("Download called on a failed job")
		return nil, nil
	}}

	c := New(poster, dl, Options{Sleep: func(context.Context, time.Duration) error { return nil }})

	rec := telemetrytest.New()
	_, err := c.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name"},
	}, rec.Emitter())
	if !errors.Is(err, ErrJobFailed) {
		t.Fatalf("err = %v, want wrapping ErrJobFailed", err)
	}

	jobs := rec.MetricPoints("graph2otel.export.jobs")
	if len(jobs) != 1 || jobs[0].Attrs["result"] != "failed" {
		t.Fatalf("graph2otel.export.jobs = %+v, want one point with result=failed", jobs)
	}
	if bytesPoints := rec.MetricPoints("graph2otel.export.bytes"); len(bytesPoints) != 0 {
		t.Fatalf("graph2otel.export.bytes = %+v, want none on a failed job", bytesPoints)
	}
}

func TestExportSASExpiredNoDownload(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	poster := &fakePoster{
		post: func(_ context.Context, _ string, _ []byte, _ map[string]string) ([]byte, error) {
			return []byte(`{"id":"job1","status":"notStarted"}`), nil
		},
		get: func(_ context.Context, _ string, _ map[string]string) ([]byte, error) {
			// Already expired by the time Export's Now() checks it.
			expiry := base.Add(-time.Hour).Format(time.RFC3339)
			return []byte(fmt.Sprintf(`{"id":"job1","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
		},
	}
	dl := &fakeDownloader{download: func(_ context.Context, _ string) ([]byte, error) {
		t.Fatal("Download called after SAS expiry")
		return nil, nil
	}}

	c := New(poster, dl, Options{Now: func() time.Time { return base }})

	rec := telemetrytest.New()
	_, err := c.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name"},
	}, rec.Emitter())
	if !errors.Is(err, ErrSASExpired) {
		t.Fatalf("err = %v, want wrapping ErrSASExpired", err)
	}
}

func TestExportParsesJSONRows(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"bare array", `[{"id":1,"name":"a"},{"id":2,"name":"b"}]`},
		{"values wrapper", `{"values":[{"id":1,"name":"a"},{"id":2,"name":"b"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			poster := &fakePoster{
				post: func(_ context.Context, _ string, _ []byte, _ map[string]string) ([]byte, error) {
					return []byte(`{"id":"job1","status":"notStarted"}`), nil
				},
				get: func(_ context.Context, _ string, _ map[string]string) ([]byte, error) {
					expiry := time.Now().Add(time.Hour).Format(time.RFC3339)
					return []byte(fmt.Sprintf(`{"id":"job1","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
				},
			}
			zipBytes := buildZip(t, "export.json", []byte(tt.body))
			dl := &fakeDownloader{download: func(_ context.Context, _ string) ([]byte, error) {
				return zipBytes, nil
			}}

			c := New(poster, dl, Options{})
			rec := telemetrytest.New()
			rows, err := c.Export(context.Background(), Request{
				ReportName: "DeviceComplianceOrgSummary",
				Select:     []string{"id", "name"},
				Format:     FormatJSON,
			}, rec.Emitter())
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			want := []Row{{"id": "1", "name": "a"}, {"id": "2", "name": "b"}}
			if len(rows) != len(want) {
				t.Fatalf("rows = %+v, want %+v", rows, want)
			}
			for i := range want {
				for k, v := range want[i] {
					if rows[i][k] != v {
						t.Fatalf("rows[%d][%q] = %q, want %q (full: %+v)", i, k, rows[i][k], v, rows)
					}
				}
			}
		})
	}
}

func TestExportRequiresNonEmptySelect(t *testing.T) {
	poster := &fakePoster{
		post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
			t.Fatal("RawPost called with an empty Select")
			return nil, nil
		},
		get: func(context.Context, string, map[string]string) ([]byte, error) {
			t.Fatal("RawGetWithHeaders called with an empty Select")
			return nil, nil
		},
	}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) {
		t.Fatal("Download called with an empty Select")
		return nil, nil
	}}

	c := New(poster, dl, Options{})
	rec := telemetrytest.New()
	_, err := c.Export(context.Background(), Request{ReportName: "DeviceInstallStatusByApp"}, rec.Emitter())
	if err == nil {
		t.Fatal("Export with empty Select: want an error, got nil")
	}
}

func TestExportEmitsSelfObsMetrics(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	poster := &fakePoster{
		post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
			return []byte(`{"id":"job1","status":"notStarted"}`), nil
		},
		get: func(context.Context, string, map[string]string) ([]byte, error) {
			expiry := base.Add(time.Hour).Format(time.RFC3339)
			return []byte(fmt.Sprintf(`{"id":"job1","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
		},
	}
	content := []byte("name\ndevice1\n")
	zipBytes := buildZip(t, "export.csv", content)
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return zipBytes, nil }}

	c := New(poster, dl, Options{Now: stepClock(base)})
	rec := telemetrytest.New()
	if _, err := c.Export(context.Background(), Request{
		ReportName: "DeviceInstallStatusByApp",
		Select:     []string{"name"},
	}, rec.Emitter()); err != nil {
		t.Fatalf("Export: %v", err)
	}

	jobs := rec.MetricPoints("graph2otel.export.jobs")
	if len(jobs) != 1 || jobs[0].Attrs["report_name"] != "DeviceInstallStatusByApp" || jobs[0].Attrs["result"] != "completed" {
		t.Fatalf("graph2otel.export.jobs = %+v, want one completed point for DeviceInstallStatusByApp", jobs)
	}

	pollCount := rec.MetricPoints("graph2otel.export.poll_count")
	if len(pollCount) != 1 || pollCount[0].Value != 1 {
		t.Fatalf("graph2otel.export.poll_count = %+v, want one point with value 1", pollCount)
	}

	duration := rec.MetricPoints("graph2otel.export.duration_seconds")
	if len(duration) != 1 {
		t.Fatalf("graph2otel.export.duration_seconds = %+v, want one point", duration)
	}

	bytesPoints := rec.MetricPoints("graph2otel.export.bytes")
	if len(bytesPoints) != 1 || bytesPoints[0].Value != float64(len(zipBytes)) {
		t.Fatalf("graph2otel.export.bytes = %+v, want one point with value %d", bytesPoints, len(zipBytes))
	}
}
