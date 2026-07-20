package exportjob

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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

// TestExportEmptySelectOmitsSelectKey pins the wire-verified fix (#203): some
// Intune reports (NoncompliantDevicesAndSettings, DeviceAssignmentStatusByConfigurationPolicy)
// reject an explicit `select` that names a localized `_loc` column — those columns
// exist only in the default output and 400 when selected. An empty Select is
// therefore valid and means "take the report's default columns": the `select` key
// must be OMITTED from the POST body entirely (an empty array is not the same as an
// absent key), and Export must proceed rather than reject it as a programming error.
func TestExportEmptySelectOmitsSelectKey(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var postedBody []byte
	poster := &fakePoster{
		post: func(_ context.Context, _ string, body []byte, _ map[string]string) ([]byte, error) {
			postedBody = body
			return []byte(`{"id":"job1","status":"notStarted"}`), nil
		},
		get: func(context.Context, string, map[string]string) ([]byte, error) {
			expiry := base.Add(time.Hour).Format(time.RFC3339)
			return []byte(fmt.Sprintf(`{"id":"job1","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
		},
	}
	zipBytes := buildZip(t, "export.csv", []byte("DeviceId\ndev1\n"))
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return zipBytes, nil }}

	c := New(poster, dl, Options{Now: stepClock(base)})
	rec := telemetrytest.New()
	rows, err := c.Export(context.Background(), Request{ReportName: "NoncompliantDevicesAndSettings"}, rec.Emitter())
	if err != nil {
		t.Fatalf("Export with empty Select: want success, got %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	var sent map[string]any
	if err := json.Unmarshal(postedBody, &sent); err != nil {
		t.Fatalf("unmarshal posted body: %v", err)
	}
	if _, present := sent["select"]; present {
		t.Errorf("posted body carries a `select` key with empty Select; want it omitted: %s", postedBody)
	}
	if sent["reportName"] != "NoncompliantDevicesAndSettings" {
		t.Errorf("posted reportName = %v", sent["reportName"])
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

// TestParseCSVRowsToleratesBOMAndBareQuotes is the live-caught regression: the
// Intune export CSVs carry a leading UTF-8 BOM and occasional bare double-quotes
// in unquoted fields, which the default encoding/csv reader rejects. parseCSVRows
// strips the BOM (so the first header isn't corrupted) and uses LazyQuotes.
func TestParseCSVRowsToleratesBOMAndBareQuotes(t *testing.T) {
	// BOM + header + a data row whose 3rd field carries a bare double-quote.
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte("DeviceName,State,Note\nPC1,ok,a\"b\nPC2,fail,plain\n")...)
	rows, err := parseCSVRows(data)
	if err != nil {
		t.Fatalf("parseCSVRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// BOM must not corrupt the first header key.
	if _, ok := rows[0]["DeviceName"]; !ok {
		t.Errorf("first header corrupted by BOM; keys=%v", rows[0])
	}
	if rows[0]["Note"] != `a"b` {
		t.Errorf("bare-quote field = %q, want a\"b", rows[0]["Note"])
	}
	if rows[1]["State"] != "fail" {
		t.Errorf("row 2 State = %q, want fail", rows[1]["State"])
	}
}
