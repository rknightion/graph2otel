package blobpipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestPollAccountsEachBlobRecordExactlyOnce(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	src := &fakeSource{blobs: map[string]string{
		name: "{malformed}\r\n" +
			recWithApp("self", "POLLER") +
			recWithApp("rejected", "THIRDPARTY") +
			`{"id":"undated","properties":{"appId":"THIRDPARTY"}}` + "\r\n" +
			recWithApp("valid", "THIRDPARTY"),
	}}
	cfg := selfTestConfig(true, "POLLER", propsAppID)
	cfg.Map = func(rec map[string]any) (telemetry.Event, bool) {
		if rec["id"] == "rejected" {
			return telemetry.Event{}, false
		}
		ev, ok := testConfig().Map(rec)
		if rec["id"] == "valid" {
			ev.Timestamp = time.Now()
		}
		return ev, ok
	}
	// A valid source record may produce several telemetry points, but its
	// emitted outcome is still one source record.
	cfg.Derive = func(map[string]any, telemetry.Event) []MetricPoint {
		return []MetricPoint{
			{Name: "test.one", Kind: MetricCounter, Value: 1},
			{Name: "test.two", Kind: MetricCounter, Value: 1},
		}
	}
	cfg.RecencyWindow = time.Hour

	outcomes := recordoutcome.NewRecorder()
	telemetryRecorder := telemetrytest.New()
	if err := Poll(
		context.Background(), cfg, newCursor(), src, telemetryRecorder.Emitter(),
		discardLogger(), nil, outcomes,
	); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	got := outcomes.Snapshot().Counts
	want := recordoutcome.Counts{
		Fetched:  5,
		Mapped:   1,
		Emitted:  1,
		Filtered: 1,
		Dropped:  2,
		Errored:  1,
	}
	if got != want {
		t.Fatalf("outcome counts = %+v, want %+v", got, want)
	}
	if err := outcomes.Snapshot().Validate(); err != nil {
		t.Fatalf("outcome reconciliation: %v", err)
	}
	if got := len(telemetryRecorder.MetricPoints("test.one")); got != 1 {
		t.Fatalf("test.one points = %d, want 1 to prove the valid record reached Derive", got)
	}
	if got := len(telemetryRecorder.MetricPoints("test.two")); got != 1 {
		t.Fatalf("test.two points = %d, want 1 to prove one record may produce multiple points", got)
	}
}

func TestPollKeepsOutcomeProgressWhenALaterBlobFails(t *testing.T) {
	src := &fakeSource{
		blobs: map[string]string{
			"tenantId=t1/a.json": rec("first"),
			"tenantId=t1/b.json": rec("unreadable"),
		},
		readErr: map[string]error{"tenantId=t1/b.json": errors.New("read failed")},
	}
	outcomes := recordoutcome.NewRecorder()

	err := Poll(
		context.Background(), testConfig(), newCursor(), src,
		telemetrytest.New().Emitter(), discardLogger(), nil, outcomes,
	)
	if err == nil {
		t.Fatal("Poll error = nil, want later blob read failure")
	}

	got := outcomes.Snapshot().Counts
	want := recordoutcome.Counts{Fetched: 1, Mapped: 1, Emitted: 1}
	if got != want {
		t.Fatalf("outcome counts after partial failure = %+v, want %+v", got, want)
	}
	if got := outcomes.Snapshot().Summarize(err, false).Result; got != recordoutcome.ResultPartial {
		t.Fatalf("result after useful progress and a later read failure = %q, want %q", got, recordoutcome.ResultPartial)
	}
}

func TestPollContainsMapperPanicAndAdvancesPastPoisonRecord(t *testing.T) {
	name := "tenantId=t1/y=2026/m=07/d=16/h=00/m=00/PT1H.json"
	data := rec("first") + rec("poison") + rec("last")
	src := &fakeSource{blobs: map[string]string{name: data}}
	cfg := testConfig()
	baseMap := cfg.Map
	cfg.Map = func(row map[string]any) (telemetry.Event, bool) {
		if row["id"] == "poison" {
			panic("bad mapper assumption")
		}
		return baseMap(row)
	}
	cur := newCursor()
	outcomes := recordoutcome.NewRecorder()
	recorder := telemetrytest.New()

	if err := Poll(
		context.Background(), cfg, cur, src, recorder.Emitter(),
		discardLogger(), nil, outcomes,
	); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	wantCounts := recordoutcome.Counts{
		Fetched: 3, Mapped: 2, Emitted: 2, Errored: 1,
	}
	got := outcomes.Snapshot()
	if got.Counts != wantCounts {
		t.Fatalf("outcome counts = %+v, want %+v", got.Counts, wantCounts)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseMappingError {
		t.Fatalf("outcome causes = %v, want [%q]", got.Causes, recordoutcome.CauseMappingError)
	}
	if got := cur.Offsets[name]; got != int64(len(data)) {
		t.Fatalf("cursor offset = %d, want %d (poison record consumed)", got, len(data))
	}
	if got := len(recorder.LogRecords()); got != 2 {
		t.Fatalf("emitted logs = %d, want 2 healthy records around the panic", got)
	}
}

func TestPollClassifiesDeadlineAsTimeout(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	err := Poll(
		context.Background(),
		testConfig(),
		newCursor(),
		&fakeSource{listErr: context.DeadlineExceeded},
		telemetrytest.New().Emitter(),
		discardLogger(),
		nil,
		outcomes,
	)
	if err == nil {
		t.Fatal("Poll error = nil, want deadline")
	}
	got := outcomes.Snapshot().Causes
	if len(got) != 1 || got[0] != recordoutcome.CauseTimeout {
		t.Fatalf("causes = %v, want [%q]", got, recordoutcome.CauseTimeout)
	}
}
