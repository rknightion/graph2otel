package discoveryparse

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
)

func TestCollectWindowReconcilesEveryGovernanceRecord(t *testing.T) {
	valid := record(
		"valid",
		fixedNow.Add(-10*time.Minute).UnixMilli(),
		fixedNow.Add(-9*time.Minute).UnixMilli(),
		successStatus(3, 1),
	)
	filtered := map[string]any{
		"_id":             "other",
		"taskName":        "SomethingElse",
		"timestamp":       fixedNow.Add(-8 * time.Minute).UnixMilli(),
		"updateTimestamp": fixedNow.Add(-7 * time.Minute).UnixMilli(),
	}
	undated := map[string]any{
		"_id":           "undated",
		"taskName":      taskNameFilter,
		"inputStreamId": "stream-1",
	}
	gs := &govServer{responses: []string{govBody(t, valid, filtered, undated)}}
	c, _ := newTestCollector(t, gs)
	outcomes := recordoutcome.NewRecorder()

	if _, err := c.CollectWindow(
		context.Background(),
		fixedNow.Add(-4*time.Hour),
		fixedNow,
		newRec().Emitter(),
		outcomes,
	); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{
		Fetched:  3,
		Mapped:   1,
		Emitted:  1,
		Filtered: 1,
		Dropped:  1,
	}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseMissingEventTime {
		t.Fatalf("causes = %v, want [%s]", got.Causes, recordoutcome.CauseMissingEventTime)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("outcomes do not reconcile: %v", err)
	}
}

func TestCollectWindowCountsOverlapRecordAsMappedAndDeduped(t *testing.T) {
	ts := fixedNow.Add(-10 * time.Minute).UnixMilli()
	upd := fixedNow.Add(-9 * time.Minute).UnixMilli()
	body := govBody(t, record("a", ts, upd, successStatus(3, 1)))
	gs := &govServer{responses: []string{body, body}}
	c, _ := newTestCollector(t, gs)

	first := recordoutcome.NewRecorder()
	if _, err := c.CollectWindow(
		context.Background(),
		fixedNow.Add(-4*time.Hour),
		fixedNow,
		newRec().Emitter(),
		first,
	); err != nil {
		t.Fatalf("first CollectWindow: %v", err)
	}

	second := recordoutcome.NewRecorder()
	if _, err := c.CollectWindow(
		context.Background(),
		fixedNow.Add(-4*time.Hour),
		fixedNow,
		newRec().Emitter(),
		second,
	); err != nil {
		t.Fatalf("second CollectWindow: %v", err)
	}

	got := second.Snapshot()
	want := recordoutcome.Counts{Fetched: 1, Mapped: 1, Deduped: 1}
	if got.Counts != want {
		t.Fatalf("second counts = %+v, want %+v", got.Counts, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("second outcomes do not reconcile: %v", err)
	}
}

func TestCollectWindowClassifiesBoundedGovernanceFailureCause(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		cancel    bool
		wantCause recordoutcome.Cause
	}{
		{
			name: "permission denied",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "forbidden", http.StatusForbidden)
			},
			wantCause: recordoutcome.CausePermissionDenied,
		},
		{
			name: "decode error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"total":`))
			},
			wantCause: recordoutcome.CauseDecodeError,
		},
		{
			name: "canceled context",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"total":0,"data":[]}`))
			},
			cancel:    true,
			wantCause: recordoutcome.CauseTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)
			client, err := mdcaclient.NewClient(
				"tenant-1",
				mdcaclient.Options{BaseURL: srv.URL, Token: "tok"},
			)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			c := New(collectors.MDCADeps{
				Client:   client,
				TenantID: "tenant-1",
				Store:    checkpoint.NewStore(t.TempDir()),
			})
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			outcomes := recordoutcome.NewRecorder()

			_, err = c.CollectWindow(
				ctx,
				fixedNow.Add(-4*time.Hour),
				fixedNow,
				newRec().Emitter(),
				outcomes,
			)
			if err == nil {
				t.Fatal("CollectWindow error = nil, want failure")
			}
			got := outcomes.Snapshot()
			if len(got.Causes) != 1 || got.Causes[0] != tc.wantCause {
				t.Fatalf("causes = %v, want [%s]", got.Causes, tc.wantCause)
			}
			if got.Counts != (recordoutcome.Counts{}) {
				t.Fatalf("counts = %+v, want all zero before a page is returned", got.Counts)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("failure outcomes do not reconcile: %v", err)
			}
		})
	}
}

func TestCollectWindowAccountsBufferedRecordsOnLaterPageFailure(t *testing.T) {
	records := make([]map[string]any, 100)
	for i := range records {
		records[i] = map[string]any{
			"_id":             i,
			"taskName":        taskNameFilter,
			"timestamp":       fixedNow.Add(-10 * time.Minute).UnixMilli(),
			"updateTimestamp": fixedNow.Add(-9 * time.Minute).UnixMilli(),
		}
	}
	first, err := json.Marshal(map[string]any{"total": 101, "data": records})
	if err != nil {
		t.Fatalf("marshal first page: %v", err)
	}
	gs := &govServer{responses: []string{string(first), `{"total":`}}
	c, _ := newTestCollector(t, gs)
	outcomes := recordoutcome.NewRecorder()
	emitted := newRec()

	if _, err := c.CollectWindow(
		context.Background(),
		fixedNow.Add(-4*time.Hour),
		fixedNow,
		emitted.Emitter(),
		outcomes,
	); err == nil {
		t.Fatal("CollectWindow error = nil, want later-page decode failure")
	}

	got := outcomes.Snapshot()
	want := recordoutcome.Counts{Fetched: 100, Errored: 100}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if len(got.Causes) != 1 || got.Causes[0] != recordoutcome.CauseDecodeError {
		t.Fatalf("causes = %v, want [%s]", got.Causes, recordoutcome.CauseDecodeError)
	}
	if len(emitted.LogRecords()) != 0 {
		t.Fatalf("emitted %d partial-page logs, want zero", len(emitted.LogRecords()))
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("failure outcomes do not reconcile: %v", err)
	}
}
