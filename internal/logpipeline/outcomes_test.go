package logpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestPollRecordOutcomesEmpty distinguishes a genuinely empty source response
// from a non-empty window whose records were all filtered or deduplicated.
func TestPollRecordOutcomesEmpty(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	cfg, cp, from, to := outcomeTestSetup()

	if _, err := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		onePageFetcher(nil),
		telemetrytest.New().Emitter(),
		outcomes,
	); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{})
	assertOutcomeSummary(t, outcomes, nil, recordoutcome.ResultEmpty, recordoutcome.CauseNone)
}

// TestPollRecordOutcomesReconcileMixedData drives every non-error terminal
// outcome through one successful poll. The two empty-id records deliberately
// prove #262's rule: each source record counts once and both are emitted even
// though neither can enter the dedupe set.
func TestPollRecordOutcomesReconcileMixedData(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recorder := telemetrytest.New()
	cfg, cp, from, to := outcomeTestSetup()
	cfg.NoServerFilter = true
	cfg.ExcludeSelf = true
	cfg.SelfClientID = "poller"
	cfg.SelfAppID = flatAppID
	cp.SeenIDs.Add("duplicate", from.Add(15*time.Minute))

	records := []map[string]any{
		{"id": "self", "appId": "poller", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
		{"id": "outside", "createdDateTime": from.Add(-time.Minute).Format(time.RFC3339)},
		{"id": "undated"},
		{"id": "new", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
		{"id": "duplicate", "createdDateTime": from.Add(15 * time.Minute).Format(time.RFC3339)},
		{"createdDateTime": from.Add(20 * time.Minute).Format(time.RFC3339)},
		{"createdDateTime": from.Add(25 * time.Minute).Format(time.RFC3339)},
	}

	if _, err := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		onePageFetcher(records),
		recorder.Emitter(),
		outcomes,
	); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{
		fetched:  7,
		mapped:   4,
		emitted:  3,
		deduped:  1,
		filtered: 2,
		dropped:  1,
	})
	assertOutcomeSummary(t, outcomes, nil, recordoutcome.ResultPartial, recordoutcome.CauseMissingEventTime)
	if got := len(recorder.LogRecords()); got != 3 {
		t.Fatalf("emitted logs = %d, want 3 (new plus two empty-id records)", got)
	}
}

// TestPollRecordOutcomesMappingPanicIsPartialSuccess makes one broken mapper
// row explicit without sacrificing the two usable rows around it. A mapper
// panic is contained to that record and classified as mapping_error; it never
// becomes a silent drop or turns one source record into multiple outcomes.
func TestPollRecordOutcomesMappingPanicIsPartialSuccess(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recorder := telemetrytest.New()
	cfg, cp, from, to := outcomeTestSetup()
	cfg.Map = func(record map[string]any) (string, telemetry.Event) {
		id, _ := record["id"].(string)
		if id == "broken" {
			panic("fixture mapper drift")
		}
		return mapByID(record)
	}
	records := []map[string]any{
		{"id": "before", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
		{"id": "broken", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
		{"id": "after", "createdDateTime": from.Add(15 * time.Minute).Format(time.RFC3339)},
	}

	if _, err := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		onePageFetcher(records),
		recorder.Emitter(),
		outcomes,
	); err != nil {
		t.Fatalf("Poll: %v; one bad record must not discard usable siblings", err)
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{
		fetched: 3,
		mapped:  2,
		emitted: 2,
		errored: 1,
	})
	assertOutcomeCauses(t, outcomes, recordoutcome.CauseMappingError)
	assertOutcomeSummary(t, outcomes, nil, recordoutcome.ResultPartial, recordoutcome.CauseMappingError)
	if got := len(recorder.LogRecords()); got != 2 {
		t.Fatalf("emitted logs = %d, want 2 usable siblings", got)
	}
}

// TestPollRecordOutcomesReliablePartialPageFailureKeepsEmittedPrefix catches
// an ordered walk retroactively reclassifying already-emitted prefix records
// as errored. Only rows returned with the failed page remain unprocessed.
func TestPollRecordOutcomesReliablePartialPageFailureKeepsEmittedPrefix(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recorder := telemetrytest.New()
	cfg, cp, from, to := outcomeTestSetup()
	cp.Watermark = from.Add(-time.Hour)
	cp.OverlapWindow = 45 * time.Minute
	cp.SeenIDs.Add("durable-before", from.Add(-30*time.Minute))
	wantSeen := maps.Clone(cp.SeenIDs)

	calls := 0
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		calls++
		if calls == 1 {
			return []map[string]any{
				{"id": "a", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
			}, "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=2", nil
		}
		return []map[string]any{{
			"id":              "c",
			"createdDateTime": from.Add(15 * time.Minute).Format(time.RFC3339),
		}}, "", errors.New("upstream page failed")
	})

	_, pollErr := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		fetcher,
		recorder.Emitter(),
		outcomes,
	)
	if pollErr == nil {
		t.Fatal("Poll error = nil, want second-page failure")
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{
		fetched: 3,
		mapped:  2,
		emitted: 2,
		errored: 1,
	})
	assertOutcomeCauses(t, outcomes, recordoutcome.CauseSourceError)
	if err := outcomes.Snapshot().Validate(); err != nil {
		t.Fatalf("outcome snapshot validation: %v", err)
	}
	assertOutcomeSummary(t, outcomes, pollErr, recordoutcome.ResultPartial, recordoutcome.CauseSourceError)
	if got := emittedIDSet(recorder); !sameSet(got, []string{"a", "b"}) {
		t.Fatalf("emitted logs = %v, want successful prefix [a b]", got)
	}
	if !cp.Watermark.Equal(from.Add(-time.Hour)) ||
		cp.OverlapWindow != 45*time.Minute ||
		!maps.Equal(cp.SeenIDs, wantSeen) {
		t.Fatalf(
			"caller checkpoint = {watermark:%v overlap:%v seen:%v}, want unchanged {%v %v %v}",
			cp.Watermark,
			cp.OverlapWindow,
			cp.SeenIDs,
			from.Add(-time.Hour),
			45*time.Minute,
			wantSeen,
		)
	}
}

// TestPollRecordOutcomesUnreliablePartialPageFailureEmitsNothing preserves the
// all-or-nothing boundary for client-sorted endpoints. Every fetched record is
// errored because no row can be mapped or emitted before the full walk drains.
func TestPollRecordOutcomesUnreliablePartialPageFailureEmitsNothing(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	recorder := telemetrytest.New()
	cfg, cp, from, to := outcomeTestSetup()
	cfg.OrderByReliable = false
	cp.Watermark = from.Add(-time.Hour)
	cp.OverlapWindow = 45 * time.Minute
	cp.SeenIDs.Add("durable-before", from.Add(-30*time.Minute))
	wantSeen := maps.Clone(cp.SeenIDs)

	calls := 0
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		calls++
		if calls == 1 {
			return []map[string]any{
				{"id": "a", "createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339)},
				{"id": "b", "createdDateTime": from.Add(10 * time.Minute).Format(time.RFC3339)},
			}, "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=2", nil
		}
		return []map[string]any{{
			"id":              "c",
			"createdDateTime": from.Add(15 * time.Minute).Format(time.RFC3339),
		}}, "", errors.New("upstream page failed")
	})

	_, pollErr := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		fetcher,
		recorder.Emitter(),
		outcomes,
	)
	if pollErr == nil {
		t.Fatal("Poll error = nil, want second-page failure")
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{
		fetched: 3,
		errored: 3,
	})
	assertOutcomeCauses(t, outcomes, recordoutcome.CauseSourceError)
	if err := outcomes.Snapshot().Validate(); err != nil {
		t.Fatalf("outcome snapshot validation: %v", err)
	}
	assertOutcomeSummary(t, outcomes, pollErr, recordoutcome.ResultFailure, recordoutcome.CauseSourceError)
	if got := emittedIDSet(recorder); len(got) != 0 {
		t.Fatalf("emitted logs = %v, want none from incomplete client-sorted walk", got)
	}
	if !cp.Watermark.Equal(from.Add(-time.Hour)) ||
		cp.OverlapWindow != 45*time.Minute ||
		!maps.Equal(cp.SeenIDs, wantSeen) {
		t.Fatalf(
			"caller checkpoint = {watermark:%v overlap:%v seen:%v}, want unchanged {%v %v %v}",
			cp.Watermark,
			cp.OverlapWindow,
			cp.SeenIDs,
			from.Add(-time.Hour),
			45*time.Minute,
			wantSeen,
		)
	}
}

// TestPollRecordOutcomesDecodeFailureUsesBoundedCause verifies decoder details
// stay out of metric labels while the bounded decode_error cause remains
// observable. On a client-sorted walk, rows fetched before the malformed page
// are retryable, not incorrectly reported as mapped.
func TestPollRecordOutcomesDecodeFailureUsesBoundedCause(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	cfg, cp, from, to := outcomeTestSetup()
	cfg.OrderByReliable = false

	calls := 0
	fetcher := pageFetcherFunc(func(_ context.Context, _ string) ([]map[string]any, string, error) {
		calls++
		if calls == 1 {
			return []map[string]any{{
				"id":              "buffered",
				"createdDateTime": from.Add(5 * time.Minute).Format(time.RFC3339),
			}}, "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=2", nil
		}
		return nil, "", fmt.Errorf("decode response body: %w", &json.SyntaxError{Offset: 42})
	})

	_, pollErr := Poll(
		context.Background(),
		cfg,
		cp,
		from,
		to,
		fetcher,
		telemetrytest.New().Emitter(),
		outcomes,
	)
	if pollErr == nil {
		t.Fatal("Poll error = nil, want malformed response failure")
	}

	assertOutcomeCounts(t, outcomes, outcomeCounts{
		fetched: 1,
		errored: 1,
	})
	assertOutcomeCauses(t, outcomes, recordoutcome.CauseDecodeError)
	assertOutcomeSummary(t, outcomes, pollErr, recordoutcome.ResultFailure, recordoutcome.CauseDecodeError)
}

type outcomeCounts struct {
	fetched  uint64
	mapped   uint64
	emitted  uint64
	deduped  uint64
	filtered uint64
	dropped  uint64
	errored  uint64
}

func outcomeTestSetup() (EndpointConfig, *checkpoint.Checkpoint, time.Time, time.Time) {
	from := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		CollectorName:   "entra.test.outcomes",
		TimeField:       "createdDateTime",
		Flavor:          FlavorGeLe,
		OrderByReliable: true,
		Map:             mapByID,
	}
	return cfg, newCheckpoint("t1", cfg.Path), from, from.Add(time.Hour)
}

func assertOutcomeCounts(t *testing.T, recorder *recordoutcome.Recorder, want outcomeCounts) {
	t.Helper()
	counts := recorder.Snapshot().Counts
	got := outcomeCounts{
		fetched:  counts.Fetched,
		mapped:   counts.Mapped,
		emitted:  counts.Emitted,
		deduped:  counts.Deduped,
		filtered: counts.Filtered,
		dropped:  counts.Dropped,
		errored:  counts.Errored,
	}
	if got != want {
		t.Errorf("outcomes = %+v, want %+v", got, want)
	}
	if got.fetched != got.mapped+got.filtered+got.dropped+got.errored {
		t.Errorf(
			"fetched reconciliation failed: %d != mapped %d + filtered %d + dropped %d + errored %d",
			got.fetched,
			got.mapped,
			got.filtered,
			got.dropped,
			got.errored,
		)
	}
	if got.mapped != got.emitted+got.deduped {
		t.Errorf(
			"mapped reconciliation failed: %d != emitted %d + deduped %d",
			got.mapped,
			got.emitted,
			got.deduped,
		)
	}
}

func assertOutcomeCauses(t *testing.T, recorder *recordoutcome.Recorder, want ...recordoutcome.Cause) {
	t.Helper()
	got := recorder.Snapshot().Causes
	if len(got) != len(want) {
		t.Fatalf("causes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("causes = %v, want %v", got, want)
		}
	}
}

func assertOutcomeSummary(
	t *testing.T,
	recorder *recordoutcome.Recorder,
	runErr error,
	wantResult recordoutcome.Result,
	wantCause recordoutcome.Cause,
) {
	t.Helper()
	got := recorder.Snapshot().Summarize(runErr, false)
	if got.Result != wantResult || got.Cause != wantCause {
		t.Errorf("summary = {Result:%q Cause:%q}, want {Result:%q Cause:%q}", got.Result, got.Cause, wantResult, wantCause)
	}
}
