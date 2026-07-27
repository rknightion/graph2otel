# Issue #291: Stream ordered logpipeline pages implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Bound decoded raw-record memory by Graph page size for the already-reliable ordered endpoints, without data loss on a later-page failure.

**Architecture:** Preserve the exported Poll and PageFetcher APIs. For OrderByReliable=true, process each successful page immediately against a private deep copy of the checkpoint; copy it back only after the terminal page succeeds. For false, preserve the full-window fetch, map, client-sort, emit commit point. telemetry.Emitter.LogEvent has no acknowledgement, so this deliberately provides bounded at-least-once retry duplicates, not exactly-once delivery.

**Tech stack:** Go 1.26.5; standard testing; existing checkpoint, recordoutcome, telemetry and telemetrytest packages.

## Binding decision receipt

The only #291 comment, posted 2026-07-26, overrides the body and is binding:

> Maintainer decision: use ordered page streaming with bounded at-least-once duplicate prefixes. OrderByReliable=true pages may emit immediately; the checkpoint remains unchanged until the full walk succeeds, so a later-page failure can duplicate the emitted prefix on retry but cannot lose the suffix. Unreliable-order endpoints retain full-window buffering and zero partial emission.

#374 subsequently records that all recommended defaults, including #291, are approved and binding. #269 is complete in f7339e805e40d2cc2b992a5ff4110c5995329fd6; its outcome contract is frozen:

~~~text
fetched = mapped + filtered + dropped + errored
mapped = emitted + deduped
~~~

For reliable page one a,b, then page two c plus an error: fetched=3, mapped=2, emitted=2, errored=1, result partial/source_error. If the failed fetch returns no rows, the emitted prefix remains fetched=mapped=emitted with partial/source_error; no imaginary source row is errored. On either error, the caller checkpoint's Watermark, OverlapWindow and SeenIDs remain unchanged. That means retry re-emits only the already emitted prefix plus the formerly unreachable suffix.

## Constraints and current applicability

- Scope only #291. Do not change collector registration/configuration, scheduler, recordoutcome types, telemetry catalog, Grafana, or #268 acknowledgement semantics.
- Existing reliable configurations are exactly: entra.directory_audits, entra.security_alerts, and four entra.signins streams (interactive, non-interactive, service-principal, managed-identity). No collector file needs an edit.
- Unreliable remains the safety boundary for agent-risk detections, provisioning, risk detections, security incidents, service-principal risk detections, and Intune audit/autopilot/enrollment events. It keeps full-window buffering, client-side sort, and zero partial emission.
- A fetch returning both records and an error counts those returned records as fetched+errored, but never maps/emits/stages them. Earlier successful reliable pages remain mapped/emitted, never retroactively errored.
- Preserve self exclusion, panic-contained Map, raw-time then mapped-time fallback, zero-time drop, NoServerFilter bounds, empty-ID handling, SeenIDs dedupe, and current newest/sawAny watermark calculation.
- Page-local raw maps and mapped events must not survive the page. Scalar totals for deferred self-excluded metric and undated wirecheck may survive until complete success.
- Transient decoded raw/mapped memory becomes O(page size) for reliable endpoints. Persistent SeenIDs stays O(overlap event rate), intentionally unchanged.

## File ownership and seam

| File | Owner | Work |
| --- | --- | --- |
| internal/logpipeline/logpipeline.go | #291 | Staged checkpoint and reliable per-page processing; preserve unreliable path. |
| internal/logpipeline/logpipeline_test.go | #291 | Immediate emission and direct checkpoint tests. |
| internal/logpipeline/collector_test.go | #291 | Durable retry/restart duplicate-prefix receipt. |
| internal/logpipeline/outcomes_test.go | #291 | #269 reliable/unreliable later-page accounting. |
| internal/logpipeline/scale_test.go | #291 | Page-peak raw-memory guard and ordered benchmark. |
| docs/scale-validation.md | #291 | Replace obsolete reliable-endpoint limitation. |

Public signatures remain exactly:

~~~go
func Poll(ctx context.Context, cfg EndpointConfig, cp *checkpoint.Checkpoint,
    from, to time.Time, fetcher PageFetcher, e telemetry.Emitter,
    outcomes *recordoutcome.Recorder) (time.Time, error)

type PageFetcher interface {
    FetchPage(context.Context, string) ([]map[string]any, string, error)
}
~~~

The sole permitted helper is private to logpipeline:

~~~go
func cloneCheckpoint(cp *checkpoint.Checkpoint) checkpoint.Checkpoint {
    next := *cp
    next.SeenIDs = maps.Clone(cp.SeenIDs)
    return next
}
~~~

Do not put this in internal/checkpoint: it would create a needless shared API. A shallow struct copy is invalid because SeenIDs is a map. InFlight and ParseHealth are not mutated by logpipeline, so their existing pointer values are safe in the private struct copy.

### Task 1: RED receipts — streaming, duplicate boundary, accounting, memory

**Files:** internal/logpipeline/logpipeline_test.go, collector_test.go, outcomes_test.go, scale_test.go.

- [ ] **Write TestPollStreamsReliablePageBeforeFetchingNext.** Use OrderByReliable=true and a two-call pageFetcherFunc; on the second call inspect emittedIDSet(rec) before returning page two. Require a already emitted. Current code fails because it retains page one in rawRecords.

~~~go
if calls == 1 {
    return []map[string]any{{"id":"a", "createdDateTime": at1}}, "page-2", nil
}
if got := emittedIDSet(rec); !sameSet(got, []string{"a"}) {
    t.Fatalf("before second fetch emitted = %v, want [a]", got)
}
~~~

- [ ] **Run its RED receipt.**

~~~sh
go test -race ./internal/logpipeline -run '^TestPollStreamsReliablePageBeforeFetchingNext$' -count=1
~~~

Expected: FAIL at the second-fetch assertion.

- [ ] **Write TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix.** Use real LogCollector, a tempdir Store, and a fresh checkpoint.NewStore(dir) before retry. First attempt returns successful page a,b then an error; require logs a,b, an error, and durable checkpoint equal to its pre-attempt watermark/overlap/deep-copied SeenIDs. Second attempt returns a,b then c; require logs a,b,c and durable save only now. Third attempt re-serves overlap; require zero logs because all IDs are now durable. This is the exact bounded at-least-once prefix receipt.

- [ ] **Run its RED receipt.**

~~~sh
go test -race ./internal/logpipeline -run '^TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix$' -count=1
~~~

Expected: FAIL because current whole-window buffering emits no prefix. Keep the checkpoint assertion even though it starts green.

- [ ] **Split the existing partial-page outcome test into explicit modes.**

~~~go
// reliable: page one a,b succeeds; page two returns c plus source error.
// Counts{Fetched:3, Mapped:2, Emitted:2, Errored:1}; partial/source_error;
// a,b logs; unchanged caller checkpoint.
func TestPollRecordOutcomesReliablePartialPageFailureKeepsEmittedPrefix(t *testing.T)

// unreliable: same source shape with OrderByReliable=false.
// Counts{Fetched:3, Errored:3}; failure/source_error; zero logs;
// unchanged caller checkpoint.
func TestPollRecordOutcomesUnreliablePartialPageFailureEmitsNothing(t *testing.T)
~~~

Both tests call Snapshot().Validate() before Summarize.

- [ ] **Run the accounting RED receipt.**

~~~sh
go test -race ./internal/logpipeline -run '^TestPollRecordOutcomes(ReliablePartialPageFailureKeepsEmittedPrefix|UnreliablePartialPageFailureEmitsNothing)$' -count=1
~~~

Expected: reliable fails under current all-buffered accounting; explicit unreliable preserves zero partial emission.

- [ ] **Write TestScaleOrderedPollDoesNotRetainPriorPagePayloads.** A reliable synthetic fetcher creates 64 pages of unique 1 MiB unused payload strings, retaining only its page number. Its sentinel final fetch runs runtime.GC then reads HeapAlloc; compare with pre-poll baseline and require less than 16 MiB retained. Use a discard Emitter so log capture is not part of measurement. Current rawRecords holds about 64 MiB at sentinel and fails; a stream releases all prior pages. Add BenchmarkPollOrderedPageMemory using the same page generator and b.ReportAllocs; leave BenchmarkPollWindowMemory explicitly unreliable.

- [ ] **Run the scale RED receipt.**

~~~sh
go test -race ./internal/logpipeline -run '^TestScaleOrderedPollDoesNotRetainPriorPagePayloads$' -count=1
~~~

Expected: FAIL above 16 MiB. If it does not, verify unique payload generation and sentinel order; do not weaken the fixture.

### Task 2: GREEN implementation — staged ordered pages

**File:** internal/logpipeline/logpipeline.go.

- [ ] **Add cloneCheckpoint and create working := cloneCheckpoint(cp) before walking.** Every mutation targets working, never cp; only *cp = working after a successful terminal page is allowed.

- [ ] **Preserve the false branch verbatim in behavior.** It may retain current rawRecords/all design: collect all successful pages; a fetch error calls failFetchedRecords(outcomes, fetched, cause) because no row committed; map only after complete walk; sort by time; emit; calculate high-water against working.

- [ ] **Implement reliable branch without record accumulation.** After each successful FetchPage, process that page in server order before requesting next link. Page processing updates scalar newest, sawAny, selfExcluded, undated, outcomes and working.SeenIDs; it returns no raw/mapped slice. On fetch error, first add fetched for returned length, then errored only for that unprocessed length and fetchFailureCause; return cp.Watermark without copying working back. Earlier prefix outcomes remain mapped/emitted.

- [ ] **Commit after terminal page only.** Compute Watermark/Overlap/EvictStale using existing formula on working. Emit deferred scalar effects, assign *cp = working, return high water. Every error path returns before assignment, so CollectWindow cannot save partial progress.

- [ ] **Run focused GREEN tests.**

~~~sh
go test -race ./internal/logpipeline -run '^(TestPollStreamsReliablePageBeforeFetchingNext|TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix|TestPollRecordOutcomes(ReliablePartialPageFailureKeepsEmittedPrefix|UnreliablePartialPageFailureEmitsNothing)|TestScaleOrderedPollDoesNotRetainPriorPagePayloads)$' -count=1
go test -race ./internal/logpipeline -count=1
~~~

Expected: PASS. Check repeated-next-link and max-page tests still cannot emit partial records for unreliable configs; add a reliable companion only if one silently encoded the old global zero-emission rule.

### Task 3: Documentation and final verification

**File:** docs/scale-validation.md.

- [ ] **Replace known post-v1 reliable limitation with this operator contract:**

~~~text
OrderByReliable=true streams successful pages immediately. Decoded raw-record
memory is bounded by a page, while durable overlap SeenIDs remains bounded by
the overlap window. The checkpoint commits only after the terminal page, so a
later fetch failure replays the already-emitted prefix on retry (bounded
at-least-once) and never skips the un-emitted suffix.

OrderByReliable=false still buffers and client-sorts a complete window. It
emits nothing and advances no checkpoint when pagination fails.
~~~

Link new guards; do not claim exactly-once delivery or removal of SeenIDs memory.

- [ ] **Run final gates.**

~~~sh
go test -race ./internal/logpipeline -count=1
go test -race ./...
go vet ./...
golangci-lint run
git diff --check
make check
~~~

Expected: all zero. make check is required completion gate; no generated-doc/catalog step is needed because registry/config/signal surface did not change.

## Adversarial review and shared-child conflicts

Before commit, answer yes:

~~~text
No failed ordered walk can mutate caller SeenIDs through shallow map alias.
No already emitted prefix is reclassified as errored.
No unreliable walk emits before full fetch and client sort.
No raw page is retained for scalar counters or wirecheck.
No checkpoint write occurs per page and no local-only cache suppresses crash retries.
No claim or mechanism attempts exactly-once without backend acknowledgement.
~~~

- #269 is closed, but its logpipeline outcome assertions are shared seam; preserve names/types/equations and alter only per-row classification. Do not touch internal/recordoutcome.
- #275's undated-record drop remains before dedupe/watermark on both branches.
- #289 may consume outcome totals for cost attribution. Coordinate before any shared scheduler/self-observability/outcome change; none is in this plan.
- #292 has dirty availability/admin/Grafana WIP in shared worktree but no file overlap. Do not format, stage, or touch it.
- #268 owns transactional OTLP acknowledgement. Exactly-once is expressly out of scope.

**Decision needed:** None. The ordered streaming / bounded at-least-once duplicate-prefix choice is approved and binding.
