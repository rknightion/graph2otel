# Issue #291 implementation report

## Status

`DONE_WITH_CONCERNS`

The issue plan is implemented in the isolated detached worktree
`/tmp/graph2otel-291.mv85yN` at baseline
`f7339e805e40d2cc2b992a5ff4110c5995329fd6`. No files were staged, committed,
or pushed, and GitHub was not mutated.

The implementation concern is limited to the full `make check` receipt:
its vet and repository-wide race-test phases passed, but its bundled
`.tools/golangci-lint` invocation stopped on two gosec findings in unchanged,
out-of-diff files. Package lint and the separately installed full-repo lint
both passed.

## Implemented contract

- `OrderByReliable=true` processes and emits each successful page before
  fetching the next page.
- `Poll` deep-copies the checkpoint, including `SeenIDs`, and mutates only that
  working copy during a reliable walk.
- The caller checkpoint is assigned only after the terminal page succeeds.
- A later reliable fetch failure leaves the emitted prefix visible and
  retryable, while rows returned with the failed page are fetched and errored
  but never mapped or emitted.
- `OrderByReliable=false` retains the complete-window buffer, client-side sort,
  zero partial emission, and zero checkpoint advancement on a failed walk.
- Reliable raw-record retention is page-bounded. Persistent overlap `SeenIDs`
  remains intentionally bounded by the overlap window.
- Reliable repeated-next-link and `maxPages` failures retain the same contract:
  the successful prefix is emitted and retryable, the caller checkpoint is
  unchanged, and no source row is fabricated as errored.
- The documentation describes bounded at-least-once prefix replay. It makes no
  exactly-once claim.
- Public `Poll` and `PageFetcher` signatures are unchanged.

## RED evidence

All production code was untouched while these receipts were captured.

1. Immediate reliable-page emission:

   ```text
   go test -race ./internal/logpipeline -run '^TestPollStreamsReliablePageBeforeFetchingNext$' -count=1
   --- FAIL: TestPollStreamsReliablePageBeforeFetchingNext
       before second fetch emitted = [], want [a]
   ```

2. Durable retry duplicate-prefix semantics:

   ```text
   go test -race ./internal/logpipeline -run '^TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix$' -count=1
   --- FAIL: TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix
       first attempt emitted = [], want successful prefix [a b]
   ```

   The unchanged durable-checkpoint assertion passed before the expected prefix
   assertion failed.

3. Reliable/unreliable record-outcome accounting:

   ```text
   go test -race ./internal/logpipeline -run '^TestPollRecordOutcomes(ReliablePartialPageFailureKeepsEmittedPrefix|UnreliablePartialPageFailureEmitsNothing)$' -count=1
   --- FAIL: TestPollRecordOutcomesReliablePartialPageFailureKeepsEmittedPrefix
       outcomes = {fetched:3 mapped:0 emitted:0 ... errored:3},
       want {fetched:3 mapped:2 emitted:2 ... errored:1}
       summary = {Result:"failure" Cause:"source_error"},
       want {Result:"partial" Cause:"source_error"}
       emitted logs = [], want successful prefix [a b]
   ```

   The explicit unreliable companion passed, preserving the old all-or-nothing
   behavior.

4. Bounded retained-page memory:

   ```text
   go test -race ./internal/logpipeline -run '^TestScaleOrderedPollDoesNotRetainPriorPagePayloads$' -count=1
   --- FAIL: TestScaleOrderedPollDoesNotRetainPriorPagePayloads
       retained heap at sentinel = 67158856 B,
       want less than 16777216 B
   ```

## Independent review fixes: RED evidence

The independent review requested explicit reliable companions for the two
pagination guard branches and a comparative memory assertion. Because the
production branches already implemented the intended behavior, each new guard
was mutation-checked before its final GREEN run.

1. Reliable repeated-next-link and page-cap conservation:

   A temporary mutation changed both reliable guard branches to call
   `failFetchedRecords`, recreating the incorrect "re-error the whole prefix"
   behavior. The new tests failed exactly on the frozen reconciliation
   equation:

   ```text
   go test -race ./internal/logpipeline -run '^TestPollReliable(RepeatedNextLink|PageCap)KeepsPrefixRetryable$' -count=1

   TestPollReliableRepeatedNextLinkKeepsPrefixRetryable:
   outcomes = {fetched:1 mapped:1 emitted:1 errored:1},
   want {fetched:1 mapped:1 emitted:1 errored:0}
   fetched reconciliation failed: 1 != 1 + 1

   TestPollReliablePageCapKeepsPrefixRetryable:
   outcomes = {fetched:1000 mapped:1000 emitted:1000 errored:1000},
   want {fetched:1000 mapped:1000 emitted:1000 errored:0}
   fetched reconciliation failed: 1000 != 1000 + 1000
   ```

   The mutation was removed. The tests also assert no fetch past the repeated
   or capped boundary, a deep-equal unchanged caller checkpoint
   (`Watermark`, `OverlapWindow`, and `SeenIDs` included), the exact
   `source_error` cause, visible prefix logs, and prefix replay on a successful
   retry.

2. Comparative page-bounded memory:

   A temporary mutation retained reliable pages in `rawRecords`. The
   strengthened 4-page versus 64-page test failed with growth proportional to
   page count:

   ```text
   go test -race ./internal/logpipeline -run '^TestScaleOrderedPollDoesNotRetainPriorPagePayloads$' -count=1 -v
   retained heap: 4 pages=4197640 B, 64 pages=67154224 B,
   growth=62956584 B
   FAIL: want each sample below the documented eight-page (8 MiB) GC allowance
   ```

   The mutation was removed. The final guard requires both samples below
   8 MiB and growth below 4 MiB, so a sixteenfold page-count increase must
   remain near-flat rather than merely landing below one generous absolute cap.

## GREEN evidence

Focused #291 guards:

```text
go test -race ./internal/logpipeline -run '^(TestPollStreamsReliablePageBeforeFetchingNext|TestLogCollectorReliableFailureRetriesOnlyEmittedPrefix|TestPollRecordOutcomes(ReliablePartialPageFailureKeepsEmittedPrefix|UnreliablePartialPageFailureEmitsNothing)|TestScaleOrderedPollDoesNotRetainPriorPagePayloads)$' -count=1
ok github.com/rknightion/graph2otel/internal/logpipeline
```

Independent review guards:

```text
go test -race ./internal/logpipeline -run '^TestPollReliable(RepeatedNextLink|PageCap)KeepsPrefixRetryable$' -count=1
ok github.com/rknightion/graph2otel/internal/logpipeline 2.519s
```

Repeated race memory guard:

```text
go test -race ./internal/logpipeline -run '^TestScaleOrderedPollDoesNotRetainPriorPagePayloads$' -count=10 -v
PASS (10/10)
4-page retained samples: 0-7032 B
64-page retained samples: 13176-19072 B
growth samples: 6976-19072 B
```

Full package:

```text
go test -race ./internal/logpipeline -count=1
ok github.com/rknightion/graph2otel/internal/logpipeline 3.146s
```

Repository-wide race suite:

```text
go test -race ./...
exit 0
```

Static checks:

```text
go vet ./...
exit 0

golangci-lint run
0 issues.

.tools/golangci-lint run ./internal/logpipeline/...
0 issues.

git diff --check
exit 0
```

Full completion gate:

```text
make check
go vet ./...                       PASS
go test -race ./...                PASS
.tools/golangci-lint run           FAIL
```

The bundled full-repo lint reported:

```text
internal/admin/status.go:26:2:
G101 Potential hardcoded credentials

internal/collector/scheduler.go:179:23:
G404 Use of weak random number generator
```

Neither file is modified by this work. The separately installed
`golangci-lint` is also v2.12.2 and returned `0 issues`; the bundled binary is
v2.12.2 as well, but was built with a different Go patch version. No unrelated
suppression or code change was made.

## Exact diff files

Tracked worktree changes:

- `docs/scale-validation.md`
- `internal/logpipeline/collector_test.go`
- `internal/logpipeline/graphclient_adapter_test.go`
- `internal/logpipeline/logpipeline.go`
- `internal/logpipeline/logpipeline_test.go`
- `internal/logpipeline/outcomes_test.go`
- `internal/logpipeline/scale_test.go`

`internal/logpipeline/graphclient_adapter_test.go` was not in the original
ownership table. During GREEN, its foreign-next-link test proved to encode the
superseded global zero-partial-emission rule for a reliable first page. The
coordinating thread explicitly authorized the minimal #291 contract update:
the SSRF rejection remains pinned, the reliable prefix is visible, and the
caller checkpoint remains unchanged.

No scheduler, collector implementation, recordoutcome, telemetry, catalog,
Grafana, registration, or configuration files were changed.

## Adversarial self-review

- **Yes:** no failed ordered walk can mutate caller `SeenIDs` through a shallow
  map alias. `cloneCheckpoint` uses `maps.Clone`, and tests compare the original
  map after an emitted-prefix failure.
- **Yes:** no already-emitted prefix is reclassified as errored. Reliable fetch
  failures add `Errored` only for the rows returned with that failed fetch;
  repeated-link and page-cap failures add a cause without inventing a row.
- **Yes:** unreliable walks emit only after the complete fetch, map, and
  client-side sort.
- **Yes:** reliable processing retains no raw or mapped slice across pages.
  The comparative 4-page/64-page, 1 MiB-per-page sentinel guard shows near-flat
  retained heap and passed 10/10 race runs.
- **Yes:** no checkpoint write occurs per page. `LogCollector` saves only after
  `Poll` returns success; `Poll` copies the working checkpoint back only at the
  terminal commit point.
- **Yes:** there is no local-only cache that suppresses retry duplicates.
- **Yes:** records returned together with a fetch error are counted as fetched
  and errored, then discarded before mapping/emission.
- **Yes:** #275's undated drop, mapper panic containment, self exclusion,
  no-server-filter bounds, empty-ID behavior, dedupe, watermark calculation,
  and deferred scalar effects remain on both branches.
- **Yes:** neither code nor documentation claims exactly-once delivery.

## Handoff

The detached worktree is preserved with unstaged, uncommitted changes. The
coordinator can review and import the patch. The only unresolved receipt is the
out-of-diff full-repo gosec discrepancy described above.
