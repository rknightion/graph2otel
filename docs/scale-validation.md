# Scale & soak validation

Validates the polling model against the two failure modes a paper analysis can't
catch — silent data loss around watermarks, and memory growth on large paginated
walks — plus confirms the client-side throttle limiters actually pace requests
rather than only modelling the budget. Tracks issue #32.

## What was tested vs the theoretical envelope

The log-export feasibility study sized graph2otel against ~50k users generating
~10M sign-in events/day on a single app registration and concluded it fits the
throttle budget in theory. Rather than stand up a real tenant at that scale
(neither casual nor authorized), this validation drives the **actual** framework
components the envelope depends on — the per-workload rate limiter, the
logpipeline `Poll` drain/dedupe/watermark path, and the file-backed
`CheckpointStore` restart path — deterministically, via the `TestScale*` tests in
`internal/graphclient` and `internal/logpipeline` (run under `go test -race`).

The theoretical ceiling stands; what's **practically confirmed** below is the
correctness of the mechanisms that keep the exporter inside it.

## Throttle ceilings hold under load

`internal/graphclient/scale_test.go`:

- **Reporting workload (5 req/10s, no `Retry-After`).** A burst of 7 requests is
  paced to ~4s (burst 5, then 2 tokens at 2s each), proving the limiter is on the
  request path and enforces the ceiling — not merely configured. Graph sends no
  `Retry-After` on this workload, so this client-side limiter is the only thing
  keeping the exporter under budget.
- **Per-tenant isolation.** One tenant saturating its reporting burst does not
  delay another tenant's first request — the limiter keys buckets per tenant, so
  a busy tenant can't starve a quiet one.
- **Budget drift guard.** The configured rates are pinned to the documented Graph
  ceilings (reporting 5/10s, Identity Protection 1/s, Intune export 48/min); a
  change to a budget fails the test until the docs are updated too.

## Watermark correctness across restart

`internal/logpipeline/scale_test.go` — `TestScaleWatermarkDurableAcrossRestart`:

Drives the real `LogCollector` Load → Poll → Save chain, then simulates a crash by
constructing a **brand-new `Store` over the same on-disk directory** (nothing
carried in memory) and polling an overlapping window. That second poll re-serves
already-seen events **plus a late arrival whose timestamp predates the first
poll's watermark** (i.e. it was still landing out of order when the process died).

Confirmed:

- **No data loss** — the late arrival is captured, because the restart resumes
  from `watermark − overlap`, not from `watermark`.
- **Bounded duplication** — already-seen events are not re-emitted; dedupe is by
  immutable event `id` against the persisted `SeenIDs` set, which survives the
  restart on disk.
- **New events still flow.**

This is the failure mode the feasibility study flagged as the real risk (not raw
throughput): a naive high-water mark with no safety lag silently drops
out-of-order events. The safety-lag + overlap + id-dedupe model is what prevents
it, and this test is its regression guard.

## Memory behavior on large paginated walks

`internal/logpipeline/scale_test.go` —
`TestScaleOrderedPollDoesNotRetainPriorPagePayloads`,
`BenchmarkPollOrderedPageMemory`, `BenchmarkPollWindowMemory`, and
`TestScalePollMemoryBoundedByWindowNotBacklog`:

Client-side ordering (`OrderByReliable=false`) requires `Poll` to drain the
whole window into an in-memory slice before sorting and emitting. Consequences:

- **Per-poll memory scales with the window's record count, not the total
  backlog.** Each collector caps a single poll at its `MaxWindow` (e.g. 24h), so a
  cold-start backfill of a 30-day (or 2-year Intune audit) retention window walks
  in `MaxWindow`-sized chunks — memory stays flat across the backfill rather than
  growing with the backlog. The disjoint-windows test confirms window N's records
  are released before window N+1 (no cross-poll accumulation / leak).
- **The bound is `MaxWindow × event-rate`.** For a very large tenant this can
  still be large: a 24h window on a 10M-sign-ins/day stream holds ~10M records in
  memory during that poll. The tuning knob is `MaxWindow` — large tenants should
  set a smaller window (e.g. 1–4h) so each poll drains a proportionally smaller
  slice.

### Ordered vs client-sorted delivery contract

`OrderByReliable=true` streams successful pages immediately. Decoded raw-record
memory is bounded by a page, while durable overlap `SeenIDs` remains bounded by
the overlap window. The checkpoint commits only after the terminal page, so a
later fetch failure replays the already-emitted prefix on retry (bounded
at-least-once) and never skips the un-emitted suffix. The ordered scale test
guards page-bounded retention; the collector restart test guards prefix replay
and terminal checkpoint persistence.

`OrderByReliable=false` still buffers and client-sorts a complete window. It
emits nothing and advances no checkpoint when pagination fails. The repeated
next-link, page-cap, and unreliable partial-page outcome tests guard this
all-or-nothing boundary.

## Practically-confirmed envelope

| Property | Theoretical (feasibility study) | Practically confirmed here |
|---|---|---|
| Reporting throttle (5/10s, no Retry-After) | fits at 50k users | limiter enforces the ceiling under burst + isolates per tenant |
| Identity Protection (1/s) | fits | budget pinned + enforced |
| Watermark under out-of-order arrival + restart | flagged as the real risk | no data loss / bounded dupes across an induced mid-cycle restart |
| Memory on backfill | not analyzed | ordered raw records are page-bounded; client-sorted polls remain `MaxWindow × event-rate`; both stay flat across a backfill |

Not tested: a live run against a real ~50k-user / ~10M-events-day tenant (not
available/authorized). The component-level guarantees above are what such a run
would exercise; a confirmatory live pass at whatever scale is authorized can be
layered on later without changing these conclusions.
