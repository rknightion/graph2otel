# O365 Management Activity API — how `m365.activity` actually works

The Office 365 Management Activity API (`manage.office.com`) feeds `m365.activity`
(default-on) via `internal/o365activityclient` + `internal/o365pipeline`. It is a
**stable v1.0** transport (2,000 req/min per tenant) with a subscription → content-blob
model built for continuous ingest — chosen over the Graph audit query API, which is
beta-only on this tenant and 429s on rapid job creation (#100, #109). App roles:
`ActivityFeed.Read` on the O365 Management APIs service principal
(`c5393580-f805-4401-95e8-94b7a6ef2fc2`); add `ActivityFeed.ReadDlp` only when the
operator explicitly selects `DLP.All`.

Everything below is live-measured (2026-07-16, #100) unless noted. The doc-vs-wire
scorecard ran **6-0 against Microsoft's documentation** — treat the docs as hypotheses.

## Wire format traps

- **`CreationTime` is NOT RFC3339.** It arrives zone-less (`"2015-06-29T20:03:19"`) —
  `time.Parse(time.RFC3339, …)` fails and would silently drop **every** record. The
  mapper tries `RFC3339Nano` first (so a future `Z` is honored), then falls back to
  `"2006-01-02T15:04:05.999999999"` parsed as UTC — with **no `time.Now()` fallback**
  (a stamped-on-arrival record silently claims to have happened now; worse than a drop).
- **Docs declare camelCase enums; the wire returns PascalCase.** Requests take camelCase
  (`exchangeAdmin`), responses return PascalCase (`ExchangeAdmin`) — the API passes the
  classic O365 names straight through (#98 corroborates from the query-API side).
- **The published `AuditLogRecordType` table misses ~27% of this tenant's live types.**
  Six observed members are absent from the docs at any int, plus RecordType 117. So the
  unknown-int path fires on day one: `m365.activity` emits `record_type_id`
  **unconditionally** (the only lossless form) and `record_type` only when the int
  resolves. **Never guess a name** — a guessed name is a silent convergence break; an
  absent one is visibly unknown. Docs rows containing a space ("Viva Engage") are
  deliberately omitted — that is post-rename display text, the wire keeps the old name.

## Subscription lifecycle traps

- **AF20024 is undocumented and fires on every re-start of an enabled subscription.**
  `POST /subscriptions/start` on an already-enabled content type → 400 `AF20024` ("The
  subscription is already enabled. No property change."). It is a **success condition**
  (the desired state holds): `IsAlreadyEnabled` treats it as one (`55e3999`). Without
  that, the collector works exactly once per tenant, then fails every tick forever.
  The test fake reproduces the 400 — a fake returning 200 unconditionally is kinder than
  the wire and proves nothing.
- **`POST /subscriptions/start` is a WRITE operation** — the second break in graph2otel's
  read-only property (after the Intune reports-export job).
- **No server-side filtering exists.** Subscribe only to content types actually mapped —
  never `Audit.General` by default (it is the catch-all, including Teams; opt-in only).

## Teams audit filtering

To keep Microsoft Teams (25) and Microsoft Teams Admin (57) records from
`Audit.General`, set the following in that tenant's YAML. Use `[25]` if you do
not want the admin records. Neither list is a catch-all for Teams-related audit
records.

```yaml
o365_activity:
  content_types: [Audit.General]
  record_type_allow_list: [25, 57]
```

The API still lists and downloads the full `Audit.General` blobs. The allow-list
saves downstream log ingest, not API traffic. It selects by numeric `RecordType`,
not workload or operation, and applies to all configured content types. Endpoint
DLP (63) and other non-matching records are counted as `filtered` before mapping.
Omitting the list or setting it to `[]` leaves record selection unchanged. The
checkpoint still advances through the blobs, so widening or removing the list
does not replay records that were filtered before.

Live-measured 2026-11-25: a read-only probe of the existing `Audit.General`
subscription saw `TeamCreated`, `MemberAdded`, `TeamSettingChanged`,
`ChannelAdded`, `TabAdded` and `TeamsSessionStarted` under type 25, and
`TeamsAdminAction` and `WriteUserObjPreference` under type 57. It did not see
meeting join activity. These records currently use the generic `m365.audit`
attributes, including `operation` and `record_type_id`. A Teams session's
`object_id` stays opaque; the probe does not establish that it identifies a
team, channel or meeting.

If you need to reduce what you fetch, the experimental Graph collector
`m365.unified_audit` uses a fixed server-side `recordTypeFilters` list that
includes `microsoftTeams`, `microsoftTeamsAdmin` and `teamsQuarantineMetadata`,
among other record types, and excludes Endpoint DLP. This is not a Teams-only
query or a configurable workload filter. Disable `m365.activity` before
enabling the alternative. Graph uses a slower, beta async query and can
throttle query creation.

## Windowing and retention

- **`/subscriptions/content` caps the list range at 24 HOURS** — `startTime`/`endTime`
  must both be set or both omitted and be ≤24h apart; a wider request → 400 `AF20055`.
  Worse: a >24h range that *does* return 200 may be **silently partial** (per the API
  reference). Always chunk into ≤24h sub-windows (`o365activityclient.MaxWindow`).
- **There is NO 12-hour delay for first content** (docs claim one). Content listed ~2
  minutes after subscribe, with the oldest `contentCreated` ~22h **before** the
  subscription existed — Microsoft backfills on subscribe. Never build a "wait before
  first poll" behavior; never tell a reader an empty first poll is expected.
- **The "7-day content expiry" is unverified and probably a docs conflation.** Live:
  `contentExpiration` ~20 days after `contentCreated`. AF20051 is a *retrieval* bound;
  AF20030/AF20055 are a *startTime lookback* bound (`MaxLookback` — measured). **Always
  read `contentExpiration` off the wire; never derive expiry from a constant.**

## Cursor and dedupe rules (mutation-proven, `o365pipeline`)

- **A cursor's clock and its eviction clock must be the SAME clock, and here it is the
  ARRIVAL clock.** Seen-set ids evict on their blob's `contentCreated` (arrival), never
  the record's own `CreationTime` (event) — one content blob can contain events that
  occurred before an earlier blob's, so evicting on event time drops ids whose blobs are
  still re-listable inside the overlap window → silent duplicates. The rule is NOT
  "prefer arrival time" — it is that the two clocks must match; envelope `time` *loses*
  on the blob sign-in categories by the same rule (see blob-ingest.md).
- **Guard the empty dedupe id.** A bare `"record:"` key for an id-less record matches
  every later id-less record — record two onward vanish silently forever. Companion
  rule: **undedupeable is degraded; misdated is wrong — only wrong justifies a drop.**
  An id-less record is still emitted; a record with no parseable event time is dropped.

## Operational behavior

- **The defaults (`Audit.Exchange` + `Audit.SharePoint`) carry ZERO content on a small
  tenant, and the collector looks 100% healthy doing it** — `runs=1 failures=0` with an
  empty checkpoint is the steady state, not a fault. `advance()` moves the watermark only
  to blobs actually consumed. Anyone validating against defaults will conclude it is
  broken, or worse, that it works.
- **`m365.unified_audit` must be disabled wherever `m365.activity` runs** — both emit
  `m365.audit` with the same ids; both on = every record twice.

## Current completion state

All four #100 residuals are discharged. The classic schema emits its UPN-shaped identity as
`user_id` rather than asserting that every value is a UPN; the `WindowCollector` adapter lives in
`internal/o365pipeline`; `SECURITY.md` records the subscription-start write; and `DLP.All` was
live-measured with three records. A dedicated `DLP.All` mapper is deliberately absent: those
records are normally empty on m7kni and `DetectedValues` contains the matched secret in cleartext.
Any future mapper must be built from a live sample, emit classification metadata only, and exclude
`DetectedValues`.
