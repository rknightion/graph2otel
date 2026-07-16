# graph2otel

Polls the Microsoft Graph API (Entra ID + Intune) and exports **OpenTelemetry-native
metrics + logs** over OTLP, optimized for Grafana Cloud. Single static Go binary, OTLP
push only — there is no Prometheus pull endpoint. Multi-tenant from day one: one process
can poll several tenants concurrently. Focus: Entra ID directory/sign-in/audit activity
and Intune device compliance monitoring. See `README.md` for the user-facing pitch.

> **Status:** pre-1.0, active development. Version starts at `0.1.0`
> (`.release-please-manifest.json`). The Architecture section below tracks the actual
> code — update it as the composition root and collectors land; don't let it drift into
> aspirational fiction.

## Commands

```sh
go build ./cmd/graph2otel   # build the binary (or: go build ./...)
go test -race ./...         # unit + integration tests (race detector on)
go vet ./...
golangci-lint run           # lint (v2 config, .golangci.yml)
golangci-lint fmt           # apply gofmt + goimports
make check                  # vet + test + lint + govulncheck + build — the green bar
```

`make check` is the full gate; run it before every commit. CI runs the same steps.

## Development methodology

- **Work directly on `main` and push unprompted.** This is an `rknightion` repo with
  GitHub Issues as the source of truth — commit straight to `main` and push immediately
  once a completing commit lands (the push is what fires the issue-closing keyword). No
  feature branches, no PR flow for first-party work. Bypass-on-push output ("Bypassed
  rule violations...") is expected admin behavior, not an error.
- **GitHub issues are the record of intent and progress**, not this file. Before starting
  substantial work, file an issue with the plan + acceptance criteria; keep it live as you
  work (tick checkboxes, comment at checkpoints); close it via a `Closes #NN` trailer on
  the completing commit. A future session with no memory of this one should be able to
  reconstruct what happened from GitHub alone.
- **Specs & plans are local scratch, never committed:** brainstorming/design docs and
  implementation plans live under `docs/superpowers/` (gitignored). Adversarially
  self-review a plan before acting on it — attack it for placeholders, contradictions,
  hidden assumptions, and scope creep.
- **Strict TDD:** failing test → watch it fail for the right reason → minimal code →
  green → refactor. Standard-library `testing` only — no testify or other third-party
  assertion library.
- Keep `go build ./... && go vet ./... && go test -race ./...` and `golangci-lint run`
  green after every change; commit a **green** state between units of work — evidence,
  not assertion.
- **Conventional Commits:** `type(scope): subject` (`feat`/`fix`/`perf`/`refactor`/`docs`/
  `chore`/`ci`/`build`/`test`). release-please's changelog sections show `feat`/`fix`/
  `perf`/`refactor`; `docs`/`test`/`chore`/`ci`/`build` are hidden.

## Architecture (the seams)

Intended shape, closest architectural analogs: `sf2loki`'s Source/Sink/CheckpointStore
composition-root pattern (poll a tenant-scoped SaaS API, single global instance, avoid
over-building HA prematurely) and `tailscale2otel`'s poll → `telemetry.Emitter` facade.

- **Multi-tenant config** (`internal/config`) — a `tenants` list, each entry a tenant ID +
  client ID + per-domain collector overrides. Auth material (client secret/certificate)
  comes from environment variables consumed by `azidentity.DefaultAzureCredential`, never
  from YAML.
- **Graph client factory** — wraps `msgraph-sdk-go` v1.0, re-attaches Kiota's default
  middlewares (retry, redirect, compression, telemetry) explicitly under our own
  OTEL-instrumented transport, and applies per-workload client-side rate limiters
  (directory RU budget / reporting 5-per-10s / Identity-Protection 1-per-s / Intune
  general + elevated Devices tier / Intune reports-export 48-per-min) — none of these
  workloads reliably send `Retry-After`, so backoff is our own responsibility.
- **Collector framework** (ported from tailscale2otel) — typed `SnapshotCollector`
  (inventory → OTEL metric gauges/counters) and `WindowCollector` (event streams → OTEL
  logs, checkpointed watermark + overlap + seen-id dedupe, since none of the log
  endpoints support delta queries or reliable server-side ordering). A `Registry` +
  goroutine-per-collector `Scheduler` with stagger.
- **Telemetry emitter facade** (`internal/telemetry`, arrives with the framework) — the
  only thing touching OTLP metrics + logs, so exporter details never leak into
  collectors. Grafana Cloud auth header + the `/v1/metrics` / `/v1/logs` URL-path
  distinction live here, once.
- **CheckpointStore** — file-based, namespaced per tenant + endpoint, storing
  `{watermark, overlap_window, seen_ids}` so a restart resumes from `watermark - overlap`
  rather than re-fetching or dropping data across out-of-order arrivals.
- Single-instance, no HA/leader-election in v1 — none of the polled Graph endpoints
  support consumer-group/delta semantics that would make multi-replica coordination
  pay for itself. Revisit only if a real multi-replica requirement shows up.

**v1 skeleton package layout:** only `internal/config` and `internal/version` exist in
the scaffold. Framework packages (`internal/telemetry`, `internal/graphclient`,
`internal/collector`, `internal/checkpoint`, …) land via the M1 backlog issues, not the
scaffold — keeps the initial CI fast and the diff reviewable.

## Config & secrets

- **Env var prefix:** `G2O_`, double-underscore for nesting (koanf layered:
  defaults < YAML < env) — e.g. `otlp.endpoint` → `G2O_OTLP__ENDPOINT`.
- **Top-level config keys:** `tenants` (list: `tenant_id`, `auth`, per-domain collector
  overrides), `otlp`, `collectors`, `log_level`, `admin`. See `config.example.yaml`.
- **Auth:** Microsoft Entra ID app registration (tenant ID + client ID + client secret or
  certificate), consumed via `azidentity.DefaultAzureCredential` from
  `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` or
  `AZURE_CLIENT_CERTIFICATE_PATH`. Never in YAML. Grant the minimum read-only Graph API
  application permission scopes each enabled collector needs.
- `config.local.yaml` and `.env` are gitignored — never commit credentials.

## Metric namespaces

Exported domain metrics use OTLP dot notation: `entra.*` for Entra ID signals, `intune.*`
for Intune signals. Self-observability (collector success/duration/staleness, build
info) uses `graph2otel.*`. Keep these namespaces consistent across collectors — a new
collector emitting outside its domain's namespace is a bug.

## OpenTelemetry dependency lockstep

`go.opentelemetry.io/otel` (core, v1.44.0) and `go.opentelemetry.io/otel/sdk/log`
(v0.20.0) are a **lockstep pair** — the log SDK's minor version tracks the core SDK's
release train and they must be bumped together, never independently. Renovate groups them
(see `renovate.json`); if you bump one by hand, bump the other to its matching release
and re-run `make check`.

## Cardinality: metrics carry aggregates, logs carry entities

**This is a data-modeling rule, not a privacy control.** Read that first — the old "PII
guidance" framing caused real bugs (#110, #111) by reading as "graph2otel withholds PII."
It does not. graph2otel exports UPNs, device names/serials/IMEIs, sign-in IPs and geo,
group membership and cert thumbprints to the configured OTLP backend **by design** —
eleven `WindowCollector`s exist to do exactly that, and `SECURITY.md` enumerates the full
inventory. graph2otel is used as a SIEM feed; per-entity detail is the point. Treat the
OTLP backend as a trusted sink and scope its credentials accordingly — that is the actual
control, not withholding data.

The rule governs **which pipeline** each shape of data takes, and it is justified by cost
and queryability, never by confidentiality:

- **Per-entity data never becomes an OTEL metric label.** Per-user/per-device/per-sign-in
  identifiers (UPN, device ID, IP, correlation ID) are log attributes, not metric label
  dimensions. Grafana Cloud bills metrics on **active series**, so one series per UPN
  grows with tenant size (hence the active-series cap, #105); a series keyed by a sign-in
  or correlation ID gets exactly one sample ever — the pathological TSDB case. It also
  buys nothing: a LogQL `count by` over the log twin answers the same question off data
  already shipped.
- **Metrics carry bounded, tenant-shaped aggregates** — counts by compliance state, by
  operating system, by policy, by risk level, by license SKU. A metric series whose
  cardinality grows with tenant size (rather than with the number of policies/states/
  categories) is a bug.
- **HARD RULE — "not a metric label" means LOG TWIN, never dropped.** Any per-entity data
  too high-cardinality for a metric label MUST still be emitted as a log. A snapshot
  collector that fetches per-entity rows, decodes only the bounded enums to bucket a
  count, and discards the rest is a **bug** — that data reaches no pipeline and the
  collector can answer "how many" but never "which one". `telemetry.Emitter` exposes
  `LogEvent`, so a `SnapshotCollector` emits both from one fetch — see
  `entra/risk` for the reference shape (bounded gauge + one log per entity, no extra
  Graph calls). Bounded-but-useless-as-a-series data (a label name, where every series
  would be 1) takes the same path: log twin, not metric label, not dropped.
- **The one genuine content exclusion is about SECRETS, not PII**, and it stays:
  `intune/auditevents` emits the **names** of changed `modifiedProperties` but never
  their old/new **values**, which can carry credentials and certificates.
- Default to **read-only, least-privilege** Graph API scopes; never request more than the
  declared signal needs.

## Project-wide gotchas

- **Log attributes are Loki structured metadata, not stream labels** (#90, verified live
  2026-07-16). Every log attribute graph2otel emits (`event_name`, `app_id`,
  `activity_display_name`, `severity`, …) is Loki *structured metadata*; only `service_name`
  is a stream label. So a `{event_name="entra.signin"}` stream selector matches **zero rows
  silently** — the single most common way to build a Grafana alert that never fires. Always
  `{service_name="graph2otel"} | event_name=`…` | attr=`…`` (label-filters after the
  selector; `=~`/`!=`/`or`/`ip(…)` all work there). See `docs/signals.md`.
- **No delta query exists** for any of the log-shaped endpoints (`signIns`,
  `directoryAudits`, `provisioning`, `riskDetections`, `riskyUsers`, Intune
  `auditEvents`). Every `WindowCollector` owns its own watermark — there is no
  server-side cursor to lean on.
- **Two independent Graph throttle ceilings with no `Retry-After`:** the reporting
  workload (5 req/10s per app per tenant) and the Identity Protection workload (1 req/s
  per tenant, across all apps). Intune has its own tighter ceiling again, and the Intune
  reports-export API is tighter still (48/min per app). Client-side rate limiters are not
  optional.
- **Four separate sign-in pollers are required**, not one: interactive, non-interactive,
  service principal, and managed identity sign-in event types cannot be combined in a
  single `signInEventTypes` filter query.
- **The `signInEventTypes` filter is beta-only** (M3, verified live 2026-07-15). A
  `GET /v1.0/auditLogs/signIns?$filter=…signInEventTypes/any(t: t eq 'nonInteractiveUser')`
  returns **HTTP 400** — `"Could not find a property named 'signInEventTypes' on type
  'microsoft.graph.signIn'"` — for `nonInteractiveUser`, `servicePrincipal`, AND
  `managedIdentity`. The same query on `/beta/auditLogs/signIns` returns 200. Microsoft's
  docs (updated 2025-06-30) document these filters only on `/beta` and call beta "not
  recommended for production." So the three filtered sign-in streams (`entra.signins.
  non_interactive` / `.service_principal` / `.managed_identity`) target the beta endpoint via
  `logpipeline.EndpointConfig.BaseURLOverride` and are `Experimental` (opt-in); only the
  interactive stream (`entra.signins.interactive`, the v1.0 default slice, no filter) is v1.0
  and default-on. Confirmed under app-only cert auth with `AuditLog.Read.All`.
- **Identity Protection caps `$top` at 500, not 1000** (M3, verified live). A
  `GET /identityProtection/riskDetections?$top=1000` returns **HTTP 400** — `"Invalid page
  size specified: '1000'. Must be between 1 and 500 inclusive."` The `logpipeline` engine
  defaults `PageSize` to 1000, so IPC-workload window collectors must set
  `EndpointConfig.PageSize=500` explicitly. Watch for similar per-endpoint page-size ceilings
  on other paged endpoints (check when a paged collector 400s on page size).
- **`/security/incidents` caps `$top` at 50, not 1000** (#109, verified live 2026-07-16). A
  `GET /security/incidents?$top=1000` returns **HTTP 400** — `"The limit of '50' for Top query
  has been exceeded. The value from the incoming request is '1000'."` Same class as the IPC
  ceiling above; `entra.security_incidents` sets `EndpointConfig.PageSize=50`.
- **The M365 audit query API is beta-only on this tenant** (#109, verified live 2026-07-16).
  `POST /v1.0/security/auditLog/queries` returns **HTTP 404 `UnknownError`** (empty message)
  even under a token carrying `AuditLogsQuery.Read.All`; `POST /beta/security/auditLog/queries`
  returns **201**. Graph's docs list a v1.0 form, but it isn't served here — same beta-only
  reality as `signInEventTypes`. `m365.unified_audit` targets beta via
  `jobpipeline.QueryConfig.BaseURLOverride` and is `Experimental` (opt-in).
- **Streams sharing a Graph path need distinct `CheckpointKey`s** (M3). The four sign-in
  collectors all poll `/auditLogs/signIns`; without a per-stream
  `logpipeline.EndpointConfig.CheckpointKey` they collide on one checkpoint namespace and
  dedupe each other's events away. Each sets `"/auditLogs/signIns#<eventType>"`.
- **Reports export API needs a write-level scope just to create the export job**, even
  though a read-only exporter only ever reads the result back — document this, don't
  silently request more scope than that one exception requires.
- **`$count` segment serves `text/plain`, not JSON** (M2, verified live). A
  `GET /users/$count` (and any `/{type}/$count`) returns a bare integer as
  `text/plain`; requesting it with `Accept: application/json` returns **HTTP
  415**. `collectors.Count` sets `Accept: text/plain` + `ConsistencyLevel:
  eventual` for this — always count through it, never a hand-rolled `$count` GET.
- **`/users/$count` rejects a `signInActivity` filter with HTTP 502** (M2,
  verified live). The `$count` path segment can't filter on `signInActivity`;
  use the collection form `GET /users?$filter=…&$count=true&$top=1` reading
  `@odata.count` (`collectors.CountViaCollection`) for signInActivity-based
  counts. Simple-property filters (accountEnabled, userType) are fine on the
  `$count` segment.
- **URL-encode every `$filter` value** (M2, verified live). A raw
  `$filter=appId eq '<guid>'` with literal spaces/quotes makes a malformed URL
  and Graph returns **HTTP 400**; always `url.QueryEscape` the filter expression.
- **`$select=keyCredentials` on a collection GET is throttled ~150 req/min per
  tenant** (M2) — tighter than the general directory ceiling. Paging
  `/applications` + `/servicePrincipals` for credential data in a large tenant
  can approach it; keep `$select` minimal.
- **Graph cannot see everything** — but this list was **over-broad and is now narrower** (#130,
  audited live 2026-07-16). **`NetworkAccessTrafficLogs` DOES have a Graph endpoint** and is
  **removed** from this list: `GET /beta/networkAccess/logs/traffic` returns **403
  `Authentication_MSGraphPermissionMissing`** whose message *names the scopes it wants* —
  `NetworkAccess-Reports.Read.All` (least-privileged read) or `NetworkAccess.Read.All`. A 403
  that names a scope is a **missing grant, not a missing endpoint**. (v1.0 400s — beta-only
  route.) Not granted, because m7kni has **no Global Secure Access** and the category produces
  **zero rows** here, so it could not be verified end-to-end — but the "no Graph endpoint at
  all, confirmed permanent" claim was **wrong** and must not be re-asserted for GSA tenants.
  The genuinely permanent ones — `MicrosoftGraphActivityLogs`, `EnrichedOffice365AuditLogs`,
  `ADFSSignInLogs`, and Intune `OperationalLogs` — have no Graph endpoint and exist only via
  diagnostic settings (→ **Storage**, per #89). Specifics, all confirmed permanent **and
  re-audited against the non-Graph first-party API surface**:
  `EnrichedOffice365AuditLogs` is Sentinel-side ML enrichment synthesized downstream (no
  source API anywhere upstream, not just "not in Graph"). Intune **`OperationalLogs`** is
  the compliance-notification/SLA-alert *fired-event* stream (e.g. `AlertType: "Managed
  Device Not Compliant"`) — Graph exposes only the notification *templates*
  (`deviceManagement/notificationMessageTemplates`, config only), never the fired-alert
  event; distinct from compliance *state*, which the compliance/manageddevices collectors
  do poll (live-verified 2026-07-15, #94). graph2otel is not a full replacement for that
  pipeline. **The escape hatch for all of these is the fallback-ingest path — an Azure
  Storage account fed by diagnostic settings** (#89, decided 2026-07-16). Log Analytics and
  Event Hub were both evaluated and **rejected**: LA cannot express deletion (purge is
  throttled, async with a 30-day SLA, GDPR-only-authorised, and *"doesn't affect billing"*)
  and cannot receive Defender's streaming API at all; Event Hub costs **£8.34/mo standing**
  and buys only **~12 seconds** of latency, because the ~4-minute floor is Entra-side, not
  destination-side. Storage is **~£0.85/mo** (measured; the earlier £0.05–0.24 figure was WRONG —
  it assumed ~1 append/min, the real rate is ~4× that at 247 appends/hr, and the bill is almost
  all WRITE ops, not storage). The correction does NOT reopen the decision — #89 pre-registered
  that it was not close enough for a 4× cost error to flip it. **Cost here is exactly measurable,
  never modelled:** `append_blob_committed_block_count` is a direct count of billable AppendBlock
  ops (an append blob supports no other write). Storage is shared by #89 and #106, and blobs
  delete for real. **The consumer is BUILT** (`internal/blobpipeline` + `entra.graph_activity` +
  three sign-in categories, live-verified 2026-07-16): see
  [`docs/blob-ingest.md`](docs/blob-ingest.md) and the README honest-scope
  section, not Graph. Opt-in via one per-tenant key, `blob_ingest.account_url` — unset (the
  default) registers no blob collectors at all.
- **Blob layout is NOT what Microsoft documents** (#89, verified live 2026-07-16). For a
  **tenant-level** (`microsoft.aadiam`) resource the prefix is **`tenantId=<guid>/`**, NOT the
  documented `resourceId=/tenants/<tid>/providers/...` — every published example is
  subscription-scoped. Full path:
  `insights-logs-<category-lowercased>/tenantId=<guid>/y=/m=/d=/h=/m=00/PT1H.json`, JSON Lines,
  **append blobs**. Coding to the docs yields a collector that finds nothing.
- **A blob for a long-closed hour KEEPS GROWING, and nothing signals when it stops** (#89,
  verified live; **model REFINED 2026-07-16 — the earlier "never settles" framing was wrong**).
  Blobs are partitioned by **event time**, and on enablement Azure backfills history into those
  hour buckets **progressively, oldest-first**. While backfill is working on hour N, that blob
  grows regardless of how long ago N closed — an `h=00` blob was still being appended to **13
  hours** later. **Once backfill passes an hour, that hour FREEZES** (measured: `h=00`/`h=01`/
  `h=11`/`h=12`/`h=13` all stopped at a fixed size + append-block count while `h=02` was still
  filling and `h=03` had only just appeared). So a "complete" state does exist — but **nothing
  tells you when it is reached and it is not derivable from the clock**, which is why the
  design is unchanged: cursor is a **byte offset per blob** (a watermark cannot express this;
  an append blob never rewrites a byte), and the consumer **re-checks every seen blob**, never
  walks forward and forgets. Cheap in steady state: only 1–2 blobs actually grow per tick
  (live-measured — a restart re-read 2 of 8 blobs and emitted 9 records vs 7,993 on the cold
  start). This is also why the consumer is **read-only**: deleting a "safely closed" hour
  would have destroyed data still arriving. **STILL OPEN:** whether a frozen hour can EVER
  grow again once enablement backfill is fully done — not answerable until m7kni finishes
  backfilling. Re-measure before assuming either way; the design is safe under both.
- **Data-plane RBAC fails SILENTLY on Azure** (#89, verified live — the most dangerous trap on
  this path, indistinguishable from "no data yet"). `Owner` grants blob **container** list/create
  (control-plane) but **NOT** blob *content* reads — that needs **`Storage Blob Data Reader`**.
  Worse for Event Hub: receiving needs **`Azure Event Hubs Data Receiver`**, and without it the
  SDK returns **0 events with NO error** while the hub reports hundreds.
- **Blob record field TYPES are inconsistent within one record — never map a blob category by
  reading the docs** (#89, verified against a 335-record live sample 2026-07-16). Three live
  traps, each of which produces a silently-wrong collector rather than an error:
  (a) **`durationMs` is a STRING (`"497815"`) at the top level and an INT (`497815`) inside
  `properties` — on the SAME record.** Bind to `properties` for every number; the top-level
  `resultSignature` is likewise a stringified status code.
  (b) **`level` is `"Informational"` on EVERY `MicrosoftGraphActivityLogs` record, including
  the 500s** (sample spanned 200/201/204/400/401/403/404/500). Deriving severity from it marks
  every server error INFO forever. Use `properties.responseStatusCode`. And `level` is a
  **numeric string (`"4"`)** on `SignInLogs` — so a severity mapper SHARED across blob
  categories is wrong twice over. Map per category.
  (c) **`resourceId` casing differs per category** (`/TENANTS/…/MICROSOFT.AADIAM` on MGAL vs
  `/tenants/…/Microsoft.aadiam` on SignInLogs). Never match on it.
  Records are JSON Lines with **CRLF** terminators. The `properties.__UDI_RequiredFields_*` keys
  are Microsoft's internal ingestion plumbing — drop them.
- **The blob envelope `time` is the INGESTION time, and on sign-in categories it is NOT the event
  time** (#135, verified live 2026-07-16 across ~700 records of all three sign-in categories).
  `time` and `properties.createdDateTime` were **never** equal — 0 of 700 — and the gap is
  **VARIABLE (28s–1077s)**, so it cannot even be recovered by subtracting a constant. Bind sign-in
  timestamps to **`properties.createdDateTime`**, with **no fallback** to `time` (a fallback
  silently reintroduces the bug). `MicrosoftGraphActivityLogs` binds to `time` and is **correct**
  to — there `time` == `properties.timeGenerated` byte-for-byte. That is the trap: the shipped
  neighboring collector models the opposite rule, so **copying it onto a sign-in stream backdates
  every record by a random couple of minutes, with no error**. The earlier "31 minutes" figure on
  #135 was n=1 and is NOT a constant.
- **The blob envelope IS consistent within a category family, and is NOT across families** (#135).
  This refines the "map per category" rule rather than contradicting it: the three sign-in
  categories were diffed field-by-field and share one schema with **zero type conflicts** (their
  only differences are additive optional fields), so they correctly share ONE mapper. MGAL vs
  sign-ins do not agree on anything (`time`, `level`, `resourceId` casing, `durationMs` type all
  differ). Verify agreement against live samples before sharing a mapper; do not assume it either
  way.
- **The blob `properties` object IS the Graph `signIn` resource** (#135, verified field-for-field
  across live samples of all four sign-in categories). Every field the polled `mapSignIn` reads is
  present in every blob category, so `entra/signins` reuses ONE mapper for both the polled and blob
  paths and the two sources are drop-in equivalents — same `entra.signin` event name, same
  attributes, same `id`. Do not write a second sign-in mapper; an attribute added for one source
  must be right for the other. (`properties.id` == the polled `signIn.id`, so the two are
  dedupe-able downstream if both run.)
- **Azure diagnostic-settings delivery is AT-LEAST-ONCE: ~2.3% of blob records arrive more than
  once** (#138, measured live 2026-07-16 across every category with data; one event arrived
  **3×**). A re-delivery is a separate line — usually in the SAME hour blob — with a
  **byte-identical `properties` payload** and a **fresh envelope `time`** (one `h=04` blob held the
  same sign-in at line 15 / envelope `04:09:50` and line 20 / envelope `04:16:16`). **This is not a
  cursor bug and the cursor cannot fix it**: both copies are real distinct bytes. Proven exact —
  across a cold start plus a restart, for all 1,035 emitted ids the emitted count **equalled** the
  in-blob count, with zero over-emission and zero loss. So a cross-run "duplicate" on restart is
  Azure re-delivering into newly-appended bytes, NOT a checkpoint bug — do not "fix" the cursor.
  Consequence: `logpipeline` dedupes (seen-id set in its checkpoint) but **`blobpipeline` does
  not**, so blob-sourced collectors ship ~2.3% duplicates today, `entra.graph_activity` included.
  Rates: MGAL 302/11,134 (2.71%), spsp 18/771, mspsp 6/216, niu 1/40. Measured DURING enablement
  backfill — re-measure post-backfill (#137) before treating 2.3% as steady-state.
- **A blob-sourced collector is a `SnapshotCollector`, not a `WindowCollector`** — the interface
  split is about the CURSOR, not the signal shape. A blob collector emits logs but cannot use a
  scheduler-supplied `[from, to]` range (see the backfill entry above), so `Collect(ctx, e)` is
  the fit and the scheduler needs no change. Blob collectors register via
  `collectors.RegisterBlob` / `BlobDeps` — the third construction path alongside `Deps` and
  `WindowDeps`, and the smallest: no Graph client, no page fetcher, no license caps.
- **Purview/M365 policy config is S&C-PowerShell-only — no Graph list/count** (#99).
  Several Purview surfaces have no Graph enumerable equivalent, so there is no "count of
  policies per mode" metric to build: **DLP policy authoring/simulation state** (Block vs
  TestWithNotifications, covered locations) via `Get/Set-DlpCompliancePolicy` /
  `Get/Set-DlpComplianceRule` (Graph's `protectionScopes/compute` only *evaluates*
  synthetic input, it does not list policies); **retention *policy* location bindings** via
  `Get/Set-RetentionCompliancePolicy` (but retention *label* **definitions** ARE Graph-
  exposed at `security/labels/retentionLabels` — only the policy binding is missing);
  **label encryption activation** — **this one is WRONG and is resolved** (#99, verified live
  2026-07-16): it is **not** portal-only. The sensitivity-label catalog exposes **`hasProtection`
  per label**, and it discriminates correctly on m7kni (`Highly Confidential`=True; Personal /
  Public / General / Confidential=False). **No new scope needed** — `SensitivityLabel.Read` is
  already granted. The residual (narrower) gap is the protection *template* detail — rights,
  expiry — which stays unexposed. **Azure RMS is ruled out for label config**: its five app-only
  roles are `Content.DelegatedReader/Writer/SuperUser/Writer` + `Application.Read.All` — all
  about consuming/producing protected *content*, never reading label configuration — and
  `api.aadrm.com` issues a token then serves an **IIS 404 HTML page**, not an API. Two notes: `DLP.All` sensitive-data content is **open** — the O365
  Management Activity API exposes an **`ActivityFeed.ReadDlp`** Application role, literally
  *"DLP policy events including detected sensitive data"*, which is the purpose-built answer
  and is being verified under #100; and the unified-audit-log toggle `Set-AdminAuditLogConfig`
  (Exchange Online cmdlet) is a fresh-tenant deployment prerequisite but is **already on for
  m7kni**, so not a blocker there.
- **Microsoft Graph is NOT the only first-party API available** (#100, #126, 2026-07-16). An
  app registration can hold Application permissions on many other first-party APIs, and two
  "permanent gap" verdicts were overturned in one session by checking them. Live-verified as
  present and **app-only capable** in this tenant: **Office 365 Management APIs**
  (`c5393580-f805-4401-95e8-94b7a6ef2fc2`) exposing `ActivityFeed.Read`,
  `ActivityFeed.ReadDlp`, `ServiceHealth.Read`. **Do NOT treat "no Graph endpoint" as "no
  API"** — check the other first-party resources before recording a permanent gap.
- **The O365 Management Activity API is NOT redundant** (#100 — **reopened**; its earlier
  "closed as redundant" verdict was wrong and this entry previously told you not to re-chase
  it). It was closed on a *data-equivalence* test ("same rows as `security/auditLog/queries`" —
  true) when the question was *ingest fitness*, where it wins decisively: **stable v1.0** (vs
  the audit query API being **beta-only**, which is the sole reason `m365.unified_audit` is
  Experimental), **2,000 req/min per tenant** (vs 429-on-rapid-create, #98), and a
  subscription→content-blob model built for continuous SIEM ingest (vs a **>10-minute** async
  query). Its content types are exhaustive by construction — **`Audit.General` is an explicit
  catch-all**, and `Audit.AzureActiveDirectory` is first-class — so there is **no coverage gap**
  vs `auditLogQuery`. Its only real losses: **7-day content expiry** (moot — Loki rejects older
  samples anyway) and **no server-side filtering** (real — so subscribe only to the content
  types actually mapped; **never `Audit.General` by default**). `POST /subscriptions/start` is
  a **write operation** — the second break in the read-only property, after the reports-export
  job.
- **Re-audited and CONFIRMED PERMANENT — tested against the non-Graph first-party API surface,
  do NOT re-chase** (#130 audit, 2026-07-16, probed as `graph2otel-poller`):
  **the dedicated Microsoft Intune API (`0000000a-0000-0000-c000-000000000000`) exposes ZERO
  app-only roles** — delegated-only, and `api.manage.microsoft.com` is NXDOMAIN. That is the
  strongest possible negative: no grant, licence, or consent can ever unblock it for an
  app-only poller, so Graph is the *only* Intune route and Intune `OperationalLogs` stays a
  storage-path signal (#94). **`deviceManagement/monitoring/alertRecords`/`alertRules` is Cloud
  PC-only** (every rule template is `cloudPc*`; no `deviceNotCompliant` template exists) — it is
  NOT the OperationalLogs fired-alert stream even if granted. **DLP policy enumeration** has no
  Graph route and the Purview Ecosystem API's 17 app-only roles are all
  `ProcessContent`/`Assets`/`ProtectionScopes.Read` — **Purview APIs evaluate content against
  policy, they never enumerate policy**; that pattern holds across the whole surface.
  **Retention policy bindings** stay 500/Forbidden with `RecordsManagement.Read.All` present
  (Application: Not supported).
- **The `intune.devices` full-fleet page-walk is irreducible BY DESIGN, not by API limitation.**
  `managedDeviceOverview` exists and IS already used as a bounded cross-check
  (`intune.devices.overview.*`) — but it can never replace the walk, because
  `manageddevices.go` emits a **log twin per device** and those per-device rows ARE the
  deliverable, not merely an input to a count. Replacing the walk with a bounded count would
  delete the twins and violate the hard rule above. (It also could not substitute even if the
  rule allowed it: its OS summary sums to 9 against a real fleet of 10 — no Linux bucket.)
- **When closing an issue as "redundant", state which question the test answered.** "Same rows"
  and "same fitness for purpose" are different claims. Both #100 and #109 were closed on the
  wrong question, and both wrong verdicts then propagated into this file's do-not-redo list,
  where they actively suppressed re-investigation for months.
- **Purview label enumeration: sensitivity labels WORK; only retention labels are blocked**
  (#126, live-verified 2026-07-16 — this **corrects** #109, which was wrong). **Sensitivity
  labels are NOT app-only-blocked.** #109 concluded "permanent app-only gap" after testing
  the right endpoint with the *wrong scope*: the app held `InformationProtectionPolicy.Read.All`,
  a different permission. Granting **`SensitivityLabel.Read`** (an Application role —
  `allowedMemberTypes: ['Application']`) makes
  `GET /security/dataSecurityAndGovernance/sensitivityLabels` return **200 with the full
  tenant catalog**, on v1.0 and beta. `SensitivityLabels.Read.All` is **not** needed — the
  least-privileged form serves tenant-wide labels.
  **Gotcha: `displayName` is present but ALWAYS null — the value is in `name`.** Binding to
  `displayName` (the obvious choice) emits empty labels and looks like a data bug.
  **Retention labels ARE still blocked, and that half of #109 stands**:
  `/security/labels/retentionLabels` and `/security/triggerTypes/retentionEventTypes` →
  **HTTP 500 `DataInsightsRequestError` "...FAILED - Forbidden"** on both v1.0 and beta, with
  `RecordsManagement.Read.All` present in the token — Microsoft documents **Application: Not
  supported** for that endpoint. `purview/labels.isUnavailable` must keep matching the specific
  `DataInsightsRequestError`+`Forbidden` 500 pair (NOT bare `status 500` — a generic 500 must
  still surface) while **no longer swallowing sensitivity-label 403s**.
  **The lesson, which cost a wrong "permanent" verdict:** a 403 means *missing consent* far more
  often than *product limitation*. Before declaring an app-only gap, check the endpoint's
  documented Application permission and confirm the app actually holds **that** role — not a
  similarly-named one. `eDiscovery.Read.All` is the counter-example (#102): granted, in the
  token, and it **still** 401s — so both outcomes are real; verify, never infer.
- **Probe as `graph2otel-poller`, never as another app.** Any "can graph2otel see X?" answer is
  only valid under the poller's own identity (`2c92ce28-126c-47c1-82b0-410b64502989`). Probing
  with a different app registration reports *that* app's access and silently produces wrong
  conclusions — this is exactly how #109's verdict went wrong. Note app-only tokens embed
  `roles` at issue time, so a token minted before a grant will not carry it; mint a fresh one.
- **Intune `managedDevices` has no `$count` segment** (M4, verified live). A
  `GET /deviceManagement/managedDevices/$count` returns **HTTP 400** — `"No OData
  route exists that match template ~/singleton/navigation/$count"` (its backend is
  `DeviceFE/StatelessDeviceFEService`, not the directory OData stack). AND
  `operatingSystem` is **not** a server-`$filter`able property on that collection. So
  there is no bounded `$count`/`$filter` slice for the fleet — page the full collection
  with a trimmed `$select` and bucket/count **client-side** (as `intune/manageddevices`
  and `intune/malware` do). This is the deliberate exception to "never page the full
  collection."
- **Intune signals "feature not provisioned" via HTTP 400 `ResourceNotFound` /
  "not found for segment", not 403/404** (M4, verified live). A tenant that hasn't
  onboarded a feature returns a **400** whose body carries `"code":"ResourceNotFound"`
  or message `"Resource not found for (the) segment '<x>'"` — seen on
  `userExperienceAnalyticsOverview` (analytics not enabled), per-template
  `templates/{id}/deviceStateSummary` (template type has no summary), and others.
  (`exchangeConnectors` is a variant: **HTTP 501 `NotSupported`** when no Exchange
  connector is provisioned.) Collectors must recognize this **specific signature** and
  skip that sub-fetch gracefully (log Info, drop only that metric, don't fail the
  collector) — but must **NOT** blanket-swallow all 400s: a genuine malformed-query 400
  (the `$count`, `$top=1000`, unescaped-`$filter` bugs above) must still surface as a
  real error.
- **Per-device Intune sub-resources 404 routinely** (M4, verified live). A
  `GET /managedDevices/{id}/windowsProtectionState` returns **404 `ResourceNotFound`**
  for a Windows device that simply hasn't reported that sub-resource yet — a normal
  no-data condition, not a failure. A per-device sweep must skip-and-count these, never
  fail the whole collector, and should emit an empty snapshot (not all-zeros) when
  **zero** devices returned readable data, so "no data" is never misread as "0 enabled."
- **Deprecated Intune endpoints can return an empty body** (M4, verified live). The
  product-deprecated `windowsInformationProtectionPolicies` (WIP) endpoints return an
  **empty response body** → `json.Unmarshal` fails with `"unexpected end of JSON input"`.
  Treat an empty body as an empty list (zero rows), and treat such deprecated-endpoint
  fetches as best-effort — never fail the collector on them.
- **Some Intune event endpoints reject a server-side `$filter`** (M5, verified live).
  `troubleshootingEvents` and `autopilotEvents` don't support a `$filter` on their time
  field; the logpipeline engine's `EndpointConfig.NoServerFilter` omits the server filter
  and bounds the window CLIENT-SIDE instead (heavier — no lower bound on the wire — but
  correct). `auditEvents` DOES support a time `$filter`, so it uses the normal path.
- **The reports export API needs one WRITE scope just to create a job** (M5). `POST
  /deviceManagement/reports/exportJobs` requires one of `DeviceManagement*.ReadWrite.All`
  even though the exporter only reads the result back — the single break in graph2otel's
  read-only property. Export report collectors are opt-in (`Experimental`) and declare
  that one scope; document it, don't request more than one.
- **Not every "available report" supports export, and reportName/select are exact-match**
  (M5, verified live). `POST exportJobs` 400s with NO fuzzy match on a wrong `reportName`
  or `select` column — always smoke-test names/columns against a live tenant. Beyond wrong
  names: (a) some reports listed in Microsoft's available-reports catalog are **not
  export-supported** — `DeviceEnrollmentFailures` → 400 `"PostExportJobAsync not supported
  for reportType"`; (b) some require a **mandatory filter** and have no fleet-wide form —
  `DeviceInstallStatusByApp` → 400 `"restriction filter needed"` (needs a per-app
  `ApplicationId`), so use the aggregate variant (`AppInstallStatusAggregate`) where one
  exists; per-policy reports (feature updates) likewise need a `PolicyId` fan-out.
- **Intune export CSVs are not RFC-4180-strict** (M5, verified live). They carry a leading
  **UTF-8 BOM** (corrupts the first header name if not stripped) and **bare double-quotes
  in unquoted fields** (Go's `encoding/csv` rejects with `"bare \""`). The `exportjob`
  parser strips the BOM and sets `LazyQuotes = true` + `FieldsPerRecord = -1`. Always send
  an explicit `select` — Microsoft warns default columns can change without notice.
