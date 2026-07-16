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

## Cardinality & PII guidance

Entra ID and Intune data are **not** low-cardinality infrastructure metadata — sign-in
logs, device compliance records, and directory objects carry real PII (UPNs/emails,
device names, sign-in IP addresses, group memberships). The boundary rule (see
`SECURITY.md` for the full rationale):

- **High-cardinality, per-entity data never becomes an OTEL metric label.** Per-user,
  per-device, per-sign-in identifiers (UPN, device ID, IP address, correlation ID) belong
  in the **logs** pipeline as structured attributes, not as metric label dimensions.
- **Metrics carry bounded, tenant-shaped aggregates** — counts by compliance state, by
  operating system, by policy, by risk level, by license SKU. A metric series whose
  cardinality grows with tenant size (rather than with the number of policies/states/
  categories) is a bug.
- Default to **read-only, least-privilege** Graph API scopes; never request more than the
  declared signal needs.

## Project-wide gotchas

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
- **Graph cannot see everything.** `MicrosoftGraphActivityLogs`,
  `EnrichedOffice365AuditLogs`, `ADFSSignInLogs`, `NetworkAccessTrafficLogs`, and most of
  Intune `OperationalLogs` have no Graph endpoint at all — they exist only via diagnostic
  settings → Event Hub/Log Analytics. Specifics, all confirmed permanent:
  `EnrichedOffice365AuditLogs` is Sentinel-side ML enrichment synthesized downstream (no
  source API anywhere upstream, not just "not in Graph"). Intune **`OperationalLogs`** is
  the compliance-notification/SLA-alert *fired-event* stream (e.g. `AlertType: "Managed
  Device Not Compliant"`) — Graph exposes only the notification *templates*
  (`deviceManagement/notificationMessageTemplates`, config only), never the fired-alert
  event; distinct from compliance *state*, which the compliance/manageddevices collectors
  do poll (live-verified 2026-07-15, #94). graph2otel is not a full replacement for that
  pipeline. **The escape hatch for all of these is the fallback-ingest path (Event Hub /
  Log Analytics query) — see [`docs/event-hub-fallback.md`](docs/event-hub-fallback.md)
  and the README honest-scope section**, not Graph.
- **Purview/M365 policy config is S&C-PowerShell-only — no Graph list/count** (#99).
  Several Purview surfaces have no Graph enumerable equivalent, so there is no "count of
  policies per mode" metric to build: **DLP policy authoring/simulation state** (Block vs
  TestWithNotifications, covered locations) via `Get/Set-DlpCompliancePolicy` /
  `Get/Set-DlpComplianceRule` (Graph's `protectionScopes/compute` only *evaluates*
  synthetic input, it does not list policies); **retention *policy* location bindings** via
  `Get/Set-RetentionCompliancePolicy` (but retention *label* **definitions** ARE Graph-
  exposed at `security/labels/retentionLabels` — only the policy binding is missing);
  **label encryption activation** (Azure RMS, portal-only). Confirmed permanent. Two
  non-gaps to not re-chase: `DLP.All` sensitive-data content is **open/pending** a
  live-verify of whether `security/auditLog/queries` mirrors it (not a settled gap); and
  the unified-audit-log toggle `Set-AdminAuditLogConfig` (Exchange Online cmdlet) is a
  fresh-tenant deployment prerequisite but is **already on for m7kni**, so not a blocker
  there.
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
