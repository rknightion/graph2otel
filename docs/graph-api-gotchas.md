# Graph API gotchas — the live-verified quirk ledger

Every entry here was verified against a real tenant (m7kni) under the poller's own
identity unless tagged otherwise. **Evidence tags**: `[live YYYY-MM-DD, #issue]` means
measured on the wire; `[docs-only]` means believed from documentation and cheap to
re-open; `[n=1]` means a single observation. Microsoft's documentation has been wrong on
essentially every load-bearing detail on this project's path — **wire over docs, always**
(see the scorecards in [o365-management-api.md](o365-management-api.md)).

Before adding an entry: state the current truth positively, tag the evidence, link the
issue. Do not record correction narratives here — those live on the issues.

## Query mechanics (all workloads)

- **URL-encode every `$filter` value** `[live, M2]`. A raw `$filter=appId eq '<guid>'`
  with literal spaces/quotes makes a malformed URL → HTTP 400. Always `url.QueryEscape`
  the filter expression.
- **`$count` segment serves `text/plain`, not JSON** `[live, M2]`. `GET /users/$count`
  (any `/{type}/$count`) returns a bare integer; requesting `Accept: application/json`
  → HTTP 415. `collectors.Count` sets `Accept: text/plain` + `ConsistencyLevel: eventual`
  — always count through it, never a hand-rolled `$count` GET.
- **`/users/$count` rejects a `signInActivity` filter with HTTP 502** `[live, M2]`. Use
  the collection form `GET /users?$filter=…&$count=true&$top=1` reading `@odata.count`
  (`collectors.CountViaCollection`) for signInActivity-based counts. Simple-property
  filters (accountEnabled, userType) are fine on the `$count` segment.
- **Per-endpoint `$top` ceilings differ and 400 when exceeded.** The `logpipeline` engine
  defaults `PageSize` to 1000; override per endpoint:
  - Identity Protection: **500** `[live, M3]` — `"Invalid page size specified: '1000'"`.
  - `/security/incidents`: **50** `[live 2026-07-16, #109]`.
  Check for a page-size ceiling whenever a paged collector 400s.
- **`$select=keyCredentials` on a collection GET is throttled ~150 req/min per tenant**
  `[live, M2]` — tighter than the general directory ceiling. Keep `$select` minimal when
  paging `/applications` + `/servicePrincipals`.

## Throttling (no Retry-After)

Independent ceilings, none of which reliably send `Retry-After` — client-side limiters in
`internal/graphclient` are not optional:

| workload | ceiling |
| --- | --- |
| reporting | 5 req / 10 s per app per tenant |
| Identity Protection | **1 req/s per tenant, across ALL apps** |
| Intune general | own tier; Devices endpoints elevated |
| Intune reports-export | 48 req/min per app |
| directory `keyCredentials` select | ~150 req/min per tenant |

## Sign-in logs

- **Four separate sign-in pollers are required** `[live, M3]`: interactive,
  non-interactive, service principal, and managed identity event types cannot be combined
  in one `signInEventTypes` filter.
- **The `signInEventTypes` filter is beta-only** `[live 2026-07-15, M3]`. On v1.0 it
  returns HTTP 400 (`"Could not find a property named 'signInEventTypes'"`) for all three
  non-interactive types; the same query on `/beta` returns 200. Hence the three filtered
  streams target beta via `BaseURLOverride` and are `Experimental`; only
  `entra.signins.interactive` (the v1.0 default slice, no filter) is default-on.
  The blob path retires this beta dependency — see [blob-ingest.md](blob-ingest.md).
- **Streams sharing a Graph path need distinct `CheckpointKey`s** `[live, M3]`. The four
  sign-in collectors all poll `/auditLogs/signIns`; without per-stream
  `EndpointConfig.CheckpointKey` (`"/auditLogs/signIns#<eventType>"`) they collide on one
  checkpoint namespace and dedupe each other's events away.
- **No delta query exists for any log-shaped endpoint** (`signIns`, `directoryAudits`,
  `provisioning`, `riskDetections`, `riskyUsers`, Intune `auditEvents`). Every
  `WindowCollector` owns its watermark; there is no server-side cursor.

## M365 audit query API

- **`POST /v1.0/security/auditLog/queries` is beta-only on this tenant**
  `[live 2026-07-16, #109]`: v1.0 → 404 `UnknownError` (empty message) even with
  `AuditLogsQuery.Read.All` in the token; `/beta` → 201. `m365.unified_audit` targets
  beta and is `Experimental`. The stable-transport alternative is the O365 Management
  Activity API (`m365.activity`, default-on) — see
  [o365-management-api.md](o365-management-api.md). The two emit the same `m365.audit`
  ids: **never enable both on one tenant.**

## Intune

- **`managedDevices` has no `$count` segment** `[live, M4]` — HTTP 400 `"No OData route
  exists"` (its backend is DeviceFE, not the directory OData stack), and
  `operatingSystem` is not server-filterable. Page the full collection with a trimmed
  `$select` and bucket client-side — the deliberate exception to "never page the full
  collection". The walk is irreducible **by design**: the per-device log twins ARE the
  deliverable (a bounded count cannot replace them; also `managedDeviceOverview`'s OS
  summary sums to 9 on a real fleet of 10 — no Linux bucket). #132 tracks the one
  possible retirement route (blob inventory categories).
- **"Feature not provisioned" is HTTP 400 `ResourceNotFound` / "not found for segment",
  not 403/404** `[live, M4]` (variant: `exchangeConnectors` → 501 `NotSupported`).
  Recognize the specific signature and skip that sub-fetch gracefully — but do NOT
  blanket-swallow 400s: malformed-query 400s (page size, unescaped filter) must surface.
- **Per-device sub-resources 404 routinely** `[live, M4]` — e.g.
  `windowsProtectionState` for a device that hasn't reported it. Skip-and-count, never
  fail the sweep; emit an empty snapshot (not all-zeros) when zero devices returned data.
- **Deprecated endpoints can return an empty body** `[live, M4]` — WIP policies return
  empty → `json.Unmarshal` fails. Treat empty body as empty list; deprecated fetches are
  best-effort.
- **`troubleshootingEvents` and `autopilotEvents` reject a time `$filter`** `[live, M5]`
  — use `EndpointConfig.NoServerFilter` (client-side window bounding; heavier but
  correct). `auditEvents` DOES support the filter.

### Intune reports-export API

- **Creating an export job needs a WRITE scope** (`DeviceManagement*.ReadWrite.All`)
  `[live, M5]` even though the exporter only reads results — one of exactly two breaks in
  the read-only property (the other: O365 `POST /subscriptions/start`). Export collectors
  are `Experimental` and declare that one scope.
- **`reportName`/`select` are exact-match, no fuzzy errors** `[live, M5]`. Some catalog
  reports are not export-supported (`DeviceEnrollmentFailures` → 400); some require a
  mandatory filter (`DeviceInstallStatusByApp` needs `ApplicationId` — use
  `AppInstallStatusAggregate`). Smoke-test names/columns live.
- **Export CSVs are not RFC-4180-strict** `[live, M5]`: leading UTF-8 BOM + bare quotes
  in unquoted fields. The `exportjob` parser strips the BOM, sets `LazyQuotes`,
  `FieldsPerRecord=-1`. Always send an explicit `select`.
- **Enum columns return NUMERIC CODES, not names** `[live 2026-07-16, #142]`:
  `Platform` → `'1','2','3','5'`, etc. Microsoft returns a localized `<Col>_loc` sibling
  anyway (already fetched, currently discarded) — but a **bitmask** field
  (`ProductStatus`) has NO `_loc` sibling and a name-keyed lookup can never hit. Never
  test enum columns against hand-written names (`"platform": "windows"` has never been on
  the wire). `AllDeviceCertificates` is UNVERIFIED (zero certs on m7kni). #142 owns the fix.

## Purview / labels

- **Sensitivity labels work app-only** `[live 2026-07-16, #126]`:
  `GET /security/dataSecurityAndGovernance/sensitivityLabels` → 200 with
  `SensitivityLabel.Read` (an Application role; `SensitivityLabels.Read.All` not needed).
  **`displayName` is present but ALWAYS null — bind `name`.** Label encryption activation
  is readable via `hasProtection` per label; the residual gap is protection *template*
  detail (rights, expiry) only.
- **Retention labels are app-only-blocked** `[live 2026-07-16, #109/#126]`:
  `/security/labels/retentionLabels` → 500 `DataInsightsRequestError` + "Forbidden" on
  v1.0 and beta with `RecordsManagement.Read.All` granted (documented Application: Not
  supported). `purview/retentionlabels.isRetentionUnavailable` must match that
  **specific** signature — a generic 500 must still surface, and a sensitivity-label 403
  must fail the collector (#126 residual).
- **Purview/M365 policy *configuration* is S&C-PowerShell-only** `[live, #99]`: DLP
  policy state, retention policy bindings. The Purview Ecosystem API's app-only roles all
  evaluate content against policy — they never enumerate policy. Retention label
  *definitions* and sensitivity labels ARE Graph-exposed.
- **eDiscovery is the counter-example to "403 = missing scope"** `[live-measured
  2026-07-17, #102/#148]`: `eDiscovery.Read.All` granted and in the token still 401'd.
  No Graph scope fixes it — the data plane simply did not know the principal. Registering
  it Purview-side via S&C PowerShell (`New-ServicePrincipal` + `Add-RoleGroupMember
  eDiscoveryManager` + `Add-eDiscoveryCaseAdmin`) moved `security/cases/ediscoveryCases`
  from 401 to **200 on the first probe**, no replication wait. So **401 with the scope
  present means a missing data-plane registration, not a missing scope** — a different
  failure from the 403 above, and the reason to verify rather than infer. The procedure
  is [`data-plane-registration.md`](data-plane-registration.md).

## Permanent gaps and the fallback path

Signals with **no API anywhere** (re-audited against the non-Graph first-party surface,
`[live 2026-07-16, #130 audit]`): `EnrichedOffice365AuditLogs` (Sentinel-side synthesis),
`ADFSSignInLogs`, Intune `OperationalLogs` (fired-alert stream; Graph has only the
templates; the dedicated Intune API `0000000a-…` exposes **zero app-only roles** and
`api.manage.microsoft.com` is NXDOMAIN — no grant can ever unblock it), DLP policy
enumeration, retention policy bindings.

Corrected non-gaps: `NetworkAccessTrafficLogs` has a beta endpoint that names its own
scope (#130 — out of scope until a GSA tenant exists); Purview sensitivity labels (#126).

The escape hatch for blob-only categories is diagnostic settings → Azure Storage →
`internal/blobpipeline` — see [blob-ingest.md](blob-ingest.md).

## Process rules that keep these entries honest

- **Probe as `graph2otel-poller`** (`2c92ce28-126c-47c1-82b0-410b64502989`), never
  another app — a different app's access answers a different question (#109's wrong
  verdict). App-only tokens embed `roles` at issue time: mint fresh after a grant.
- **A 403 usually means missing consent, not product limitation.** Before declaring an
  app-only gap, confirm the app holds the endpoint's *documented* Application permission
  — not a similarly-named one (#126). But grants can also be insufficient (#102) —
  verify, never infer, in both directions.
- **"No Graph endpoint" ≠ "no API".** Check the other first-party resources (O365
  Management APIs, etc.) before recording a permanent gap (#100, #126).
- **When closing an issue as "redundant", state which question the test answered.**
  "Same rows" and "same fitness for purpose" are different claims — #100 and #109 were
  both closed on the wrong question and the wrong verdicts then suppressed
  re-investigation.
