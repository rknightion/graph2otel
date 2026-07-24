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
- **Two Endpoint Analytics segments reject `$top` ENTIRELY — there is no ceiling to stay
  under** `[live-measured 2026-07-21, #199/#225]`. This is a distinct trap from the ceilings
  above, and the more dangerous one, because the natural fix (lower the page size) never works:

  | segment | bare list | `$top=5` / `50` / `200` | `$count=true` | `$orderby` |
  | --- | --- | --- | --- | --- |
  | `userExperienceAnalyticsDeviceStartupProcesses` | **200, rows** | **400** | 400 | 200 |
  | `userExperienceAnalyticsDeviceStartupHistory` | **200, rows** | **500** | 500 | 500 |

  Note the two answer with **different status codes for the same cause**, so a 500 from
  `DeviceStartupHistory` is not a transient Graph fault — do not retry it, drop the parameter.
  No shipped collector is exposed: `collectors.GetAllValues` paginates with the
  `Prefer: odata.maxpagesize` header and never emits `$top`. Any new collector that reaches
  for `$top` on a UXA segment would be.

  **This cost a real false verdict.** A probe of `DeviceStartupProcesses` carried `?$top=5`,
  got the 400, and the segment was recorded on #199 as "400 on a plain list on both versions;
  needs a device-scoped route that has not been resolved" — a route problem attributed to a
  tenant that in fact returns rows. Along with #222 and the `hardwareInformation` list-vs-single
  stub, that is three verdicts in one week where a malformed request degraded into a plausible
  empty-or-error result and got written down as a fact about the tenant. **Before parking
  anything as blocked-on-data, vary the request shape first** — bare vs `$select` vs `$top`
  vs single-entity vs cast segment — and only then attribute the emptiness to the tenant.
- **The bare `userExperienceAnalyticsDeviceStartupProcesses` list serves ONE device, and
  says nothing about it** `[live-measured 2026-07-24, #255, verified twice]`. A bare `GET`
  of that segment returns the rows of a single device — m7kni answered **5 rows / 1 device**
  while holding **27 rows across 7** — and carries **no `@odata.nextLink`**, so the response
  contains no signal that anything is missing. `Prefer: odata.maxpagesize` does not change it,
  so this is not a page-size problem and not a `collectors.GetAllValues` bug: that helper
  correctly concludes it has the whole collection. **Which** device gets served rotates
  between polls, which is why the behavior first read as a rolling window rather than as a
  dropped fetch.

  **The fix is a per-device fan-out, and the EDM says it is impossible.** The beta
  `$metadata` annotates `userExperienceAnalyticsDeviceStartupProcess/managedDeviceId` as
  `"Supports: $select, $OrderBy. Read-only."` — **no `$filter`** — yet
  `?$filter=managedDeviceId eq '<guid>'` returns that device's full row set every time.
  Wire over docs, in the direction that matters most: an author who trusts the annotation
  rules out the only working fix and ships a collector emitting 18.5% of the data. The
  filter also rides `POST /beta/$batch` — a three-device batch returned `200/200/200` with
  10, 5 and 3 rows, matching the counts measured serially — so `intune.endpoint_analytics`
  pays the N+1 at `ceil(N/20)` requests per cycle, the same shape as
  `intune.hardware_inventory` below. Note the sub-responses came back **out of request
  order** (2, 1, 0): correlate a `$batch` reply by its sub-request `id`, never by position.
  The `+`-for-space form `url.QueryEscape` produces
  (`?$filter=managedDeviceId+eq+%27<guid>%27`) is accepted inside a `$batch` sub-request URL
  too, verified separately from the literal-space form a probe sends.

  **The lesson beyond this segment:** a `200` carrying rows is not evidence the collection
  is complete. `CLAUDE.md`'s "a green tick is not evidence of data" covers empty-success;
  this is *partial* success, which is worse, because there is nothing anomalous to notice.
  When a collection is per-entity in nature, cross-check its row count against an entity
  list you already hold.
- **`$count=true` on `userExperienceAnalyticsModelScores` returns the count and DROPS the
  rows** `[live-measured 2026-07-24, #194]`. `?$count=true` answers `200` with
  `@odata.count: 1` and `"value": []`, while the bare list returns the row. The count is
  right; the collection is silently empty. This matters more than it sounds: `count=0` is
  the exact wording several UXA segments were parked on as blocked-on-data, and a probe
  reaching for `$count` to test emptiness gets a zero-length collection from a segment that
  has data. **Read the rows, not the count**, when deciding whether a segment is populated.
- **`$orderby=id` returns 500 on `userExperienceAnalyticsAppHealthDeviceModelPerformance`**
  `[live-measured 2026-07-24, #194]` while the bare list returns `200`. Same family as the
  `$top` entry above — an OData parameter that looks universally safe, is not, and answers
  with a 5xx that reads like a transient fault. It is not transient; drop the parameter.
- **`hardwareInformation` is a STUB on a list GET and only materializes on a single-entity
  GET** `[live-measured 2026-07-21, #199]`. `GET /beta/deviceManagement/managedDevices?$select=hardwareInformation`
  returns all 40 keys with 6-8 populated; `GET .../managedDevices/{id}?$select=hardwareInformation`
  returns 16-21. `$expand` is rejected ("Property 'hardwareInformation' … not expandable") and
  `$filter=id eq '…'` on that collection 400s. **`$batch` is the escape hatch** — 20 sub-requests
  per POST, every sub-response fully populated — which is what makes `intune.hardware_inventory`
  affordable. The property does not exist on the v1.0 type at all.
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
- **A quarantine record's `auditData` arrives as the GENERIC subtype**
  `[live-measured 2026-07-23, #233]`. Graph's beta metadata declares a dedicated
  `quarantineAuditRecord`, but the wire carries
  `"@odata.type": "#microsoft.graph.security.defaultAuditData"` — so code that switched on
  the typed subtype would never fire. Read the fields off the generic object.
  Wire over docs, again.
- **All four quarantine record-type filters are accepted** `[live-measured 2026-07-23, #233]`:
  `quarantine`, `quarantineMetadata`, `teamsQuarantineMetadata`, `updateQuarantineMetadata`.
  A query carrying all four returned 201 and completed with real records.
  `teamsQuarantineMetadata` is the read-only route to **Teams** quarantine, which the
  Exchange Online transport cannot reach at `Security Reader` privilege.
- **`auditData.ExtendedProperties` contains an entry NAMED `RequestType` on ordinary AAD
  sign-in records** `[live-measured, #233]` (value `OAuth2:Authorize`). It is a list entry,
  not a top-level `auditData` key, so reading the field is correct — but an implementation
  that searched `ExtendedProperties` **by name** would stamp `request_type` on every
  sign-in in the tenant. The quarantine `RequestType` is a top-level integer enum and is
  **undocumented**: Microsoft publishes no member list, so graph2otel emits the raw number
  rather than a guessed label.

## Defender for Office 365 (MDO)

- **The "supported streaming event types" doc is WRONG on at least five rows**
  `[live-measured 2026-07-23, #241]`. Microsoft's
  [supported-event-types](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types)
  page lists **`BehaviorInfo` and `BehaviorEntities` as "Not available"** in every cloud — they
  are streaming to this tenant's storage account right now (`defender.behavior` /
  `defender.behavior_entity`). The same table **omits `IdentityInfo`, `MessageEvents` and
  `MessageUrlInfo` entirely**, all three of which are also streaming. Anyone who checks that page
  before proposing a table will reject buildable ones. This is the wire-over-docs rule landing on
  a page nobody had checked against the account: **enumerate the storage account's containers, not
  the doc.** (This also cleared #233's blocker: `MessageEvents` was recorded as having "never held
  a single row" — the container exists now.)
- **`security/collaboration/analyzedEmails` SILENTLY IGNORES its date parameters**
  `[live-measured 2026-07-23, #233]`. `startDateTime`/`endDateTime` are accepted, return
  HTTP 200, and change nothing: the response is a **~20-hour rolling window** whatever you
  ask for. `$filter`, `$count` and `$orderby` are all rejected outright. So there is no
  request that bounds this collection, and no metric can be defined over it with a stated
  window — which is why the Threat Explorer surface was evaluated for quarantine coverage
  and **rejected** in favor of `EmailPostDeliveryEvents` (a proper event with an action,
  trigger and result) plus the Exchange Online transport below. Re-open only if
  server-side filtering ships. Contrast the EXO section: that API *rejects* what it does
  not understand, which is a materially better contract to build on.
- **`EmailPostDeliveryEvents` is the only signal that shows a message MOVING into or out
  of quarantine.** `EmailEvents.DeliveryLocation` records where a message landed at
  delivery time and never mentions it again; the post-delivery table records ZAP, manual
  and automated remediation, and redelivery. Both key on `NetworkMessageId`. See
  [signals.md](signals.md#quarantine-one-dataset-across-four-transports).

## Exchange Online admin API (quarantine, MDO policy)

Not Graph. A fourth first-party API (`outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand`)
running PowerShell cmdlets app-only, and the **only** route to quarantine queue depth and MDO
policy state — neither has any Graph endpoint. Client: `internal/exoclient`. The `beta` in the
path is Exchange's own segment, **not** a Graph beta surface, so the
[api-drift.md](api-drift.md) canary does not apply to it.

- **It needs TWO grants and neither alone does anything** `[live-measured 2026-07-23, #233]`.
  Measured progression: **401** with neither → **403** with the app role only → **200** with
  both.
  - App role **`Exchange.ManageAsApp`** (`dc50a0fb-09a3-484d-be87-e023b12c6440`) on the
    *Office 365 Exchange Online* service principal (`01deb58a-8c47-4d14-888c-84c4a7844905`)
    — authentication. That SP exposes three near-identical roles
    (`Exchange.ManageAsApp`, `Exchange.ManageAsAppV2`, `Exchange.AdminAPI.ManageAsApp`);
    only the first is correct.
  - An Entra **directory role** on the service principal — authorization. `Security Reader`
    is the least-privileged sufficient one. This is the unusual half: a directory-role
    assignment is a portal action, not something scope consent can grant, so no amount of
    app-role work will move a 403.
- **A 403 body may not be JSON at all** `[live-measured 2026-07-23, #233]`. An unauthorized
  or unknown cmdlet answers 403 with a long run of NUL bytes. A JSON-only client panics or
  reports a decoder error on what is the **single most likely production failure** (a
  missing directory role). Treat non-JSON as an expected branch.
- **The useful error text is buried; `error.message` is always `"Invalid Operation"`**
  `[live-measured]` — on every failure, regardless of cause. Resolve in this order:
  `error.innererror.internalexception.message` → `error.details[0].message` (strip its
  leading `|Dotted.Type.Name|` prefix) → `error.message`. The unwrapped text is genuinely
  good: an invalid enum value returns the complete list of valid members, which is the
  cheapest way to discover an enum.
- **PowerShell PREFIX-MATCHES enum values, so a wrong value returns 200 with zero rows**
  `[live-measured 2026-07-23, #233]`. `QuarantineTypes=File` "worked" only by
  prefix-matching `FileTypeBlock`. A collector hard-coding a plausible-but-wrong value gets
  a clean 200 and permanently empty results. **Validate against the enum list, never
  against a 200.** The authoritative `QuarantineTypes` members, from the error body:
  `Spam, TransportRule, Bulk, Phish, HighConfPhish, Malware, SPOMalware,
  DataLossPrevention, FileTypeBlock, AdminTriggered, PPI`. Note `Email`, `TeamsMessage` and
  `SharePointOnline` are **not** members — those are `EntityType` values, a different
  parameter.
- **`PageSize=0` returns HTTP 200 with zero rows** rather than erroring `[live-measured]`.
  A zero-valued config is therefore permanent silence indistinguishable from an empty
  result. `PageSize=1001` is *accepted* rather than clamped or rejected; 1000 is the
  documented maximum and the real ceiling is **`[unmeasured]`** (the test tenant held 2
  messages). Paging is `Page`/`PageSize`, **1-indexed**, with no total count and no
  next-link — a short page is the only termination signal.
- **What it DOES reject, it rejects loudly** `[live-measured]`: an unknown parameter name
  → 400 `AmbiguousParameterSetException`; an invalid enum value → 400. And unlike
  `analyzedEmails` above, **`Get-QuarantineMessage`'s `StartReceivedDate`/`EndReceivedDate`
  genuinely filter server-side** — a future start returns 0 rows, a past end returns 0 rows,
  and a boundary inside the data splits it correctly.
- **`-EntityType` is denied to `Security Reader`** `[live-measured 2026-07-23, #233]`:
  `Teams`/`Email`/`SharePointOnline` → **403** (`File` → 400). The entity-scoped view is
  the documented route to quarantined **Teams** messages, so those are unreachable at
  read-only privilege — consistent with their `AdminOnlyAccessPolicy` tag. Do not send the
  parameter at all; the response carries `EntityType` on each row regardless.
- **`ReleaseStatus=NOTRELEASED` is the queue-depth query** `[live-measured]` — held only,
  filtered server-side, so no client-side filtering is needed. `RELEASED` and `NOTRELEASED`
  returned complementary sets on the test tenant, which is what proves it filters rather
  than being ignored.
- **A quarantine row's `Identity` is `<NetworkMessageId>\<recipient-guid>`.** Split on the
  backslash to recover the join key onto every other quarantine signal.

## Intune

- **`managedDevices` has no `$count` segment** `[live, M4]` — HTTP 400 `"No OData route
  exists"` (its backend is DeviceFE, not the directory OData stack), and
  `operatingSystem` is not server-filterable. Page the full collection with a trimmed
  `$select` and bucket client-side — the deliberate exception to "never page the full
  collection". The walk is irreducible **by design**: the per-device log twins ARE the
  deliverable (a bounded count cannot replace them; also `managedDeviceOverview`'s OS
  summary sums to 9 on a real fleet of 10 — no Linux bucket). #132 tracks the one
  possible retirement route (blob inventory categories).
- **A 400/404 "not found for segment" is a WRONG-URL bug, not "feature not provisioned"**
  `[live-measured 2026-07-18, #179]`. This corrects an earlier M4 reading. A valid Intune
  segment returns 200 (with `insufficientData` / empty on an immature tenant), never a
  segment-404 — so a `ResourceNotFound` / "not found for segment" naming a route segment
  means graph2otel asked for a URL that does not exist. Surface it **loudly**; do not skip
  it. Swallowing it as a tenant gap hid two dead UXA URLs for the life of the collector
  (below). Only a genuine **403** (not licensed/permitted) is a quiet skip. (Variant:
  `exchangeConnectors` → 501 `NotSupported`.)
- **User Experience Analytics (UXA / Endpoint Analytics) surface** `[live-measured
  2026-07-18, #179]`: there is **no tenant-wide overview singleton** — `userExperience
  AnalyticsOverview` 400s on both v1.0 and beta (segment removed); use the per-device
  `userExperienceAnalyticsDeviceScores` (v1.0) for the score signal. Startup history is
  **singular** `userExperienceAnalyticsDeviceStartupHistory` (the plural `…Histories`
  400s). `batteryHealthDevicePerformance` and `resourcePerformance` are **beta-only** (400
  on v1.0). Device scores use **`-1` as a "not enough data" sentinel**, not a real 0-100
  value — exclude it from score aggregates.
- **A UXA score has TWO ways of saying "no score", and only one of them is the `-1` sentinel**
  `[live-measured 2026-07-24, #194]`. The other is the field simply **not being on the wire**.
  `meanResourceSpikeTimeScore` was present and `100.0` on a `ModelScores` row in the morning
  and had vanished from the same row that afternoon, with no other change. In Go a plain
  `float64` turns that omission into `0`, which sails through a `>= 0` sentinel guard and
  publishes an entity scoring **zero** on a category it was never assessed on — worse than the
  `-1` the guard was written to catch, because nothing is left on the wire to filter. **Score
  fields on these segments must be `*float64`**; `nil` means never mentioned. Caught by
  deploy-verification against Grafana Cloud, not by any test — the fixture had the field.
- **What gates a UXA ROLLUP segment being published is UNKNOWN — it is not device count**
  `[live-measured 2026-07-24, #194/#199]`. Microsoft documents a five-device "insufficient
  data" floor for Endpoint Analytics scores, and the empty rollup segments were read through
  that lens for a week: `ModelScores` was recorded as needing "≥5 scored devices sharing one
  model string", `DeviceStartupProcessPerformance` as needing boot telemetry from more than
  one device. Both readings are refuted by the same day's wire:
  - `ModelScores` published a bucket with **`modelDeviceCount: 1`** while a **five**-device
    model bucket that existed on the same tenant that day was absent — the exact inverse of
    the theory.
  - `DeviceStartupProcessPerformance` stayed at 0 rows after boot telemetry went from 3
    records across 2 devices to 11 across 6, and scored devices from 4 to 10.

  The documented floor is real for the *score* Microsoft computes; it does not explain which
  rollup rows get published. **Do not attach a device-count unblock condition to an empty UXA
  rollup** — it will read as testable, pass, and change nothing. The per-device siblings
  (`DeviceScores`, `DeviceStartupProcesses`, `ResourcePerformance`) return rows on a tiny
  tenant and are the reliable source; the rollups are opportunistic.
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
- **Retention labels are app-only-blocked, but `security/labels` blocking is per-COLLECTION,
  not per-root** `[live 2026-07-16 #109/#126; re-measured 2026-07-23 #237]`: on
  `RecordsManagement.Read.All`, `authorities` (3 rows), `categories` (13), `citations` (5),
  and `filePlanReferences` (0) all return **200**; only `/security/labels/retentionLabels`
  and `/security/labels/departments` 500 `DataInsightsRequestError` + "Forbidden" (documented
  Application: Not supported). `purview/retentionlabels.isRetentionUnavailable` must match that
  **specific** signature — a generic 500 must still surface, and a sensitivity-label 403 must
  fail the collector (#126 residual).
- **DLP policy state IS readable app-only** `[live-measured 2026-07-23, #237]` — this was
  previously (wrongly) recorded as having no API.
  `GET /beta/security/dataSecurityAndGovernance/policyFiles` returns the full DLP policy set on
  scopes the poller already holds (no grant, no data-plane registration): id `DlpPolicy` with
  `content` = base64 of **UTF-16LE** XML (6 policies / 8 rules; per-policy `mode`
  Enforce/AuditAndNotify; per-policy workload bindings; per-rule actions). v1.0 400s
  (`policyFiles` is not a segment there); beta only. #246 builds it. The earlier "the Purview
  Ecosystem API's app-only roles evaluate content against policy, never enumerate it" was true
  of the #99 Ecosystem roles and is **false of Graph's `dataSecurityAndGovernance`**.
- **Retention policy *bindings* remain S&C-PowerShell-only** `[live, #99]` — only DLP fell,
  not the pair. Retention label and sensitivity-label *definitions* ARE Graph-exposed.
- **eDiscovery is the counter-example to "403 = missing scope"** `[live-measured
  2026-07-17, #102/#148]`: `eDiscovery.Read.All` granted and in the token still 401'd.
  No Graph scope fixes it — the data plane simply did not know the principal. Registering
  it Purview-side via S&C PowerShell (`New-ServicePrincipal` + `Add-RoleGroupMember
  eDiscoveryManager` + `Add-eDiscoveryCaseAdmin`) moved `security/cases/ediscoveryCases`
  from 401 to **200 on the first probe**, no replication wait. So **401 with the scope
  present means a missing data-plane registration, not a missing scope** — a different
  failure from the 403 above, and the reason to verify rather than infer. The procedure
  is [`data-plane-registration.md`](data-plane-registration.md).

### Four app-only refusal signatures on the Purview/security surface — they mean different things

Observed in one session on this surface `[live-measured 2026-07-23, #237]` and routinely
conflated. The status code alone is not the verdict; the body is:

| signature | meaning |
| --- | --- |
| `500 DataInsightsRequestError` / "FAILED - Forbidden" | Purview DataInsights backend refuses app-only for that collection. No scope or shape moves it — this is a genuine per-collection gap |
| `403 InsufficientGraphPermissions` (JSON) | Graph gateway; normally grantable — but check the app role actually exists first |
| `403` HTML from `Microsoft-Azure-Application-Gateway/v2` | not a Graph error; the delegated-only signature. A JSON-only client fails to decode it (and see the intermittent-`UnknownError` gotcha — an HTML 403 also arrives wrapped in `{"code":"UnknownError"}`; retry before recording a verdict) |
| `401 ServiceFabricGraphAuthenticationMiddleware.ValidateToken` | data-plane registration missing (#102) — can appear on a sub-resource of a case whose parent is served fine |

Two that are **not** refusals: `500 HostNotFound` and `404 TenantDeploymentNotFound` mean the
backend service is not provisioned for the tenant. Do not record those as gaps.

## Permanent gaps and the fallback path

Signals with **no API anywhere** (re-audited against the non-Graph first-party surface,
`[live 2026-07-16, #130 audit]`): `EnrichedOffice365AuditLogs` (Sentinel-side synthesis),
`ADFSSignInLogs`, Intune `OperationalLogs` (fired-alert stream; Graph has only the
templates; the dedicated Intune API `0000000a-…` exposes **zero app-only roles** and
`api.manage.microsoft.com` is NXDOMAIN — no grant can ever unblock it), retention policy
bindings.

> **Correction (`live-measured 2026-07-23, #237`):** "DLP policy enumeration" was previously
> listed here as having no API. It is readable app-only via
> `GET /beta/security/dataSecurityAndGovernance/policyFiles` (see the Purview / labels section
> above); #246 builds it. Only retention policy *bindings* remain a genuine gap.

Intune `OperationalLogs` is a **Graph** gap only: its diagnostic-settings blob container
`insights-logs-operationallogs` now carries a live fired-alert sample on the verification
tenant `[live-measured 2026-07-18, #171]`, so it is buildable via the blob escape hatch
below even though Graph never exposes it.

Corrected non-gaps: `NetworkAccessTrafficLogs` has a beta endpoint that names its own
scope (#130); Purview sensitivity labels (#126).

**Reachable but never populated on the verification tenant** — a different class from the
above: the endpoint works, the tenant has nothing to report, and no realistic tenant change
produces a row. Mapping against zero rows is the blind mapping this project forbids, so these
are recorded rather than left on an open issue behind an unblock condition that cannot fire
`[live-measured 2026-07-22 → 2026-07-24, #199]`:

| segment | status | why it stays empty |
| --- | --- | --- |
| `userExperienceAnalyticsDevicesWithoutCloudIdentity` | beta `200`, 0 rows (v1.0 `400`) | an **exception list** — empty is the healthy answer |
| `userExperienceAnalyticsNotAutopilotReadyDevice` | beta `200`, 0 rows (v1.0 `400`) | same, and the tenant has **zero** Autopilot device identities and zero deployment profiles (#201), so it stays empty at any fleet size |
| `userExperienceAnalyticsDeviceStartupProcessPerformance` | `200` + `"@odata.count":0` on **both** versions | **unknown.** Five separate explanations were tested and every one was refuted — see below |

The first two were re-probed on three separate days across a fleet that grew 10 → 17 devices,
with the request shape varied (bare / `$orderby` / `$select`) each time. If a tenant with
Autopilot registrations ever appears, this entry is the pointer back.

**`DeviceStartupProcessPerformance` is in this table for a different reason, and it is worth
reading before anyone re-opens it.** It is the fleet-wide per-process rollup of
`userExperienceAnalyticsDeviceStartupProcesses`, whose per-device sibling ships as
`intune.device_startup_process` and returns rows. These are the five theories that were
tested and killed, so that none of them is proposed a sixth time:

1. **Device count / the documented five-device EA floor** — refuted: `ModelScores` published a
   bucket with `modelDeviceCount: 1` while a five-device bucket on the same tenant was absent.
2. **Insufficient boot telemetry** — refuted: startup history went 3 records/2 devices → 11/6,
   and scored devices 4 → 10. The segment did not move. This condition was chosen *because* it
   was testable; it fired and changed nothing.
3. **A malformed request** — refuted: bare, three numeric `$filter`s, two `$orderby`s,
   `$select`, `Prefer: odata.maxpagesize`, single-entity and `/$count`, on both versions.
4. **The per-process input only exists on one device** — refuted: the input exists on
   **7 devices / 27 (device, process) rows**; a rollup over it would trivially yield rows.
5. **A model-keyed aggregation axis being broken** — the `summarizeDevicePerformanceDevices`
   function accepts only `model` (`200`, 0 rows); `none`, `allRegressions`, `modelRegression`,
   `manufacturerRegression` and `operatingSystemVersionRegression` all `400` with the same
   backend error as the five UXA segments that return `500`. The summarize path is broadly
   non-functional here, so it explains nothing specific to this segment.

The handler itself is demonstrably real and model-faithful: `$select=bogusProperty` returns an
EDM-aware `400` naming the type, `$filter` is accepted on exactly the three properties the EDM
annotates as filterable and rejected on the three it does not, and the binding is an ordinary
`ContainsTarget` collection nav identical in kind to the populated siblings. There is no
`summarize` function for startup processes and none of the 77 `deviceManagementReports`
actions touches this data, so the async export API is not an alternate route.

**Do NOT attach an unblock condition to this segment.** Four of the five theories above were
recorded at the time as confident, reasoned verdicts, and each cost a probing round to undo.
Re-probe it opportunistically if something else brings you back to this collector.

> **#130 deferral has FIRED (`live-measured 2026-07-23, #239`).** The condition was "out of
> scope until a GSA tenant exists" — a GSA tenant now exists: `GET /beta/networkAccess/tenantStatus`
> → `200 {"onboardingStatus":"onboarded"}`. GSA POSTURE (tenantStatus, forwardingProfiles,
> filteringPolicies, the two settings objects) is readable on `Policy.Read.All` today, no grant.
> GSA TRAFFIC LOGS (`/beta/networkAccess/logs/traffic`) still 403 — needs a `NetworkAccess.Read.All`
> (or `NetworkAccess-Reports.Read.All`) grant; response shape unmeasured, mapper unwritten until the
> grant lands. Both pieces tracked on #239.

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

## PIM role-management alerts (`identityGovernance/roleManagementAlerts`)

**The `$filter` is MANDATORY, and its absence lies about why** `[live-measured 2026-07-24, #256]`.
A bare list of any of the three segments answers:

```
GET /beta/identityGovernance/roleManagementAlerts/alerts
400 {"errorCode":"MissingProvider","message":"The provider is missing.","instanceAnnotations":[]}
```

That reads like PIM not being provisioned on the tenant, or the segment not existing. It is
neither — the scope filter is not an optimization on this surface, it is part of the request:

```
?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'
```

With it, all three of `alerts`, `alertDefinitions` and `alertConfigurations` answer `200` with 7
rows each. The wire-verified URL encoding is `?$filter=scopeId+eq+'/'+and+scopeType+eq+'DirectoryRole'`
(spaces as `+`, quotes and slash literal) — the same encoding `entra/pimrolepolicies` uses on the
identically shaped `roleManagementPolicies` filter. Same class as the Intune EA `$top` that is
rejected at every value: a query parameter whose absence produces an error naming something else.

**`v1.0` has no `roleManagementAlerts` segment at all** (`400`), so the surface is beta-only →
`Experimental` (#183).

**`alertIncidents` is not reachable**: `400 Resource not found for the segment 'alertIncidents'`
even with the filter present. `incidentCount` on the alert row is therefore the finest granularity
this surface offers — the flagged entities themselves cannot be enumerated by this route, and
nothing should promise them.

**`lastModifiedDateTime` is the .NET zero date `0001-01-01T08:00:00Z`** on every alert that has
never fired. It means ABSENT, not "modified in year 1" — drop it rather than emit it
(the absent-vs-sentinel rule). `lastScannedDateTime` is always real.

**The alert id embeds the tenant GUID** (`DirectoryRole_<tid>_StaleSignInAlert`), so the raw id is
per-tenant cardinality and can never be a metric label; the stripped type suffix is a bounded
catalog and is. `alertDefinitionId` is byte-identical to the row's own `id` on all three segments,
so it is a join key, not a second field worth emitting.

**No P2 licence is needed to READ the alerts.** The verification tenant holds no Entra ID Premium
P2 and still got `200` + 7 rows — one of which is Microsoft's own `InvalidLicenseAlert`,
`severityLevel: high`, saying so. What the licence bounds is what the other six alerts can ever
report, not whether the endpoint answers.
