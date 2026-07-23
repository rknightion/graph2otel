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

- **`security/collaboration/analyzedEmails` SILENTLY IGNORES its date parameters**
  `[live-measured 2026-07-23, #233]`. `startDateTime`/`endDateTime` are accepted, return
  HTTP 200, and change nothing: the response is a **~20-hour rolling window** whatever you
  ask for. `$filter`, `$count` and `$orderby` are all rejected outright. So there is no
  request that bounds this collection, and no metric can be defined over it with a stated
  window — which is why the Threat Explorer surface was evaluated for quarantine coverage
  and **rejected** in favour of `EmailPostDeliveryEvents` (a proper event with an action,
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

Intune `OperationalLogs` is a **Graph** gap only: its diagnostic-settings blob container
`insights-logs-operationallogs` now carries a live fired-alert sample on the verification
tenant `[live-measured 2026-07-18, #171]`, so it is buildable via the blob escape hatch
below even though Graph never exposes it.

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
