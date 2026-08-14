---
id: doc-0003
title: Closed GitHub issues (pre-Backlog history index)
type: other
created_date: '2026-08-14 16:28'
updated_date: '2026-08-14 16:36'
---
> **Historical index of work tracked on GitHub Issues before this repo moved to Backlog.md on
> 2026-08-14.** The issues themselves were **deleted from GitHub** on that date, so `gh issue view
> <N>` will 404. Their full bodies and all 920 replies are archived in
> `archive/github-issues-2026-08-14.json` — that file is the record, this table is the index into it.
> The load-bearing detail (closing decisions, corrections, live-measured evidence) is in the
> comments, so read the archive, not just this table:
>
> ```sh
> jq '.[] | select(.number == 374)' archive/github-issues-2026-08-14.json
> ```
>
> The archive is redacted — GUIDs, two UPNs, a device name, a public IP and the telemetry backend's
> host and stack id were replaced with stable placeholders. `archive/README.md` has the mapping and
> explains why the redaction is deliberately narrow.

**Why these were not imported as tasks.** Backlog IDs follow creation order, so an imported task
could never carry the number the history already cites. `AGENTS.md`, the reference docs under
`docs/`, the commit log and code comments all reference this work as `#NNN`; keeping the GitHub
numbers as the only ID space over this history is what keeps those references resolvable. Four
hundred `Done` rows would also drown the board's only real signal — what is left. **Cite closed work
as `#NNN`; cite new work as `GTO-NNNN`.**

**The commits column is every commit whose message cites the issue**, newest first, capped at three.
It is a lead, not a verdict: a commit may cite an issue it only touches, and a squashed or un-citing
commit leaves the column empty. 350 of 402 rows resolved to at least one commit.

`~` in the outcome column marks an issue closed as **not planned** (39 of 402) —
it records a decision *not* to do something, which is usually the more expensive fact to re-derive.

One issue is **not** in this table: `#78`, Renovate's Dependency Dashboard, which is still open on
GitHub and is recreated by Renovate on every run.

| # | closed | outcome | title | commits |
| --- | --- | --- | --- | --- |
| 426 | 2026-08-10 |  | Detection: exclude Entra 50097 from the CA-failure limb of g2o-detect-interactive-signin-anomaly | `197718b` |
| 425 | 2026-08-10 |  | Blob collectors re-list every 5 minutes from 11 duplicated constants; the listing is billed and buys no freshness | `00d6227` |
| 423 | 2026-08-10 |  | Microsoft Graph beta drift on consumed operations | `805a9f5` |
| 422 | 2026-08-10 |  | Self-obs: a livelocked collector is still invisible — nothing watches the #417 fingerprint | `1e952db` |
| 421 | 2026-08-06 |  | Self-obs: no alert on OTLP export failures — every backend rejection class is unwatched | `71eb181` |
| 420 | 2026-08-06 |  | Self-obs: no alert on either data-loss counter (over_horizon, attrs_truncated) | `9b15523` |
| 419 | 2026-08-06 |  | Log records silently lost: structured metadata exceeds Loki's 64 KiB limit, batch rejected with HTTP 400 | `71eb181`, `9b15523`, `864e6c6` |
| 418 | 2026-08-06 |  | sign_in_event_types is never set on v1.0-polled interactive sign-ins (beta-only property) | `6215b4f` |
| 417 | 2026-08-06 |  | Cold-start target never clears: 8 window collectors livelocked on one 15-minute window for 11 days | `1e952db`, `c47ee47` |
| 413 | 2026-08-04 |  | fix(ci): grafana-sync silently pushes nothing — gcx emits JSON only in agent mode, so every push reports 0/0 | `912fca0`, `fc5cb94` |
| 408 | 2026-08-04 |  | fix(selfobs): a correctly-handled tenant-entitlement 403 still ratchets scrape staleness, paging critical forever | `a6b0038` |
| 406 | 2026-08-01 |  | g2o-collector-staleness: 10m pending window so a firewall reboot doesn't page | `7b04434` |
| 405 | 2026-07-29 |  | Publish the dashboard and alert rules to the m7kni stack from CI | `7ef1aa6` |
| 404 | 2026-07-28 |  | docs: record why no log attribute here can be promoted to a Loki index label | `0811619` |
| 403 | 2026-07-27 |  | fix(ci): internal/annotations hangs for the full 10-minute timeout in the coverage job | `31a30ec` |
| 402 | 2026-08-04 |  | feat(telemetry): add a bounded event_domain resource attribute so the single hot log stream can be split | `82d0f92`, `3cbd879` |
| 401 | 2026-07-27 |  | fix(ingest): never emit a record older than the backend accept window — clamp to 165h | `9b15523`, `b4fcaec` |
| 400 | 2026-07-27 |  | feat(annotations): publish curated domain events to Grafana annotations via an operator-supplied service account | `7f977e3`, `186b981` |
| 399 | 2026-07-27 |  | feat(dashboards): make Grafana v2 dynamic dashboard capabilities first-class | `96d3ebf`, `97e08b6`, `855acef` |
| 398 | 2026-07-27 |  | fix(startup): resolve live Intune export failures and wire-value drift | `99623a9` |
| 397 | 2026-07-27 |  | fix(intune.updates): decode live feature-profile endOfSupportDate | `2cdd71e` |
| 396 | 2026-07-27 |  | fix(telemetry): classify intentional unavailable sub-fetches correctly | `2cdd71e` |
| 395 | 2026-07-27 |  | investigate production degradation in Intune and Purview collectors |  |
| 389 | 2026-07-27 | ~ | feat(replay): add mutable-state MDCA discovery replay adapter |  |
| 388 | 2026-07-27 | ~ | feat(replay): add fail-closed Exchange message-trace replay adapter |  |
| 387 | 2026-07-27 | ~ | feat(replay): add O365 Activity arrival-clock replay adapter |  |
| 386 | 2026-07-27 | ~ | feat(replay): add immutable Azure blob replay adapter |  |
| 385 | 2026-07-27 | ~ | feat(replay): deliver sealed replay spools over OTLP |  |
| 384 | 2026-07-27 | ~ | feat(replay): add Graph window and unified-audit query adapters |  |
| 383 | 2026-07-27 | ~ | feat(replay): add descriptor-gated isolated local replay core |  |
| 382 | 2026-07-27 | ~ | tracker(replay): implement deterministic isolated replay workflow |  |
| 380 | 2026-07-26 |  | fix(docs): reconcile operator documentation with the shipped v1.0.0 surface | `3c09e42` |
| 379 | 2026-07-27 | ~ | epic(post-v1): syslog, flow-log, and portable SIEM integrations |  |
| 378 | 2026-08-04 |  | epic(post-v1): M365, Exchange, Defender for Office, MDCA, and backup coverage |  |
| 377 | 2026-08-04 |  | epic(post-v1): Intune, Windows 365, and Defender endpoint coverage |  |
| 376 | 2026-08-04 |  | epic(post-v1): Entra governance, Purview, and secure-access coverage | `d4293c8` |
| 375 | 2026-07-27 |  | epic(post-v1): operational Grafana dashboards, alerts, rules, and investigations | `cf8932b`, `d94458b` |
| 374 | 2026-07-26 |  | epic(post-v1): runtime correctness, ingest integrity, and operator safety |  |
| 373 | 2026-07-27 | ~ | feat(integrations): publish OCSF and ECS mapping packs for graph2otel logs |  |
| 372 | 2026-07-27 | ~ | spike(integrations): design an explicit-storage VNet flow-log companion |  |
| 371 | 2026-07-27 | ~ | feat(integrations): ship a supported syslog and CEF companion configuration |  |
| 370 | 2026-07-29 |  | spike(purview): validate a secret-safe Audit.DLP.All mapper on a deliberate match | `28364a5`, `df24b9f` |
| 369 | 2026-07-28 | ~ | spike(m365): assess Microsoft 365 Backup protection and job health |  |
| 368 | 2026-07-28 |  | spike(m365): assess serviceActivity operational telemetry | `0811619` |
| 367 | 2026-07-27 |  | feat(m365): emit deduplicated service-health update posts | `a936984`, `2483dd4` |
| 366 | 2026-07-28 | ~ | spike(purview): assess DataSecurityEvents advanced-hunting sharing |  |
| 365 | 2026-07-28 | ~ | spike(defender): prove CampaignInfo availability and volume |  |
| 364 | 2026-07-28 | ~ | spike(m365): measure Teams call-record volume and late-version behavior |  |
| 363 | 2026-07-28 |  | spike(m365): prove least-privilege app-only inbox-rule inventory | `a936984`, `fed98f8` |
| 362 | 2026-07-28 |  | feat(m365): collect daily collaboration activity reports | `f7745e8` |
| 361 | 2026-07-28 |  | spike(mdca): collect discovered cloud-app risk and traffic inventory | `f7745e8` |
| 360 | 2026-07-28 | ~ | spike(m365): collect private and shared Teams channel membership |  |
| 359 | 2026-07-28 |  | feat(m365): collect mailbox usage, quota state, and inactivity | `04653d2` |
| 358 | 2026-07-28 |  | spike(defender): collect connection-filter allow and block posture | `4ca32f7` |
| 357 | 2026-07-28 |  | spike(defender): collect outbound-spam policy and rule posture | `4ca32f7` |
| 356 | 2026-07-28 |  | spike(m365): collect mailbox audit-bypass associations | `04653d2` |
| 355 | 2026-07-28 |  | spike(m365): collect FullAccess and SendAs mailbox delegation | `a936984`, `fed98f8` |
| 354 | 2026-07-28 |  | spike(defender): collect MDO policy assignment, exclusions, and precedence | `4ed2c00` |
| 353 | 2026-07-27 |  | feat(m365): collect Exchange accepted-domain posture | `2483dd4` |
| 352 | 2026-07-28 |  | spike(intune): complete the diagnostic-settings census with subscription RBAC | `8296010` |
| 351 | 2026-07-28 |  | feat(intune): add per-device feature-update outcome twins | `0811619` |
| 350 | 2026-07-28 |  | spike(defender): scope a bounded Exposure Graph collector | `4ed2c00` |
| 349 | 2026-07-28 | ~ | spike(defender): ingest DisruptionAndResponseEvents without history replay |  |
| 348 | 2026-08-10 |  | spike(intune): assess Endpoint Analytics anomaly detail and affected devices |  |
| 347 | 2026-07-28 | ~ | spike(intune): extend Windows Updates with quality policies, rings, approvals, and compliance changes |  |
| 346 | 2026-07-28 | ~ | spike(intune): collect Cloud PC inaccessible-device and regional quality reports |  |
| 345 | 2026-07-28 | ~ | spike(intune): collect Cloud PC connectivity and health-check events |  |
| 344 | 2026-07-28 | ~ | spike(intune): collect Cloud PC lifecycle and network-connection health |  |
| 343 | 2026-07-27 |  | fix(intune): classify iosDeviceFeaturesConfiguration instead of folding it into other |  |
| 342 | 2026-07-27 |  | fix(intune): map live CertificateStatus Issued as healthy |  |
| 341 | 2026-07-27 |  | fix(entra): add the live insiderRiskPolicy recommendation type to wirecheck |  |
| 340 | 2026-08-04 | ~ | spike(entra): map PreAuthenticationDiscoveryLogs after the first real sample |  |
| 339 | 2026-08-04 | ~ | spike(entra): map MicrosoftGraphPolicyLogs after the first real sample |  |
| 338 | 2026-07-29 |  | spike(entra): validate and collect Global Secure Access traffic telemetry | `4fce107` |
| 337 | 2026-07-27 |  | feat(entra): add an allowlisted privileged-group member-count gauge | `099ba59`, `2483dd4` |
| 336 | 2026-07-29 |  | spike(entra): assess Tenant Governance related-tenant discovery | `e627e02` |
| 335 | 2026-07-29 | ~ | spike(core): assess Tenant Configuration Management drift monitoring |  |
| 334 | 2026-07-28 |  | spike(entra): assess Entra Backup and Recovery protection health | `a467c3e` |
| 333 | 2026-07-28 |  | spike(entra): collect Agent ID blueprint and agent governance posture | `e627e02`, `d4293c8` |
| 332 | 2026-07-28 | ~ | spike(defender): assess user-reported email threat submissions |  |
| 331 | 2026-07-28 | ~ | spike(defender): assess attack-simulation outcomes and training completion |  |
| 330 | 2026-07-28 | ~ | spike(purview): assess retention-event propagation health |  |
| 329 | 2026-07-28 | ~ | spike(entra): find a bounded PIM for Groups assignment inventory |  |
| 328 | 2026-07-28 | ~ | spike(entra): collect Entitlement Management request and approval flow |  |
| 327 | 2026-07-28 | ~ | spike(entra): collect Entitlement Management package and assignment posture |  |
| 326 | 2026-07-28 | ~ | spike(entra): collect Lifecycle Workflows execution health |  |
| 325 | 2026-07-28 | ~ | spike(entra): assess administrative units and scoped role assignments |  |
| 324 | 2026-07-28 | ~ | spike(entra): assess authentication-context inventory and policy linkage |  |
| 323 | 2026-07-28 |  | feat(purview): collect eDiscovery hold, custodian, and operation health | `863faa7` |
| 322 | 2026-07-28 |  | feat(entra): collect authentication-strength policy posture | `4fce107`, `d4293c8` |
| 321 | 2026-07-28 |  | feat(entra): collect cross-tenant access trust posture | `d4293c8` |
| 320 | 2026-07-28 |  | feat(entra): inventory custom directory-role definitions and granted actions | `d4293c8` |
| 319 | 2026-07-28 |  | feat(entra): collect access-review instance and decision progress | `0811619` |
| 318 | 2026-07-28 |  | feat(entra): emit Conditional Access policy and named-location state twins | `04653d2` |
| 317 | 2026-07-28 |  | feat(entra): emit authentication-method policy configuration twins | `04653d2` |
| 316 | 2026-07-26 |  | fix(entra): emit the missing service-principal ownership twin | `04bb058` |
| 315 | 2026-07-27 |  | fix(entra): stop fabricating zero recommendation impact and emit state twins | `2483dd4` |
| 314 | 2026-07-26 |  | fix(gate): include Grafana assets in the documented full local check | `98fc188` |
| 313 | 2026-07-27 |  | feat(security): ship a curated detection and hunting content pack | `d40d0a4`, `77810ce` |
| 312 | 2026-07-26 |  | feat(dashboard): add an executive health and data-loss summary to self-observability | `b6efee6` |
| 311 | 2026-07-27 |  | feat(dashboards): add a cross-domain graph2otel landing dashboard | `97e08b6` |
| 310 | 2026-07-27 |  | feat(dashboards): annotate graph2otel deploys, versions, and configuration changes | `8c80228` |
| 309 | 2026-07-27 |  | perf(dashboards): add a generated query and render performance budget | `cf8932b`, `5fb7873`, `96d3ebf` |
| 308 | 2026-07-27 |  | feat(gate): run semantic PromQL and LogQL smoke tests against a real backend | `860eb40`, `8a9d4b3` |
| 307 | 2026-07-27 |  | feat(alerting): add clickable runbooks, dashboard context, and annotation linting | `2189448`, `e75d76d`, `c837527` |
| 306 | 2026-07-27 |  | feat(gate): validate every LogQL filter and group key against the signal catalog | `77810ce` |
| 305 | 2026-07-27 |  | feat(grafana): generate entity-centric investigation pivots | `186b981`, `77810ce` |
| 304 | 2026-07-27 |  | fix(dashboards): generate honest units, titles, mappings, and thresholds | `e75d76d`, `0ee422c` |
| 303 | 2026-07-26 |  | feat(dashboards): distinguish disabled, unavailable, healthy-empty, and failed signals | `97e08b6`, `ebba3c1` |
| 302 | 2026-07-27 |  | feat(dashboards): separate operational overviews from exhaustive signal explorers |  |
| 301 | 2026-07-26 |  | fix(dashboards): prevent silent cross-tenant aggregation | `ee7acec` |
| 300 | 2026-07-27 |  | chore(alerting): put production SIEM and legacy Entra rules under a reproducible source of truth | `d40d0a4`, `d94458b` |
| 299 | 2026-07-27 |  | fix(alerting): make collector staleness interval-aware | `2189448`, `f71cf6e` |
| 298 | 2026-07-26 |  | fix(alerting): stop treating rule evaluation errors as OK | `2189448`, `f71cf6e`, `55ff9ea` |
| 297 | 2026-07-27 |  | fix(recording-rules): preserve tenant identity and define late-arrival semantics | `00d6227`, `9b15523`, `b4fcaec` |
| 296 | 2026-07-27 |  | fix(alerting): route generated warning alerts to a deliberate receiver | `860eb40`, `1881eb2` |
| 295 | 2026-07-27 |  | fix(dashboards): select the intended Prometheus and Loki datasources by default | `855acef`, `2566636` |
| 294 | 2026-07-27 |  | fix(grafana): repair and test the HTTP provisioning workflow | `2189448` |
| 293 | 2026-07-27 |  | fix(alerting): stop the sample notification policy from owning the root route | `860eb40`, `1881eb2` |
| 292 | 2026-07-26 |  | feat(telemetry): emit collector availability and skip-reason state | `2074e01` |
| 291 | 2026-07-26 |  | perf(logpipeline): stream ordered endpoint pages instead of buffering full windows | `066c8aa` |
| 290 | 2026-07-25 |  | spike(ops): design a deterministic isolated replay and export workflow |  |
| 289 | 2026-07-26 |  | feat(ops): attribute volume and cost budgets per collector and transport | `468d4a0`, `6a97e7d` |
| 288 | 2026-07-25 |  | feat(telemetry): generate the complete self-observability signal catalog | `9f903b2` |
| 287 | 2026-07-25 |  | fix(docs): align backfill warnings with the measured seven-day rejection contract | `7bb3fe9` |
| 286 | 2026-07-25 |  | fix(packaging): make the standalone-container quickstart runnable and persistent | `7bb3fe9` |
| 285 | 2026-07-25 |  | fix(build): use one version source for the binary and build_info | `34d2f21` |
| 284 | 2026-07-25 |  | fix(telemetry): stamp tenant identity on process-level self-observability | `7bb3fe9` |
| 283 | 2026-07-25 |  | fix(graphclient): detect raw REST response-body overflow | `34d2f21` |
| 282 | 2026-07-25 |  | fix(blobpipeline): persist cursor changes caused only by blob deletion pruning | `34d2f21` |
| 281 | 2026-07-25 |  | fix(blobpipeline): fail loudly on an oversized record with no newline | `34d2f21` |
| 280 | 2026-07-25 |  | fix(transports): do not send one more request after retry cancellation | `34d2f21` |
| 279 | 2026-07-25 |  | fix(o365): recover subscriptions disabled after process startup | `34d2f21` |
| 278 | 2026-07-25 |  | fix(mdca): fail closed when discovery pagination reaches its cap | `34d2f21` |
| 277 | 2026-07-25 |  | fix(ingest): guard log and job pagination against repeated cursors and page loops | `34d2f21` |
| 276 | 2026-07-25 |  | fix(exportjob): bound SAS downloads by time and detect size overflow | `34d2f21` |
| 275 | 2026-07-25 |  | fix(ingest): drop event records with no parseable timestamp | `7bb3fe9` |
| 274 | 2026-07-25 |  | fix(exportjob): surface terminal job-state clear failures | `34d2f21` |
| 273 | 2026-07-25 |  | fix(jobpipeline): make terminal query checkpoint clears durable | `34d2f21` |
| 272 | 2026-07-25 |  | fix(blobpipeline): return a degraded tick after blob read or cursor-save failures | `34d2f21` |
| 271 | 2026-07-25 |  | fix(o365): do not advance the shared watermark past a pre-list failure | `34d2f21` |
| 270 | 2026-07-25 |  | fix(graphclient): enforce the valid-host allowlist for raw REST requests | `34d2f21` |
| 269 | 2026-07-25 |  | feat(telemetry): add end-to-end record outcome accounting | `f7339e8` |
| 268 | 2026-07-26 |  | feat(telemetry): expose real OTLP delivery health for metrics and logs | `d6d960d` |
| 267 | 2026-07-25 |  | feat(ops): add meaningful readiness and retain failed tenants in status | `6d0e195` |
| 266 | 2026-07-26 |  | fix(auth): make the authenticated application identity authoritative | `1b8069c` |
| 265 | 2026-07-26 |  | fix(config): reject unknown keys, collector names, and transport typos | `2277ba1` |
| 264 | 2026-07-25 |  | fix(preflight): validate permissions for the actual enabled collector set | `7bb3fe9` |
| 263 | 2026-07-25 |  | Deploy current generated Grafana dashboards and alert/recording rules to m7kni |  |
| 262 | 2026-07-25 |  | bug(jobpipeline): an empty record id is added to SeenIDs as "", so every later empty-id record in the window is silently deduped away | `0d4bd53` |
| 261 | 2026-07-24 |  | bug(intune.devices): the blob path lowercases CompliantState but the bucket map is camelCase — InGracePeriod and ConfigManager both land in 'other' | `3d129cb` |
| 260 | 2026-07-24 |  | feat(entra): entra.access_reviews — data exists despite the licence caveat, and one review is InProgress right now | `0811619`, `3d129cb` |
| 259 | 2026-07-24 |  | feat(intune): intune.windows_updates — WUfB deployment service is NOT empty here, contrary to the Phase 6 prediction | `3d129cb` |
| 258 | 2026-07-24 |  | feat(intune): intune.cloud_pki — a silently-expiring private CA is a fleet-wide auth outage, and nothing watches it | `3d129cb` |
| 257 | 2026-07-24 |  | feat(intune): intune.rbac — Intune's own role store is separate from Entra directory roles, and an Intune-custom-role admin is invisible today | `3d129cb` |
| 256 | 2026-07-24 |  | feat(entra): entra.pim_alerts — Microsoft's own pre-computed privileged-access findings, with their remediation text | `3d129cb` |
| 255 | 2026-07-24 |  | bug(intune.device_startup_process): the bare list serves ONE device — the collector emits 5 of 27 available rows and nothing signals the loss | `2ce5a77`, `3d129cb` |
| 254 | 2026-07-23 |  | feat(m365): m365.message_trace — per-message mail flow, keyset-paged, must ship off by default | `4fce107`, `f7745e8`, `0f9b5da` |
| 253 | 2026-07-24 |  | feat(m365): m365.exchange_connectors — the last #250 collector, blocked on a connector existing | `c2feef6`, `2800ef4` |
| 252 | 2026-07-23 |  | feat(defender): defender.oauth_app — OAuthAppInfo posture (the #249 deferred fourth) | `b4ed339` |
| 251 | 2026-07-25 |  | epic: coverage-gap program — 6-lane live-tenant research, 3 tracker corrections, 1 production defect, 4 tiers of new coverage | `3d129cb`, `9721555`, `27c2258` |
| 250 | 2026-07-23 |  | feat(m365/defender): Exchange Online posture pack — 8 collectors on the shipped EXO engine, no new transport, no new grant | `85ae23f`, `702a395`, `9b51997` |
| 249 | 2026-07-23 |  | feat(defender): hunting-query engine + DeviceTvm* coverage — 24,912 live vulnerability instances, on a granted scope used by nothing | `9721555`, `702a395`, `b4ed339` |
| 248 | 2026-07-23 |  | feat(intune): Managed Google Play bind health + Autopilot sync staleness — two singletons, no grant, fold into existing collectors | `9bd01ff` |
| 247 | 2026-07-23 |  | feat(m365): Teams installed apps (sideloaded + RSC grants) and channel census (shared channels) — both invisible today | `966483c` |
| 246 | 2026-07-23 |  | feat(purview): DLP policy inventory + enforcement mode — the largest uncovered compliance surface, on held scopes | `93f5da5`, `e777fb2` |
| 245 | 2026-07-23 |  | feat(entra): tenant policy posture — 11 bounded CIS-shaped switches, all readable on held scopes | `197ea8d` |
| 244 | 2026-07-23 |  | feat(entra): ownerless apps (21 of 27 live) + federated identity credentials — the trust edge credential_expiry cannot see | `1c4e405` |
| 243 | 2026-07-23 |  | fix(entra.secure_score): 234 per-control rows are fetched and discarded every hour — #114 log-twin violation on a shipped collector | `fd8cb41` |
| 242 | 2026-07-23 |  | feat(entra): PIM role-activation policy settings — 145 policies readable on held scopes, and nothing says what it takes to activate a role | `46492cb` |
| 241 | 2026-07-23 |  | feat(defender): 4 unread blob containers — behaviour layer + Teams message security, already billed and deleted unread | `02d8e08` |
| 240 | 2026-07-23 |  | fix(m365.storage): all four reports can fail and the collector still reports 100% success — zero data, green tick | `f7745e8`, `07d6bb6` |
| 239 | 2026-07-23 |  | feat(entra): Global Secure Access — #130's 'until a GSA tenant exists' deferral has fired, tenant reports onboarded | `4fce107`, `27c2258`, `861d339` |
| 238 | 2026-07-23 |  | feat(obs): diagnostic-settings census gate — 6 enabled containers are read by nothing, and #134's 'needs a different identity' premise is wrong | `0018b32`, `861d339` |
| 237 | 2026-07-23 |  | docs: 'DLP policy enumeration' is NOT a permanent gap — /beta/security/dataSecurityAndGovernance/policyFiles returns the full policy set on held scopes | `e777fb2` |
| 236 | 2026-07-23 |  | fix(telemetry): GaugeSnapshot clobbers across tenants — observable state is keyed by metric name only | `3acbcc7` |
| 235 | 2026-07-23 |  | epic(telemetry): automatic per-metric cardinality limiting — top-N by significance + an 'other' bucket, retiring the hand-maintained allow-lists | `703ab88`, `c703629`, `3acbcc7` |
| 234 | 2026-07-25 |  | Extend wirecheck across the collectors: stop silently bucketing unrecognized Microsoft values | `e627e02`, `4ac6a0f`, `c703629` |
| 233 | 2026-07-23 |  | feat(collectors): Defender quarantine coverage — email + Teams, audit history + flow metrics | `e627e02`, `02d8e08`, `850e932` |
| 232 | 2026-07-22 |  | docs: security-alert transports emit different value vocabularies for the same attributes (and defender.* is no longer Experimental) | `f22d647` |
| 231 | 2026-07-22 |  | fix(obs): OTEL SDK errors bypassed the app logger — OTLP export rejections landed unstructured on stderr | `d06cb83` |
| 230 | 2026-07-22 |  | test(telemetrytest): Recorder captured every non-string log attribute value as empty — numeric twin attributes were unassertable | `65ce1ff`, `9a3efc0` |
| 228 | 2026-07-22 |  | storage-report.py over-estimates the blob bill ~4.7x: hardcoded 7300 B/append is 4.9x low; measure AppendBlock instead | `fd1531e` |
| 227 | 2026-07-21 |  | admin: runtime, throughput, fleet and throttle-headroom trend charts on the status page | `e4a7439` |
| 226 | 2026-07-22 |  | intune.device_startup twin never lands in Loki — event-time-stamped log records may be silently dropped when backdated | `d06cb83`, `65ce1ff`, `9a3efc0` |
| 225 | 2026-07-22 |  | intune.endpoint_analytics: stale audit-doc claim + uncollected AppHealthDevicePerformance + where the #114 twin exception now sits | `8a131c0`, `4a976fc` |
| 224 | 2026-07-21 |  | fix(intune.endpoint_analytics): -1 'insufficient data' sentinel is recorded into boot/login time histograms | `1577068` |
| 223 | 2026-07-21 |  | fix(intune.settings_catalog): baseline filter matches 1 of 3 security baselines — Defender and Edge baselines are silently uncovered | `c3d61d2` |
| 222 | 2026-07-21 |  | fix(intune.settings_catalog): security-baseline summary 400s on every run, and its field names are all wrong | `8a131c0`, `b85fc1b`, `15d2f16` |
| 220 | 2026-07-21 |  | feat(ops): Microsoft Graph beta-endpoint drift canary | `15d2f16`, `f6a957a` |
| 219 | 2026-07-25 |  | feat(ops): generate alert + recording rules from a single source + CI validate gate | `66b991d` |
| 218 | 2026-07-24 |  | feat(ops): dashboards-as-code — metric catalogue + builder + coverage gate + CI | `66b991d`, `6ddaaf4`, `aedd01b` |
| 217 | 2026-07-20 | ~ | spike(admin): optional pprof-pull endpoints behind admin auth | `6312c02` |
| 216 | 2026-07-20 |  | ci: upload test coverage to Codacy (non-gating) | `6312c02` |
| 215 | 2026-07-20 |  | feat(admin): cardinality tab on the operator console | `6312c02` |
| 214 | 2026-07-20 |  | feat(ops): helm values.schema.json + helm-docs README | `6312c02` |
| 213 | 2026-07-20 |  | docs(ops): document the dashboard/alert deploy path (gcx push / GitSync) | `6312c02` |
| 212 | 2026-07-20 |  | feat(config): *_file secret siblings for OTLP token + Pyroscope password | `6312c02` |
| 211 | 2026-07-20 |  | feat(admin): config tab on the operator console (secrets presence-only) | `6312c02` |
| 210 | 2026-07-20 |  | feat(ops): committed pre-commit hook + make install-hooks | `6312c02` |
| 209 | 2026-07-20 |  | feat(ops): extract notices.sh + sbom.sh scripts, add make targets, bake /licenses into image | `765a590`, `6312c02` |
| 207 | 2026-07-20 |  | collectors: intune.remediation_run_states — proactive-remediation per-device health (read-only beta) | `709be25` |
| 206 | 2026-07-20 |  | console: align with fleet operator-console standard (t2o tabbed layout, auto-refresh, wider table) | `e17788a` |
| 205 | 2026-07-20 |  | collectors: intune.epm_elevation_events — per-elevation SIEM stream (needs export watermark) | `9883cfd` |
| 204 | 2026-07-20 |  | collectors: 6 Intune export-report gaps from the #202 catalog sweep | `709be25`, `9fc685e` |
| 203 | 2026-07-20 |  | fix(exportjob): two report collectors 400 — export rejects explicit _loc columns in select | `a436064`, `9fc685e`, `6041bfc` |
| 202 | 2026-07-20 |  | collectors: intune.autopilot_deployment_apps + _scripts — device-prep (V2) Apps & Scripts tabs | `709be25`, `9fc685e`, `14c14cb` |
| 201 | 2026-07-21 | ~ | feat(intune): #193 residue — AutopilotV1 (blocked-on-data) + EPM by-device/user/publisher variants | `45f0fe0`, `bfbe749`, `2ac12bb` |
| 200 | 2026-07-20 |  | feat(collectors): defender.alert_info + defender.url_click_event — the 2 remaining advanced-hunting tables (#106 follow-up) | `2ac12bb` |
| 199 | 2026-07-24 |  | feat(collectors): Intune Advanced Analytics device-inventory coverage (Windows + Linux) — the surface distinct from EA scores | `2ce5a77`, `8a131c0`, `b85fc1b` |
| 198 | 2026-07-19 |  | assess(m365): Windows365AuditLogs diagnostic category — enabled blind, Cloud PC admin audit; build / already-covered / turn off | `4608e59` |
| 197 | 2026-07-19 |  | design(intune): metrics-via-graph + logs-via-blob split for intune.devices — retire the hourly full-fleet walk at scale |  |
| 196 | 2026-07-19 | ~ | spike(intune): Data Warehouse app-only feasibility + fifth-engine go/no-go |  |
| 195 | 2026-07-19 |  | feat(intune): device attestation / boot-security posture (deviceHealthAttestationState) | `96b0591`, `8625539`, `35c4afa` |
| 194 | 2026-07-24 |  | feat(intune.endpoint_analytics): add ModelScores + AnomalySeverityOverview + WFA + per-app app-health detail | `45f0fe0`, `b9c594c`, `4a976fc` |
| 193 | 2026-07-20 |  | feat(intune): wire high-value Reports export-job reportNames (compliance/config/update aggregates, assignment failures, Autopilot, EPM) | `0811619`, `2ac12bb`, `5059d84` |
| 192 | 2026-07-21 |  | Intune reporting/analytics/DW coverage: spike + build-out tracker | `45f0fe0`, `bfbe749`, `770aaaa` |
| 191 | 2026-07-19 |  | feat(entra): recycle-bin (deletedItems) coverage — census of recoverable deleted objects | `3647b21` |
| 190 | 2026-07-19 |  | feat(entra): extract modifiedProperties (role name, granted scope) on directory_audits consent/role events | `4fce107`, `1d73fe7` |
| 189 | 2026-07-19 |  | feat(blob-metrics): intune.enrollment_event.count derivation (F5 of #128) | `703ab88`, `d34dd87`, `09f3621` |
| 188 | 2026-07-19 |  | docs(blob-metrics): recording-rule-vs-emit heuristic + intune.compliance_alert example (F4 of #128) | `703ab88`, `d34dd87`, `53d0ba1` |
| 187 | 2026-07-19 |  | feat(blob-metrics): entra.signin.count across the blob sign-in family (F3 of #128) | `fdc92d8` |
| 186 | 2026-07-19 |  | feat(blob-metrics): MGAL native histograms — request.duration + response.size (F2 of #128) | `c8f3d4a` |
| 185 | 2026-07-19 |  | feat(blob-metrics): entra.graph_activity.endpoint_requests counter + URI normalization (F1 of #128) | `86c2cf7`, `bbdcb58` |
| 184 | 2026-07-19 |  | Audit: which graph-only metric+twin collectors could be blob-sourced (near-total no; 2 additive AuditLogs candidates) |  |
| 183 | 2026-07-18 |  | Experimental should mean 'Graph beta API' only — un-gate Defender advanced-hunting + m365.servicemessages | `4fce107`, `e627e02`, `a467c3e` |
| 182 | 2026-07-18 |  | feat(m365): message-center collector (serviceAnnouncement/messages) | `8cf65f5`, `66d3d62` |
| 181 | 2026-07-18 |  | Defender cloudappevents: 100%-noise sample + high volume — needs an ActionType/Workload filter before build-or-disable |  |
| 180 | 2026-07-18 |  | feat(intune.devices): widen $select — model, manufacturer, wiFiMacAddress, partnerReportedThreatState on the device log twin | `fd06d6a`, `5b770e9` |
| 179 | 2026-07-18 |  | bug(intune): endpoint_analytics calls dead/wrong UXA endpoints and mis-skips them as 'not available on this tenant' | `4a976fc`, `5b770e9`, `e64f5a4` |
| 178 | 2026-07-19 |  | feat(admin): surface transport (graph/blob) + twin coverage + cursor state in the status UI | `1e952db`, `5f75ac9`, `1f4dcb8` |
| 177 | 2026-07-18 |  | verify: live-confirm the 5-collector posture batch (#122/#123/#124/#125) |  |
| 176 | 2026-07-19 |  | feat: extend self-exhaust exclusion beyond blob — measure + decide the Graph-polled and m365.activity transports | `66d55eb` |
| 175 | 2026-07-17 |  | purview/sensitivitylabels: description twin attr empty on live wire — text is in toolTip, mapper reads description | `0654039`, `932c62b` |
| 174 | 2026-07-17 |  | intune/scripts: runSummary + remediation counts decode to 0 — wire is top-level, decoder assumes {"value":{…}} envelope | `54489d6`, `55e473d` |
| 173 | 2026-07-18 |  | feat(entra): mfaregistration could surface userType (member/guest) + system-preferred-method posture - the endpoint sends them, the $select drops them | `b2dfa9d`, `af81e3a`, `19568fd` |
| 172 | 2026-07-17 |  | bug(intune): auditevents Body renders an empty action - it interpolates activity, which is null on the wire; displayName carries the name | `a1cf204`, `98a9bb1` |
| 171 | 2026-07-18 |  | docs: Intune OperationalLogs blob path is buildable now - corrects blob-ingest.md's 'no live sample' framing (Graph gap in #94 unaffected) | `cf0c520` |
| 170 | 2026-07-17 |  | bug(m365): unifiedaudit's client_ip mapper line is dead - clientIp is null on every record, the real IP is nested in auditData | `2fe6b2c`, `21cf716` |
| 169 | 2026-07-17 |  | bug(entra): securityincidents' tags mapper line is dead - the wire sends customTags/systemTags, never tags | `7870b38`, `21cf716`, `37f6071` |
| 168 | 2026-07-17 |  | bug(entra): directoryaudits initiator_app_id maps a field that's always null on app-initiated records - servicePrincipalId is the real identifier | `478c1a5`, `e1c126b` |
| 167 | 2026-07-17 |  | bug(entra): provisioning service-principal attribution has never emitted - servicePrincipal is an object, not a collection, and the name field is displayName | `b3f38e5`, `21cf716`, `4010ce7` |
| 166 | 2026-07-17 |  | bug(intune): intune.enrollment_failure logs carry no id - the one window collector that cannot be pivoted back to its source record | `00e8e6f` |
| 165 | 2026-07-17 |  | test: most collector fixtures were written from Microsoft docs, not the wire - the project rule they violate is its own hardest-won one | `e627e02`, `c2feef6`, `2800ef4` |
| 164 | 2026-07-17 |  | build: the signal goldens understate what 12 collectors emit - graphactivity records 0 of its 22 attributes | `3e0a7b8`, `51ffdac`, `37f6071` |
| 163 | 2026-07-17 |  | fix(m365)!: user_principal_name holds the classic UserId, which is only ~91% UPN-shaped - the name lies | `53fc618`, `fa3395f` |
| 162 | 2026-07-24 |  | feat(dashboards): zero log panels ship - the signal that answers 'which one' has no surface | `6ddaaf4` |
| 161 | 2026-07-17 |  | refactor(telemetry): 199 attribute-name literals, 27 duplicate setStr helpers, and tenant_id means two things - build the registry | `b2dfa9d`, `af81e3a`, `edf715d` |
| 160 | 2026-07-17 |  | bug(alerts): README claims every metric carries tenant_id (it does not) - and the compliance-ratio rules silently blend tenants into one wrong number | `77810ce`, `b0293c4` |
| 159 | 2026-07-17 |  | feat(entra): entra.risk_detections drops userAgent, tokenIssuerType, geo and display name - all on the wire, all high SIEM value | `c7864d6` |
| 158 | 2026-07-17 |  | bug(dashboards): intune-fleet-overview filters a domain metric by tenant_id - the panel returns no data, always | `77810ce`, `b0293c4`, `59489eb` |
| 157 | 2026-07-17 |  | bug(intune): malware log twin warns on every healthy device - checks productStatus == "noStatus" but live healthy is "noStatusFlagsSet" | `aae4e69` |
| 156 | 2026-07-17 |  | build(intune): nothing enforces the shared productStatus vocabulary across the two Defender transports - bit 24 already drifted | `0e2b327`, `aae4e69`, `e701bbd` |
| 155 | 2026-07-19 |  | bug(entra): riskyUsers.isDeleted reports false for a deleted user - entra.risk's gauge counts ghosts forever | `1df2370`, `57ac365` |
| 154 | 2026-07-18 |  | feat: opt-in exclusion of graph2otel's own exhaust from the exported signal | `66d55eb`, `ad92d56`, `7728619` |
| 153 | 2026-07-17 |  | bug(entra): risk_type is a silent null on the Graph path, and riskyUsers.isDeleted reports false for a deleted user | `21cf716`, `94f6ca9`, `57ac365` |
| 152 | 2026-07-18 |  | blob ingest is a cost feedback loop: graph2otel is 59.9% of its own MicrosoftGraphActivityLogs volume, and real cost is ~4x the documented figure | `ad92d56`, `7728619` |
| 151 | 2026-07-17 |  | bug(m365): user_id means UserKey on m365.unified_audit and UserId on m365.activity - one attribute, two semantics | `21cf716`, `fa3395f`, `94f6ca9` |
| 150 | 2026-07-17 |  | bug(intune): intune.malware buckets multi-flag productStatus to "other" - same modelling error as #142, second transport, live on 1 of 3 Windows devices | `aae4e69`, `e701bbd` |
| 149 | 2026-07-17 |  | docs: how operators register their own poller app for eDiscovery (and any other non-Graph data plane needing S&C PowerShell) | `98c1dad` |
| 148 | 2026-07-18 |  | needs-rob batch: the four maintainer tenant actions, in one sitting (unblocks #102, #106, #129, #100) | `98e7e78`, `98c1dad` |
| 147 | 2026-07-17 |  | fix(jobpipeline): cold checkpoint cannot adopt an in-flight async job — restart on first deploy still orphans and re-creates | `a14f34d` |
| 146 | 2026-07-17 |  | meta: tracker + CLAUDE.md reorganisation — stop the agent-confusion doom loop | `7002932`, `bc0bb30` |
| 145 | 2026-07-19 |  | feat(mdca): Cloud Discovery parse failures are invisible - the upload 200s while MDCA rejects the file, and nothing polls the governance log | `850e932`, `e8ee309` |
| 144 | 2026-07-16 |  | fix(collectors): nothing enforces transport mutual-exclusion — camden ships every non-interactive + service-principal sign-in TWICE, measured | `2ac12bb`, `603cd69`, `7551f59` |
| 143 | 2026-07-17 |  | fix(dashboards/docs): `docs/signals.md` claims every metric carries `tenant_id` - it does not, and the entra dashboard filters on it | `e627e02`, `77810ce`, `edf715d` |
| 142 | 2026-07-17 |  | fix(intune): export reports return raw enum CODES, not names - `platform=2` ships live, and Defender's status bucket can never match | `e627e02`, `c2feef6`, `2800ef4` |
| 141 | 2026-07-17 |  | feat(telemetry): no record says where it came from, and 198 attribute names are bare literals - define an attribute registry with a provenance attribute | `1f4dcb8`, `edf715d`, `b0293c4` |
| 140 | 2026-07-17 |  | build(docs): nothing gates the signals we actually emit - metric AND log event names drift unguarded | `6ddaaf4`, `b2dfa9d`, `dc49fc1` |
| 139 | 2026-07-16 |  | build(docs): generate the collector reference from the registry — 8 of 57 collectors are undocumented and nothing catches it | `77810ce`, `97e08b6`, `0f9b5da` |
| 138 | 2026-07-18 |  | fix(blobpipeline): Azure delivers at-least-once — ~2.3% of blob-sourced records are duplicates | `5776acb`, `9832447`, `180caf8` |
| 137 | 2026-07-18 |  | Re-measure the blob engine's two open questions once m7kni finishes backfilling | `fd1531e`, `5776acb`, `7728619` |
| 135 | 2026-07-20 |  | feat(collectors): map the remaining 19 blob diagnostic categories (engine shipped; they land unread today) | `2ac12bb`, `4608e59`, `1df2370` |
| 134 | 2026-07-18 |  | Assess 3 unknown Entra diagnostic categories: GraphNotificationsActivityLogs, MicrosoftGraphPolicyLogs, PreAuthenticationDiscoveryLogs (enabled blind — decide build or disable) | `0018b32`, `861d339`, `60d7571` |
| 133 | 2026-07-20 |  | feat(collectors): three uncovered Identity Protection signals — SP risk detections, risky agents, agent risk events (no collector today) | `99670c8`, `3e0a7b8`, `9d50c0b` |
| 132 | 2026-07-18 |  | Verify: do Intune Devices/DeviceComplianceOrg blob categories carry per-device inventory? (could retire the hourly full-fleet page-walk) | `635421d`, `fd06d6a`, `6192aa2` |
| 131 | 2026-07-16 | ~ | Spike: dual-ship model — Graph poll for real-time metrics, blob for comprehensive logs (corrects the 'mutually exclusive source' assumption) | `09f3621`, `bc0bb30`, `6192aa2` |
| 130 | 2026-07-17 |  | NetworkAccessTrafficLogs is NOT a Graph gap — /beta/networkAccess/logs/traffic exists and names its scope (CLAUDE.md wrong) | `27c2258`, `861d339`, `f2a3ccd` |
| 129 | 2026-07-19 |  | Verify risk-signal mappings against a real event: synthesise a UserRiskEvent on m7kni (needs maintainer tenant action) | `f7c9739`, `9f4a4be`, `c7864d6` |
| 128 | 2026-07-19 |  | Spike: derive OTEL metrics from blob-only signals (recency-gated <1h, never backfill) — gated on #137 | `00d6227`, `0c64deb`, `441e193` |
| 127 | 2026-07-18 |  | SharePoint tenant sharing posture: external sharing + legacy auth config via Graph /admin/sharepoint/settings | `171b0c4` |
| 126 | 2026-07-17 |  | Purview sensitivity labels: collector rebuilt on SensitivityLabel.Read — residual: narrow isUnavailable + guard test + SECURITY.md | `5d49f57`, `98c1dad`, `504d83b` |
| 125 | 2026-07-18 |  | Entra users: joint user_type x account_enabled population counts (disabled guests are unanswerable today) | `b2dfa9d`, `af81e3a` |
| 124 | 2026-07-18 |  | Intune: OS version breakdown for patch-level fleet visibility (free, rides existing fetch) | `b2dfa9d`, `af81e3a` |
| 123 | 2026-07-18 |  | Entra directory sync errors: surface onPremisesProvisioningErrors alongside sync freshness | `2bcf98d`, `b2dfa9d`, `af81e3a` |
| 122 | 2026-07-18 |  | Entra licensing: subscription state (suspended/warning/lockedOut + capabilityStatus) + group license assignment errors | `b2dfa9d`, `af81e3a` |
| 121 | 2026-07-19 |  | Microsoft Teams inventory: ownerless teams, guest exposure, membership counts | `debb0e1` |
| 120 | 2026-07-18 |  | SharePoint + OneDrive storage utilisation: tenant capacity + per-drive quota state | `d40add3` |
| 119 | 2026-07-18 |  | M365 service health: per-service status + incident/advisory stream | `f08f994`, `66d3d62`, `c581d13` |
| 118 | 2026-07-16 |  | fix(checkpoint): resume in-flight async jobs across restarts + make the backfill window configurable | `a14f34d`, `4ab4523` |
| 117 | 2026-07-16 |  | fix: checkpoints are discarded on every redeploy (no compose volume, Helm defaults to emptyDir) + async job ids are not resumable | `7551f59`, `aad052d` |
| 116 | 2026-07-18 |  | Epic/spike: does graph2otel need a real cache layer (Redis sidecar or similar), or is in-process + a persistent volume enough? |  |
| 115 | 2026-07-16 |  | perf(collectors): entra.mfaregistration polls the whole user directory every 15 min — hourly is the right default | `adc6df4`, `b0b75ac` |
| 114 | 2026-07-16 |  | fix(collectors): finish the log-twin sweep — 6 collectors drop the detail that makes them actionable | `864e6c6`, `702a395`, `1f99aa6` |
| 113 | 2026-07-16 |  | test: LogRecord.Severity vs telemetry.Severity are different scales — one assertion is vacuous, the API is a footgun | `f8e29e3` |
| 112 | 2026-07-16 |  | docs: the cardinality rule is a data-modeling rule, not a PII exclusion — reframe it and state the log-twin principle | `df24b9f`, `4fce107`, `f7745e8` |
| 111 | 2026-07-16 |  | fix(collectors): purview label collectors drop the label catalog with no log twin | `94f6ca9`, `6ff35fe`, `417f420` |
| 110 | 2026-07-16 |  | fix(collectors): entra.risk drops the risky-entity detail with no log twin | `94f6ca9`, `6ff35fe`, `417f420` |
| 109 | 2026-07-16 |  | Live-verify fixes: security_incidents $top=50, m365 audit beta-only, purview app-only degradation | `5d49f57`, `078b5de`, `f2a3ccd` |
| 108 | 2026-07-16 |  | ci: speed up goreleaser cross-compile (trim matrix, cache, relax -p) | `2a8c833`, `2b516ae` |
| 107 | 2026-07-15 |  | Pyroscope: collect all profile types by default, incl. goroutine-leak (GOEXPERIMENT) | `cf01fba` |
| 106 | 2026-07-18 |  | feat(collectors): Defender advanced-hunting table ingest via streaming API → Storage — engine exists, needs export enablement + per-table mappers | `2ce5a77`, `1f99aa6`, `c7180b9` |
| 105 | 2026-07-16 |  | Add active-series cardinality cap + ≤1 DPM per-series governance (parity with tailscale2otel/opnsense-exporter) | `0ab7ac5` |
| 104 | 2026-07-16 |  | Metric panels double for ~5-10 min after every redeploy (service_version churn on :main + OTLP push staleness) | `3acbcc7`, `2103ac3`, `519c002` |
| 103 | 2026-07-16 |  | Config registry + generators + drift-check gate (parity with tailscale2otel/opnsense-exporter) | `3e0146c`, `0ab7ac5` |
| 102 | 2026-07-19 |  | feat(collectors): Purview eDiscovery case inventory gauge | `5d49f57`, `98c1dad`, `d8615b1` |
| 101 | 2026-07-16 |  | feat(collectors): Purview sensitivity + retention label inventory gauges | `b66596d` |
| 100 | 2026-07-18 |  | m365.activity: O365 Management Activity API collector — SHIPPED; residual: UPN convergence, DLP.All verify, adapter move, SECURITY.md | `df24b9f`, `77810ce`, `97e08b6` |
| 99 | 2026-07-16 |  | docs: honest-scope note — signals with no Graph/REST path regardless of API choice (M365 + Purview) | `9b51997`, `e777fb2`, `d8615b1` |
| 98 | 2026-07-16 |  | spike: live-verify security/auditLogQuery record shape, licensing gate, and polling latency (M365 + Purview) | `a14f34d`, `6ff35fe`, `b66596d` |
| 97 | 2026-07-16 |  | feat(collectors): M365 unified-audit collector via Graph security/auditLogQuery | `b66596d`, `e04eed7`, `6801985` |
| 96 | 2026-07-16 |  | chore: validate DeviceComplianceOrg/Devices metric parity — Intune decommission readiness |  |
| 95 | 2026-07-16 |  | spike: verify remoteActionAudits Graph endpoint liveness, dedupe against intune.audit_events | `3a22cdd` |
| 94 | 2026-07-16 |  | docs: state Intune OperationalLogs (compliance-alert events) as a permanent Graph gap | `60d7571`, `cf0c520`, `d8615b1` |
| 93 | 2026-07-16 | ~ | feat(collectors): Defender advanced-hunting collector for AlertInfo/AlertEvidence parity | `26eaedf` |
| 92 | 2026-07-16 |  | feat(collectors): entra.security_incidents — Graph security/incidents WindowCollector | `b66596d` |
| 91 | 2026-07-16 |  | Self-instrumentation: graphclient HTTP 4xx/5xx counter as a narrow substitute for the Graph-403-burst rule | `2103ac3`, `07f829b` |
| 90 | 2026-07-16 |  | Recreate the entra-security Grafana alert group on graph2otel-native signals | `77810ce`, `d94458b`, `6ddaaf4` |
| 89 | 2026-07-16 |  | Research spike + build: pick ONE fallback-ingest transport — Log Analytics query-and-delete vs Event Hub pub/sub (evaluate cost + completeness first) | `00d6227`, `fd1531e`, `7728619` |
| 88 | 2026-07-16 |  | logpipeline: add an async job-poll collector mode (create → poll → page) | `6801985` |
| 87 | 2026-07-16 |  | Polling intervals + response caching + Graph rate-limit headroom on large tenants | `c0b96b8`, `ce7f6e9` |
| 86 | 2026-07-20 |  | Epic: replace the traditional Entra/Intune/Defender/M365/Purview log-export pipeline with graph2otel-native ingest | `b66596d` |
| 85 | 2026-07-19 |  | Admin UI + profiling residuals: rate-limiter headroom panel, profiling docs, pprof AC closure | `2e69d67`, `fd361c9`, `9f0c9cb` |
| 84 | 2026-07-15 |  | entra.signin_activity under-declares Reports.Read.All (runtime 403, preflight blind) | `fc0cfe5` |
| 83 | 2026-07-16 |  | intune.app_install_status emits unbounded per-app_name cardinality (app catalog, not deployed apps) | `14c14cb`, `96b0591`, `94f6ca9` |
| 82 | 2026-07-15 |  | Dashboards + alerts use pre-normalization metric names (missing OTLP→Prometheus unit/type suffixes) | `3cbd879`, `b0293c4`, `62c3850` |
| 79 | 2026-07-25 |  | v1.0 launch tracker: graph2otel from scaffold to release | `83a7203`, `765a590`, `6312c02` |
| 75 | 2026-07-15 |  | Entra service-principal / credential / app sign-in activity (beta) | `d4f2cae` |
| 74 | 2026-07-15 |  | Entra recommendations (beta) | `e1c222d` |
| 73 | 2026-07-15 |  | Entra agreements (terms of use) + acceptance counts | `22c42d1` |
| 72 | 2026-07-15 |  | Entra authentication-methods policy config | `9d3db52`, `3555357` |
| 71 | 2026-07-15 |  | Entra risky users + risky service principals (current-risk gauges) | `5a9ce18` |
| 70 | 2026-07-15 |  | Entra consent surface: oauth2 grants + app-role assignments | `9604905`, `02f5ff5` |
| 69 | 2026-07-15 |  | Entra MFA / auth-methods registration summaries | `9d3db52` |
| 68 | 2026-07-15 |  | Entra Secure Score + control profiles | `e4683dc` |
| 67 | 2026-07-15 |  | enrollment configuration metrics | `d427cdf` |
| 66 | 2026-07-15 |  | Entra directory roles + PIM active/eligible assignments | `ff33946` |
| 65 | 2026-07-15 |  | Group Policy analytics (migration readiness) metrics | `17a1502` |
| 64 | 2026-07-15 |  | scripts + proactive remediation summary metrics | `17a1502` |
| 63 | 2026-07-15 |  | certificate state + NDES health metrics | `17a1502` |
| 62 | 2026-07-15 |  | Apple token expiry metrics (APNS / VPP / DEP) | `d427cdf` |
| 61 | 2026-07-15 |  | Windows malware / Defender state metrics | `d427cdf` |
| 60 | 2026-07-15 |  | endpoint analytics (User Experience Analytics) metrics | `17a1502` |
| 59 | 2026-07-15 |  | Windows Update rings + feature/quality/driver update profile metrics | `17a1502` |
| 58 | 2026-07-15 |  | Entra Conditional Access policies + named locations | `16d4c7b` |
| 57 | 2026-07-15 |  | Windows Autopilot devices + deployment profiles metrics | `17a1502` |
| 56 | 2026-07-15 |  | app protection / MAM (+ legacy WIP) metrics | `17a1502` |
| 55 | 2026-07-15 |  | mobile apps catalog + app config policy metrics | `d427cdf` |
| 54 | 2026-07-15 |  | Settings Catalog, template intents & security baselines metrics | `17a1502` |
| 53 | 2026-07-15 |  | device configuration profiles + status-overview metrics | `17a1502` |
| 52 | 2026-07-15 |  | device compliance policies + rollups + per-policy/per-setting status metrics | `d427cdf` |
| 51 | 2026-07-15 |  | connector health metrics (Exchange / MTD / NDES) | `d427cdf` |
| 50 | 2026-07-15 |  | detectedApps software-inventory metrics | `d427cdf` |
| 49 | 2026-07-15 |  | managedDevices inventory + managedDeviceOverview metrics | `d427cdf` |
| 48 | 2026-07-15 |  | Entra app + service-principal credential expiry (flagship compliance metric) | `c7cc115` |
| 47 | 2026-07-15 |  | Entra organization: tenant details + directory-sync freshness | `bc0d5a3` |
| 46 | 2026-07-15 |  | Entra domains: verified/federated/managed posture gauges | `be169c8` |
| 45 | 2026-07-15 |  | Entra licensing: subscribedSkus utilization + assignment errors | `b2dfa9d`, `e6f6244` |
| 44 | 2026-07-15 |  | Entra devices: directory-device aggregates + stale-device gauge | `4edea3c` |
| 43 | 2026-07-15 |  | Entra groups: population aggregates + role-assignable count | `c02d4e5` |
| 42 | 2026-07-15 |  | Defender agents health report (DefenderAgents, export-only) | `fe68c16` |
| 41 | 2026-07-15 |  | Fleet certificate inventory report (AllDeviceCertificates, export-only) | `fe68c16` |
| 40 | 2026-07-15 |  | Enrollment failures report (EnrollmentFailures, beta export) | `971667e` |
| 39 | 2026-07-15 |  | Entra users: population aggregates + stale-account gauge | `cede7dd`, `5278959`, `9604905` |
| 38 | 2026-07-15 |  | Windows feature-update device states report (export-only) | `0811619` |
| 37 | 2026-07-15 |  | App install status report (DeviceInstallStatusByApp, export-only) | `2caaa40`, `c5b0108`, `fe68c16` |
| 36 | 2026-07-15 |  | Entra directory summary counts: entra.directory.objects.total per object type | `c9e9449` |
| 35 | 2026-07-25 |  | v1.0.0 release checklist | `5278959`, `06e3cdb`, `83a7203` |
| 34 | 2026-07-15 |  | Docs completeness pass: README, permission setup guide, per-collector reference | `9642643` |
| 33 | 2026-07-15 |  | PII & cardinality audit gate (pre-v1 release blocker) | `5278959`, `9642643`, `f71c871` |
| 32 | 2026-07-15 |  | Scale/soak validation against throttle budgets and watermark durability | `e0ce876` |
| 31 | 2026-07-15 |  | Docs site: Zensical setup + m7kni-net-site hub onboarding | `9642643` |
| 30 | 2026-07-15 |  | Example alert rules: credential expiry, compliance drop, collector staleness, throttle saturation | `ff22eb0` |
| 29 | 2026-07-15 |  | Grafana dashboard: graph2otel self-observability | `6193d39`, `f71c871` |
| 28 | 2026-07-15 |  | Grafana dashboard: Intune fleet overview | `f71c871` |
| 27 | 2026-07-15 |  | Grafana dashboard: Entra ID compliance overview | `f71c871` |
| 26 | 2026-07-15 |  | Helm chart: package graph2otel for Kubernetes, wire into publish pipeline | `271a4d8` |
| 25 | 2026-07-15 |  | Security alerts WindowCollector: /security/alerts_v2 | `d7814ce`, `a466fb7` |
| 24 | 2026-07-15 |  | Risk detections WindowCollector: /identityProtection/riskDetections (IPC 1 req/s) | `d7814ce` |
| 23 | 2026-07-15 |  | Provisioning logs WindowCollector: /auditLogs/provisioning (strict gt/lt) | `21d0a57`, `5e50913`, `26c4531` |
| 22 | 2026-07-15 |  | Directory audit logs WindowCollector: /auditLogs/directoryAudits | `d7814ce` |
| 21 | 2026-07-15 |  | Sign-ins (managed identity) WindowCollector: signInEventTypes filter | `7e55f03` |
| 20 | 2026-07-15 |  | Sign-ins (service principal) WindowCollector: signInEventTypes filter | `7e55f03` |
| 19 | 2026-07-15 |  | Sign-ins (non-interactive user) WindowCollector: signInEventTypes filter | `7e55f03` |
| 18 | 2026-07-15 |  | Sign-ins (interactive) WindowCollector: /auditLogs/signIns default slice | `7e55f03` |
| 17 | 2026-07-15 |  | Reports export-job subsystem: generic POST/poll/download/parse client | `d2db843`, `fe68c16`, `971667e` |
| 16 | 2026-07-15 |  | Autopilot deployment events WindowCollector (beta) | `971667e` |
| 15 | 2026-07-15 |  | Enrollment troubleshooting events WindowCollector | `971667e` |
| 14 | 2026-07-15 |  | Intune audit events WindowCollector | `971667e` |
| 13 | 2026-07-15 |  | Log pipeline engine: generic watermark poller for all WindowCollectors | `e0ce876`, `ed2d70a`, `a830310` |
| 12 | 2026-07-15 |  | Admin/health endpoint: /healthz + per-collector status page | `5b7e0ac`, `a830310`, `0a88fb0` |
| 11 | 2026-07-15 |  | Permission preflight subcommand (graph2otel check) | `fbdb72b`, `5b7e0ac`, `06396c5` |
| 10 | 2026-07-15 |  | License-tier detection + graceful per-collector degradation | `eb2a6a9`, `5b7e0ac` |
| 9 | 2026-07-15 |  | Self-observability: per-collector scrape.success/duration/staleness + build_info | `5b7e0ac`, `a830310`, `da4513d` |
| 8 | 2026-07-15 |  | Telemetry provider + Emitter facade: OTLP grpc/http/stdout, Grafana Cloud auth, cardinality limit, in-memory Recorder | `f372948`, `da4513d` |
| 7 | 2026-07-15 |  | CheckpointStore: file-based watermark/overlap/seen-ids, namespaced per tenant+endpoint | `6adfce2`, `0a88fb0` |
| 6 | 2026-07-15 |  | Collector framework: Collector/SnapshotCollector/WindowCollector interfaces, Registry, Scheduler | `a830310`, `da4513d` |
| 5 | 2026-07-15 |  | Per-workload client-side rate limiters + own exponential backoff (no Retry-After) | `ed2d70a`, `c578bb2`, `013484b` |
| 4 | 2026-07-15 |  | Graph client factory: msgraph-sdk-go adapter with Kiota default middlewares re-attached under OTEL-instrumented transport | `c578bb2`, `408d3ba`, `013484b` |
| 3 | 2026-07-15 |  | Auth: per-tenant DefaultAzureCredential wiring + Graph scope handling | `06396c5` |
| 2 | 2026-07-15 |  | Multi-tenant config expansion + per-collector interval/enable config | `0a88fb0` |
| 1 | 2026-07-15 |  | Project bootstrap: research, scaffold, and v1 backlog | `7d182ad` |
