# graph2otel

Polls Microsoft Graph (Entra ID / Intune / Defender / M365 / Purview) — plus an Azure
Storage blob fallback and the O365 Management Activity API — and exports
**OpenTelemetry-native metrics + logs** over OTLP, optimized for Grafana Cloud. Single
static Go binary, OTLP push only (no Prometheus pull endpoint). Multi-tenant from day
one. Used as a **SIEM feed**: per-entity detail in logs is the point. See `README.md`
for the user-facing pitch.

> **Status:** **v1.0.0 shipped 2026-07-25** — live in production on a real tenant.
> `docs/collectors.md` is generated from the registry and drift-gated (the authoritative
> collector count). Releases are release-please driven.
>
> **The tracker is Backlog.md as of 2026-08-14, not GitHub Issues.** The current worklist
> is `backlog task list --plain`. All 402 closed issues were archived and the issues
> themselves deleted, so `#NNN` no longer resolves on GitHub: it resolves to
> `archive/github-issues-2026-08-14.json`, indexed by the *Closed GitHub issues* doc
> (`backlog doc list --plain`). That covers the launch tracker (#79), the release
> checklist (#35) and the post-launch integrity audit (#374) — read them there for
> history, not current state. Keep this file to *current truth*; correction history lives
> in the archive and in task notes.

## Commands

```sh
go build ./cmd/graph2otel   # build the binary (or: go build ./...)
go test -race ./...         # unit + integration tests (race detector on)
go vet ./...
golangci-lint run           # lint (v2 config, .golangci.yml)
golangci-lint fmt           # apply gofmt + goimports
make tidy                   # tidy root, tools/graphdrift, and both OTLP/HTTP fork modules
make forks-check            # vet/test/tidy + provenance gate for both third_party forks
make tools-check            # vet + test the separate tools/graphdrift module
make check                  # root + tools + forks + lint/vuln/tidy/build — the green bar
```

`make check` is the full gate; it covers the root module, `tools/graphdrift`, and
the two modules under `third_party/`. Run it before every commit. CI runs the same
steps.

## Development methodology

- **Work directly on `main` and push unprompted.** This is an `rknightion` repo — commit
  straight to `main` and push immediately once a completing commit lands. No feature
  branches, no PR flow for first-party work. Bypass-on-push output is expected admin
  behavior, not an error.
- **Backlog tasks are the record of intent and progress**, not this file. Before
  substantial work, create a task with a plan and acceptance criteria; keep it live as
  you work; finalize it in one call on completion. A future session with no memory of
  this one must be able to reconstruct what happened from the checkout alone — which is
  now literally true, since the tracker is in the repo.
- **Tracker hygiene (from the #146 post-mortem — these rot cost real days):**
  - When a later note reverses an earlier claim, **correct the earlier one the same day**.
    If a task's description contradicts its notes, the newest note wins; fix the
    description before moving on.
  - Any **"do not X yet"** must name its unblock condition, so a later reader can check
    whether it has fired.
  - Every do-not-redo / verified-fact entry carries its **evidence class**:
    `live-measured (date, task or #issue)` / `docs-only` / `n=1`. Docs-only and n=1 are
    cheap to re-open; do not give them the same armor as measured facts.
- **Strict TDD:** failing test → watch it fail for the right reason → minimal code →
  green → refactor. Standard-library `testing` only — no third-party assertion libraries.
- Commit a **green** state between units of work — evidence, not assertion.
- **Conventional Commits:** `type(scope): subject`. release-please shows
  `feat`/`fix`/`perf`/`refactor`; `docs`/`test`/`chore`/`ci`/`build` are hidden.
- **Specs & plans are local scratch, never committed:** `docs/superpowers/` (gitignored).
- Sub-agents never commit; the coordinating thread commits and **verifies every diff
  itself** — a returned brief is not evidence of correct work.
- **Validate a task's premise against the live tenant before implementing**, probing
  as `graph2otel-poller` (never another app identity). Live-tenant mutations (app
  registrations, scope grants, diagnostic settings) need exact scopes named and explicit
  maintainer approval first.
- **Wire over docs.** Microsoft's documentation has been wrong on essentially every
  load-bearing detail on this project's path. Never assert API behavior from docs alone;
  measure, then record with a `live-measured` tag.

## Architecture (the seams)

Closest analogs: `sf2loki`'s composition-root pattern, `tailscale2otel`'s poll →
`telemetry.Emitter` facade.

- **Raw REST for all collectors** via `internal/graphclient` (OTEL-instrumented
  transport, per-workload client-side rate limiters, own backoff — the throttled
  workloads send no `Retry-After`). `msgraph-sdk-go` remains for exactly **one** call
  site (`internal/license/graphclient_adapter.go`, subscribedSkus); do not add typed-SDK
  usage and do not "clean up" that one. Beta endpoints via `BaseURLOverride` +
  `Experimental()` opt-in (default off).
- **4 ingest engine shapes**, one per transport shape:
  - `internal/logpipeline` — watermark window polling for Graph log endpoints (no delta
    query exists on any of them; watermark + overlap + seen-id dedupe).
  - `internal/jobpipeline` + `internal/exportjob` — async create→poll→download jobs
    (M365 audit query, Intune report exports).
  - `internal/blobpipeline` — Azure Storage byte-offset consumer (see
    `docs/blob-ingest.md`).
  - `internal/o365pipeline` + `internal/o365activityclient` — O365 Management Activity
    API subscription/content-blob model (see `docs/o365-management-api.md`).
- **Collector framework** (`internal/collector`, `internal/collectors`) — typed
  `SnapshotCollector` (bounded gauges + log twins) and `WindowCollector` (event streams →
  logs). 7 registration paths: `Deps`/`All`, `WindowDeps`/`WindowAll`,
  `BlobDeps`/`RegisterBlob`, `O365Deps`/`O365All`, `MDCADeps`/`RegisterMDCA`,
  `EXODeps`/`RegisterEXO`, `HuntDeps`/`RegisterHunt`/`HuntAll` (#249, the
  advanced-hunting query API). **`internal/collectordoc` must walk every registration
  path** — a gate that cannot see a collector reports coverage it does not have
  (#139/#100 incident: a fourth path landed and the coverage test stayed green over a
  missing collector). `Rows` takes one slice per path
  (`snapshot, window, blob, o365, mdca, exo, hunt`), so **adding an eighth path means
  changing its signature in the same commit** — that is the whole mechanism keeping the
  gate honest, and it is why this count must be corrected the moment a path lands.
- **Telemetry emitter facade** (`internal/telemetry`) — the only thing touching OTLP.
  It only sets non-zero timestamps: a record with no parseable event time must be
  **dropped**, never stamped on arrival (it would silently claim to have happened now).
  **Undedupeable is degraded; misdated is wrong — only wrong justifies a drop.**
- **CheckpointStore** — file-based, namespaced per tenant + endpoint. Needs a persistent
  volume in production (the compose reference mounts one; the Helm chart defaults to an
  `emptyDir`, so production installs must set `persistence.enabled=true`). Fail fast if
  the configured checkpoint path is unwritable.
- **Transport is exclusive per collector**: `source: graph` XOR `blob`, enforced by
  config `ConflictsWith` (#144). There is no dual mode (#131 closed rejecting it — the
  log-shaped collectors emit zero metrics, so dual ≡ blob). The one genuinely
  dual-capable signal (`intune.devices`) is #132's question.
- Single-instance, no HA/leader-election in v1.

## Config & secrets

- **Env var prefix:** `G2O_`, double-underscore nesting (koanf: defaults < YAML < env) —
  `otlp.endpoint` → `G2O_OTLP__ENDPOINT`. The config surface is registry-driven with a
  drift gate (`docs/env-vars.md` is generated; new keys must register or CI fails).
- **Auth:** Entra app registration via `azidentity.DefaultAzureCredential`
  (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` or
  `AZURE_CLIENT_CERTIFICATE_PATH`). Never in YAML. Minimum read-only scopes per enabled
  collector — with exactly two write-scope breaks, both documented: Intune reports-export
  job creation and O365 `POST /subscriptions/start`.
- Blob ingest is opt-in via one per-tenant key, `blob_ingest.account_url` — unset
  registers no blob collectors.
- `config.local.yaml` and `.env` are gitignored — never commit credentials.

## Telemetry model

- **Namespaces:** domain metrics use `entra.*` / `intune.*` / `m365.*` / `purview.*` /
  `defender.*` / `mdca.*`; self-observability uses `graph2otel.*`. A collector emitting
  outside its domain's namespace is a bug. `defender.*` is the Microsoft Defender XDR
  advanced-hunting tables (#106) — log-only blob collectors, a peer domain to the
  others (not folded into entra/m365). On by default when `blob_ingest` is
  configured (read-only Azure Storage ingest, not a beta Graph surface) — they are
  NOT `Experimental`, which is now reserved for genuine Graph *beta* APIs only
  (#183). Setting `blob_ingest.account_url` is the whole opt-in. `mdca.*` is
  Microsoft Defender for Cloud Apps (#145) — the Cloud Discovery governance-log
  parse-health signal, a peer domain reached over the **legacy portal API** (NOT
  Graph): a static `Authorization: Token` credential, no azidentity/app-role scope,
  no Graph successor — so `mdca.discovery_parse` IS `Experimental`, and setting the
  tenant's `mdca.portal_url` + `mdca.token_file` is the opt-in.
- **Two opt-in interfaces, gated identically, meaning different things** (#254).
  `Experimental` = a genuine Graph *beta* surface (#183). `HighVolume` = a firehose
  whose rate scales with **traffic**, not tenant size (`m365.message_trace` is one
  record per message per recipient). Both register only when config explicitly
  enables them. Do not reach for `Experimental` to mean "expensive": it would tell
  an operator a GA endpoint is beta while hiding the one fact they need. A
  `HighVolume` collector MUST carry a **measured** volume figure in its
  `collectordoc` annotation — "high volume" with no number is not something anyone
  can plan capacity against.
- **`tenant_id` is on EVERY signal** — domain and self-obs, metrics and logs (#143).
  `telemetry.WithTenant` stamps it at the emitter boundary, so no collector sets it
  itself: `Deps.TenantID` is for the collector's own use (URLs, prefixes, checkpoint
  keys), never for labeling. An empty tenant stamps nothing. It is deliberately a
  **metric** label — the opposite of `ingest_transport` below — because without it two
  tenants' domain metrics are the *same series*, not merely unsliceable. It never means a
  tenant named inside a record: `/security/alerts_v2` carries its own `tenantId` holding
  the same value (live-measured), and graph2otel deliberately does not map it.
- **Every log record names its transport**: `ingest_transport` ∈ `graph` / `blob` /
  `o365_activity` / `audit_query` / `report_export` (#141). It is stamped at the **emitter
  boundary** (`telemetry.WithTransport`), not in the engines — 15 collectors emit with no
  engine, and `exportjob` never emits at all. Outermost stamp wins: the Scheduler sets the
  `graph` baseline, each engine and the 3 export collectors override it. **Log-only** — a
  metric label would change series identity (#82). It is deliberately NOT called `source`
  (four live meanings). Attribute-name registry work is the open half of #141.
- **Sign-ins are transport-identical; risk is NOT.** A blob and a Graph sign-in differ only
  by `ingest_transport` (one shared mapper, gated). Risk records differ in their field set
  (`riskType` is blob-only and does not exist on Graph v1.0) — so do not generalize the
  sign-in case, which is what #141/#138 reason from. See `docs/signals.md`.
- **Log attributes are Loki structured metadata, not stream labels** (#90, live). Only
  `service_name` is a stream label, so `{event_name="entra.signin"}` matches **zero rows
  silently** — the most common way to build an alert that never fires. Always
  `{service_name="graph2otel"} | event_name=…`. See `docs/signals.md`.
- **OTLP→Prometheus normalization is real** (#82): gauges gain
  `_ratio`/`_seconds`/`_percent`, counters `_total`. Dashboards/alerts use normalized names.
- **OTEL lockstep:** `go.opentelemetry.io/otel` (v1.44.0) and `otel/sdk/log` (v0.20.0)
  bump together, never independently (Renovate-grouped).
- **A collector that ASSUMES a value set declares it to `internal/wirecheck`** (#233/#234).
  Every load-bearing fact here was measured, and a measurement is true of one tenant at one
  moment; when Microsoft adds an enum member the API still answers 200 and the collector
  quietly buckets it to `"unknown"`. Watch the fields whose value keys a **metric label** —
  there an unmapped member moves series membership, so the number itself becomes wrong.
  **Derive the `Enum` from the map the collector already keys on**, never restate it, so the
  watched set cannot drift from the mapped set. Report-only: an unexpected value must never
  drop a record. **Where no evidence exists — no fixture, no live sample, no constant the
  code keys on — leave the field UNWATCHED and say so in the package doc.** One observed
  value is not a value set, and a watchdog that fires on correct data is worse than none:
  it trains the reader to ignore the signal. ~12 collectors are unwatched on exactly these
  grounds and that is a recorded decision, not a backlog. See `docs/signals.md`.

## Cardinality: metrics carry aggregates, logs carry entities

**A data-modeling rule, not a privacy control** (#112 — the old "PII guidance" framing
caused real bugs #110/#111 and a third recurrence on #100). graph2otel exports UPNs,
device serials, IPs, group membership to the OTLP backend **by design**; the backend is
a trusted sink and scoping its credentials is the actual control. The rule only decides
*which pipeline* each shape of data takes, justified by cost and queryability:

- **Per-entity data never becomes a metric label.** Grafana Cloud bills on active
  series; a series keyed by UPN/device/sign-in grows with tenant size or gets one sample
  ever. A LogQL `count by` over the log twin answers the same question free.
- **Metrics carry bounded, tenant-shaped aggregates** — counts by state/OS/policy/risk
  level. A series whose cardinality grows with tenant size is a bug.
- **HARD RULE — "not a metric label" means LOG TWIN, never dropped** (#114). A collector
  that fetches per-entity rows, buckets a count, and discards the rest is a bug: it can
  answer "how many" but never "which one". `telemetry.Emitter` exposes `LogEvent`;
  `entra/risk` is the reference shape (bounded gauge + one log per entity, one fetch).
- **Bounding a metric is CENTRAL now, not per-collector** (#235). `internal/telemetry`'s
  limiter caps every metric at `cardinality.per_metric_limit` (5000) and the process at
  `cardinality.global_limit` (100000), keeping the top series by value and folding the
  tail into a named `other` bucket — additive metrics get the tail summed, non-additive
  ones (score/ratio/percent/duration, decided from the UNIT) get it dropped and counted,
  because a fabricated aggregate is worse than the loss. The OTEL SDK's own cap is
  disabled; ours supersedes it. **Do not write a new per-collector allow-list** — the two
  that existed were retired here, and both had discarded 100% of the live data on m7kni
  while reporting healthy. New units must be classified in `internal/semconv/additive.go`
  or CI fails.
- **The limiter is NOT permission to label by entity.** With a 5000 cap on a 50k-user
  tenant, a UPN label buys an arbitrary 5000 series plus a meaningless bucket, at full
  cost, answering nothing the log twin does not answer better. The two rules above stand
  unchanged.
- **The one content exclusion is SECRETS, not PII, and it is exactly one field:**
  `intune/auditevents` emits the *names* of changed `modifiedProperties` but never their
  old/new *values* (for a credential change, the value IS the credential). **Do not
  generalize it by feel** — an "awkward to model" argument is not an "unsafe to ship"
  argument; that mistake shipped three times (#110/#111, then `ExtendedProperties` on
  #100, now emitted). Change it only on evidence of a secret observed in a field.
- Default to read-only, least-privilege scopes.

## Domain reference docs — read before touching the matching area

| area | doc | contents |
| --- | --- | --- |
| Any Graph/Intune/Purview endpoint work | `docs/graph-api-gotchas.md` | every live-verified API quirk: page-size ceilings, beta-only filters, throttle table, Intune export traps, Purview label state, permanent-gap ledger, probe rules |
| Anything blob-shaped | `docs/blob-ingest.md` | layout, byte-offset cursor design, backfill/freeze behavior, at-least-once duplicates, per-category envelope mapping rules |
| `m365.activity` / O365 Management API | `docs/o365-management-api.md` | wire-format traps (CreationTime, PascalCase, unknown record types), AF20024, 24h window cap, arrival-clock dedupe rules |
| Signal naming + LogQL | `docs/signals.md` | event names, structured-metadata querying, tenant_id truth |
| Adding/changing a **beta** endpoint | `docs/api-drift.md` | the beta drift canary: `spec/graph-beta-surface.json` must list every beta-consuming package (gated both ways), then `make graphdrift-update` |

These docs carry the deep lore that used to live in this file. **They are current-truth
references with evidence tags — keep them that way** (state the truth positively; leave
correction narratives in task notes).

## Top traps (the ones that bite across all areas)

- **Four separate sign-in pollers** are required; the `signInEventTypes` filter is
  beta-only; streams sharing a Graph path need distinct `CheckpointKey`s. [live, M3]
- **No delta query on any log endpoint** — every `WindowCollector` owns its watermark.
- **Client-side rate limiters are not optional** — reporting 5/10s, Identity Protection
  1/s per tenant across ALL apps, Intune export 48/min, none send `Retry-After`.
- **Per-endpoint `$top` ceilings 400 when exceeded** (IPC 500, `/security/incidents` 50)
  — check whenever a paged collector 400s.
- **An empty Loki query is not evidence of a drop.** Backdated log records are indexed
  through a late-data path and are **not queryable for some minutes** after being accepted,
  so a verification query run right after a poll returns zero rows for records that are
  there. The accept window is **7 days** and rejection is a loud per-entry HTTP 400 naming
  the limit — that error, not an empty result, is the evidence of loss
  (`live-measured 2026-07-22, #226`). This exact confusion produced both #226's false premise
  and a fabricated "4h horizon" during its own investigation. See `docs/signals.md`.
- **A green tick is not evidence of data.** Empty-collection success is the steady state
  for several collectors (risk signals on a healthy tenant, `m365.activity` defaults on
  a small tenant). A mapping bug is invisible when the list is always empty — which is
  why #129 (synthesize a risk event) exists, and why mappers are written against live
  samples, never docs or hand-written fixtures (`"platform": "windows"` was never on the
  wire — #142).
- **A milestone deferral for a milestone that has passed is unfinished work wearing a
  rationale** — no collector may cite one (the #110–#115 log-twin sweep found a lineage
  of collectors each citing the last as precedent for work never built).

## Task tracking

The tracker is **Backlog.md**, in `backlog/`, committed to git. `backlog task list --plain`
is the queue; `backlog doc list --plain` lists the durable docs. Everything below is
enforced by `.claude/hooks/backlog-guard.py` (with `.claude/hooks/backlog-guard_test.py`
covering both directions), because each failure mode is silent and unrepairable.

- **Read the fan-out protocol doc before designing a wave, and the wave operating model
  doc for this project's own rules.** `backlog doc list --plain` shows both.
- **Never use `--notes` or `--plan` bare.** They *silently replace* the whole section,
  destroying another session's writes with no warning and exit 0. Use `--append-notes`
  and `--append-plan`. This is an open upstream bug, not a misunderstanding.
- **Never hand-edit task, draft, doc, decision or milestone markdown.** Section
  boundaries are HTML-comment markers; break one and the section is *silently dropped* at
  exit 0 — the data stays in the file but is invisible to the CLI until the next write
  destroys it for real. There is no repair command; `backlog doctor` only fixes duplicate
  task IDs. `backlog/config.yml` is the one exception and is edited by hand, because
  list-valued keys cannot be set through `backlog config set`.
- **Finalize in one call**, so an interrupted session cannot leave finished work looking
  unfinished: `backlog task edit GTO-0007 --check-ac 1 --check-ac 2 -s Done`.
- **Never let two agents edit the same task.** v1.50.x fixed the edit funnel, but not
  reorder, draft saves, the TUI path, `doc update` or decision updates.
- **`backlog/` is committed, so keep new account identifiers and personal data out of
  tasks, docs and decisions** — no UPNs, device names, serials, tenant or object GUIDs,
  IP addresses. Write the shape, not the instance: "the tenant's second service account",
  `<container>/<blob>`. Aggregate counts, timings and structural findings are fine. The
  project's own vocabulary (`m7kni`, `camden`, the storage account) is *not* covered — it
  is already in hundreds of tracked files and in `README.md`, so tokenising it here would
  protect nothing; the rule is about not introducing identifiers the repo does not
  already publish. Sweep before committing:

  ```sh
  rg -ni 'DESKTOP-|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|@[a-z0-9.-]+\.(io|com|net)|\b(?:\d{1,3}\.){3}\d{1,3}\b' backlog/
  ```

  **Do not write that sweep with `rg -E`.** `-E` is ripgrep's `--encoding` flag, not
  "extended regex": it swallows the pattern as an encoding name and the sweep then matches
  nothing while exiting like a clean run. That exact mistake produced a false all-clear
  during the migration itself.
- **Statuses are `To Do`, `In Progress`, `Parked`, `Done`.** `Parked` means attempted and
  blocked, with a **concrete resume boundary** in the notes — the specific next probe or
  decision, never "needs investigation".
- **Do not build a workflow on decisions.** They are half-built upstream: no `decision
  edit`/`view`/`update`, no supersede mechanism, no status validation. Durable reference
  goes in **docs**; tasks are the unit.

`#NNN` refers to the pre-2026-08-14 GitHub issues, which were deleted — see the *Closed
GitHub issues* doc and `archive/`. New work is `GTO-NNNN`.

<!-- BACKLOG.MD GUIDELINES START -->
<!-- backlog.md-instructions-version: 1.50.1 -->
<CRITICAL_INSTRUCTION>

## Backlog.md Workflow

This project uses Backlog.md for task and project management.

**For every user request in this project, run `backlog instructions overview` before answering or taking action.**

Use the overview to decide whether to search, read, create, or update Backlog tasks.

Before task lifecycle actions, read the matching detailed guide:
- `backlog instructions task-creation` before creating or splitting tasks
- `backlog instructions task-execution` before planning, changing status or assignee, adding a plan or implementation notes, or implementing task work
- `backlog instructions task-finalization` before checking acceptance criteria, writing final summaries, or moving tasks to terminal statuses

Use `backlog <command> --help` before running unfamiliar commands. Help shows options, fields, and examples.

Do not edit Backlog task, draft, document, decision, or milestone markdown files directly. Use the `backlog` CLI so metadata, relationships, and history stay consistent.

</CRITICAL_INSTRUCTION>
<!-- BACKLOG.MD GUIDELINES END -->
