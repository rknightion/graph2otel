# graph2otel

Polls Microsoft Graph (Entra ID / Intune / Defender / M365 / Purview), plus an Azure Storage
blob fallback and the O365 Management Activity API, and exports OpenTelemetry-native metrics
and logs over OTLP. Single static Go binary, OTLP push only (no Prometheus pull endpoint),
multi-tenant. It is used as a **SIEM feed**: per-entity detail in the logs is the point.
It runs in production against a live tenant.

## Task interface

- Recipes marked `[confirm]` write to a live Grafana stack. Never pass `--yes` or `JUST_YES=1`
  by hand, and run `just` with stdin from `/dev/null` so a prompt cannot be answered by
  accident. The reviewed `.github/workflows/grafana-sync.yml` invocation is the sole sanctioned
  `--yes`.
- `just check` covers all four Go modules (root, `tools/graphdrift`, and both `third_party/`
  OTLP forks) plus the generated-asset drift gates. `just ci` adds the container smoke leg.
- Committed generated artifacts are drift-gated and are never hand-edited. `docs/collectors.md`
  is generated from the collector registry and is the authoritative collector count; `just gen`
  regenerates every generated artifact.

## Working rules

- **Validate a task's premise against the live tenant before implementing**, probing as
  `graph2otel-poller` and never another app identity. Live-tenant mutations (app registrations,
  scope grants, diagnostic settings) need exact scopes named and explicit maintainer approval
  first.
- **Wire over docs.** Microsoft's documentation has been wrong on essentially every load-bearing
  detail on this project's path. Never assert API behaviour from docs alone: measure it, then
  record it with a `live-measured` tag.
- **Test-first, as a deliberate override of the global operating-model testing policy**: failing
  test, watch it fail for the right reason, minimal code, green, refactor.
- Standard-library `testing` only. No third-party assertion libraries.
- Mappers are written against live samples, never docs or hand-written fixtures.
- Conventional Commits, `type(scope): subject`. release-please surfaces
  `feat`/`fix`/`perf`/`refactor`; `docs`/`test`/`chore`/`ci`/`build` are hidden.
- The tracker is Backlog.md in `backlog/`, committed to git, and it is the record of intent and
  progress rather than this file. Its CLI has data-destroying traps: see
  `reference/backlog-workflow.md` before touching a task, doc or decision.

## Architecture (the seams)

Closest analogs in the fleet: `sf2loki`'s composition-root pattern, `tailscale2otel`'s poll to
`telemetry.Emitter` facade.

- **Raw REST for all collectors** via `internal/graphclient` (OTEL-instrumented transport,
  per-workload client-side rate limiters, own backoff, because the throttled workloads send no
  `Retry-After`). `msgraph-sdk-go` remains for exactly **one** typed call site,
  `internal/license/graphclient_adapter.go` (`subscribedSkus`); do not add typed-SDK usage and
  do not "clean up" that one. Beta endpoints go through `BaseURLOverride` plus an
  `Experimental()` opt-in, default off.
- **4 ingest engine shapes**, one per transport shape:
  - `internal/logpipeline` - watermark window polling for Graph log endpoints (no delta query
    exists on any of them; watermark + overlap + seen-id dedupe).
  - `internal/jobpipeline` + `internal/exportjob` - async create/poll/download jobs (M365 audit
    query, Intune report exports).
  - `internal/blobpipeline` - Azure Storage byte-offset consumer.
  - `internal/o365pipeline` + `internal/o365activityclient` - O365 Management Activity API
    subscription and content-blob model.
- **Collector framework** (`internal/collector`, `internal/collectors`): typed
  `SnapshotCollector` (bounded gauges plus log twins) and `WindowCollector` (event streams to
  logs). 7 registration paths: `Deps`/`All`, `WindowDeps`/`WindowAll`,
  `BlobDeps`/`RegisterBlob`, `O365Deps`/`O365All`, `MDCADeps`/`RegisterMDCA`,
  `EXODeps`/`RegisterEXO`, `HuntDeps`/`RegisterHunt`/`HuntAll`. **`internal/collectordoc` must
  walk every registration path** - a gate that cannot see a collector reports coverage it does
  not have, which has already shipped once. `collectordoc.Rows` takes one slice per path
  (`snapshot, window, blob, o365, mdca, exo, hunt`), so **adding an eighth path means changing
  that signature in the same commit**. That signature is the whole mechanism keeping the gate
  honest.
- **Telemetry emitter facade** (`internal/telemetry`) is the only thing touching OTLP. It only
  sets non-zero timestamps: a record with no parseable event time must be **dropped**, never
  stamped on arrival, which would silently claim it happened now. Undedupeable is degraded;
  misdated is wrong, and only wrong justifies a drop.
- **CheckpointStore** is file-based, namespaced per tenant and endpoint. It needs a persistent
  volume in production: the compose reference mounts one, the Helm chart defaults to an
  `emptyDir`, so production installs must set `persistence.enabled=true`. Fail fast if the
  configured checkpoint path is unwritable.
- **Transport is exclusive per collector**: `source: graph` XOR `blob`, enforced by the
  `ConflictsWith` collector interface in `internal/collectors/conflicts.go`. There is no dual
  mode, and that was decided rather than deferred: the log-shaped collectors emit zero metrics,
  so dual is identical to blob. `intune.devices` is the one genuinely dual-capable signal and
  its mode remains an open question.
- Single instance. No HA or leader election.

## Config and secrets

- **Env var prefix `G2O_`**, double-underscore nesting, koanf precedence defaults < YAML < env:
  `otlp.endpoint` becomes `G2O_OTLP__ENDPOINT`. The config surface is registry-driven with a
  drift gate; `docs/env-vars.md` is generated and a new key must register or CI fails.
- **Auth** is an Entra app registration through `azidentity.DefaultAzureCredential`
  (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` or
  `AZURE_CLIENT_CERTIFICATE_PATH`). Never in YAML. Read-only least-privilege scopes per enabled
  collector, with exactly two documented write-scope breaks: Intune reports-export job creation
  and O365 `POST /subscriptions/start`.
- Blob ingest is opt-in via one per-tenant key, `blob_ingest.account_url`. Unset registers no
  blob collectors. MDCA is opt-in via `mdca.portal_url` plus `mdca.token_file`.
- `config.local.yaml` and `.env` are gitignored.

## Top traps

- **Four separate sign-in pollers** are required: Graph cannot combine user and
  servicePrincipal/managedIdentity event types in one `signInEventTypes` filter, and the filtered
  streams are beta-only. Streams sharing a Graph path need distinct `CheckpointKey`s.
- **No delta query on any log endpoint.** Every `WindowCollector` owns its watermark.
- **Client-side rate limiters are not optional**: reporting 5 per 10s, Identity Protection 1 per
  second per tenant across ALL apps, Intune export 48 per minute. None send `Retry-After`.
- **Per-endpoint `$top` ceilings 400 when exceeded** (IPC 500, `/security/incidents` 50). Check
  this first whenever a paged collector 400s. Two Endpoint Analytics segments reject `$top`
  outright, with no ceiling to stay under, and answer 400 on one and 500 on the other for the
  same cause; page them with `Prefer: odata.maxpagesize`, which is what `collectors.GetAllValues`
  already does.
- **An empty Loki query is not evidence of a drop.** Backdated log records are indexed through a
  late-data path and are **not queryable for some minutes** after being accepted, so a
  verification query run right after a poll returns zero rows for records that are there. The
  accept window is 7 days and rejection is a loud per-entry HTTP 400 naming the limit. That
  error, not an empty result, is the evidence of loss.
- **A green tick is not evidence of data.** Empty-collection success is the steady state for
  several collectors (risk signals on a healthy tenant, `m365.activity` defaults on a small
  tenant). A mapping bug is invisible when the list is always empty.
- **A milestone deferral for a milestone that has passed is unfinished work wearing a
  rationale.** No collector may cite one.

## Deeper references

| Read before | Doc | What it holds |
| --- | --- | --- |
| Adding or changing any metric, log attribute, namespace or opt-in gate | `reference/telemetry-model.md` | namespaces, `Experimental` vs `HighVolume`, `tenant_id` and `ingest_transport` stamping, the `wirecheck` value-set watchdog, the cardinality boundary and the one secret exclusion |
| Creating, editing or finalising a Backlog task, doc or decision | `reference/backlog-workflow.md` | the flags that silently replace a section, the unrepairable hand-edit, statuses and evidence classes, the identifier sweep, what `#NNN` resolves to |
| Any Graph/Intune/Purview endpoint work | `docs/graph-api-gotchas.md` | every live-verified API quirk: page-size ceilings, beta-only filters, throttle table, Intune export traps, Purview label state, permanent-gap ledger, probe rules |
| Anything blob-shaped | `docs/blob-ingest.md` | layout, byte-offset cursor design, backfill and freeze behaviour, at-least-once duplicates, per-category envelope mapping |
| `m365.activity` or O365 Management API work | `docs/o365-management-api.md` | wire-format traps (CreationTime, PascalCase, unknown record types), AF20024, the 24h window cap, arrival-clock dedupe |
| Naming a signal or writing a LogQL query | `docs/signals.md` | event names, structured-metadata querying, `tenant_id` truth |
| Adding or changing a **beta** endpoint | `docs/api-drift.md` | the beta drift canary: `spec/graph-beta-surface.json` must list every beta-consuming package, gated both ways, then `just graphdrift-update` |

These docs are current-truth references with evidence tags. Keep them that way: state the truth
positively and leave correction narratives in task notes.

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
