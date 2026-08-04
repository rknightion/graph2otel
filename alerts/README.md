# graph2otel — example alert rules

Example Grafana alert rules that complement the dashboards in `../dashboards/`.

`rules/` holds one **Grafana App Platform** `AlertRule` manifest per rule
(`rules.alerting.grafana.app/v0alpha1`), **generated** by
[`grafana/build_rules.py`](../grafana/build_rules.py) — do not hand-edit them;
`make grafana-check` fails on a hand-edited file. Edit the `RULES` or
`DETECTIONS` list in that script, then run `make rules`. This file (the prose
below) stays hand-authored: the generator never touches it. Deploy with
`make rules-push`, documented in
[Deploying observability](../docs/deploying-observability.md).

**Per-rule runbooks live on the docs site:**
[Alert runbooks](https://m7kni.io/graph2otel/runbooks/). Every rule carries a
`runbook_url` annotation pointing at its own section there, plus
`__dashboardUid__` + `__panelId__` so Grafana renders a link to the panel showing
the same signal. Both are generated from the rule uid and from
`dashboards/graph2otel.json`, and `make grafana-check` fails on a runbook anchor
or panel that does not exist (#307). The doc blocks below carry the design
rationale — thresholds, why a companion exists, what was rejected; the runbook
page carries what to *do* when one fires.

graph2otel ships **rules only** — no contact point, notification policy, or
route in any form (#293/#296). Every rule instead carries a stable, documented
label set (`pipeline`/`severity`/`source`/`category`, plus an optional
`component` on two rules) so you can write your own notification-policy route
against it — see
[Operator-owned routing](../docs/deploying-observability.md#operator-owned-routing)
for the label reference and a worked example route. A repository-content gate
rejects any future committed file under `alerts/` that
looks like a contact point, policy, or route.

Fourteen rule objects across six alert categories, matching the four bullets in
tracking issue #30 (credential/token expiry, compliance drop, collector
staleness, throttle saturation) plus MDCA Cloud Discovery parse health added by
#145 and record-integrity accounting added by #269. Each category ships one
**primary** rule (`isPaused: false`) plus one or more **companion** rules
(`isPaused: true`) — a different source metric or severity tier for the same
failure mode; the MDCA category ships two
default-enabled rules instead, since neither covers the other's failure mode
(see doc block 5). This mirrors the default-disabled pattern in the sibling
`tailscale2otel` repo's `deploy/alerts/tailscale2otel.grafana-rules.yaml`:
enable a companion in the Grafana UI once you've decided it fits your tenant.

## Metric naming: OTLP → Prometheus normalization

graph2otel emits **OTLP** metrics. Grafana Cloud (Mimir) normalizes names on
ingest: dots become underscores, and unit/type suffixes get appended
(`_total` on counters, `_seconds`, `_ratio`, …). Every `expr` below queries
the **normalized** form — e.g. `entra.credentials.expiring.total` becomes
`entra_credentials_expiring_total`, `graph2otel.scrape.staleness` becomes
`graph2otel_scrape_staleness_seconds` (a time-unit gauge gains `_seconds`; a
unit-`1` gauge gains `_ratio`; a percent gauge gains `_percent`). The exprs
below were verified against a live Grafana Cloud Mimir. Exact normalization
still depends on your OTLP→Prometheus pipeline config; some setups preserve
original names or omit suffixes — adjust the query if yours differs.

## Multi-tenant

Every metric carries a `tenant_id` label — domain and self-observability alike
(#143). Every rule groups `by (tenant_id, …)` (or aggregates `by (tenant_id)`
alone), so a rule fires **per tenant** — one alert instance per tenant crossing
the threshold, not one alert for the whole fleet. The `{{ $labels.tenant_id }}`
annotation template surfaces which tenant is affected.

The one exception: a deployment that configures **no tenant id** stamps no
label, and every `by (tenant_id)` rule collapses to a single unnamed group. That
is correct for a single-tenant deploy — the group is the whole deployment — but
it means `{{ $labels.tenant_id }}` renders empty. Configure a tenant id to get it
back.

This was not always true. Before #143 the label existed on `graph2otel.*` only,
so the six domain rules below grouped by a label their metrics did not have.
`sum by (tenant_id)` on a label-less metric does not return nothing — it collapses
to one unlabeled group and keeps firing — so the rules worked on one tenant and
would have silently blended a second one into the same number. The ratio rules
(`intune-compliance-ratio`, `intune-noncompliant-spike`) are where that mattered:
a blended compliance percentage is a wrong number, not a missing one.

## `datasourceUid`

Every Prometheus query uses the portable Grafana Cloud default,
`"grafanacloud-prom"` (same convention as `tailscale2otel`). Replace it with
your actual Prometheus/Mimir datasource UID (`gcx datasources list`, or
Connections → Data sources in the Grafana UI) before importing.

## Evaluator errors and no data

Every generated alert uses `execErrState: Error`. A datasource outage, invalid
query, or evaluator failure is therefore visible as an evaluation error rather
than a healthy rule. The generator rejects `execErrState: OK` unless that rule
supplies an explicit `exec_error_waiver` annotation explaining why the
silent-green behavior is intentional.

`noDataState` is configured separately. Several collectors are legitimately
healthy with no matching records, so absence remains `OK` for those rules.
Collector staleness deliberately uses `noDataState: Alerting`; each rule's
section below documents its own empty-state behavior.

## Doc block 1 — Credential & token expiry

**Rules:** `g2o-entra-cred-expiry-critical` (primary), `g2o-entra-cred-expiry-warning`,
`g2o-intune-apple-token-expiry-critical`, `g2o-intune-cert-expiry-critical` (companions).

**What/why:** app/service-principal client secrets and certificates, Apple
MDM tokens (APNS/VPP/DEP), and Intune-managed certificates all expire
silently if nobody's watching — and when they do, sign-in or device
management breaks with little warning. All four sources fire when there's
material soon-expiring inventory.

**Threshold rationale:** `entra_credentials_expiring_total` and
`intune_certificate_days_until_expiry` are **bucketed counts**, not raw
days-until gauges (per the cardinality boundary rule — never a metric label
per credential). The primary rule fires on `> 0` in the most urgent bucket
(`lt_7d`/`expired` for Entra credentials, `0d_7d`/`expired` for Intune
certificates — **note the bucket label values differ between the two
collectors**: `lt_7d`/`lt_30d`/`lt_90d`/`gt_90d`/`expired` for Entra
credential expiry vs. `0d_7d`/`7d_30d`/`30d_90d`/`over_90d`/`unknown` for
Intune certificates). The paused `g2o-entra-cred-expiry-warning` companion
uses the `lt_30d` bucket as an earlier warning tier. There is no `lt_14d` /
`7d_14d` bucket in either collector — the fixed bucket boundaries are 7/30/90
days, not 7/14/30 — so "30/14/7 day thresholds" collapses to the two buckets
that actually exist (7d and 30d); tune your own bucket boundaries in the
collector if 14d matters to you.

`intune_apple_token_days_until_expiry` is the one raw days-remaining gauge in
this group (per-`token_name`, but the Apple token set is tiny and
admin-configured — typically 1-5 tokens — so this is a bounded, not
per-entity, dimension). Its threshold (`< 14`) is an exact day count rather
than a bucket boundary.

**False positive looks like:** a credential that was already scheduled for
rotation and is expiring on purpose (the alert can't distinguish "expiring
and forgotten" from "expiring and already being replaced" — that's an
operational process gap, not a query bug). A cert/credential inventory that
churns fast (short-lived certs by design) will also stay perpetually in the
`lt_30d` bucket — if that's expected for your tenant, only enable the `lt_7d`
critical tier.

**Applicability:** the Entra credential rule needs the `entra.credential_expiry`
collector enabled (default on). The Apple token rule only produces data for
tenants that actually use Apple MDM (APNS cert configured, VPP tokens, or DEP
onboarding settings) — otherwise the series is simply absent, which is why
`noDataState: OK`. The Intune certificate rule needs the `intune.certificates`
collector enabled (beta, opt-in).

## Doc block 2 — Compliance drop

**Rules:** `g2o-intune-compliance-ratio-low` (primary),
`g2o-intune-compliance-noncompliant-spike` (companion).

**What/why:** `intune_compliance_devices{state=...}` is the Intune compliance
rollup. The primary rule tracks the compliant fraction of the fleet; the
companion tracks a sharp swing in the non-compliant count even before the
fraction crosses the primary's threshold.

**Threshold rationale:** primary fires when
`compliant / total < 0.9` — a round, conservative "10% of your fleet is
out of compliance" starting point with no fleet history to calibrate
against. The `and sum(...) >= 5` guard on both rules suppresses firing on
tiny fleets (a 2-device pilot tenant where one device going non-compliant is
a 50% swing). The companion fires when the non-compliant share rises by more
than 10 percentage points within an hour (`delta(...) / total > 0.1`) — a
faster, absolute-swing signal for a big compliant fleet where the ratio alone
takes a while to cross 90%.

**False positive looks like:** a scheduled compliance re-evaluation window
right after a new policy rollout (devices transiently drop out of
`compliant` before checking in against the new baseline) — widen `for` or the
threshold if your tenant does frequent policy pushes. The `>= 5` guard is
itself a source of a *false negative* on genuinely tiny fleets; raise or
lower it to match your smallest real tenant.

**Applicability:** needs the `intune.compliance` collector enabled — inapplicable
(no data, `noDataState: OK`) if Intune device compliance isn't configured for
that tenant, or the collector is disabled.

## Doc block 3 — Collector staleness

**Rules:** `g2o-collector-staleness` (primary),
`g2o-collector-degraded-sustained` and `g2o-checkpoint-persist-errors`
(companions).

**What/why:** `graph2otel_scrape_staleness_seconds` (from `#9`) is seconds since a
collector's last *successful* scrape — the same signal covers both a
SnapshotCollector going quiet (Graph calls failing) and a WindowCollector's
watermark stalling (log-shaped endpoints have no delta query, so a stuck
watermark silently stops advancing). The companion,
`graph2otel_checkpoint_persist_errors_total`, catches a narrower failure:
the window succeeded but its watermark isn't reaching disk, so a restart can
re-poll or drop an already-processed window depending on the checkpoint
store.

**Threshold rationale (#299 — interval-aware, replacing the fixed placeholder):**
the primary used to fire at a hand-picked `> 3600` seconds ("3x a 20-minute
default poll interval"), which was wrong for anything but a ~20-minute
collector — graph2otel's collectors range from minutes to 24h. It now fires on
`graph2otel_scrape_staleness_seconds / graph2otel_collector_expected_interval_seconds
> 3`: each collector's own staleness divided by ITS OWN effective poll interval
(`graph2otel.collector.expected_interval`, the scheduler's resolved value —
reflecting a clamped or defaulted interval, never the raw config override), so a
5-minute and a 24-hour collector each get a correct threshold with no manual rule
edit. Both metrics carry exactly `(tenant_id, collector)`, so the division is a
plain one-to-one vector match — no `on()`/`ignoring()` needed. The multiplier is
`3`, not `2`: several workloads have mandatory client-side rate limiters
(reporting 5/10s, Identity Protection 1/s per tenant, Intune export 48/min) that
make an occasional missed poll routine rather than a fault, and 3x is the margin
that tolerates one missed poll plus backoff jitter without paging on that. The
companion fires on any increment (`> 0`) over a 15m window with `for: 0m` — even
one failed persist is worth a (paused, low-severity) notification, since it's a
data-durability signal, not a noisy one.

**False positive looks like:** a long-running Graph API call near a collector's
interval boundary can transiently push the ratio above 3 for one cycle; the `for:
10m` window and the 3x margin together are meant to absorb one slow cycle, not
zero margin.

**What staleness deliberately stopped covering (#408), and what took it over:** a
collector that meets a permanent tenant-entitlement 403 *declines* its run — it
records `permission_denied`, returns no error, and stamps last-success — so
staleness stays flat and the primary rule stays silent. That is the point: an
unlicensed endpoint can never be actioned, and this rule paged **critical**
against three of them continuously for four days on m7kni before the fix. A 403
the collector could not handle still returns an error and still climbs staleness,
so a hard authorization failure has not gone quiet. The gap that opened was a
genuinely *revoked* consent grant, which produces the same declined outcome and
is very much actionable; `g2o-collector-degraded-sustained` covers it at
**warning** on `graph2otel_scrape_success_ratio` staying `0` across a 6h window.
That metric is level-triggered — re-exported on every OTLP interval rather than
only when a scrape finishes — so `max_over_time` over a fixed 6h window is
correct for a 24-hour collector without the interval division the primary needs.

**Applicability and no-data semantics — corrected (#299):** self-obs metrics are
emitted by every running collector, so this rule applies to all of them
uniformly. `noDataState: Alerting` on the primary (not the group default `OK`)
protects against the WHOLE query returning zero rows — every collector's
staleness/expected-interval pair gone at once, meaning the exporter process
died, or (the degenerate case) a tenant's only collector was removed. **It does
NOT mean, and previously mis-stated, that one collector's series disappearing
triggers it.** Grafana evaluates this multi-dimensional rule per
`(tenant_id, collector)` combination the query actually returns: when a single
collector is deliberately removed (a code change) or disabled (a config change),
its own ratio series simply stops existing on the next evaluation and that
alert INSTANCE resolves silently — the surviving collectors' instances, and the
rule's `noDataState`, are unaffected. That silent disappearance is the correct,
non-accidental outcome for a deliberately removed collector, not an omission:
there is nothing left to alert on for a signal nothing emits anymore.

## Doc block 4 — Throttle saturation

**Rules:** `g2o-throttle-saturation` (primary),
`g2o-throttle-budget-consumption` (companion).

**What/why:** graph2otel's client-side rate limiter (`#5`, M1) proactively
gates requests per workload (directory RU budget, reporting 5/10s, Identity
Protection 1/s, Intune general/elevated/reports-export 48/min tiers) — none of
these reliably send `Retry-After`, so a 429 always means the client-side gate
already let through more than the server wanted, and silent throttling
degrades data freshness before anything else visibly breaks.
`graph2otel_throttle_count_total` is a dedicated counter of observed 429s per
workload (`internal/graphclient/ratelimit_transport.go`), which is a cleaner
throttle signal than inferring it from generic scrape errors — this issue's
own acceptance text expected a "best-effort" signal via `scrape.errors`, but
the rate-limiter transport already emits a purpose-built counter, so the
primary rule keys on that instead.

**Threshold rationale:** primary fires when `rate(graph2otel_throttle_count_total[10m])`
is above 0, sustained for 15m — i.e. throttling that is not a one-off blip but
is still happening 10-15 minutes later. This is deliberately workload-agnostic
(any sustained throttling on any workload is worth knowing about, whether
that's the Identity Protection workload's 1 req/s ceiling or the reporting
workload's 5/10s one) rather than a per-ceiling count threshold — split by the
`workload` label (already grouped in the query) if you want workload-specific
sensitivity. The companion tracks `graph2otel_throttle_limit_percentage_percent`
(from Graph's `x-ms-throttle-limit-percentage` response header, when present)
sustaining above 80% for 15m.

**False positive looks like:** a brief burst at process startup (initial
snapshot collectors all racing to fill their first poll) can produce a
transient nonzero rate without indicating a sustained problem — the `for: 15m`
window is meant to filter that out; widen it if startup bursts routinely last
longer than that in your deployment.

**Applicability:** applies whenever any Graph workload throttles; the
companion additionally requires Graph to actually send the
`x-ms-throttle-limit-percentage` header on a 429, which isn't guaranteed on
every workload — absence of the companion's data does **not** mean the
budget is healthy, treat `g2o-throttle-saturation` as the primary signal and
the companion as a bonus when the header happens to be present. A dedicated
per-workload budget-consumption gauge (rather than only-on-429 header
capture) is a plausible follow-up if this proves too sparse in practice.

## Doc block 5 — MDCA Cloud Discovery parse health

**Rules:** `g2o-mdca-parse-failing` (default-enabled),
`g2o-mdca-uploads-stopped` (default-enabled — the one that catches a dead
pipeline).

**What/why:** a Microsoft Defender for Cloud Apps Cloud Discovery upload
(`upload_url` → PUT blob → `done_upload`) returns `200 {"success":true}` the
moment the blob lands and a parse task is **queued** — that is all it means.
The parse runs asynchronously and writes its verdict **only** to the MDCA
governance log, as a `DiscoveryParseLogTask`. So every uploader is structurally
blind to whether its data actually parsed: on the live tenant (2026-07-17) a
malformed CEF line produced **22 consecutive silent parse failures** while
every hourly upload reported green and zero transactions landed. The
`mdca.discovery_parse` collector (`#145`) is the missing poll; these two rules
turn its signals into alerts.

**Why two rules:** they catch different failures and neither covers the other.
`g2o-mdca-parse-failing` keys on
`increase(mdca_discovery_parse_tasks_total{is_success="false"}[1h]) > 0` — any
parse failure in the last hour (the `template` label names which failure). But
a **dead uploader emits no failed tasks at all**, so that rule stays green
forever while data silently stops. `g2o-mdca-uploads-stopped` covers exactly
that: `mdca_discovery_parse_last_success_age_seconds > 10800` (3h) — the age
gauge is emitted every tick from persistent state and keeps **climbing** when
uploads stop, which a failure counter structurally cannot do.

**Threshold rationale:** the failure rule fires on the first failure in an hour
(`gt 0`, `for: 5m`) — a parse failure is never normal. The silence rule's
10800s (3h) is a placeholder for ~3× your upload cadence; the live pipeline
uploads hourly, so 3h means three missed uploads. Replace both defaults with
values matched to your own cadence.

**False positive looks like:** the silence rule's `noDataState` is `OK`
because a tenant with no Cloud Discovery streams legitimately emits no series —
absence is not silence. Once a stream has parsed successfully once, its age
gauge is always present, so the rule only fires on a real stall, not on a
never-configured tenant.

**Applicability:** requires the `mdca.discovery_parse` collector to be
configured (the tenant's `mdca.portal_url` + `mdca.token_file` set); it is
opt-in and `Experimental`, since the MDCA portal API is a legacy surface with
no Graph successor. `input_stream_id` and `template` are the only labels, both
tenant-shaped and bounded.

## Doc block 6 — End-to-end record integrity

**Rules:** `g2o-record-integrity-loss` (default-enabled),
`g2o-payload-type-mismatch` (paused companion).

**What/why:** every collector run reconciles source records through
`fetched = mapped + filtered + dropped + errored` and
`mapped = emitted + deduped`. One source record counts once even when it emits
several metric points and a log twin. The primary rule watches
`graph2otel_record_outcomes_total{outcome=~"dropped|errored"}`: either outcome
means graph2otel fetched a record that did not become useful telemetry.

`dropped` is a deliberate rejection, most importantly a record with no
parseable event time — graph2otel drops it instead of silently claiming it
happened now. `errored` is decode or processing failure. Intentional filters
and overlap dedupe are separate outcomes and do not fire this rule.

The companion watches `graph2otel_payload_type_mismatches_total`. It is
report-only: an otherwise usable record is still emitted, while the metric
names the source-controlled field and the expected/actual JSON types. Field
values never enter labels or logs through this signal.

**Threshold rationale:** the integrity-loss primary fires on the first dropped
or errored record in a 15-minute window (`gt 0`, `for: 0m`). Record loss is not
a normal steady state, so it is enabled by default. The type-mismatch companion
uses the same threshold but is paused until the tenant's ordinary payload-shape
baseline is established; optional fields can vary across Microsoft workloads
without making an otherwise usable record wrong.

**False positive looks like:** a deliberately tolerated malformed source row
still appears as loss because graph2otel cannot turn it into truthful
telemetry. That is not a false measurement, but an operator may choose a wider
window or routing policy for a chronically noisy upstream. A type-mismatch alert
can be noisy if a field legitimately has several wire shapes; keep it paused,
measure the live payload, then correct the collector's expected-type set.

**Applicability:** the primary applies to every running collector and groups by
tenant, collector, and ingest transport. The companion appears only where a
collector has an explicit type expectation and observes a mismatch. Neither
metric contains source record identifiers or values.

## Detection examples — rule group `graph2otel-detections` (all paused)

Eleven **portable security detections** built on graph2otel's log signals, generated into
`rules/` from the `DETECTIONS` list alongside the health rules but placed in their own rule group and
Grafana folder (`graph2otel detections`). They are not graph2otel health monitoring — everything
above this section is. The separation is so the two are never confused, and so provisioning one is
not implicitly agreeing to the other.

**Every detection is paused, and the generator refuses to ship one that is not.** None of these
thresholds has been measured on more than one tenant. Each carries a `tuning_required` annotation
naming the measurement it needs on *your* tenant, and the query that produces that measurement is on
the [hunting-queries page](../docs/hunting.md) — a named measurement with no way to take it is a rule
nobody can safely enable. A detection that fires on correct data is worse than no detection: it
teaches responders to ignore the channel.

First wave (#300), adapted from detections running on a real tenant:

| uid | what it catches |
| --- | --- |
| `g2o-detect-privileged-directory-change` | app credential or secret added, admin consent, app-role or delegated-permission grant, new application or service principal, directory-role member added, owner added, Conditional Access policy changed |
| `g2o-detect-security-alert-unresolved` | an unresolved medium/high alert from **any** Microsoft source on the security API — Defender for Endpoint, Defender for Cloud Apps and Entra ID Protection all arrive on one stream |
| `g2o-detect-security-incident-active` | an active medium/high **incident**, the correlation layer above alerts — deliberately overlapping with the row above |
| `g2o-detect-graph-403-burst` | one application taking more than 10 Graph authorization denials in 5 minutes |
| `g2o-detect-interactive-signin-anomaly` | a real user sign-in that Conditional Access blocked, or that Entra ID Protection scored `atRisk`/`confirmedCompromised` |

The activity list in the first rule is the genuinely valuable, tenant-independent part: reconstructing
"which directory activities mean someone is establishing persistence" is the hard half of that
detection, and it is the same list on every tenant.

Second wave (#313), each one keyed on an (event, attribute) pair no rule above already asks about:

| uid | what it catches | provenance |
| --- | --- | --- |
| `g2o-detect-exchange-inbox-rule-change` | an inbox rule created, changed or removed — the rule that hides the replies is present in nearly every business email compromise | email hiding rules, MITRE T1564.008 |
| `g2o-detect-mailbox-permission-grant` | mailbox, recipient or folder permission granted: durable access that survives the owner's password reset and is invisible to them | additional email delegate permissions, MITRE T1098.002 |
| `g2o-detect-identity-risk-detection` | a medium/high Identity Protection detection, naming **why** — impossible travel, unfamiliar properties, anonymised or malicious address, leaked credentials, password spray | Entra ID Protection risk detection types |
| `g2o-detect-workload-identity-risk` | a service principal flagged `atRisk` or `confirmedCompromised` — the workload-identity half of Identity Protection, and the half nobody watches | Entra Workload ID Protection |
| `g2o-detect-legacy-auth-signin` | a sign-in over a protocol that cannot be challenged for MFA | Microsoft secure-score guidance to block legacy authentication |
| `g2o-detect-mail-remediation-failed` | Defender tried to remove an already-delivered malicious message and the removal did not land | zero-hour auto purge / post-delivery remediation |

Two things about the second wave worth stating rather than discovering:

- **Every value they match on is a Microsoft spelling this project has not measured on the wire for
  that exact field**, so every regex is case-insensitive and every tuning note names the hunt that
  confirms the spelling first. A regex that never matches is indistinguishable from a quiet tenant —
  the value-level twin of querying an attribute that does not exist.
- **Two of them key on the same `m365.audit` operation field and are still separate rules.** An inbox
  rule is usually the mailbox owner's own doing and is noisy; a delegation grant is an administrative
  act, rarer, and remediated differently. One threshold cannot serve both base rates.

All eleven carry `category=identity-threat`, which is deliberately not split further: the label's job
is to route to a security responder, and a finer split would be a routing decision made on the
operator's behalf.

Nothing carries a tenant id, application id, network address or geography, and a test asserts that.
Where a per-tenant value would improve a rule — an expected sign-in country, for instance — the
description says so rather than shipping a placeholder that looks like a real value.

### What was deliberately NOT shipped as a rule

Four concepts were considered and are documented as [hunts](../docs/hunting.md) instead. The reason
is the same each time: a rule that cannot fire, or fires forever, is worse than a query someone runs.

- **Federated identity credential added**, **standing consent grants** and **privileged role
  membership** are all **inventories**, not event streams. A snapshot collector re-emits every
  existing row on every poll, so `count_over_time(...) > 0` over one is true forever. The *act* of
  granting consent, adding a role member or adding an application credential is already covered by
  `g2o-detect-privileged-directory-change`; what these three answer is the different question of what
  is standing granted right now, which is a thing to read rather than page on.
- **Destructive Intune administrative action.** This project has only ever observed `Create` for
  `activity_operation_type` on the wire. A rule matching a deletion spelling nobody has seen might
  never fire, so the hunt takes the measurement and you write the rule against what you measured.
- **Impossible travel computed from raw sign-ins.** Loki cannot join, so correlating two sign-ins by
  distance and time is not expressible. `g2o-detect-identity-risk-detection` reads Microsoft's own
  `impossibleTravel` verdict instead — not a shortcut, the only correct way to have the detection.

### The pattern that is documented but not shipped: single-source workload identities

One detection shape is worth knowing and cannot be shipped, because it is specific by nature: a
**workload identity that legitimately signs in from exactly one place**.

Automation service principals — a CI runner, a scheduled sync job, a self-hosted integration — usually
authenticate from one network and nowhere else. Any sign-in for that application that is failed, or
from an unexpected source address, is therefore anomalous in a way that needs no baseline and no
machine learning:

```logql
{service_name="graph2otel"} | event_name=`entra.signin` | app_id=`<the application id>` | status_error_code!=`0`
```

plus an equivalent term for source address, ORed together and alerted above zero.

The reason to detect rather than prevent is a licensing one worth stating plainly: **Conditional
Access IP-locking for workload identities requires Microsoft Entra Workload ID**, a separate paid
add-on. Without it there is no way to *stop* a leaked service-principal credential being used from
anywhere in the world — but graph2otel's sign-in stream lets you *notice* within one evaluation
interval, at no extra licence cost. That is a materially better position than nothing, and it is the
main reason this pattern is documented here.

Build one rule per such application. Each is a few lines, and each is unavoidably specific to your
tenant, which is exactly why they are yours to write and not ours to ship.

## Validating

`make grafana-check` proves each manifest is well-formed, that every metric name
resolves against the generated signal catalog, that every log filter names an
attribute graph2otel really emits, and that no committed file has drifted from
the generator. It cannot prove a rule EVALUATES — that needs a live Grafana, and
`promtool` does not apply here since this is Grafana's own alert-rule schema
rather than Prometheus ruler YAML.

The outstanding live step is confirming that the default-enabled rules provably
fire under a synthetic bad state: credential expiry, compliance ratio, collector
staleness, record integrity loss, throttle saturation, MDCA upload stoppage, and
MDCA parse failure. That is **not done here**.

## Loading

`make rules-push GRAFANA_CONTEXT=<gcx-context>` deploys the health rules, and
`INCLUDE_DETECTIONS=1` additionally deploys the paused detection pack into its own
folder. `make rules-readback` compares the stack against the repository field by
field. See
[Deploying observability](../docs/deploying-observability.md) for the four
non-guessable API requirements this wraps.

graph2otel ships no contact point, notification policy, or route — that is an
explicit operator decision this repository does not make for you (#293/#296).
Wire your own receiver and notification-policy route against the
`pipeline`/`severity`/`source`/`category`/`component` labels documented in
[Operator-owned routing](../docs/deploying-observability.md#operator-owned-routing),
which also gives a worked example route.
