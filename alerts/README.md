# graph2otel — example alert rules

Example Grafana alert rules that complement the dashboards in `../dashboards/`.
One file:

- [the generated manifests](graph2otel-alerts.yaml) — Grafana-managed alert
  rules (file provisioning: `apiVersion: 1` + `groups:`). **Generated** by
  [`grafana/build_rules.py`](../grafana/build_rules.py) (#219) — do not
  hand-edit it; `make grafana-check` fails on a hand-edited file. Edit the
  `RULES` list in that script, then run `make rules`. This file (the prose
  below) stays hand-authored: the generator never touches it.

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

**Rules:** `g2o-collector-staleness` (primary), `g2o-checkpoint-persist-errors`
(companion).

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
5m` window and the 3x margin together are meant to absorb one slow cycle, not
zero margin.

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

## Detection examples — `graph2otel-detections.yaml` (all paused)

A second, separate file ships five **portable security detections** built on graph2otel's log
signals. They are not graph2otel health monitoring — everything above this section is. They live in
their own file, rule group and Grafana folder so the two are never confused, and so provisioning one
is not implicitly agreeing to the other.

**Every rule in that file is paused, and the generator refuses to ship one that is not.** None of
these thresholds has been measured on more than one tenant. Each carries a `tuning_required`
annotation naming the measurement it needs on *your* tenant before it is safe to enable. A detection
that fires on correct data is worse than no detection: it teaches responders to ignore the channel.

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

Nothing in the file carries a tenant id, application id, network address or geography, and a test
asserts that. Where a per-tenant value would improve a rule — an expected sign-in country, for
instance — the description says so rather than shipping a placeholder that looks like a real value.

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

```bash
python3 -c "import yaml; yaml.safe_load(open('alerts/rules/*.yaml'))"
```

Parses as well-formed YAML matching Grafana's file-provisioning shape
(`apiVersion: 1` + `groups:`, each rule the canonical `A` query → `B`
reduce(last) → `C` threshold pipeline, `condition: C`). **Full validation
needs a live Grafana** — `promtool` doesn't apply here since this is the
Grafana-managed provisioning schema, not Prometheus ruler YAML. Import the
file into a real Grafana Cloud instance (file provisioning path, or the HTTP
provisioning API, `POST /api/v1/provisioning/alert-rules`) to confirm each
rule evaluates and the seven default-enabled rules provably fire under a
synthetic bad-state condition: credential expiry, compliance ratio, collector
staleness, record integrity loss, throttle saturation, MDCA upload stoppage,
and MDCA parse failure. That step is **not done here** and is called out as
outstanding in issue #30's acceptance criteria.

## Loading

- **File provisioning** (self-hosted Grafana / Grafana Agent config): drop
  the file in `/etc/grafana/provisioning/alerting/` and restart Grafana. It
  creates the `graph2otel` folder and the rule group.
- **Grafana Cloud:** file-provisioning isn't importable via the UI directly;
  use Terraform (`grafana_rule_group`) or
  [Grizzly](https://grafana.github.io/grizzly/), which consume this same
  file-provisioning model, or the HTTP provisioning API.

graph2otel ships no contact point, notification policy, or route — that is an
explicit operator decision this repository does not make for you (#293/#296).
Wire your own receiver and notification-policy route against the
`pipeline`/`severity`/`source`/`category`/`component` labels documented in
[Operator-owned routing](../docs/deploying-observability.md#operator-owned-routing),
which also gives a worked example route.
