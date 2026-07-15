# graph2otel — example alert rules

Example, hand-authored Grafana alert rules that complement the dashboards in
`../dashboards/`. Two files:

- [`graph2otel-alerts.yaml`](graph2otel-alerts.yaml) — Grafana-managed alert
  rules (file provisioning: `apiVersion: 1` + `groups:`).
- [`graph2otel-contactpoints.yaml`](graph2otel-contactpoints.yaml) — a
  documented no-op contact point + root notification policy, so the rule
  group has somewhere to attach. **Replace it** with your own receiver before
  relying on these alerts to page anyone.

Ten rule objects across four alert categories, matching the four bullets in
tracking issue #30: credential/token expiry, compliance drop, collector
staleness, and throttle saturation. Each category ships one **primary** rule
(`isPaused: false`) plus one or more **companion** rules (`isPaused: true`) —
a different source metric or severity tier for the same failure mode. This
mirrors the default-disabled pattern in the sibling `tailscale2otel` repo's
`deploy/alerts/tailscale2otel.grafana-rules.yaml`: enable a companion in the
Grafana UI once you've decided it fits your tenant.

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

Every metric carries a `tenant_id` label. Every rule groups `by (tenant_id,
…)` (or aggregates `by (tenant_id)` alone), so a rule fires **per tenant** —
one alert instance per tenant crossing the threshold, not one alert for the
whole fleet. The `{{ $labels.tenant_id }}` annotation template surfaces which
tenant is affected.

## `datasourceUid`

Every Prometheus query uses the portable Grafana Cloud default,
`"grafanacloud-prom"` (same convention as `tailscale2otel`). Replace it with
your actual Prometheus/Mimir datasource UID (`gcx datasources list`, or
Connections → Data sources in the Grafana UI) before importing.

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

**Threshold rationale:** the primary fires at `> 3600` seconds — documented
as "3x a 20-minute default poll interval." **This is a placeholder, not a
tuned default** — replace `3600` with 3x *your* configured collector
interval in seconds (e.g. an hourly collector wants `> 10800`). The companion
fires on any increment (`> 0`) over a 15m window with `for: 0m` — even one
failed persist is worth a (paused, low-severity) notification, since it's a
data-durability signal, not a noisy one.

**False positive looks like:** a long-running Graph API call near a
collector's interval boundary can transiently push staleness above a
too-tight multiple; 3x margin is meant to absorb one slow cycle, not zero
margin. If a tenant's poll interval is deliberately very short (seconds), a
static 3600s floor may never trip even when genuinely stale — scale the
threshold to the interval, don't hardcode 3600.

**Applicability:** self-obs metrics are emitted by every running collector,
so this rule applies to all of them uniformly; `noDataState: Alerting` on the
primary (not the group default `OK`) because a fully missing series here
means the exporter process died or that collector was removed — same
semantics as `tailscale2otel`'s `ExporterDown`.

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
sensitivity. The companion tracks `graph2otel_throttle_limit_percentage` (from
Graph's `x-ms-throttle-limit-percentage` response header, when present)
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

## Validating

```bash
python3 -c "import yaml; yaml.safe_load(open('alerts/graph2otel-alerts.yaml'))"
python3 -c "import yaml; yaml.safe_load(open('alerts/graph2otel-contactpoints.yaml'))"
```

Both parse as well-formed YAML matching Grafana's file-provisioning shape
(`apiVersion: 1` + `groups:`/`contactPoints:`/`policies:`, each rule the
canonical `A` query → `B` reduce(last) → `C` threshold pipeline,
`condition: C`). **Full validation needs a live Grafana** — `promtool` doesn't
apply here since this is the Grafana-managed provisioning schema, not
Prometheus ruler YAML. Import the file into a real Grafana Cloud instance
(file provisioning path, or the HTTP provisioning API,
`POST /api/v1/provisioning/alert-rules`) to confirm each rule evaluates and
the four primary rules provably fire under a synthetic bad-state condition —
that step is **not done here** and is called out as outstanding in issue #30's
acceptance criteria.

## Loading

- **File provisioning** (self-hosted Grafana / Grafana Agent config): drop
  both files in `/etc/grafana/provisioning/alerting/` and restart Grafana. It
  creates the `graph2otel` folder and the rule group.
- **Grafana Cloud:** file-provisioning isn't importable via the UI directly;
  use Terraform (`grafana_rule_group` / `grafana_contact_point` /
  `grafana_notification_policy`) or [Grizzly](https://grafana.github.io/grizzly/),
  which consume this same file-provisioning model, or the HTTP provisioning
  API.

Wire the `severity` (`critical`/`warning`) and `category`
(`credential-expiry`/`compliance`/`self-observability`/`throttle`) labels
into your own notification policy routes once you replace the no-op contact
point.
