# Grafana annotations

graph2otel can publish a curated, closed set of Microsoft domain events into Grafana as
**annotations**, so a dashboard explains *"what changed at 14:00"* without any external
automation. It is **opt-in and off by default**.

## This is graph2otel's one non-OTLP egress path

graph2otel is OTLP-push-only: no Prometheus endpoint, no generic output framework, no Event
Hub, no Log Analytics pipeline. That invariant was **narrowly amended** for annotations and
nothing else. The annotation writer speaks exactly one call — `POST /api/annotations` — to
exactly one destination, and metrics and logs do not gain a second path. The narrowness is
carried by the service-account token's scope; see [The required Grafana
permission](#the-required-grafana-permission).

Nothing here polls Microsoft Graph. Annotations are derived from records the existing
collectors already emit, observed at the telemetry emitter boundary. There is no Graph client
in `internal/annotations`, and enabling the feature adds **no new endpoint and no new Graph
scope**.

## Enabling it

Setting `grafana_annotations.url` is the whole opt-in. Unset (the default) registers no writer,
opens no client, and logs nothing.

```yaml
grafana_annotations:
  url: "https://grafana.example.com"
```

The token is a credential, so it comes from the environment or a mounted file, never committed
YAML:

```sh
export G2O_GRAFANA_ANNOTATIONS__TOKEN='glsa-...'
# or, for a Kubernetes/Docker secret mount:
#   grafana_annotations.token_file: /run/secrets/grafana-annotation-token
```

Every key and its default is in [Environment Variables](env-vars.md) under
`G2O_GRAFANA_ANNOTATIONS__*`.

### The required Grafana permission

Create a Grafana **service account** whose only role is **Annotations writer**
(`fixed:annotations:writer`) and issue it a token. The underlying action/scope pair the API
checks is:

| action | scope |
| --- | --- |
| `annotations:create` | `annotations:type:organization` (or `annotations:type:dashboard` when `dashboard_uid` is set) |

graph2otel requires, requests and uses **no other Grafana permission** — no dashboard read, no
alert-rule access, no folder management. A deployment that hands over a broader token still
works, but the documented minimum is annotation write, and keeping it there is what keeps
"annotations only" from quietly becoming "arbitrary Grafana write".

> Evidence class: the action/scope pair is **docs-only** (Grafana RBAC reference). The role
> name is the maintainer's specification.

### It fails fast, on purpose

If `url` is set and the token cannot actually write an annotation, **the process refuses to
start** and names the missing permission. The startup check is not a synthetic probe — it is
the real process-start annotation (see [Lifecycle marker](#lifecycle-marker)), so proving the
permission leaves no junk behind and needs no `annotations:delete`.

Discovering a dead token at the first real event would mean the annotations an operator is
relying on for incident context are simply absent at the moment they look, with nothing in the
process having said so.

## The tag contract

Every annotation carries a small, closed, low-cardinality tag set. **`graph2otel` is the
selector a dashboard annotation query should filter on**; the rest narrow it.

| tag | on | meaning |
| --- | --- | --- |
| `graph2otel` | every annotation | the root selector |
| `tenant_id:<guid>` | every annotation with a tenant | the Entra tenant, so a marker follows the tenant dropdown |
| `category:<category>` | every annotation | one of `config_posture`, `security_incident`, `service_health`, `license`, `lifecycle` |
| `rule:<rule id>` | every annotation | the curated rule that produced it (see below) |
| `severity:<value>` | when the source record carries one | alert/incident severity, or service-health classification |
| `rollup` | interval summaries only | this is one annotation summarizing an interval, not a single event |

Tags are deliberately free of entity ids and hashes: Grafana indexes annotation tags, so a
per-entity tag would grow the tag store without ever being queried.

## The curated event set

Four categories. Each is independently gated by `grafana_annotations.categories.<name>.enabled`,
and each can be switched between per-event and per-interval publishing with `.rollup`.

### `config_posture` — "what changed at 14:00"

Rolled up by default: it is the highest-volume of the four on an active tenant, and its rate
scales with administrative activity.

| rule | source signal | what qualifies |
| --- | --- | --- |
| `entra.conditional_access_policy_changed` | `entra.directory_audit` | a successful audit whose activity names conditional access |
| `intune.policy_changed` | `intune.audit_event` | a successful audit in the `DeviceConfiguration` / `Compliance` / `DeviceCompliancePolicy` category |
| `entra.admin_consent_granted` | `entra.consent_grant` | a grant whose `consent_type` is `AllPrincipals` (tenant-wide admin consent) |
| `entra.app_credential_added` | `entra.app_credential` | a credential appearing on an application |

### `security_incident` — timeline context, not a page

Individually annotated: naturally low volume, and a rolled-up count would lose the one thing an
operator needs — which incident.

| rule | source signal | what qualifies |
| --- | --- | --- |
| `entra.security_alert_active` | `entra.security_alert` | severity `medium`/`high` and status `new`/`inProgress` |
| `entra.security_incident_active` | `entra.security_incident` | severity `medium`/`high` and status `active` |

`low` and `informational` are deliberately excluded: a healthy tenant produces a steady trickle
of them, and a picket fence of low-severity markers is what stops operators reading annotations
at all.

### `service_health` — the failure that is not graph2otel's fault

Individually annotated. This is the single most useful annotation for an operator triaging a red
dashboard, because it explains collector degradation graph2otel did not cause.

| rule | source signal | what qualifies |
| --- | --- | --- |
| `m365.service_health_issue_open` | `m365.service_health_issue` | an unresolved issue |
| `m365.service_health_issue_resolved` | `m365.service_health_issue` | the same issue once resolved |

### `license` — why a collector says `limited`

Rolled up by default: a tenant-wide license change moves many SKUs at once.

This category is derived from the `entra.license.consumed` and `entra.license.enabled` **gauge
snapshots**, not from a log record — "the SKU set changed" and "a SKU is exhausted" are
comparisons between two snapshots, so they are properties of neither snapshot alone.

| rule | what qualifies |
| --- | --- |
| `entra.license_sku_added` | a subscribed SKU not in the previous snapshot |
| `entra.license_sku_removed` | a subscribed SKU that disappeared |
| `entra.license_units_changed` | a SKU's prepaid unit count changed |
| `entra.license_exhausted` | the **transition** into consumed >= enabled units |

Exhaustion fires on the transition only. A SKU sitting at its ceiling for a month is one event,
not one per poll.

### Lifecycle marker

`category:lifecycle`, rule `graph2otel.startup`: one annotation per configured tenant per
process start, carrying the build version and a one-way, secret-free configuration
fingerprint — the same `config.fingerprint` the `graph2otel.startup` log record carries. It has
no category gate, matching that log record.

"Configuration changed" is a **comparison, not a field**: two consecutive markers whose
fingerprints differ is a configuration change, and two whose versions differ is an upgrade. The
marker itself never claims something changed.

## Volume control

Enough annotations and every dashboard becomes an unreadable picket fence, at which point
operators stop reading them and the feature is worse than absent. Four mechanisms bound it:

- **Curation.** The rule set is closed, and each rule has a predicate — a directory audit that
  is not a conditional-access change is not annotated at all.
- **Rollup.** A rolled-up category publishes one **region** annotation per
  `rollup_interval` per tenant, carrying a count and a bounded summary of at most five distinct
  titles plus a `+N more`.
- **Dedupe.** Every annotation has a stable key derived from `(tenant, rule, source identity)`
  and nothing else — no clock, no counter. A re-delivery from an overlapping poll window, or
  after a restart, derives the same key and is suppressed. The key set is persisted in the
  checkpoint directory and evicted after `dedupe_retention` (48h default).
- **Rate limit.** `max_per_minute` (60 default) is a hard ceiling on what reaches Grafana.
  Overage is dropped and counted; it is never delayed, because a marker that arrives long after
  the moment it explains is worse than absent.

State-shaped sources re-emit their **whole current set** every tick, so their first observed set
**primes silently**: publishing it would annotate every consent grant and every app credential
that already existed, at once. The residual cost is that a first-ever occurrence landing in the
very first tick after a restart is not annotated.

## Failure isolation

Nothing about annotation publishing can block or fail collection.

- Enqueueing never blocks. A full queue drops and counts.
- A Grafana outage, an expired token or a 429 is counted, logged at WARN, and otherwise
  invisible to the poller.
- The only fatal failure is at startup, deliberately.

Three self-observability metrics report it, in the same shape as OTLP delivery health:

| metric | labels | meaning |
| --- | --- | --- |
| `graph2otel_annotation_published_total` | `category`, `tenant_id` | annotations Grafana accepted |
| `graph2otel_annotation_dropped_total` | `reason`, `tenant_id` | annotations that did not reach Grafana |
| `graph2otel_annotation_degraded` | — | 1 while the most recent write failed and no later write has succeeded |

`reason` is a closed set: `duplicate`, `queue_full`, `local_rate_limited`, `unauthorized`,
`rate_limited`, `rejected`, `server_error`, `transport`.

**`reason="duplicate"` is the steady state, not a fault.** A state-shaped source re-emits its
whole set every tick and every already-published identity lands there. Alert on
`graph2otel_annotation_degraded` and on `reason="unauthorized"`, never on the duplicate count.

`graph2otel_annotation_degraded` carries no `tenant_id`, and that is truthful rather than an
omission: one Grafana endpoint and one token serve the whole process, so a per-tenant series
would claim a tenant-specific fault where none exists. It is the same scope as
`graph2otel_otlp_delivery_degraded`.

## Content safety

No secret and no raw effective configuration ever reaches annotation text.

Annotation text is built from a **per-rule allow-list** of attribute keys, never from the whole
attribute map, so a field added to a source record later cannot silently ride out to Grafana.
The lifecycle marker carries the version and the one-way fingerprint, never the configuration.

The [cardinality rule](pii-cardinality-audit.md) is unaffected: annotations are neither metrics
nor logs, and the tag set carries no per-entity value.

## Persistence

The dedupe key set lives in `checkpoint_dir` alongside the collectors' watermarks, under
`grafana-annotations` per tenant. It needs the **same persistent volume**: without one, every
restart republishes everything inside the source collectors' overlap windows. The Helm chart
defaults to an `emptyDir`, so production installs must set `persistence.enabled=true`.
