# Why This Exporter

*Last reviewed: 2026-08.*

Microsoft already gives you several ways to get this data out, and for some tenants one of
them is the whole answer. This page states what `graph2otel` does differently and why, so you
can decide whether it earns a place in your stack. It describes this codebase; it makes no
claims about how anything else is implemented.

## What already exists

**Diagnostic settings to Log Analytics, Event Hub or a storage account.** The native route
for Entra ID sign-in and audit logs. It is first-party, needs no service of your own, and if
your analytics live in Azure it is very hard to argue with.

**The Defender XDR and Intune portals, and Advanced Hunting.** Authoritative and interactive,
with query languages built for the data. They are consoles, not a metrics pipeline: they are
where you go to answer a question, not where a dashboard or an alert rule lives.

**Your own Graph API scripts.** For a handful of specific numbers this is often correct, and
the whole thing fits in a file you can read. Most of what follows is about what stops being
true at 170 collectors, several tenants, and a metrics bill.

## Design choices specific to this exporter

**Metrics and logs are separated by a cardinality rule, not by convenience.** Bounded,
tenant-shaped aggregates become metrics; per-entity and event detail becomes logs. A user,
device or event identifier is never a metric label. The line is drawn precisely: a series
whose cardinality grows with *tenant size* is a bug, while one bounded by the number of
*admin-configured objects* — policies, profiles, rings, agreements — is within the rule. This
is audited against the actual collector source and live-emitted OTLP, as a release gate, and
that audit corrected the documentation rather than agreeing with it. See
[PII & Cardinality Audit](pii-cardinality-audit.md).

**Silent upstream drift is treated as the main failure mode.** Graph responses decode into
fixed Go structs, so when Microsoft renames or drops a field the collector keeps returning
HTTP 200 and starts emitting zeros — a green tick over no data. The
[API drift canary](api-drift.md) is a spec diff that surfaces that on the day it lands. It
needs no tenant, no app registration and no CI secrets, which is why it can run continuously.

**The collector inventory is generated, not written.** The
[collector reference](collectors.md) is checked against the same seven registration paths the
application itself uses, so the documented inventory and the shipped one cannot disagree. A
hand-maintained list of 170 collectors is a list that is wrong.

**OTLP only, deliberately.** Native OTLP metrics and logs, pushed. There is no Prometheus
endpoint to expose, scrape or firewall — which matters for something reading tenant-wide
security data, where an inbound listener is a liability rather than a feature.

**One binary, several tenants.** Multi-tenant polling from a single static binary, rather
than one deployment per tenant.

**Least privilege is documented per collector.** [Permissions](permissions.md) states what
each collector needs, so you can grant the subset matching the collectors you actually enable
instead of consenting to everything and hoping.

## When to pick something else

**Your analytics already live in Azure.** Diagnostic settings into Log Analytics is the
shorter path, and KQL over the raw tables is more expressive than anything derived here.

**You want raw sign-in logs in a SIEM, unaggregated.** Export them natively. This produces
bounded aggregates plus structured log records, which is a different shape.

**You need a handful of specific numbers.** A small Graph script is less to run and less to
understand. The machinery above exists for drift, cardinality cost, multi-tenant scale and
permission sprawl — problems a narrow use case does not have.

**You need something Graph does not expose.** The API is the ceiling.
[Graph API Gotchas](graph-api-gotchas.md) is honest about where those edges are, including
surfaces that exist only in beta.

## See also

- [Collectors](collectors.md) — the generated inventory of all 170
- [Signals](signals.md) and [Derived Metrics](derived-metrics.md) — what is emitted
- [Architecture](architecture.md) — how the data plane fits together
- [Security](security.md) and [Permissions](permissions.md) — scope and least privilege
