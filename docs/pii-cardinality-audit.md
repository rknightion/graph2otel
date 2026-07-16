# PII & cardinality audit (pre-1.0 release gate)

Audits every metric label set and every log attribute emitted by every shipped
collector against the cardinality boundary rule in `CLAUDE.md` and `SECURITY.md`,
and reviews the Graph API permission scopes each collector requests. Tracks issue
#33; a completed pass is a prerequisite for the v1.0.0 tag (#35).

The audit was run against the **actual** collector source and live-emitted
telemetry (the M2–M5 stdout OTLP captures), not the documentation's aspirational
description — the docs' sensitivity list predated the collectors, and this audit
is what confirms or corrects it.

## The rule being enforced

High-cardinality, per-entity data (per-user, per-device, per-sign-in identity —
UPNs, device/user/object IDs, IP addresses, correlation IDs, serial numbers,
thumbprints) is **never** a metric label. It belongs in the **logs** pipeline as
structured attributes. Metrics carry only bounded, tenant-shaped aggregates —
counts by state / OS / policy / risk level / severity. A metric series whose
cardinality grows with **tenant size** (users, devices, sign-ins) is a bug; a
series bounded by the number of **admin-configured objects** (policies, profiles,
rings, agreements — dozens to hundreds) is within the rule.

**This is a data-modeling rule, not a privacy control** (#112). It is enforced for
cost and queryability — active-series billing, and the fact that a series keyed by
a sign-in ID gets exactly one sample — not to withhold data from the backend. The
"PII" in this document's title describes **what is exported and where it lands**;
it does not describe an exclusion. Everything in `SECURITY.md`'s sensitivity list
is exported by design.

The rule's **second half**, added after this audit's original pass: per-entity data
too high-cardinality for a metric label MUST still be emitted as a **log twin** —
never dropped. The original audit checked only that nothing leaked *onto a metric*,
which is why it passed two collectors (`entra.risk`, the Purview label collectors)
that were silently discarding per-entity detail entirely. Those were fixed in #110
and #111. **An audit pass must now check both directions**: nothing per-entity on a
metric label, AND nothing per-entity fetched-then-dropped without a log twin.

## The both-directions sweep (complete, #114)

All 38 snapshot collectors were audited in the second direction. Roughly 20 are pure
`$count`/pre-aggregated-report shapes — no per-entity data ever reaches memory, so
there is nothing to drop. Twelve had the decode-and-drop shape and now emit a log
twin: `entra.roles`, `entra.consent`, `entra.credential_expiry`,
`entra.signin_activity`, `entra.mfaregistration`, `entra.domains`, `entra.risk`,
`intune.malware`, `intune.manageddevices`, `intune.certificates`,
`intune.appprotection`, plus the two Purview label collectors.

**One more was missed by that sweep and fixed in #83:** `intune.app_install_status`.
The sweep recorded `intune/defenderreport` and `intune/certinventoryreport` as the
export-report collectors that "already emit a log twin" and moved on — but the third
export-report collector had the same shape and no twin: it fetched a row per app,
bucketed a device count, and discarded the rest. It was missed because this document
already *claimed* it emitted per-row logs (see Logs below), so a sweep checking the
docs rather than `grep LogEvent` on the package would tick it off. **A wrong claim in
an audit doc does not just fail to catch a bug — it actively hides it from the next
audit.** Check the source, not this file.

**Two are audited, deliberate exceptions with no twin** — recorded here so a future
sweep does not re-litigate them, and documented in their package docs:

- `entra.agreements` — ToU acceptance is a legal/HR/compliance question, not a
  security signal.
- `intune.endpointanalytics` — boot/startup performance is an ops question; the
  Intune console answers it better.

**Root cause worth remembering.** These were not accidents. `signinactivity` deferred
its twin to "M3/M5" *"consistent with the credential-expiry collector's decision"*,
and `malware` deferred to `windowsDeviceMalwareStates` "deferred to M5" — a lineage of
collectors each citing the last as precedent for deferring work that never got built,
with the "PII guidance" framing making the deferral look principled. No collector
should cite a milestone deferral for a milestone that has passed; if one does, it is
unfinished work wearing a rationale.

## Scope of the review

30 collector packages (18 Entra, 12 Intune families) + the framework
self-observability metrics + the `internal/exportjob` self-obs. Every
`Gauge`/`GaugeSnapshot`/`Counter`/`Histogram` call and its label keys; every
`LogEvent` attribute set; every `RequiredPermissions()`.

## Metrics — PASS (zero cardinality-boundary violations)

**No metric label anywhere carries a device ID, serial, IMEI, UPN, user ID, IP
address, or per-sign-in/per-event identifier.** Every metric label resolves to
one of:

- a **bounded enum / bucket** — compliance state, OS, trust type, risk level,
  severity, connector type, install state, expiry bucket, health signal, etc.;
- a **fixed threshold** — `threshold_days` (30/90), staleness buckets;
- an **admin-configured object name** — `policy_name`, `profile_name`,
  `ring_name`, `script_name`, `report_name`, `baseline_name`, `cert_profile_name`,
  `token_name`, `intent_name`, `config_name`. These are bounded by the count of
  objects an admin has created (dozens–hundreds), **not** by tenant size, and are
  capped with an `"other"` leftover where the source is free-text (autopilot
  `group_tag`, cert `issuer`, detected-app / UXA app-name allow-lists). Within
  the rule.

**Corrected by #83 — this section's original PASS was wrong.** It classified
`intune.app_install_status`'s `app_name` under "admin-configured object name"
above and passed it on that basis. Live data refuted both halves of that
classification: the AppInstallStatusAggregate report returns a row for every app
in the tenant's Intune **catalog**, not the set an admin deployed, so `app_name`
was bounded by the catalog rather than by admin-created objects; and it carried
no `"other"` cap despite the sentence above asserting free-text labels are capped.
On the 6-device m7kni lab tenant it took **341** distinct values, and
341 × 5 install states × 4 platforms produced **1,870 active series from that one
collector** — scaling with the app catalog, so an enterprise catalog would produce
tens of thousands. Fixed in #83 by dropping `app_name` to the collector's new
`intune.app_install_status` log twin and summing the metric into
`install_state` × `platform` (~20 series, fixed by Microsoft's report schema).
A guard test now fails if `app_name` is reintroduced as a label.

**The generalizable lesson:** "it's an object name, so it's admin-bounded" is an
inference about the *source data*, not an observation of it — and here the
inference was wrong in a way only live data exposed. An entity name is bounded by
whatever populates the collection it came from; check what that actually is
(catalog vs deployment, tenant-wide vs admin-created) before granting it a label.

Explicitly verified that the highest-risk collectors read **no** per-entity field
into their metric path at all: `intune.manageddevices` and `intune.malware` never
read device ID/serial/IMEI/name/UPN; `entra.risk` and `entra.signinactivity`
deliberately keep per-entity fields out of metrics and (where applicable) defer
them to logs.

### Minor observations (not violations, not release-blocking)

- `entra.agreements.acceptances.total` uses the agreement **object ID** as its
  `agreement` label rather than a display name. Cardinality is bounded by the
  number of terms-of-use agreements (a handful per tenant), so it does **not**
  violate the rule, but a display name would read better on a dashboard. Left as
  a post-1.0 polish item against the agreements collector, not fixed here.
- The framework self-obs metrics carry `tenant_id` (bounded by configured tenant
  count) and `collector` / `metric.name` / `report_name` / `tier` / `error.type`
  (all bounded enums). Clean.

## Logs — PASS (per-entity data correctly confined to logs)

The boundary rule **inverts** for logs: per-entity detail belongs here. The
WindowCollectors (`entra.signins` ×4, `entra.directory_audit`,
`entra.provisioning`, `entra.risk_detection`, `entra.security_alert`,
`intune.audit_event`, `intune.enrollment_event`, `intune.autopilot_event`) and
the three export-report per-row logs (`intune.device_certificate`,
`intune.defender_agent`, `intune.app_install_status`) carry the expected
per-entity attributes: UPNs, user/device IDs, device names/serials, IPs,
locations, correlation/request/incident IDs, certificate thumbprints/serials/
subjects, provisioning identity IDs/names, sign-in resource/SP IDs/names. All of
this is legitimate log-attribute payload.

`intune.app_install_status` is the exception to that attribute list: it is a
per-**app** twin, not a per-entity one, carrying app identity (name, id,
publisher, platform) and the five raw per-state device counts. Its source report
(AppInstallStatusAggregate) has no device rows at all, so there is no per-device
identity for it to carry — see the collector's package doc. **This entry also
corrects a false claim in this document's original pass**, which asserted the
app-install collector emitted "per-device rows"; it emitted no logs whatsoever
until #83, and per-device detail is not obtainable from its report regardless.

One deliberate protection confirmed in code: `intune.audit_event` emits the
**names** of changed properties (`modified_property_names`) but **never** their
old/new values, which can carry credentials, certificates, or PII. Guarded by a
dedicated redaction test in the collector.

`SECURITY.md`'s "Telemetry payload sensitivity" list was **updated** by this audit
to enumerate the categories actually emitted (it previously omitted opaque
correlation/incident IDs, certificate identifiers, security-alert/risk detail, and
sign-in/provisioning identity IDs/names) and to record the modified-property-value
redaction.

## Permission scopes — PASS (one inconsistency fixed)

Every collector requests a **read-only** Graph scope matched to its own signal,
with exactly one documented exception: the three Intune **export-report**
collectors (`intune.app_install_status`, `intune.cert_inventory`,
`intune.defender_agents`) each require **one write-level scope**,
`DeviceManagementManagedDevices.ReadWrite.All`, solely to *create* an export job
(`POST /deviceManagement/reports/exportJobs`) — a documented Microsoft Graph
requirement, not a graph2otel design choice. graph2otel only reads the exported
result back; it never writes Intune configuration or device state. These
collectors are opt-in (`Experimental`), so a read-only deployment never requests
the write scope at all.

**Fixed during the audit:** the preflight's `ExpectedExceptionScopes` /
`DocumentedRequiredScopes` (`internal/preflight/known.go`) named
`DeviceManagementConfiguration.ReadWrite.All` as the export exception, but the
collectors actually declare `DeviceManagementManagedDevices.ReadWrite.All`. The
preflight would therefore have flagged the real scope as unexpected
over-privilege. Aligned `known.go` (and its tests) to the declared scope.

No collector requests a scope broader than its signal needs.
`DeviceManagementManagedDevices.PrivilegedOperations.All` (remote wipe and other
destructive actions) is explicitly in the never-request list.

## Verdict

**Gate cleared.** Zero unresolved cardinality-boundary violations in metrics;
per-entity data correctly confined to logs; the sensitivity documentation
corrected against actual emission; permission scopes least-privilege with the one
documented, opt-in export-job write exception, and its preflight record fixed.
The one minor observation (agreements object-ID label) is bounded and tracked as
post-1.0 polish, not a release blocker.

**This verdict has been wrong three times, and each time in the same way.** The
original pass cleared `entra.risk` and the Purview label collectors (#110, #111 —
fetched-then-dropped), and cleared `intune.app_install_status`'s `app_name` on an
inference about the source data that live telemetry refuted (#83, 1,870 series
from a 6-device tenant). Every one of those was found by looking at **live
emission or collector source**, never by re-reading this document — which by then
was asserting the bug did not exist. Treat a "PASS" here as a record of what was
checked on a given date, not as a property of the code: re-derive it from
`grep -rn 'GaugeSnapshot\|LogEvent'` and a live series count before relying on it.
