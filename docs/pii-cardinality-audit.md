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
`intune.defender_agent`, and the app-install per-device rows) carry the expected
per-entity attributes: UPNs, user/device IDs, device names/serials, IPs,
locations, correlation/request/incident IDs, certificate thumbprints/serials/
subjects, provisioning identity IDs/names, sign-in resource/SP IDs/names. All of
this is legitimate log-attribute payload.

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
