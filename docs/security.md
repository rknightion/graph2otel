# Security & data handling

This page summarizes graph2otel's operational security posture — what data it handles,
where that data goes, and the configuration levers available to reduce exposure. For the
canonical, authoritative version (kept alongside the code, not duplicated content) plus
vulnerability reporting instructions, see
[`SECURITY.md`](https://github.com/rknightion/graph2otel/blob/main/SECURITY.md) in the
repo.

## Reporting a vulnerability

Report privately via GitHub's private vulnerability reporting — do not open a public
issue for a security bug:

**<https://github.com/rknightion/graph2otel/security/advisories/new>**

See `SECURITY.md` for the full disclosure process, timelines, and scope.

## Telemetry payload sensitivity

graph2otel exports **identity and device management data** from every tenant it's
configured against. Depending on which collectors are enabled, that includes user
principal names / email addresses and user object IDs; device names, serial numbers,
IMEIs, and other hardware identifiers; sign-in IP addresses, geographic locations, and
client application identifiers; directory/group/role membership and app credential
metadata; device compliance and configuration policy state; opaque correlation/request/
incident/job/cycle/change identifiers; certificate identifiers (thumbprints, serial
numbers, subject/issuer names); security alert and risk-detection details; and sign-in/
provisioning source/target identity IDs and display names.

This list is confirmed against the **actual** collector emission by the pre-1.0 PII &
cardinality audit — see [docs/pii-cardinality-audit.md](pii-cardinality-audit.md) — not
just design intent. That audit also confirmed the boundary rule below holds in code: all
of the above per-entity data is confined to the **logs** pipeline as structured
attributes; no metric label anywhere is keyed by a user, device, or per-event identity.
One deliberate protection worth calling out: the Intune audit-event stream emits the
**names** of changed properties but never their old/new values, which can carry
credentials, certificates, or PII.

All of this is exported over **OTLP to the configured backend** (for example Grafana
Cloud). **Treat the OTLP backend as a trusted data sink** — anyone with read access to it
can see this metadata for every configured tenant. Scope backend credentials and Graph
API app registration permissions accordingly.

## The cardinality boundary rule

**This rule is not a privacy control, and it does not reduce what graph2otel exports.**
Everything listed above is exported by design. The rule decides only **which pipeline**
carries each shape of data, for cost and queryability reasons — not confidentiality.

High-cardinality, per-entity data (per-user, per-device, per-sign-in event data — UPNs,
device IDs, IP addresses, correlation IDs) is **never** attached as an OTEL metric label.
That data belongs in the **logs** pipeline (sign-in logs, audit logs, provisioning logs,
Intune audit events) as structured log attributes, not as metric label dimensions.
Metrics carry only **bounded, tenant-shaped aggregates** — counts by compliance state, by
operating system, by policy, by risk level — never a metric series keyed by user or
device identity. This is a hard modeling rule, not a tuning knob: a metric series whose
cardinality grows with tenant size is a bug, not a feature request. Backends bill metrics
on active series, and a series keyed by a sign-in or correlation ID receives exactly one
sample — the worst case for a time-series database.

The rule has a **second half**: per-entity data too high-cardinality for a metric label
MUST still be emitted as a **log** — never discarded. "Not a metric label" means "log
twin". Every bounded aggregate metric has a per-entity log stream behind it, so you can
always get from *how many* to *which ones*. See
[Signals](signals.md#cardinality-shape) for how this maps onto the emitted namespaces.

If you want less exposure, use the levers below — not the cardinality rule.

## Levers to reduce exposure

- Enable only the collectors you need per tenant (`collectors:` in
  [Configuration](configuration.md)) — a disabled collector makes zero Graph API calls
  and exports zero data for that domain.
- Use least-privilege, read-only Graph API application permissions — never grant write
  scopes beyond what the Intune reports export API unavoidably requires for that one
  feature. Run `graph2otel check` to confirm your app registration's grants match what
  your enabled collectors actually need before your first real poll — see
  [Getting Started](getting-started.md#auth-setup).
- Where a domain has both a snapshot/aggregate signal and a raw per-entity export, prefer
  the aggregate; per-entity detail should be pulled on demand, not mirrored wholesale
  into metric label sets.

## Secrets handling

- Auth material (client secret / client certificate path) is supplied via
  **environment variables** consumed by `azidentity.DefaultAzureCredential`
  (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, or
  `AZURE_CLIENT_CERTIFICATE_PATH`) — never as literal values in YAML. The `tenants` list
  in config only carries `tenant_id` / `client_id` and per-domain collector toggles.
  `config.local.yaml` and `.env` are gitignored for this reason.
- Secrets are **never logged**. A code path that logs a secret or a full OAuth token is a
  vulnerability — report it per the process above.

## Related pages

- [docs/pii-cardinality-audit.md](pii-cardinality-audit.md) — the collector-by-collector
  audit that confirmed the boundary rule above holds against actual emitted telemetry.
- [docs/scale-validation.md](scale-validation.md) — validation of the throttle limiters
  and watermark/checkpoint durability under load, the mechanisms this project's scale
  claims depend on.

## License

`graph2otel` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`) — see
[`LICENSE`](https://github.com/rknightion/graph2otel/blob/main/LICENSE).
