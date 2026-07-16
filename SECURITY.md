# Security & data handling

This document covers two things: how to **report a vulnerability** in `graph2otel`
(immediately below), and the **operational security posture** of the service — what data
it handles, where that data goes, and the configuration levers operators should be aware
of. For the user-facing pitch see `README.md`.

## Reporting a vulnerability

**Report privately. Do not open a public issue for a security bug.**

Use GitHub's private vulnerability reporting, which is enabled on this repository:

- **<https://github.com/rknightion/graph2otel/security/advisories/new>**

That channel is private between you and the maintainer until a fix ships, and it is the
only supported way to report. A useful report includes the affected version or commit, the
configuration involved (redact tenant IDs/secrets), what an attacker gains, and the steps
to reproduce it. A proof of concept helps but is not required.

### Supported versions

Only the **latest release** is supported. Fixes land on `main` and ship in the next
release; there are no backports to older tags.

### Disclosure process and timelines

This is a single-maintainer hobby project, so these are honest targets rather than a
commercial SLA:

| Stage | Target |
| --- | --- |
| Acknowledge your report | within 5 working days |
| Initial assessment (accepted / rejected, with reasoning) | within 10 working days |
| Fix released for an accepted vulnerability | within 90 days of acknowledgement, and sooner where severity warrants it |

Coordinated disclosure: please give me the 90 days to ship a fix before disclosing
publicly. Once a fix is released I will publish a GitHub Security Advisory (which assigns
a CVE) and credit you by name unless you would rather stay anonymous. If a report is
rejected I will say why, and you are then free to disclose as you see fit. If I have gone
quiet past the targets above, treat that as a reason to chase me, not as a reason to sit on
the bug indefinitely.

### Scope

In scope: the `graph2otel` binary and its container image. Notably in scope is anything
that could leak an app registration secret/certificate, a tenant's Graph API token, or
per-tenant telemetry into logs, metrics, or process output it shouldn't reach.

Out of scope: vulnerabilities in Microsoft Graph, Entra ID, or Intune themselves (report
those to [MSRC](https://msrc.microsoft.com/report)), and vulnerabilities in your OTLP
backend.

## Telemetry payload sensitivity

`graph2otel` exports **identity and device management data** from every tenant it's
configured against. Depending on which collectors are enabled, that data includes, among
other things:

- user principal names (UPNs) / email addresses, and user object IDs;
- device names, serial numbers, IMEIs, and other hardware identifiers;
- sign-in IP addresses, geographic locations, and client application identifiers;
- directory/group/role membership and app credential metadata;
- device compliance and configuration policy state;
- opaque correlation / request / incident / job / cycle / change identifiers (GUIDs);
- certificate identifiers — thumbprints, serial numbers, subject and issuer names;
- security alert titles, categories, and provider/incident identifiers, plus risk-detection
  event types and details;
- sign-in and provisioning source/target identity IDs and display names (users, service
  principals, applications, and target resources).

This list was confirmed against the **actual** collector emission by the pre-1.0 PII &
cardinality audit (see `docs/pii-cardinality-audit.md`), not just the design intent. That
audit also confirmed the boundary rule below holds in code: **all** of the above per-entity
data is confined to the **logs** pipeline as structured attributes; **no** metric label
anywhere is keyed by a user, device, or per-event identity. One deliberate protection worth
calling out: the Intune audit-event stream emits the **names** of changed properties but
**never** their old/new values (which can carry credentials, certificates, or PII).

All of this is exported over **OTLP to the configured backend** (for example Grafana
Cloud). **Treat the OTLP backend as a trusted data sink** — anyone with read access to it
can see this metadata for every configured tenant. Scope backend credentials accordingly,
and scope Graph API app registration permissions to the minimum your enabled collectors
need (see `README.md`'s auth section).

### The cardinality boundary rule

**This rule is not a privacy control, and it does not reduce what graph2otel exports.**
Everything in the inventory above is exported by design. The rule decides only **which
pipeline** carries each shape of data, and it exists for cost and queryability reasons:

High-cardinality, per-entity data (per-user, per-device, per-sign-in event data —
UPNs, device IDs, IP addresses, correlation IDs) is **never** attached as an OTEL metric
label. That data belongs in the **logs** pipeline (sign-in logs, audit logs, provisioning
logs, Intune audit events), as structured log attributes, not as metric label dimensions.
Metrics carry only **bounded, tenant-shaped aggregates** — counts by compliance state, by
operating system, by policy, by risk level — never a metric series keyed by user or
device identity. This is a hard modeling rule, not a tuning knob: a metric series that
would grow with tenant size (rather than with the number of policies/states/categories) is
a bug, not a feature request. Backends bill metrics on active series, and a series keyed
by a sign-in or correlation ID receives exactly one sample — the worst case for a
time-series database. A `count by` over the logs answers the same question anyway.

The rule has a **second half**, which is what keeps it from becoming a data-loss rule:
per-entity data too high-cardinality for a metric label MUST still be emitted as a **log**
— never discarded. "Not a metric label" means "log twin". A collector that fetches
per-entity rows and drops everything but a bucketed count is a bug, because that data then
reaches no pipeline at all and the signal can answer "how many" but never "which one".

If you need less exposure, the levers below are the supported way to get it — not the
cardinality rule.

### Levers to reduce exposure

- Enable only the collectors you need per tenant (`collectors:` in `config.example.yaml`)
  — a collector that isn't enabled makes zero Graph API calls and exports zero data for
  that domain.
- Use least-privilege, read-only Graph API application permissions (see `README.md`) —
  never grant write scopes beyond what the Intune reports export API unavoidably requires
  for that one feature.
- Where a domain has both a snapshot/aggregate signal and a raw per-entity export, prefer
  the aggregate; per-entity detail should be pulled on demand, not mirrored wholesale into
  metric label sets.

## Secrets handling

- Auth material (client secret / client certificate path) is supplied via
  **environment variables** consumed by `azidentity.DefaultAzureCredential`
  (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` or
  `AZURE_CLIENT_CERTIFICATE_PATH`) — never as literal values in YAML. The `tenants` list in
  config only carries `tenant_id` / `client_id` and per-domain collector toggles.
  `config.local.yaml` and `.env` are gitignored for this reason.
- Secrets are **never logged**. If you find a code path that logs a secret or a full OAuth
  token, that's a vulnerability — report it per the process above.

## License

`graph2otel` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`) — see [`LICENSE`](./LICENSE).
