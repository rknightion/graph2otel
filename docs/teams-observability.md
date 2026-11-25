# Teams observability

Use the Teams profile for call and media investigation, PSTN and Direct Routing
attempts, inventory, usage reports and Microsoft service health. It is not a
replacement for every Call Quality Dashboard (CQD) field or Teams admin report.

## Teams-only quickstart

1. [Install graph2otel](getting-started.md#install) from a release that includes
   the Teams profile and these collectors, or build from source. Set up an
   [app-only identity](getting-started.md#auth-setup). In Entra, add only the
   [generated minimum Graph application permissions for `[teams]`](permissions.md#collector-profiles)
   and have a tenant administrator grant consent. Do not add delegated
   permissions. If you override collector selection, use the scope column in the
   [generated collector reference](collectors.md) for the collectors you select.
2. Save this as `config.yaml`, replacing the example directory GUID. Copy the
   [sample sites CSV](teams-sites.example.csv) to `teams-sites.csv` and replace
   its example rows with your site's networks, or omit `sites_file` until you
   have a site map. The path belongs to the tenant and is relative to the
   process working directory. For a container, mount it read-only and use the
   path inside the container.

   ```yaml
   profiles: [teams]
   tenants:
     - tenant_id: "00000000-0000-0000-0000-000000000000"
       teams:
         sites_file: ./teams-sites.csv
   checkpoint_dir: ./checkpoints
   otlp:
     protocol: stdout
   ```

3. With the intended app identity and config, check the granted roles before
   starting the poller:

   ```sh
   graph2otel check --config config.yaml
   ```

   `check` contacts Microsoft. It checks the app token against the selected
   collectors, not whether those collectors will return rows or whether OTLP
   delivery works. A subscribed-SKU warning can be expected with the minimum
   Teams grants; do not widen consent just to silence it. `stdout` suppresses
   network export, not Microsoft polling, and prints sensitive records. For
   deployment, configure your [OTLP destination](configuration.md#otlp) and put
   the checkpoint directory on writable persistent storage.

### Teams alongside the wider Graph profile

Use `profiles: [graph, teams]` for both sets of collectors in one process.
A tenant can replace that list with its own `profiles` setting. Teams Phone
number and user configuration inventory are in **both** profiles, with read
permissions separate from call records; selecting both does not collect the
inventory twice. The Teams-only permission list is not enough for combined
mode. Use the [profile and scope columns](collectors.md) and rerun `check` after
changing profiles or overrides.

### Optional enrichment and inputs

- **Sites and internal domains.** Site mapping runs locally. It prefers a
  matching reported subnet, then tries the endpoint IP; unmatched endpoints
  remain `unmapped`. Use site names that identify locations, not people or
  devices. See [site CSV validation, atomic replacement and domain matching](configuration.md#teams-site-mapping-and-internal-domains).
  Internal-domain classification does not filter external participants.
- **ASN and GeoIP.** Optionally mount your own MaxMind-format ASN or City
  databases read-only and set `tenants[].teams.geoip.asn_db`,
  `tenants[].teams.geoip.city_db`, or both. Neither is configured by default.
  Only an eligible public reflexive IP is used, never the relay or a trace hop. The results describe approximate network
  locations, not people, and are log attributes, not metric labels. See
  [local database setup and update rules](configuration.md#teams-offline-asn-and-geoip).
- **Voice application analytics (VAAC).** Off by default, even in Teams-only
  mode. Auto attendant and call queue legs depend on this separate, unsupported
  Microsoft password-sign-in integration. Graph consent and `check` do not
  cover it. Leave it off if your policy requires MFA or otherwise blocks the
  flow. Do not relax authentication or Conditional Access to enable it. See
  [VAAC configuration](configuration.md#teams-voice-application-analytics).
- **Call record webhook.** Off by default. Polling works without a public
  listener. [Call record notifications](https://github.com/rknightion/graph2otel/blob/main/docs/call-notifications.md) can shorten
  discovery delay without adding coverage; polling still handles discovery
  and recovery. Follow the dedicated HTTPS and client-state requirements if
  you opt in; do not expose the admin listener.

## View and query the data

Import the separate [Teams dashboard](https://github.com/rknightion/graph2otel/blob/main/dashboards/graph2otel-teams.json)
using the [dashboard import instructions](deploying-observability.md#dashboards).
It needs Grafana 13 or newer. Select the Prometheus or Mimir datasource for
metrics and Loki for logs, then select a tenant and time range. Start from calls,
site network measurements or service health and drill into the call or site
when you need the evidence behind a chart. An empty panel is not a health verdict.

The generated Teams alerts ship paused. Before enabling one, check the
[Teams runbooks](runbooks.md#teams-operations-paused-examples) for traffic and
working-hours assumptions and route service incidents separately from pages.
Use the [alert deployment process](deploying-observability.md#alert-rules) to
manage and verify the rules.

Use the [generated signal catalogue](https://github.com/rknightion/graph2otel/blob/main/spec/signal-catalog.json)
for exact event names, attribute keys, metric names and units. The
[collector reference](collectors.md) explains which source and permissions
produce each signal. Neither implies that every upstream field is available on
every row.

In Loki, filter `event_name` and call fields as
[structured metadata](signals.md#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels),
not stream labels. For example:

```logql
{service_name="graph2otel"} | event_name="teams.call_stream" | stream_health="poor"
```

Add a `tenant_id` metadata filter when investigating a single tenant. Query the
source event time, not the time the collector ran. Previously completed calls
can arrive late, and Loki can take longer to index accepted backdated records.
If the query is empty, check the time range and export errors and query again
later. [Backend acceptance limits and indexing delay](signals.md#backdated-log-records-accepted-to-7-days-but-not-queryable-immediately)
are separate from Graph retention.

## Migrate existing Teams queries

Use these as starting points, not schema or row-count equivalences.

| Previous log family | graph2otel signal | What changes |
| --- | --- | --- |
| Call metadata | `teams.call` | A completed detail version, not a live call. Use the call ID and version when comparing with streams. |
| Stream details and CQD quality | `teams.call_stream` | Directional media and endpoint evidence for streams in each segment. Missing or unsupported inputs can leave quality unclassified. |
| PSTN usage | `teams.pstn_call` | PSTN report rows, not a reconstruction from call streams. |
| Direct Routing | `teams.direct_routing_call` | Direct Routing attempts, not a count of unique calls. |
| Auto attendant (AA) | `teams.auto_attendant_call` | Call legs, only with the separate VAAC opt-in. |
| Call queue (CQ) | `teams.call_queue_call` | Call legs, only with VAAC. Queue shares describe newly observed legs with known results, not event-time rates. |
| Service announcements | `m365.service_health_issue`, `m365.service_health_post` | Service health issues and their posts, not the full Message Center feed. With the Teams profile, closure logs are for previously observed open issues, not a replay of resolved history. |
| Collection health | `graph2otel.collector.availability`, `graph2otel.collector.watermark_timestamp` | Use self-observability metrics for state and progress, not the absence of Teams events. See [collector availability](signals.md#collector-availability). |

Teams audit is separate from calls. The existing [Teams audit filter](o365-management-api.md#teams-audit-filtering)
selects records in the wider M365 audit feed, not the Teams-only profile.
Filtering by record type does not provide samples or mappings for nested Teams
payloads.
Likewise, Phone inventory covers number assignments and the supported fields
of user configuration. It does not map nested `telephoneNumbers` or
`effectivePolicyAssignments`, or emit a policy count. See the
[Phone inventory boundary](graph-api-gotchas.md#teams-phone-inventory).

### What not to infer from quality metrics

[Call quality rules](signals.md#teams-call-quality) use the CQD criteria only
where Graph supplies matching inputs. Graph direction names the sender and
receiver, not CQD inbound or outbound. Non-H264S screen sharing cannot reliably
be classified from the available fields, and legacy sharing lacks CQD's tile
and delay measurements. A relay address shows **allocation**, not media
traversal. A reported transport or partial network trace is not a reconstructed
route. There is no bounded unique-caller count, poor-device share or
relay-use share.

The bounded call and stream metrics use a fixed cohort rule: only the first
accepted complete version of each call contributes observations. A later complete
version can increment the health transition counter if the verdict changes; it
does not recount the call or rewrite the original distribution. Metrics count
observations at collection time, while logs retain version and source time.
Site and other metric dimensions are bounded, and clipping or skipped samples
can reduce coverage without dropping the corresponding logs. See
[counting call metrics](signals.md#counting-call-metrics) for the cohort,
checkpoint and budget rules.

## Privacy and network boundaries

Depending on the source and fields present, Teams call, stream and Phone logs
can carry user principal names (UPNs), display names, IP addresses, device
names, and phone numbers. The dashboard reads those same records. Call and
participant identifiers are for log investigations, not metric labels. Limit
access and retention on the receiving backend and treat `stdout` and any
captured output as sensitive. See [Security](security.md).

The poller contacts Microsoft for authentication and the selected APIs. In OTLP
mode it sends telemetry, including log attributes, to the sink **you configure**.
Site and optional GeoIP lookups stay in the process: graph2otel makes no off-box
IP lookup requests and does not fetch the GeoIP databases for you. This is a
lookup boundary, not a promise that the exported logs contain no IP addresses.
