# Upstream API drift canary

graph2otel decodes Microsoft Graph responses into fixed Go structs. When Graph renames
or drops a field, the affected collector keeps returning HTTP 200 and starts emitting
zeros — a green tick over no data, the failure mode `docs/graph-api-gotchas.md` keeps
warning about. The drift canary exists to make that change visible on the day it lands
rather than on the day someone notices a flat panel.

It is a **spec diff**, not a live-payload check: it needs no tenant, no app registration
and no CI secrets.

## Scope: beta only, deliberately

| surface | watched | why |
| --- | --- | --- |
| `https://graph.microsoft.com/beta` | yes | no compatibility contract — Microsoft documents beta as subject to change without notice. Almost every beta consumer here is on beta because the resource has no v1.0 form at all; the exception is the sign-in streams, where the path exists on v1.0 but the `signInEventTypes` filter they need does not. |
| `https://graph.microsoft.com/v1.0` | no | versioned and contractually stable. A breaking change there would arrive as a new version path, not as a silently retyped property, so a daily diff would only ever report additions. |

Watching v1.0 would enlarge the snapshot and the report volume materially to detect a
class of change that does not happen. If Microsoft ever breaks v1.0 in place, the
mechanism here extends to it by adding v1.0 operations to the manifest — nothing in the
tool is beta-specific except the default `metadata_url`.

## Coverage

26 packages, 28 collectors, 79 beta operations. The authoritative list is
`spec/graph-beta-surface.json`; `TestBetaDriftDocNamesEveryWatchedCollector` fails if a
collector listed there stops being named below.

| domain | collectors |
| --- | --- |
| Entra ID | `entra.agent_risk_detections`, `entra.app_ownership`, `entra.gsa`, `entra.pim_alerts`, `entra.recommendations`, `entra.risky_agents`, `entra.signin_activity`, `entra.signins.non_interactive`, `entra.signins.service_principal`, `entra.signins.managed_identity` |
| Intune | `intune.apple_tokens`, `intune.autopilot`, `intune.autopilot_events`, `intune.certificates`, `intune.cloud_pki`, `intune.connectors`, `intune.device_encryption`, `intune.endpoint_analytics`, `intune.gpo_analytics`, `intune.hardware_inventory`, `intune.remediation_run_states`, `intune.scripts`, `intune.settings_catalog`, `intune.updates`, `intune.windows_updates` |
| M365 | `m365.teams`, `m365.unified_audit` |
| Purview | `purview.dlp_policies` |

Not covered, and not a gap in this canary: `mdca.discovery_parse` reaches the legacy
Defender for Cloud Apps portal API, which publishes no machine-readable schema; the
`defender.*` and blob-transport collectors read Azure Storage blobs, whose envelope shape
is covered by `docs/blob-ingest.md` and the `internal/signalcapture` goldens instead.

## The three artifacts

| file | role |
| --- | --- |
| `spec/graph-beta-surface.json` | manifest — every Go package that builds a beta URL, the collectors in it, and the paths it requests. Hand-maintained, code-gated. |
| `spec/graph-beta-snapshot.json` | the committed slice of the beta EDM: the type each operation resolves to, plus the definition of every type in that closure. Generated. ~96 KB. |
| `tools/graphdrift` | a standard-library-only Go module that fetches the live CSDL, rebuilds the slice, and diffs it. |

### Source format: CSDL, from the live service

The snapshot is sliced from `https://graph.microsoft.com/beta/$metadata` — the OData EDM
(CSDL XML) the service publishes about itself.

Live-measured 2026-07-21: HTTP 200 **anonymously**, no `Authorization` header, 7.2 MB,
`Content-Type: application/xml`. That is the whole reason the canary needs no credentials.

CSDL was chosen over the OpenAPI descriptions in `microsoftgraph/msgraph-metadata`
because it is what the service itself serves (wire, not a downstream mirror on a
conversion lag), and because the EDM is directly *walkable*: entity sets and singletons
bind to types, navigation properties chain from them, so a request path resolves to a
type by construction. The generated OpenAPI has synthesized operation ids and duplicates
each type per operation, which makes both the slicing and the diff noisier.

### Slicing

For each manifest path the tool walks the EDM from the service container:

- the first segment is an entity set or singleton;
- `{id}` is a key segment and does not change the type;
- a segment containing a `.` is a derived-type cast;
- anything else is a navigation property (searched up the base-type chain), and failing
  that a bound function or action whose binding parameter matches the current type.

The slice is then the resolved type, its base-type chain, and the complex/enum types its
own properties reference — one hop, with their base chains. Navigation targets are **not**
followed: a navigation property a collector actually requests has its own manifest entry,
and following them blindly pulls in most of the 5,800-type document. The result is 59
operations and 137 types.

The snapshot deliberately records **no** schema version, generation timestamp, or
annotations. Anything that moves without the contract moving would make the file churn
daily and the canary worthless.

### Two paths the EDM does not model

Both live-verified as working; both recorded in the manifest with the evidence, so they
read as documented gaps rather than as failures.

| path | gap |
| --- | --- |
| `/deviceManagement/userExperienceAnalyticsAnomalySeverityOverview` | returns 200 on the wire, but the beta EDM declares `userExperienceAnalyticsAnomalySeverityOverview` only as a `ComplexType` with no container or navigation binding. Marked `unmodeled`; the type is still watched. |
| `/deviceManagement/templates/{id}/deviceStateSummary` | modeled only on the derived `securityBaselineTemplate`, which the collector reaches without a cast segment because its list call already filters to that template family. Resolved via `resolve_as`. |

## What counts as drift

| severity | changes | fires the canary |
| --- | --- | --- |
| `breaking` | type removed, property or navigation property removed, property/navigation type changed, base type or kind changed, enum member removed, an operation that stops resolving or resolves to a different type | yes — exit 3 |
| `info` | property, navigation property, enum member or closure type **added** | no — exit 0 |

Additions are the shape of Microsoft's routine beta churn, and none of them can break a
decoder. Reporting them without firing keeps the signal-to-noise ratio at the level where
a red run means something.

An `operation_added` / `operation_removed` change means the snapshot is out of sync with
the manifest, not that upstream moved. `TestBetaSurfaceSnapshotMatchesManifest` catches
that offline in `make check`, so it should never reach the daily run.

## Gates

| gate | where | catches |
| --- | --- | --- |
| `TestBetaSurfaceManifestCoversEveryBetaConsumer` | `internal/collectordoc` | a package building beta URLs that the manifest does not list — and a manifest entry for a package that no longer does. Reads string literals off the AST, so a comment mentioning the beta root is not a false positive. |
| `TestBetaSurfaceSnapshotMatchesManifest` | `internal/collectordoc` | a snapshot never regenerated after the manifest changed |
| `TestBetaSurfaceManifestIsWellFormed` | `internal/collectordoc` | manifest schema violations |
| `.github/workflows/graph-beta-drift.yml` | CI, daily 06:23 UTC | upstream drift |

A canary that cannot see a consumer reports coverage it does not have, which is why the
first gate runs in both directions.

## Running it

```sh
# diff the live beta metadata against the committed snapshot
make graphdrift

# refresh the snapshot (after a manifest change, or after triaging real drift)
make graphdrift-update

# other formats / a local copy of $metadata, no network
.tools/graphdrift -manifest spec/graph-beta-surface.json \
  -snapshot spec/graph-beta-snapshot.json -format json
.tools/graphdrift -manifest spec/graph-beta-surface.json \
  -snapshot spec/graph-beta-snapshot.json -metadata /tmp/beta-metadata.xml
```

Exit codes: `0` no actionable drift (clean, or additions only), `3` breaking drift, `2`
usage or IO error. The workflow treats anything other than `0` and `3` as a tool failure,
so a Microsoft outage cannot be mistaken for a clean run.

**Run the built binary, not `go run`.** Live-measured on go1.26.5: `go run` collapses any
non-zero exit to `1` and prints `exit status N` to stderr, which erases the difference
between drift and a tool failure. The make targets and the workflow both build first.
Running it under `go run -C tools/graphdrift .` is fine for eyeballing the report — just
do not branch on its exit code.

## When it fires

The daily workflow opens (or comments on) a single tracking issue labeled
`graph-beta-drift` and fails the run. Triage:

1. **Confirm against the live endpoint.** Wire over docs — the EDM is Microsoft's own
   description of itself and has been wrong before. Probe as `graph2otel-poller`.
2. **Fix or re-scope the collector** — the change is upstream, so the collector is what
   moves.
3. **Refresh the snapshot** with `go run -C tools/graphdrift . -update` and commit it with
   the fix, so the diff is reviewable next to the code change.

Refreshing the snapshot *without* a code change is only correct when the reported change
genuinely does not touch what the collector decodes — say the property it removed was
never mapped. Say so in the commit message; a silent `-update` is how a canary becomes a
rubber stamp.
