# #380 operator-documentation reconciliation plan

**Goal:** Make the repository entry points and the published Zensical site describe the released v1.0.0 operator surface, while retaining the existing source-derived documentation gates.

**Verdict:** Documentation-only. No runtime, registry, collector, dashboard, Helm, or generated-doc-generator code is needed: the relevant generated or drift-gated sources already exist. Execute only after the staged #292 availability wave is committed, because it owns the current `docs/collectors.md`, `docs/signals.md`, self-observability dashboard, catalog, and associated tests.

## Validated premise and current truth

- `v1.0.0` is the release tag at `4ac6a0f`; #35's closing comment records the verified GHCR images, binaries, SBOM/provenance, and OCI Helm chart. `README.md:8-12` nevertheless says `pre-1.0`/`v0.1.0` and calls dashboards, alerts, Helm, and the docs pass future work.
- `docs/getting-started.md:9-10,24,37,57-58` still presents a pre-release `:main` image and an unshipped Helm chart. The current container contract is the read-only UID/GID 65532 image plus a writable persistent checkpoint mount, as exercised by `make container-smoke`; the published chart source is `charts/graph2otel/README.md.gotmpl` and its rendered `README.md`.
- `README.md:3,16-30` and `docs/index.md:3-23` present a Graph/Entra/Intune-only, two-shape product. The shipped composition root has raw REST Graph clients (typed SDK only for `license/graphclient_adapter.go`'s `subscribedSkus`), four ingest-engine shapes (`logpipeline`, `jobpipeline`/`exportjob`, `blobpipeline`, `o365pipeline`), and seven registration paths. `docs/architecture.md:12-30,45-55` is specifically stale on the Kiota/typed-client and two-engine diagram.
- `README.md:153-159` gives obsolete blob-roadmap and 2.3% duplicate guidance. The current evidence in `docs/signals.md:175-206` is 2.7% MGAL / 4% sign-ins, up to x4, with exact downstream identity-key dedupe; blob ingestion deliberately does not maintain an unbounded engine seen-set (#138).
- `README.md:187-188` and `docs/index.md:39-40` incorrectly call Global Secure Access traffic permanently diagnostic-only. #239 proves the beta endpoint is reachable but currently empty (data-blocked); posture is already shipped as Experimental `entra.gsa`, while its traffic mapper awaits a real payload. `README.md:213-216` is also stale: `DLP.All` is a supported explicit O365 Activity content type in `config.example.yaml:73-93`, not an unresolved blanket claim.
- `docs/deploying-observability.md:8-10` says ten alerts. `grafana/build_rules.py` and `grafana/tests/test_build_rules.py:63-65` define and pin 14 alerts plus two recording rules; the current checked staged tree reports six generated dashboards, 319/319 catalog metrics, 372 panels, 14 alerts, and two recording rules.

## Tracked-file ownership

| Owner | Files | Exact responsibility |
| --- | --- | --- |
| #380 documentation pass | `README.md`, `docs/index.md`, `docs/getting-started.md`, `docs/architecture.md`, `docs/configuration.md`, `docs/deploying-observability.md`, `CLAUDE.md` | Replace stale release, product-surface, install, architecture, config-routing, and asset-count prose with source-derived current truth. |
| Generated output, not hand-authored | `AGENTS.md` | Regenerate from the canonical `CLAUDE.md` rule after its status/source-of-truth correction; do not edit the generated file directly. |
| Verify only unless `values.yaml` itself changes | `charts/graph2otel/README.md.gotmpl`, `charts/graph2otel/README.md`, `charts/graph2otel/values.yaml`, `docker-compose.yml`, `config.example.yaml`, `docs/env-vars.md`, `docs/collectors.md`, `docs/signals.md`, `spec/signal-catalog.json`, `dashboards/*.json`, `alerts/*`, `recording-rules/*` | These are current source/generated truth or are owned by #292. Do not use #380 to reformat or regenerate them. |

## Implementation tasks

### Task 1: Replace release and installation claims

**Files:** `README.md`, `docs/getting-started.md`, `docs/index.md`, `CLAUDE.md`, generated `AGENTS.md`.

1. Replace every pre-release/v0.1.0/`:main`/unpublished-Helm sentence with the released `v1.0.0` state and point readers to the tagged image, release assets, OCI chart, and checked-out chart option. Keep `:main` only if it is explicitly documented as an optional development edge tag, never as the default install command.
2. Make the entry-point description name the shipped domains and transports: Graph, Azure Storage blob, O365 Management Activity, MDCA portal, Exchange Online, and advanced hunting where appropriate. Link detailed setup rather than repeating per-collector inventory.
3. Keep the executable quickstart truthful: explicit `--config`, the non-root read-only container, `/tmp` tmpfs, persistent writable `checkpoint_dir`, and `graph2otel check --config`. Link to the chart rather than duplicating `values.yaml`.
4. In `CLAUDE.md`, retain only current durable project guidance (released status, generated collector reference as count authority, release history closed), then regenerate `AGENTS.md` through the repository's canonical Claude-rule generator and verify its generated hash/header changes consistently.

### Task 2: Reconcile the documentation-site architecture and configuration routes

**Files:** `docs/index.md`, `docs/architecture.md`, `docs/configuration.md`.

1. Replace the architecture Mermaid graph and adjacent text with raw REST `internal/graphclient`, the four engine shapes, the seven registration paths, checkpointing, telemetry, admin/preflight, and the source-selection/config gates. Preserve the narrow typed-SDK exception for `subscribedSkus`; do not claim broad typed-SDK/Kiota collector use.
2. Make the site home describe Graph as the core rather than the entire product. Replace the stale permanent-gap summary with links to `blob-ingest.md`, `o365-management-api.md`, `graph-api-gotchas.md`, and `collectors.md`; distinguish GSA posture (shipped) from the payload-blocked traffic mapper.
3. Expand `docs/configuration.md`'s operator map to point readers at the existing file-only per-tenant transport controls: `blob_ingest`, `o365_activity`, `mdca`, `exchange_online`, and `hunting`, plus the distinct Experimental (beta) and HighVolume gates. Keep `config.example.yaml` and generated `docs/env-vars.md` as the exact key/default authority; do not duplicate their full tables.
4. State the timestamp and duplicate behavior only from current references: unparseable event time is dropped rather than stamped on arrival, and blob duplicates are deduped downstream by structured-metadata identity keys.

### Task 3: Correct deployment/count prose without introducing manual inventories

**Files:** `docs/deploying-observability.md`; verify `charts/graph2otel/README.md.gotmpl` and generated `charts/graph2otel/README.md` without editing them.

1. Correct the alert count to 14 and describe dashboard/alert/recording counts as build-derived or drift-gated, not a second manually maintained inventory. Retain the six stable dashboard UIDs because they are the deployment API identifiers.
2. Cite the existing mechanisms in prose: `collectordoc.Rows`' seven-slice signature and golden gate for collector/path coverage; `TestEnvReferenceDocInSync` for environment reference; `grafana/build_dashboard.py --check` for dashboard/catalog coverage; `build_rules.py --check` and its exact-count test for alert/recording rules; Helm-docs for the chart README.
3. Do not change Grafana payloads, alert/rule provisioning ownership, prices/cost claims, or source-selection semantics merely to make the prose shorter.

## Verification and rendered receipts

Run after rebasing the documentation work on the committed #292 state:

```sh
go test ./cmd/graph2otel -run TestCollectorReferenceDocInSync -count=1
go test ./internal/config -run TestEnvReferenceDocInSync -count=1
make grafana-check
make helm-docs && git diff --exit-code charts/graph2otel/README.md
helm lint charts/graph2otel
helm template graph2otel charts/graph2otel >/dev/null
make container-smoke
zensical build --strict
```

Record the `make grafana-check` generated counts, the Helm/container receipts, and the Zensical build result on #380. Inspect rendered `site/index.html`, `site/getting-started/index.html`, `site/architecture/index.html`, and `site/deploying-observability/index.html`; run a rendered-text search for `pre-1.0`, `v0.1.0`, `coming soon`, `planned but not published`, and the obsolete ten-alert claim. Finish with `make check` and a focused Markdown link check over the edited documents, then the normal full issue/commit/push workflow.

## Conflict avoidance and risks

- **#292:** wait for its commit; never edit or regenerate its owned `docs/collectors.md`, `docs/signals.md`, collector inventory, self-observability board, catalog, or availability tests. Its generated counts are the baseline #380 reports.
- **#265/#266:** do not document strict unknown-config rejection or authenticated-identity fallback until those implementations land; link the current config/preflight behavior only.
- **#268:** do not imply OTLP delivery degradation changes liveness/readiness; the approved contract keeps liveness dependency-free and delivery separate.
- **#289:** do not add vendor price tables or claim collector-attributed wire cost is exact; pricing remains opt-in/operator-supplied and attribution estimated.
- **#291:** do not promise page-bounded streaming or exactly-once delivery before the approved ordered-streaming implementation lands; preserve current watermark/at-least-once wording.

**Remaining decision:** None. The approved defaults do not alter #380's documentation-only scope.

