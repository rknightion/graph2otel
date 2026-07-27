# Issue #268 Grafana/docs lane report

## Result

Implemented the generated operator surface for the frozen six
`graph2otel.otlp.delivery.*` metrics in `/tmp/graph2otel-268.4DDwyq`.

The self-observability dashboard now has a process-wide `OTLP delivery` row with:

- current exporter degradation split by `signal`;
- unstacked export attempt, accepted-callback, and failure rates split by `signal`;
- force-flush failure rate split by `signal`;
- shutdown failure lifetime total split by `signal`.

Every delivery query uses the catalog-derived normalized Prometheus name and omits tenant
and collector selectors. Metrics and logs remain independent through the bounded `signal`
dimension. No alert or recording rule was added, and no delivery state changes readiness or
liveness semantics.

`docs/signals.md` now defines the callback boundary: nil means the exporter accepted the
batch, not exactly-once delivery, a durable queue, backend ingest, retention, or
queryability. It also defines stdout as a local-writer callback, explains that delivery
metrics can disappear precisely while metrics export is broken, identifies admin status as
the process-local truth and structured logs as the raw-error path, and distinguishes
`record.outcomes{outcome="emitted"}` from exporter/backend acceptance.

## Files owned and changed

- `grafana/boards/selfobs.py`
- `grafana/tests/test_build_dashboard.py`
- `dashboards/graph2otel-self-observability.json` (deterministically regenerated)
- `docs/signals.md`

There is no `grafana/selfobs_metrics.py` in this checkout. The board already loads
self-observability metrics directly from the generated signal catalog, so no obsolete
hand-maintained metric registry was created.

No telemetry, admin, command, config, alert, recording-rule, or unrelated documentation
file was edited by this lane. Those files already dirty in the shared worktree belong to
the other #268 lanes.

## TDD receipt

RED:

```text
python3 -m unittest tests.test_build_dashboard.TestOTLPDeliveryPanels -v
FAILED
- all six catalog metrics were missing from panels
- named delivery panels did not exist
- required callback/local-fallback documentation did not exist
- no-delivery-alert assertion already passed
```

After the minimal board/docs implementation, the targeted five-test contract passed. The
full dashboard test then failed only on the expected stale generated JSON:

```text
python3 -m unittest tests.test_build_dashboard -q
FAILED: graph2otel-self-observability.json is stale - run `make dashboard`
```

After `make dashboard`, all tests and generated-artifact checks passed.

## Verification

```text
make grafana-check
coverage: 325/325 catalog metrics on a panel
rules: 14 alert rules (7 enabled, 7 paused), 2 recording rules
Ran 60 tests
OK

git diff --check
exit 0
```

Deterministic regeneration was checked by hashing the dashboard before and after a second
`make dashboard`:

```text
a234aa2c0d0296ce236444740e04d7257a401ca30591b5bf2bfd2691186eb003
a234aa2c0d0296ce236444740e04d7257a401ca30591b5bf2bfd2691186eb003
```

No files were staged, committed, pushed, or written to GitHub.
