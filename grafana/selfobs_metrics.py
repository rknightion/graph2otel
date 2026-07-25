"""Self-observability metrics the signal catalog cannot see (#218, #219).

# The one surface the catalog structurally cannot reach

``internal/signalcapture`` captures what a COLLECTOR PACKAGE's tests emit, so
``spec/signal-catalog.json`` carries only the seven ``graph2otel.*`` metrics that
collectors themselves emit. The rest of the self-observability surface — scrape
health, checkpoint persistence, export jobs, the cardinality limiter,
throttling, outbound HTTP — is emitted by the scheduler, the transport and the
telemetry package, none of which is a collector package and none of which has
a golden.

So those metrics are declared here, by hand, as ``(otel name, unit, kind)``
triples copied from their emit sites. Only the triple is hand-kept: the
Prometheus name is DERIVED by ``promname.prom_name``, the same rule the Go
catalog uses, pinned to it by ``tests/test_build_dashboard.py`` over all 274
cataloged metrics. That is what keeps the derivation honest even where the
catalog cannot reach.

# Why this is its own module, not private to one board

``grafana/boards/selfobs.py`` (the self-observability dashboard) and
``grafana/build_rules.py`` (the alert + recording rules, #219) both need this
exact set of 20 names and derived Prometheus forms. A second hand-copy in the
rules generator would be a second place for the set to drift from the first —
exactly the kind of drift #219 exists to close (the ``graph2otel_throttle_
limit_percentage`` bug was precisely a hand-typed name nobody re-derived). So
this module is the ONE declaration; both generators import ``SELF_OBS`` from
here rather than restating the triples.

These metrics are NOT covered by the dashboard coverage gate or by the rules
reverse-validation gate's catalog half — both instead check every reference
against this module's allow-list directly. Extending ``signalcapture`` to
non-collector packages is the real fix, and it belongs with ``signalcapture``,
not here.
"""

from __future__ import annotations

from promname import prom_name

# (otel name, unit, kind) triples, copied by hand from their emit sites:
#   - scrape.*, checkpoint.persist.errors  -> internal/collector/selfobs.go
#   - build_info, tenant.license_tier      -> internal/telemetry
#   - export.*                             -> internal/exportjob
#   - series.*                             -> internal/telemetry (cardinality limiter, #235)
#   - throttle.*                           -> internal/graphclient/ratelimit_transport.go
#   - http.client.request.duration,
#     graphclient.http_4xx/5xx             -> internal/graphclient/transport.go
_TRIPLES: list[tuple[str, str, str]] = [
    ("graph2otel.scrape.success", "1", "gauge"),
    ("graph2otel.scrape.duration", "s", "gauge"),
    ("graph2otel.scrape.staleness", "s", "gauge"),
    ("graph2otel.scrape.budget", "1", "gauge"),
    ("graph2otel.scrape.errors", "1", "sum"),
    ("graph2otel.checkpoint.persist.errors", "1", "sum"),
    ("graph2otel.build_info", "1", "gauge"),
    ("graph2otel.tenant.license_tier", "1", "gauge"),
    ("graph2otel.export.jobs", "{job}", "sum"),
    ("graph2otel.export.duration_seconds", "s", "gauge"),
    ("graph2otel.export.poll_count", "{poll}", "gauge"),
    ("graph2otel.export.bytes", "By", "gauge"),
    ("graph2otel.series.active", "{series}", "gauge"),
    ("graph2otel.series.limit", "{series}", "gauge"),
    ("graph2otel.series.clipped", "{series}", "gauge"),
    ("graph2otel.throttle.count", "1", "sum"),
    ("graph2otel.throttle.limit_percentage", "%", "gauge"),
    ("graph2otel.http.client.request.duration", "s", "histogram"),
    ("graph2otel.graphclient.http_4xx", "1", "sum"),
    ("graph2otel.graphclient.http_5xx", "1", "sum"),
]


class SelfObsMetric:
    """One hand-declared self-observability metric and its derived Prometheus name."""

    __slots__ = ("name", "unit", "kind", "prom")

    def __init__(self, name: str, unit: str, kind: str):
        self.name = name
        self.unit = unit
        self.kind = kind
        self.prom = prom_name(name, unit, kind)

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"SelfObsMetric({self.name!r})"


# otel name -> SelfObsMetric. The allow-list both generators import.
SELF_OBS: dict[str, SelfObsMetric] = {
    name: SelfObsMetric(name, unit, kind) for name, unit, kind in _TRIPLES
}
