"""Turns a board module's declarative SECTIONS/LOGS into a built Builder."""

from __future__ import annotations

from builder import Builder, titleize

# The paragraph every dashboard carries, because the doc paragraph has not been
# enough: the shipped alert rules AND 74 dashboard queries were both built on a
# false belief about how these signals are labelled (#143, #158, #160). It is
# repeated on every board deliberately — someone about to write their own query
# is looking at a dashboard, not at docs/signals.md.
PREAMBLE = """\
**Metrics answer "how many"; logs answer "which one".** graph2otel puts bounded,
tenant-shaped aggregates on metrics and per-entity detail on the log twin (#112).
If a panel here cannot tell you *which* device or user, the Logs row at the bottom
can.

**Metric names are the OTLP→Prometheus normalized form** — dots become underscores
and unit/type suffixes are appended (`_total` on counters, `_seconds`, `_ratio`,
`_percent`). Every query on this dashboard is generated from
`spec/signal-catalog.json`, which is itself generated from what the collectors
actually emit, so a panel cannot name a metric that does not exist.

**LogQL: attributes are structured metadata, not stream labels.** Only
`service_name` is a stream label. `{event_name="entra.signin"}` matches **zero rows,
silently** — it is not an error. Always:

```logql
{service_name="graph2otel"} | event_name=`entra.signin` | status_error_code!=`0`
```

**Empty is often correct.** Several collectors are opt-in (blob ingest, beta Graph
surfaces, high-volume feeds) and several are empty on a healthy tenant. A blank panel
is not evidence of a broken pipeline.
"""


def _entry(b: Builder, item):
    """Render one SECTIONS entry.

    Accepted forms:
      "metric.name"                      one panel, everything derived
      ("Title", ["m1", "m2"])            one panel over several metrics
      ("Title", ["m1"], {"viz": "table"}) as above, with builder overrides
    """
    if isinstance(item, str):
        b.metric(item)
        return
    title, names = item[0], item[1]
    opts = item[2] if len(item) > 2 else {}
    if title is None:
        title = titleize(names[0])
    b.metrics(names, title=title, **opts)


def build(mod, cat) -> Builder:
    """Build the dashboard a board module describes."""
    b = Builder(
        uid=mod.UID,
        title=mod.TITLE,
        description=mod.DESCRIPTION,
        tags=list(mod.TAGS),
        tenant_metric=mod.TENANT_METRIC,
        catalog=cat,
        needs_loki=bool(getattr(mod, "LOGS", ())),
    )
    b.text(PREAMBLE, title="Read this before writing your own query", h=12)
    for section_title, items in mod.SECTIONS:
        b.row(section_title)
        for item in items:
            _entry(b, item)
    # A board with panels the catalog cannot describe declares them itself.
    # Today that is only self-observability: the scheduler/transport metrics are
    # emitted outside any collector package, so no signals.json golden captures
    # them and the catalog cannot see them (see AUTHORING.md).
    extra = getattr(mod, "extra", None)
    if extra is not None:
        extra(b)
    logs = getattr(mod, "LOGS", ())
    if logs:
        b.row("Logs — which one, not how many (#162)")
        for spec in logs:
            _log_entry(b, spec)
    return b


def _log_entry(b: Builder, spec: dict):
    kind = spec.get("kind", "logs")
    args = {k: v for k, v in spec.items() if k != "kind"}
    if kind == "logs":
        b.logs(**args)
    elif kind == "rate":
        b.log_rate(**args)
    elif kind == "table":
        b.log_table(**args)
    else:  # pragma: no cover - guarded by test_boards_declare_known_log_kinds
        raise ValueError(f"unknown log panel kind {kind!r}")
