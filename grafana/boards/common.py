"""Turns a board module's declarative SECTIONS/LOGS into one domain tab.

# The mapping rule (#399 C8)

**One ``b.row()`` call becomes one leaf tab.** The rule partitions the panels a
board appended at their row markers, rather than mapping from ``SECTIONS``.

That matters because ``SECTIONS`` is not the only source of rows: the availability
row, every row a board's ``extra()`` emits (self-obs alone has twelve), and the
``LOGS`` row all reach the layout through the same ``b.row()`` call. A rule keyed
on ``SECTIONS`` would have had to special-case each of those; partitioning the
built stream covers them all by construction, and preserves self-obs's deliberate
``AVAILABILITY_PATTERN = None`` by simply emitting no availability leaf.

It also keeps the generator's existing habit of deriving rather than declaring —
titles come from ``titleize()``, coverage comes from reading expressions — instead
of adding a second layout declaration for a name to drift out of.
"""

from __future__ import annotations

import pivots
import v2
from builder import CENSUS_SENTINEL, Builder, titleize

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
surfaces, high-volume feeds) and several are empty on a healthy tenant. Check the
Signal availability row before interpreting an empty metric panel: it distinguishes
disabled, covered, healthy-empty, limited, blocked and failed collectors. An empty
availability table is unknown, not evidence that a collector is disabled.
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


def add(b: Builder, mod) -> dict:
    """Append one board module's content to the estate builder as a domain tab.

    Returns the ``TabsLayoutTab`` for the domain. Panels go into the shared
    builder, so panel ids are unique across the whole estate and the drilldown
    links — which are derived from ``panel["id"]`` at build time — follow
    automatically.
    """
    # The domain's own prose, kept as one compact panel rather than the 12-row
    # shared preamble that used to be repeated on all six boards (#311). It is
    # injected into the first leaf below, whichever row opens it.
    about = b.text(mod.DESCRIPTION, title=f"About {mod.DOMAIN}", h=4)
    start = len(b._panels)

    if not hasattr(mod, "AVAILABILITY_PATTERN"):
        raise ValueError(
            f"{mod.__name__} must declare AVAILABILITY_PATTERN; use None only "
            "when the board owns an equivalent availability presentation"
        )
    availability_pattern = mod.AVAILABILITY_PATTERN
    if availability_pattern:
        b.row("Signal availability")
        b.availability(availability_pattern)
    # Boards may add hand-authored presentation for cataloged signals that need
    # richer PromQL than the standard section renderer can express.
    extra = getattr(mod, "extra", None)
    extra_first = bool(getattr(mod, "EXTRA_FIRST", False))
    if extra is not None and extra_first:
        extra(b)
    for section_title, items in mod.SECTIONS:
        b.row(section_title)
        for item in items:
            _entry(b, item)
    if extra is not None and not extra_first:
        extra(b)
    logs = getattr(mod, "LOGS", ())
    if logs:
        b.row("Logs — which one, not how many (#162)")
        for spec in logs:
            _log_entry(b, spec)

    leaves = _leaves(b, b._panels[start:])
    if not leaves:
        raise ValueError(f"{mod.__name__} produced no rows, so it has no leaf tabs")
    _prepend(leaves[0], {"w": 24, "h": 4, "spec": about})
    # A domain whose collectors are all intentionally absent hides, but only on
    # positive evidence from a healthy census. Self-obs declares no pattern: the
    # exporter's own health must stay reachable in every state, including the one
    # where the census itself is missing.
    present = None
    if availability_pattern:
        slug = mod.DOMAIN.lower().replace("-", "_")
        present = b.sentinel(f"has_{slug}", availability_pattern)
        b.sentinel(CENSUS_SENTINEL)
    return v2.domain(mod.DOMAIN, leaves, present=present,
                     census=CENSUS_SENTINEL if present else None)


def _prepend(leaf: dict, item: dict):
    """Put one panel first in a leaf's opening row, re-packing that row."""
    rows = leaf["spec"]["layout"]["spec"]["rows"]
    grid = rows[0]["spec"]["layout"]["spec"]["items"]
    existing = [{"w": i["spec"]["width"], "h": i["spec"]["height"],
                 "spec": {"id": _id_of(i)}} for i in grid]
    rows[0]["spec"]["layout"] = v2.grid([item, *existing])


def _id_of(grid_item: dict) -> int:
    return int(grid_item["spec"]["element"]["name"].removeprefix("panel-"))


def _leaves(b: Builder, items: list) -> list:
    """Partition a board's panel stream at row markers into leaf tabs.

    Panels appended before the first row would be unreachable, so they are a
    build error rather than silently dropped: the estate's shared preamble now
    lives on the Overview tab, and nothing else should precede a row.
    """
    leaves, title, panels = [], None, []

    def flush():
        if title is not None:
            leaves.append(v2.leaf(title, [v2.rowspec("", panels)]))

    for item in items:
        if item.get("row"):
            flush()
            title, panels = item["title"], []
            continue
        if title is None:
            b.violations.append(
                f"panel {item['spec']['id']} ({item['spec'].get('title')!r}) "
                "precedes the first row and would land in no leaf tab"
            )
            continue
        panels.append(item)
    flush()
    return leaves


def _log_entry(b: Builder, spec: dict):
    kind = spec.get("kind", "logs")
    args = {k: v for k, v in spec.items() if k != "kind"}
    if kind == "logs":
        panel = b.logs(**args)
    elif kind == "rate":
        panel = b.log_rate(**args)
    elif kind == "table":
        panel = b.log_table(**args)
    else:  # pragma: no cover - guarded by test_boards_declare_known_log_kinds
        raise ValueError(f"unknown log panel kind {kind!r}")
    _pivot_links(b, panel, spec["event"])


def _pivot_links(b: Builder, panel: dict, event: str):
    """Put an entity pivot in the panel's header menu for each entity it names.

    Derived from the event's own attribute keys, so a log panel cannot advertise a
    pivot its records cannot feed and a new event carrying an identifier gets the
    link with no human step. The links are **panel** links rather than data links:
    a panel link carries no clicked-row value, and the alternative — a per-field
    data link that interpolates the identifier automatically — depends on Grafana
    rendering data links inside the log-detail view, which this lane cannot
    measure. The link therefore carries the tenant and the time range, and the
    analyst pastes the identifier they are already looking at.
    """
    keys = set(b.cat.log(event).keys)
    links = [
        {"title": entity.link_title(), "url": pivots.PIVOT_URL,
         "targetBlank": False}
        for entity in pivots.ENTITIES
        if keys & set(entity.keys)
    ]
    if links:
        panel["links"] = links
