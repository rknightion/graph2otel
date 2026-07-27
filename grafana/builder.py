"""Grafana dashboard builder for graph2otel (#218).

Pure standard library — no grafonnet, no pip install, so CI needs no
``setup-python`` step and a contributor needs nothing but python3.

# The two rules this file exists to enforce mechanically

**1. Queries are derived from the catalog, never hand-typed.** graph2otel is
OTLP-only: there is no Prometheus endpoint whose names could be read off a live
target, so the name a panel must query only exists after a backend normalizes
it. ``Builder.metric()`` looks the metric up in the catalog and renders the
normalized name, the aggregation its unit permits, and the label set it really
carries. A typo is a KeyError at build time rather than an empty panel someone
notices in six months.

This covers metric names, event names, **and** — since #306 — the attribute keys
inside a log query. It did not always: log filters were raw strings, so a
misspelled attribute was a valid LogQL stage matching nothing, silently, forever.
An earlier version of this docstring claimed otherwise, which was the exact
overstatement #306 was opened to correct. Log filters are now typed
(``logquery.f``) with a declared escape (``logquery.Raw``) and both are validated
against the event's real attribute set.

Since #304 the same rule covers **presentation**: the unit a panel formats with,
the title it claims, and any value mapping or threshold it colours with come from
``presentation.py``, an audited registry keyed by catalog metric. A hand-typed
unit was a second place for a fact to drift, and it had drifted — every
hand-written rate panel in self-observability formatted a per-second series as a
bare count.

**2. LogQL never satisfies the metric coverage gate.** PromQL and LogQL are
accumulated into two separate corpora (``_exprs`` / ``_loki_exprs``). They are
separate on purpose: a metric name appearing inside a LogQL label filter would
otherwise credit a metric that has no metric panel at all.

# The LogQL trap this file cannot let an author fall into (#90)

Every log attribute graph2otel emits lands in Loki as **structured metadata**,
not as a stream label. Only ``service_name`` is a stream label. So
``{event_name="entra.signin"}`` matches zero rows, silently, forever — it is not
an error, there is simply no stream label by that name. ``Builder.logs()`` and
friends therefore BUILD the selector; an author supplies the event name and the
attribute filters and never writes a stream selector at all.
"""

from __future__ import annotations

import json

import logquery
import presentation
import v2
from catalog import TENANT_SCOPE

# The tenant dropdown is backed by the availability census for the whole estate
# rather than by a per-domain metric. The census is emitted for every collector
# regardless of state — including disabled ones — so the dropdown populates even
# when a domain is switched off, which a domain metric like intune_devices_count
# does not.
TENANT_SOURCE_METRIC = "graph2otel.collector.availability"

# The whole estate is one v2 dashboard, and ``metadata.name`` is its identity —
# there is no top-level uid. The six per-domain uids are retired (#399).
DASHBOARD_NAME = "graph2otel"

# The census sentinel every conditional element escapes on. An entirely absent
# census means *unknown*, never *disabled* (#303), so its emptiness must make
# content visible rather than hide it.
CENSUS_SENTINEL = "census_present"

# Every panel query filters on the tenant template variable. tenant_id is on
# every signal, metric and log alike (#143).
TENANT_SEL = 'tenant_id=~"$tenant"'
RATE = "$__rate_interval"

PROM_DS = {"type": "prometheus", "uid": "${datasource}"}
LOKI_DS = {"type": "loki", "uid": "${loki_datasource}"}

# Portable Grafana Cloud defaults (#295). Every Grafana Cloud stack provisions
# its built-in Prometheus/Loki datasources under these fixed UIDs regardless of
# account name — the live m7kni stack has uid=grafanacloud-prom with display
# name grafanacloud-robknight-prom, confirming the UID is the stable, portable
# identifier and the display name is not. Saving these as the variables' saved
# `current` value is the maintainer-approved fix (issue #295, decision recorded
# 2026-07-27): a default-live render then opens on the intended backend instead
# of an empty stack default, while the dropdown stays selectable for a
# self-hosted or differently-named stack.
PROM_DATASOURCE_DEFAULT = "grafanacloud-prom"
LOKI_DATASOURCE_DEFAULT = "grafanacloud-logs"

# Exclusion regexes so a same-typed near-miss datasource is never offered as
# the resolved default (#295's second acceptance criterion: "a deployment with
# competing compatible datasources is covered"). Live-verified 2026-07-27
# against the m7kni Grafana Cloud stack (`gcx datasources list --context
# cloud`): grafanacloud-ml-metrics (the ML forecast proxy) and grafanacloud-usage
# (billing/usage metrics) are both type=prometheus; grafanacloud-alert-state-history
# and grafanacloud-usage-insights are both type=loki. These are the exact
# patterns Grafana's own Cloud Connections plugin already ships on live
# Alloy-mixin dashboards on that same stack for the same purpose — not a
# guessed regex.
PROM_DATASOURCE_EXCLUDE_REGEX = r"(?!grafanacloud-usage|grafanacloud-ml-metrics).+"
LOKI_DATASOURCE_EXCLUDE_REGEX = (
    r"(?!grafanacloud.+usage-insights|grafanacloud.+alert-state-history).+"
)

# Shown by every log panel when the Loki datasource is unset or empty, so an
# operator with no Loki sees an explanation instead of a broken-looking panel
# (#162's third acceptance criterion).
NO_LOKI = (
    "No rows. Either no Loki datasource is selected above, or nothing matched. "
    "Log attributes are structured metadata: filter with | attr=… after "
    '{service_name="graph2otel"}, never {attr="…"}.'
)

NO_METRIC = (
    "No metric rows. Check Signal availability above: this result alone is not "
    "evidence that the collector is disabled, healthy, or failed. A datasource "
    "or query error is shown separately."
)

NO_AVAILABILITY = (
    "Availability unknown. No availability rows were returned; this does not mean "
    "disabled. Verify the Prometheus datasource, tenant selection, and deployment."
)

AVAILABILITY_STATES = {
    "disabled": {"text": "Disabled"},
    "blocked": {"text": "Blocked"},
    "covered": {"text": "Covered by alternative"},
    "starting": {"text": "Starting"},
    "healthy_empty": {"text": "Healthy, empty"},
    "healthy": {"text": "Healthy"},
    "limited": {"text": "Limited"},
    "degraded": {"text": "Degraded"},
    "failed": {"text": "Failed"},
    "startup_failed": {"text": "Startup failed"},
}

AVAILABILITY_REASONS = {
    "transport_not_configured": {"text": "Transport not configured"},
    "experimental_not_enabled": {"text": "Experimental collector not enabled"},
    "high_volume_not_enabled": {"text": "High-volume collector not enabled"},
    "disabled_by_config": {"text": "Disabled by configuration"},
    "permission_denied": {"text": "Permission denied"},
    "license_unavailable": {"text": "Required licence unavailable"},
    "covered_by_alternative": {"text": "Covered by another transport"},
    "no_completed_run": {"text": "No completed run yet"},
    "license_detection_failed": {"text": "Licence detection failed"},
    "transport_initialization_failed": {"text": "Transport initialization failed"},
    "invalid_transport_configuration": {"text": "Invalid transport configuration"},
    "transport_fallback": {"text": "Running on fallback transport"},
    "empty": {"text": "Successful source response with zero rows"},
    "success": {"text": "Successful source response"},
    "partial_license": {"text": "Running with a partial licence"},
    "source_error": {"text": "Source error"},
    "decode_error": {"text": "Decode error"},
    "mapping_error": {"text": "Mapping error"},
    "missing_event_time": {"text": "Missing event time"},
    "accounting_mismatch": {"text": "Record accounting mismatch"},
    "timeout": {"text": "Timeout"},
    "panic": {"text": "Collector panic"},
    "credential_initialization_failed": {"text": "Credential initialization failed"},
    "graph_client_initialization_failed": {"text": "Graph client initialization failed"},
}

# Units, value mappings and thresholds are owned by ``presentation`` (#304), a
# separate audited registry keyed by catalog metric. They are deliberately NOT
# restated here: a second copy would drift, and the honesty gate would then have
# two places to audit instead of one.

# Words that must not be title-cased into gibberish when a panel title is
# derived from a metric name.
ACRONYMS = {
    "uxa": "UXA", "mfa": "MFA", "pim": "PIM", "ca": "CA", "epm": "EPM",
    "dlp": "DLP", "gpo": "GPO", "gsa": "GSA", "mdo": "MDO", "rbac": "RBAC",
    "wip": "WIP", "os": "OS", "dkim": "DKIM", "tpm": "TPM", "cve": "CVE",
    "cvss": "CVSS", "epss": "EPSS", "eol": "EOL", "eos": "EOS", "esp": "ESP",
    "sku": "SKU", "mtd": "MTD", "pki": "PKI", "mdm": "MDM", "id": "ID",
    "api": "API", "url": "URL", "ip": "IP", "oauth": "OAuth", "http": "HTTP",
    "tls": "TLS", "vbs": "VBS",
}


def titleize(metric_name: str) -> str:
    """Derive a panel title from a catalog metric name.

    Titles are DERIVED rather than declared so that a board module is a list of
    what is panelled, not a second place for a name to drift. An author who
    wants better words passes ``title=``.
    """
    parts = metric_name.split(".")[1:]  # drop the domain prefix
    words = []
    for p in parts:
        words.extend(p.split("_"))
    out = []
    for i, w in enumerate(words):
        if w in ACRONYMS:
            out.append(ACRONYMS[w])
        elif i == 0:
            out.append(w[:1].upper() + w[1:])
        else:
            out.append(w)
    return " ".join(out)


def group_keys(keys: list) -> list:
    """The label set a panel groups by.

    All of the metric's attribute keys, minus an ``x_id`` where an ``x_name``
    also exists: the pair names the same entity twice, and the opaque half only
    multiplies series. The catalog keeps both because that is what is emitted;
    a panel does not need both.
    """
    names = {k[: -len("_name")] for k in keys if k.endswith("_name")}
    return [k for k in keys if not (k.endswith("_id") and k[: -len("_id")] in names)]


def _metric_group_keys(metric, by: list | None) -> list:
    """Return aggregation keys without discarding emitter-boundary tenant identity."""
    keys = list(by) if by is not None else group_keys(metric.keys)
    keys = [
        key for key in keys
        if key in metric.keys or (
            key == "tenant_id" and metric.scope == TENANT_SCOPE
        )
    ]
    if metric.scope == TENANT_SCOPE and "tenant_id" not in keys:
        keys.insert(0, "tenant_id")
    return keys


def _label_legend(keys: list) -> str:
    return " ".join(f"{{{{{key}}}}}" for key in keys)


def _tenant_group_keys(keys: list | None) -> list:
    return ["tenant_id", *(key for key in (keys or []) if key != "tenant_id")]


class Builder:
    """Accumulates panels for one dashboard and renders the Grafana JSON.

    Panels are appended in construction order; rows are opened with ``row()``.
    Each row becomes one leaf tab, and its panels are packed into a 24-column
    grid by :func:`v2.grid`, so no board module ever writes an x/y coordinate.
    """

    def __init__(self, name: str, title: str, description: str, tags: list,
                 catalog, needs_loki: bool = True):
        self.name = name
        self.title = title
        self.description = description
        self.tags = tags
        self.cat = catalog
        self.needs_loki = needs_loki
        # label_values() needs a metric that actually exists for the tenant
        # dropdown to populate. One estate, one census-backed dropdown.
        tenant_source = catalog.metric(TENANT_SOURCE_METRIC)
        if tenant_source.scope != TENANT_SCOPE:
            raise ValueError(
                f"tenant dropdown metric {TENANT_SOURCE_METRIC!r} is "
                "process-scoped and has no tenant_id label"
            )
        self.tenant_metric = tenant_source.prom

        self._id = 0
        self._panels = []          # list of (kind, spec) in declaration order
        self._exprs = []           # every PromQL string, for the coverage gate
        self._loki_exprs = []      # every LogQL string, deliberately separate
        self._covered = set()      # catalog metric names a query really names
        self.violations = []       # accumulated build-time rule breaches
        self.extra_vars = []       # board-declared template variables
        self._sentinels = {}       # sentinel name -> query, declaration order

    @property
    def covered(self) -> set:
        """Catalog metric names some panel query really names."""
        return set(self._covered)

    # ----- ids and raw panel construction ---------------------------------

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _add(self, spec: dict, w: int, h: int):
        self._panels.append({"w": w, "h": h, "spec": spec})
        return spec

    def _prom_query(self, expr: str, ref: str = "A", legend: str = None,
                    instant: bool = False) -> dict:
        self._exprs.append(expr)
        self._covered |= self.cat.metrics_referenced_by(expr)
        q = {"refId": ref, "expr": expr, "datasource": PROM_DS,
             "editorMode": "code", "range": not instant, "instant": instant}
        if legend is not None:
            q["legendFormat"] = legend
        return q

    def _loki_query(self, expr: str, ref: str = "A", legend: str = None,
                    query_type: str = "range") -> dict:
        # NOT self._exprs: a metric name inside a LogQL filter must never
        # satisfy the Prometheus metric-coverage gate.
        self._loki_exprs.append(expr)
        q = {"refId": ref, "expr": expr, "datasource": LOKI_DS,
             "editorMode": "code", "queryType": query_type}
        if legend is not None:
            q["legendFormat"] = legend
        return q

    # ----- structural panels ----------------------------------------------

    def row(self, title: str):
        # The id is taken HERE, not in _layout(): _layout must be a pure function
        # of the accumulated panels, or a second render() would renumber every
        # row and the staleness gate would fire on an unchanged board.
        self._panels.append({"row": True, "title": title, "id": self._next_id()})

    def text(self, content: str, title: str = "", h: int = 4, w: int = 24):
        return self._add({
            "id": self._next_id(), "type": "text", "title": title,
            "gridPos": {}, "options": {"mode": "markdown", "content": content},
        }, w, h)

    # ----- Prometheus panels ----------------------------------------------

    def metric(self, name: str, title: str = None, by: list = None,
               viz: str = None, desc: str = "", w: int = 12, h: int = 8,
               quantile: float = 0.95):
        """Panel one cataloged metric, with everything derived from the catalog.

        The aggregation comes from ``additive``: a non-additive metric (a score,
        a ratio, a percentage, a duration) is averaged, never summed, because
        the sum of four thousand health scores is a number nobody measured
        (#235). The grouping comes from the metric's real attribute keys, so a
        panel cannot group by a label the metric does not carry.
        """
        return self.metrics([name], title=title or titleize(name), by=by, viz=viz,
                            desc=desc, w=w, h=h, quantile=quantile,
                            derive_rate_title=title is None)

    def metrics(self, names: list, title: str, by: list = None, viz: str = None,
                desc: str = "", w: int = 12, h: int = 8, quantile: float = 0.95,
                legends: list = None, derive_rate_title: bool = False):
        """Panel several related metrics together on one set of axes.

        Units, value mappings and thresholds come from the presentation registry
        (#304) whenever every metric on the panel agrees about them. A panel
        carrying four boolean tenant switches therefore shares their one cited
        0/1 mapping, while a panel mixing a flag with a count agrees on nothing
        and gets the neutral default.
        """
        queries = []
        units = set()
        any_hist = False
        for i, name in enumerate(names):
            m = self.cat.metric(name)
            keys = _metric_group_keys(m, by)
            expr = self._expr(m, keys, quantile)
            legend = None
            if legends is not None and i < len(legends):
                legend = legends[i]
            elif m.scope == TENANT_SCOPE:
                legend = _label_legend(keys)
                if len(names) > 1:
                    legend = f"{titleize(name)} {legend}"
            elif len(names) > 1 and not keys:
                legend = titleize(name)
            queries.append(self._prom_query(expr, ref=chr(65 + i), legend=legend))
            # A sum instrument is always displayed through rate(), so its unit is
            # the unit of that rate — not the counter's own unit (#304).
            units.add(presentation.rate_unit(m.unit) if m.kind == "sum"
                      else presentation.gauge_unit(m.unit))
            any_hist = any_hist or m.kind == "histogram"

        if viz is None:
            first = self.cat.metric(names[0])
            has_keys = bool(by if by is not None else group_keys(first.keys))
            viz = "stat" if (not has_keys and not any_hist and len(names) <= 3) else "timeseries"
        unit = units.pop() if len(units) == 1 else "short"
        if any_hist:
            # A histogram_quantile result is in the bucket's unit, not per second.
            unit = presentation.gauge_unit(self.cat.metric(names[0]).unit)
        entry = presentation.agreed(names)
        if entry is not None and entry.unit and not any_hist:
            unit = entry.unit
        if not desc and len(names) == 1:
            # The catalog carries the emitter's own description, captured from
            # the Go source that writes the metric. Using it costs nothing and
            # cannot drift; leaving it unused was #304's "limiting generated
            # context" finding.
            desc = self.cat.metric(names[0]).description or ""
        if derive_rate_title and any(
                self.cat.metric(n).kind == "sum" for n in names) and not any_hist:
            title = presentation.rate_title(title)
        return self._viz_panel(viz, title, queries, unit, desc, w, h, entry=entry)

    def raw(self, title: str, exprs: list, viz: str = "timeseries", unit: str = None,
            desc: str = "", w: int = 12, h: int = 8, legends: list = None,
            about: str = ""):
        """Panel a hand-written PromQL expression.

        Coverage still comes from reading the expression, not from a claim, so a
        raw panel credits exactly the metrics its text really names.

        The unit is DERIVED from those same metrics unless one is passed, for the
        same reason the query is derived: a hand-typed unit is a second place for
        a fact to drift, and it drifted — every hand-written rate panel in
        self-observability was formatted as a bare count (#304).

        ``about`` names the cataloged metric the panel is *about*, so a
        hand-written expression still takes its cited mapping and threshold from
        the presentation registry instead of declaring them locally.
        """
        queries = []
        for i, e in enumerate(exprs):
            legend = legends[i] if legends and i < len(legends) else None
            queries.append(self._prom_query(e, ref=chr(65 + i), legend=legend))
        entry = presentation.agreed([about]) if about else None
        if unit is None:
            unit = (entry.unit if entry and entry.unit
                    else self._derived_unit(exprs))
        return self._viz_panel(viz, title, queries, unit, desc, w, h, entry=entry)

    def _derived_unit(self, exprs: list) -> str:
        """The unit a hand-written expression really produces.

        Rate-shaped when the expression rates a counter, and the counter's own
        unit otherwise. ``histogram_quantile`` is deliberately not a rate: its
        result is in the bucket's unit (#304).
        """
        names = set()
        for e in exprs:
            names |= self.cat.metrics_referenced_by(e)
        if not names:
            return "short"
        rated = any(presentation.plots_a_rate(e) for e in exprs)
        units = {presentation.rate_unit(self.cat.metric(n).unit) if rated
                 else presentation.gauge_unit(self.cat.metric(n).unit)
                 for n in names}
        return units.pop() if len(units) == 1 else ("cps" if rated else "short")

    def _expr(self, m, keys: list, quantile: float) -> str:
        sel = "" if m.scope == "process" else f"{{{TENANT_SEL}}}"
        if m.kind == "histogram":
            grp = ", ".join(["le"] + keys)
            return (f"histogram_quantile({quantile}, sum by ({grp}) "
                    f"(rate({m.prom}_bucket{sel}[{RATE}])))")
        inner = f"{m.prom}{sel}"
        if m.kind == "sum":
            inner = f"rate({inner}[{RATE}])"
            agg = "sum"
        else:
            agg = "sum" if m.additive else "avg"
        if keys:
            return f"{agg} by ({', '.join(keys)}) ({inner})"
        return f"{agg}({inner})"

    def _viz_panel(self, viz: str, title: str, queries: list, unit: str,
                   desc: str, w: int, h: int, entry=None):
        # Thresholds are ALWAYS written. Omitting them is not neutral: Grafana
        # substitutes a green base with a red step at 80, which is how a neutral
        # inventory count of 95 devices rendered as an alarm (#304).
        thresholds = (entry.thresholds.field_config() if entry and entry.thresholds
                      else presentation.neutral_thresholds())
        field_config = {
            "defaults": {"unit": unit, "custom": {}, "noValue": NO_METRIC,
                         "thresholds": thresholds},
            "overrides": [],
        }
        if entry is not None and entry.mappings is not None:
            field_config["defaults"]["mappings"] = entry.mappings.field_config()
        desc = presentation.cite(desc, entry)
        options = {}
        if viz == "timeseries":
            field_config["defaults"]["custom"] = {
                "drawStyle": "line", "lineWidth": 1, "fillOpacity": 10,
                "showPoints": "never", "spanNulls": True,
            }
            options = {
                "legend": {"displayMode": "table", "placement": "bottom",
                           "showLegend": True, "calcs": ["lastNotNull", "max"]},
                "tooltip": {"mode": "multi", "sort": "desc"},
            }
        elif viz == "stat":
            # No colour unless a cited threshold says what the colour means, so
            # an empty or unmapped value cannot inherit a green "healthy" that
            # nobody measured.
            colored = bool(entry and entry.thresholds)
            options = {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "colorMode": "value" if colored else "none",
                "graphMode": "area", "textMode": "auto",
                "justifyMode": "auto", "orientation": "auto",
            }
        elif viz == "table":
            for q in queries:
                q["instant"] = True
                q["range"] = False
            options = {"showHeader": True, "cellHeight": "sm",
                       "footer": {"show": False, "reducer": ["sum"], "fields": ""}}
        elif viz == "bargauge":
            options = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                       "displayMode": "gradient", "orientation": "horizontal",
                       "showUnfilled": True}
        elif viz == "heatmap":
            options = {"calculate": False,
                       "cellGap": 1,
                       "color": {"mode": "scheme", "scheme": "Oranges", "steps": 64},
                       "yAxis": {"unit": unit}}
        return self._add({
            "id": self._next_id(), "type": viz, "title": title,
            "description": desc, "gridPos": {}, "datasource": PROM_DS,
            "fieldConfig": field_config, "options": options, "targets": queries,
        }, w, h)

    def availability(self, collector_pattern: str):
        """Add the domain's truthful current collector-state table.

        The metric value is always one. Its bounded ``state`` and ``reason``
        labels carry the meaning, so the table maps those string values rather
        than inventing a numeric health score.
        """
        metric = self.cat.metric("graph2otel.collector.availability")
        expr = (
            "max by (tenant_id, collector, collector_transport, state, reason) "
            f'({metric.prom}{{{TENANT_SEL},collector=~"{collector_pattern}"}})'
        )
        guide = (
            "Current collector state from graph2otel.collector.availability. "
            "Intentional absence is disabled "
            "(transport_not_configured, experimental_not_enabled, "
            "high_volume_not_enabled, disabled_by_config) or covered "
            "(covered_by_alternative). healthy_empty/empty is a successful "
            "zero-row source response. limited/partial_license is non-failure; "
            "blocked/license_unavailable identifies a missing entitlement, while "
            "blocked/permission_denied requires access. degraded and failed "
            "(including source_error) describe completed runtime outcomes; "
            "startup_failed describes initialization failure. An empty table is "
            "unknown, never evidence of disabled."
        )
        panel = self.raw(
            "Signal availability",
            [expr],
            viz="table",
            desc=guide,
            w=24,
            h=8,
        )
        panel["fieldConfig"]["defaults"]["noValue"] = NO_AVAILABILITY
        panel["fieldConfig"]["overrides"] = [
            _value_mapping("state", AVAILABILITY_STATES),
            _value_mapping("reason", AVAILABILITY_REASONS),
        ]
        panel["transformations"] = [
            {"id": "labelsToFields", "options": {"mode": "columns"}},
        ]
        return panel

    # ----- Loki panels (#162) ---------------------------------------------

    def _selector(self, event: str, filters: list = None,
                  by: list = None) -> str:
        """Build the ONLY correct LogQL shape for a graph2otel log record.

        ``service_name`` is the sole stream label; ``event_name`` and every other
        attribute is structured metadata and must be filtered after the pipe
        (#90). This method is the reason a board module cannot get that wrong: it
        never accepts a stream selector from the caller.

        Filters are typed (``logquery.f`` / ``logquery.Raw``) and their keys —
        along with any ``by`` group keys — are validated against the event's real
        attribute set (#306). A bare string is refused. Before that, a misspelled
        attribute was a valid LogQL stage matching nothing, silently, forever.
        """
        self.cat.log(event)  # fails the build on a misspelled event name
        self.violations.extend(
            logquery.violations(self.cat, event, filters=filters, by=by))
        parts = ['{service_name="graph2otel"}', f"| event_name=`{event}`",
                 f'| tenant_id=~"$tenant"']
        parts.extend(f"| {rendered}"
                     for rendered in logquery.render_filters(filters))
        return " ".join(parts)

    def logs(self, event: str, title: str, filters: list = None, desc: str = "",
             w: int = 24, h: int = 10):
        """Raw log lines for one event."""
        expr = self._selector(event, filters)
        q = self._loki_query(expr)
        return self._add({
            "id": self._next_id(), "type": "logs", "title": title,
            "description": desc + _loki_note(), "gridPos": {}, "datasource": LOKI_DS,
            # Neutral thresholds even on a logs panel: the gate has no exemption
            # list, because an exemption list is a second thing to audit and the
            # first collector to land in it would never come back out.
            "fieldConfig": {"defaults": {"noValue": NO_LOKI,
                                         "thresholds": presentation.neutral_thresholds()},
                            "overrides": []},
            "options": {"showTime": True, "wrapLogMessage": True,
                        "sortOrder": "Descending", "enableLogDetails": True,
                        "dedupStrategy": "none", "prettifyLogMessage": False},
            "targets": [q],
        }, w, h)

    def log_rate(self, event: str, title: str, by: list = None, filters: list = None,
                 desc: str = "", w: int = 12, h: int = 8):
        """count_over_time for one event, optionally split by structured metadata."""
        sel = self._selector(event, filters, by=by)
        keys = _tenant_group_keys(by)
        expr = f"sum by ({', '.join(keys)}) (count_over_time({sel} [$__auto]))"
        q = self._loki_query(expr, legend=_label_legend(keys))
        panel = self._viz_panel("timeseries", title, [], "short", desc + _loki_note(), w, h)
        panel["datasource"] = LOKI_DS
        panel["targets"] = [q]
        panel["fieldConfig"]["defaults"]["noValue"] = NO_LOKI
        return panel

    def log_table(self, event: str, title: str, by: list, filters: list = None,
                  topk: int = 20, desc: str = "", w: int = 12, h: int = 8):
        """Top-N breakdown of one event by a structured-metadata key.

        Range + reduce rather than an instant ``topk``: an instant query
        materializes one series per distinct value before topk runs, which walks
        straight into Loki's series cap on any wide time range.
        """
        sel = self._selector(event, filters, by=by)
        keys = _tenant_group_keys(by)
        expr = (
            f"topk({topk}, sum by ({', '.join(keys)}) "
            f"(count_over_time({sel} [$__auto])))"
        )
        q = self._loki_query(expr, legend=_label_legend(keys))
        panel = self._viz_panel("table", title, [], "short", desc + _loki_note(), w, h)
        panel["datasource"] = LOKI_DS
        panel["targets"] = [q]
        panel["fieldConfig"]["defaults"]["noValue"] = NO_LOKI
        panel["transformations"] = [
            {"id": "reduce", "options": {"reducers": ["sum"], "mode": "seriesToRows"}}
        ]
        return panel

    # ----- rendering -------------------------------------------------------

    def variables(self) -> list:
        """Every declared variable, as typed v2 objects, in picker order."""
        out = [v2.datasource_variable(
            "datasource", "Prometheus datasource", "prometheus",
            default=PROM_DATASOURCE_DEFAULT,
            regex=PROM_DATASOURCE_EXCLUDE_REGEX,
            description="Where graph2otel's OTLP metrics land after normalization. "
                        f"Defaults to Grafana Cloud's {PROM_DATASOURCE_DEFAULT}; pick "
                        "another Prometheus datasource for a different stack.",
        )]
        if self.needs_loki:
            out.append(v2.datasource_variable(
                "loki_datasource", "Loki datasource", "loki",
                default=LOKI_DATASOURCE_DEFAULT,
                regex=LOKI_DATASOURCE_EXCLUDE_REGEX,
                description="Required by the log panels. Defaults to Grafana Cloud's "
                            f"{LOKI_DATASOURCE_DEFAULT}. Leave unset and they say so "
                            "rather than looking broken.",
            ))
        out.append(v2.query_variable(
            "tenant", f"label_values({self.tenant_metric}, tenant_id)",
            label="Tenant", multi=True, include_all=True,
            description="tenant_id is on every signal (#143). A single-tenant deployment "
                        "with no tenant id configured stamps no label; select All.",
        ))
        out.extend(self.extra_vars)
        out.extend(v2.sentinel(name, query)
                   for name, query in self._sentinels.items())
        return out

    def variable(self, name: str, query: str, *, label: str = "",
                 multi: bool = False, include_all: bool = False):
        """Declare an extra visible query variable (board modules only)."""
        self.extra_vars.append(v2.query_variable(
            name, query, label=label or name, multi=multi, include_all=include_all))

    def sentinel(self, name: str, collector_pattern: str = "") -> str:
        """Declare a hidden presence sentinel and return its name.

        Idempotent, so a domain and one of its leaves can share one. With no
        pattern this is the estate-wide census sentinel, whose *emptiness* is the
        fail-visible escape every conditional element carries.

        The selector deliberately excludes only ``disabled`` and ``covered`` —
        the two states that mean intentional absence. ``starting``,
        ``healthy_empty``, ``limited``, ``blocked``, ``degraded``, ``failed`` and
        ``startup_failed`` all keep their content **visible**: a failure an
        operator cannot see is worse than an empty panel, and healthy-empty is a
        correct steady state for several collectors.
        """
        metric = self.cat.metric(TENANT_SOURCE_METRIC).prom
        if collector_pattern:
            selector = (f'{{{TENANT_SEL},collector=~"{collector_pattern}",'
                        'state!~"disabled|covered"}')
        else:
            selector = f"{{{TENANT_SEL}}}"
        query = f"label_values({metric}{selector}, collector)"
        existing = self._sentinels.get(name)
        if existing is not None and existing != query:
            raise ValueError(
                f"sentinel {name!r} already declared with a different query: "
                f"{existing!r} vs {query!r}"
            )
        self._sentinels[name] = query
        return name

    def elements(self) -> dict:
        """Every panel as a named v2 element, in declaration order."""
        out = {}
        for item in self._panels:
            if item.get("row"):
                continue
            name, element = v2.panel_element(item["spec"], item["w"], item["h"])
            out[name] = element
        return out

    def render(self, tabs: list) -> dict:
        """Assemble the single v2 dashboard manifest from the given tab layout."""
        return v2.manifest(
            name=self.name,
            title=self.title,
            description=self.description,
            tags=self.tags,
            variables=self.variables(),
            elements=self.elements(),
            tabs=tabs,
        )


def _loki_note() -> str:
    return ("\n\nNeeds a **Loki** datasource (selected above). Log attributes are Loki "
            "*structured metadata*, not stream labels: filter with "
            "`| event_name=…` after `{service_name=\"graph2otel\"}`. A stream selector "
            "on an attribute matches zero rows silently (#90).")


def _value_mapping(field: str, values: dict) -> dict:
    return {
        "matcher": {"id": "byName", "options": field},
        "properties": [{
            "id": "mappings",
            "value": [{"type": "value", "options": values}],
        }],
    }


def dumps(dashboard: dict) -> str:
    """Deterministic bytes: insertion-ordered keys, 2-space indent, trailing newline."""
    return json.dumps(dashboard, indent=2) + "\n"
