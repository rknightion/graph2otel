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

SCHEMA_VERSION = 39

# Every panel query filters on the tenant template variable. tenant_id is on
# every signal, metric and log alike (#143).
TENANT_SEL = 'tenant_id=~"$tenant"'
RATE = "$__rate_interval"

PROM_DS = {"type": "prometheus", "uid": "${datasource}"}
LOKI_DS = {"type": "loki", "uid": "${loki_datasource}"}

# Shown by every log panel when the Loki datasource is unset or empty, so an
# operator with no Loki sees an explanation instead of a broken-looking panel
# (#162's third acceptance criterion).
NO_LOKI = (
    "No rows. Either no Loki datasource is selected above, or nothing matched. "
    "Log attributes are structured metadata: filter with | attr=… after "
    '{service_name="graph2otel"}, never {attr="…"}.'
)

# UCUM unit -> Grafana field unit id. An annotation unit ("{device}") is a count
# of a thing, which Grafana renders as "short".
GRAFANA_UNITS = {
    "s": "s",
    "ms": "ms",
    "min": "m",
    "h": "h",
    "d": "d",
    "By": "bytes",
    "MB": "decmbytes",
    "%": "percent",
    "1": "short",
}

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


class Builder:
    """Accumulates panels for one dashboard and renders the Grafana JSON.

    Panels are appended in construction order; rows are opened with ``row()``.
    Layout is a 24-column shelf pack computed at render time, so no board module
    ever writes an x/y coordinate.
    """

    def __init__(self, uid: str, title: str, description: str, tags: list,
                 tenant_metric: str, catalog, needs_loki: bool = True):
        self.uid = uid
        self.title = title
        self.description = description
        self.tags = tags
        self.cat = catalog
        self.needs_loki = needs_loki
        # label_values() needs a metric that actually exists for the tenant
        # dropdown to populate; each board names one of its own.
        self.tenant_metric = tenant_metric

        self._id = 0
        self._panels = []          # list of (kind, spec) in declaration order
        self._exprs = []           # every PromQL string, for the coverage gate
        self._loki_exprs = []      # every LogQL string, deliberately separate
        self._covered = set()      # catalog metric names a query really names
        self.violations = []       # accumulated build-time rule breaches
        self.extra_vars = []       # board-declared template variables

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
                            desc=desc, w=w, h=h, quantile=quantile)

    def metrics(self, names: list, title: str, by: list = None, viz: str = None,
                desc: str = "", w: int = 12, h: int = 8, quantile: float = 0.95,
                legends: list = None):
        """Panel several related metrics together on one set of axes."""
        queries = []
        units = set()
        any_hist = False
        for i, name in enumerate(names):
            m = self.cat.metric(name)
            keys = by if by is not None else group_keys(m.keys)
            keys = [k for k in keys if k in m.keys]
            expr = self._expr(m, keys, quantile)
            legend = None
            if legends is not None and i < len(legends):
                legend = legends[i]
            elif len(names) > 1 and not keys:
                legend = titleize(name)
            queries.append(self._prom_query(expr, ref=chr(65 + i), legend=legend))
            units.add(GRAFANA_UNITS.get(m.unit, "short"))
            any_hist = any_hist or m.kind == "histogram"

        if viz is None:
            first = self.cat.metric(names[0])
            has_keys = bool(by if by is not None else group_keys(first.keys))
            viz = "stat" if (not has_keys and not any_hist and len(names) <= 3) else "timeseries"
        unit = units.pop() if len(units) == 1 else "short"
        if any_hist:
            unit = GRAFANA_UNITS.get(self.cat.metric(names[0]).unit, "short")
        return self._viz_panel(viz, title, queries, unit, desc, w, h)

    def raw(self, title: str, exprs: list, viz: str = "timeseries", unit: str = "short",
            desc: str = "", w: int = 12, h: int = 8, legends: list = None):
        """Panel a hand-written PromQL expression.

        Coverage still comes from reading the expression, not from a claim, so a
        raw panel credits exactly the metrics its text really names.
        """
        queries = []
        for i, e in enumerate(exprs):
            legend = legends[i] if legends and i < len(legends) else None
            queries.append(self._prom_query(e, ref=chr(65 + i), legend=legend))
        return self._viz_panel(viz, title, queries, unit, desc, w, h)

    def _expr(self, m, keys: list, quantile: float) -> str:
        sel = f"{{{TENANT_SEL}}}"
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
                   desc: str, w: int, h: int):
        field_config = {
            "defaults": {"unit": unit, "custom": {}},
            "overrides": [],
        }
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
            options = {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "colorMode": "value", "graphMode": "area", "textMode": "auto",
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

    # ----- Loki panels (#162) ---------------------------------------------

    def _selector(self, event: str, filters: list = None) -> str:
        """Build the ONLY correct LogQL shape for a graph2otel log record.

        ``service_name`` is the sole stream label; ``event_name`` and every
        other attribute is structured metadata and must be filtered after the
        pipe (#90). This method is the reason a board module cannot get that
        wrong: it never accepts a stream selector from the caller.
        """
        self.cat.log(event)  # fails the build on a misspelled event name
        parts = ['{service_name="graph2otel"}', f"| event_name=`{event}`",
                 f'| tenant_id=~"$tenant"']
        for f in filters or []:
            parts.append(f"| {f}")
        return " ".join(parts)

    def logs(self, event: str, title: str, filters: list = None, desc: str = "",
             w: int = 24, h: int = 10):
        """Raw log lines for one event."""
        expr = self._selector(event, filters)
        q = self._loki_query(expr)
        return self._add({
            "id": self._next_id(), "type": "logs", "title": title,
            "description": desc + _loki_note(), "gridPos": {}, "datasource": LOKI_DS,
            "fieldConfig": {"defaults": {"noValue": NO_LOKI}, "overrides": []},
            "options": {"showTime": True, "wrapLogMessage": True,
                        "sortOrder": "Descending", "enableLogDetails": True,
                        "dedupStrategy": "none", "prettifyLogMessage": False},
            "targets": [q],
        }, w, h)

    def log_rate(self, event: str, title: str, by: list = None, filters: list = None,
                 desc: str = "", w: int = 12, h: int = 8):
        """count_over_time for one event, optionally split by structured metadata."""
        sel = self._selector(event, filters)
        if by:
            expr = f"sum by ({', '.join(by)}) (count_over_time({sel} [$__auto]))"
        else:
            expr = f"sum(count_over_time({sel} [$__auto]))"
        q = self._loki_query(expr)
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
        sel = self._selector(event, filters)
        expr = f"topk({topk}, sum by ({', '.join(by)}) (count_over_time({sel} [$__auto])))"
        q = self._loki_query(expr)
        panel = self._viz_panel("table", title, [], "short", desc + _loki_note(), w, h)
        panel["datasource"] = LOKI_DS
        panel["targets"] = [q]
        panel["fieldConfig"]["defaults"]["noValue"] = NO_LOKI
        panel["transformations"] = [
            {"id": "reduce", "options": {"reducers": ["sum"], "mode": "seriesToRows"}}
        ]
        return panel

    # ----- rendering -------------------------------------------------------

    def _layout(self) -> list:
        """24-column shelf pack. Rows are full-width separators that reset x."""
        out, x, y, row_h = [], 0, 0, 0
        for item in self._panels:
            if item.get("row"):
                if x:
                    y += row_h
                    x, row_h = 0, 0
                out.append({"id": item["id"], "type": "row", "title": item["title"],
                            "collapsed": False, "panels": [],
                            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}})
                y += 1
                continue
            w, h = item["w"], item["h"]
            if x + w > 24:
                x, y, row_h = 0, y + row_h, 0
            item["spec"]["gridPos"] = {"h": h, "w": w, "x": x, "y": y}
            out.append(item["spec"])
            x += w
            row_h = max(row_h, h)
        return out

    def variables(self) -> list:
        out = [{
            "name": "datasource", "label": "Prometheus datasource", "type": "datasource",
            "query": "prometheus", "current": {}, "hide": 0, "refresh": 1,
            "description": "Where graph2otel's OTLP metrics land after normalization.",
        }]
        if self.needs_loki:
            out.append({
                "name": "loki_datasource", "label": "Loki datasource", "type": "datasource",
                "query": "loki", "current": {}, "hide": 0, "refresh": 1,
                "description": "Required by the log panels. Leave unset and they say so "
                               "rather than looking broken.",
            })
        out.append({
            "name": "tenant", "label": "Tenant", "type": "query",
            "datasource": PROM_DS, "refresh": 2, "includeAll": True, "multi": True,
            "current": {}, "options": [], "hide": 0, "sort": 1,
            "query": {"qryType": 1, "query": f"label_values({self.tenant_metric}, tenant_id)",
                      "refId": "tenant"},
            "definition": f"label_values({self.tenant_metric}, tenant_id)",
            "description": "tenant_id is on every signal (#143). A single-tenant deployment "
                           "with no tenant id configured stamps no label; select All.",
        })
        out.extend(self.extra_vars)
        return out

    def variable(self, spec: dict):
        """Declare an extra template variable (board modules only)."""
        self.extra_vars.append(spec)

    def render(self) -> dict:
        panels = self._layout()
        return {
            "uid": self.uid,
            "title": self.title,
            "description": self.description,
            "tags": self.tags,
            "editable": True,
            "graphTooltip": 1,
            "schemaVersion": SCHEMA_VERSION,
            "version": 1,
            "refresh": "5m",
            "timezone": "",
            "time": {"from": "now-24h", "to": "now"},
            "annotations": {"list": []},
            "templating": {"list": self.variables()},
            "panels": panels,
        }


def _loki_note() -> str:
    return ("\n\nNeeds a **Loki** datasource (selected above). Log attributes are Loki "
            "*structured metadata*, not stream labels: filter with "
            "`| event_name=…` after `{service_name=\"graph2otel\"}`. A stream selector "
            "on an attribute matches zero rows silently (#90).")


def dumps(dashboard: dict) -> str:
    """Deterministic bytes: insertion-ordered keys, 2-space indent, trailing newline."""
    return json.dumps(dashboard, indent=2) + "\n"
