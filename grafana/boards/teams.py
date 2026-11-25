"""Separate Teams investigation dashboard, assembled from the signal catalogue."""

from builder import (AVAILABILITY_REASONS, AVAILABILITY_STATES, LOKI_DS, NO_LOKI, NO_METRIC, RATE,
                     TENANT_SEL, Builder, _loki_note, _value_mapping)
from logquery import Raw, f
import v2

from .teams_quality import LOCAL, compliance, counter_increase, site_queries

NAME = "graph2otel-teams"
CALL = "teams.call"
STREAM = "teams.call_stream"
ISSUE = "m365.service_health_issue"
COLLECTORS = (r"teams[.](call_records|pstn_calls|direct_routing_calls|voice_apps|phone_numbers|user_configuration)"
              r"|m365[.](teams|teams_usage|servicehealth)")
# Every site-labelled metric panel follows the Site dropdown. All is ".*",
# which also keeps streams that carry no mapped site.
SITES = 'site=~"$sites"'
TEAMS_SERVICE = 'service="Microsoft Teams"'
# Packages whose metrics the Teams dashboard must place, besides the teams domain.
TEAMS_PACKAGES = ("internal/collectors/m365/teams/", "internal/collectors/m365/teamsphone/",
                  "internal/collectors/m365/teamsusage/", "internal/collectors/m365/servicehealth/")
COUNT_NOTE = ("Prometheus estimates the counter increase over the selected range from scraped samples. "
              "This is processing time, not a count of Loki rows by call start time.")
FIRST = "Health counts the first accepted complete version and is not rewritten by later versions."
RECORD_LIMIT = 250
ROW_NOTE = f" Up to {RECORD_LIMIT} recent records in the selected time range, not a census."
# Call records arrive in sparse batches, so per-second rates over a scrape-sized
# window are mostly zero. Volume panels count per slot of at least this width.
SLOT = "15m"
SLOT_NOTE = f"Counted per interval of at least {SLOT}, by processing time."
STAT_NO_VALUE = "No data yet. See panel info."


class TeamsBuilder(Builder):
    def variables(self):
        variables = super().variables()
        # Re-use the exporter census, but do not offer tenants solely on the
        # strength of unrelated collector metrics.
        variables[2] = v2.query_variable(
            "tenant", f'label_values({self.tenant_metric}{{collector=~`{COLLECTORS}`}}, tenant_id)',
            label="Tenant", multi=True, include_all=True,
            description="Select the polled tenant; All includes unlabelled single-tenant signals.",
        )
        variables[2]["spec"].update(current={"text": "All", "value": "$__all"}, allValue=".*")
        sites = v2.query_variable(
            "sites", f'label_values({self.cat.metric("teams.streams").prom}{{{TENANT_SEL}}}, site)',
            label="Site", multi=True, include_all=True,
            description="Filters the site-labelled stream metrics. All also keeps streams without a mapped site. "
                        "The exact site search on Calls is the separate Site search box.",
        )
        sites["spec"].update(current={"text": "All", "value": "$__all"}, allValue=".*")
        variables.insert(3, sites)
        return variables

    def tab(self, title, add, empty):
        """Place one tab. `empty` says why its panels can legitimately be blank."""
        start = len(self._panels)
        add(self)
        note = f"No data yet. {empty} Collector health shows whether the source ran."
        for item in self._panels[start:]:
            panel = item["spec"]
            defaults = panel.get("fieldConfig", {}).get("defaults", {})
            if "noValue" not in defaults:
                continue
            if defaults["noValue"] in (NO_METRIC, NO_LOKI):
                loki = " Log panels also need the Loki datasource." if panel.get("datasource") == LOKI_DS else ""
                defaults["noValue"] = note + loki
            else:
                defaults["noValue"] = "No data yet. " + defaults["noValue"]
            if panel["type"] == "stat":
                # A stat panel shrinks a long sentence until it is unreadable.
                panel["description"] = (panel.get("description", "") + " If it is empty: "
                                        + defaults["noValue"].removeprefix("No data yet. ")).strip()
                defaults["noValue"] = STAT_NO_VALUE
        return v2.leaf(title, [v2.rowspec("", self._panels[start:])])

    def records(self, event, title, fields, *, filters=(), desc="", h=9, panel_id=None):
        # Loki exposes structured metadata in its per-row labels frame column.
        # The keep stage is also catalog-gated, not a parser for the log body.
        columns = ("tenant_id", *fields)
        keep = Raw("keep " + ", ".join(columns), keys=columns,
                   reason="Project the structured metadata columns used in the table")
        panel = self.logs(event, title, [*filters, keep], desc + ROW_NOTE, h=h, panel_id=panel_id)
        panel["type"] = "table"
        panel["targets"][0]["maxLines"] = RECORD_LIMIT
        panel["options"] = {"showHeader": True, "sortBy": [{"displayName": "Time", "desc": True}]}
        panel["transformations"] = [
            {"id": "extractFields", "options": {"source": "labels", "format": "json",
                                               "replace": True, "keepTime": True}},
        ]
        # The panel note is for an empty result. A row that lacks one attribute
        # shows a blank cell, not the panel note.
        for kind in ("string", "number"):
            panel["fieldConfig"]["overrides"].append({
                "matcher": {"id": "byType", "options": kind},
                "properties": [{"id": "noValue", "value": ""}],
            })
        return panel


def _literal(var):
    # Interpolate inside Go template string literals, not into LogQL syntax.
    # Grafana percent-encodes quotes, backticks, spaces and backslashes.
    return '"${' + var + ':percentencode}"'


def _require(template, keys, reason):
    return Raw(f'label_format g2o_match=`{template}` | g2o_match="yes" | drop g2o_match',
               keys=keys, reason=reason)


def _matches(var, *keys, required=False, json_list=False):
    wanted = _literal(var)
    # Go urlquery uses '+' for spaces; Grafana's percentencode uses '%20'.
    def encode(expr):
        return f'({expr} | urlquery | replace "+" "%20")'

    if json_list:
        # call modalities are a JSON array, not a comma-delimited free-text field.
        expr = ('{{range fromJson .modalities}}{{if eq ' + encode('.') + ' ' + wanted
                + '}}yes{{break}}{{end}}{{end}}')
    else:
        comparisons = [f'(eq {encode("." + key)} {wanted})' for key in keys]
        expr = '{{if or ' + ' '.join(comparisons) + '}}yes{{end}}' if len(keys) > 1 else (
            '{{if ' + comparisons[0] + '}}yes{{end}}')
    empty = f'{{{{if eq {wanted} ""}}}}' + ('' if required else 'yes') + '{{else}}'
    return _require(empty + expr + '{{end}}', keys,
                    "Match a URL-safe exact value, optionally bypassing an empty input")


def _duration():
    value = _literal("min_seconds")
    # An unset minimum permits a missing duration. Invalid or missing numbers
    # are not silently coerced into measured zero when a minimum is supplied.
    template = (f'{{{{if eq {value} ""}}}}yes'
                f'{{{{else if and (eq (regexReplaceAll "^[0-9]+$" {value} "") "") .duration_seconds '
                f'(ge (float64 .duration_seconds) (float64 {value}))}}}}yes{{{{end}}}}')
    return _require(template, ["duration_seconds"], "Compare present durations to an optional numeric minimum")


def _tab_route(title):
    # Grafana 13 writes and matches lower-case scene routes; a mixed-case
    # dtab can silently select Overview even with valid scoped variables.
    return v2.slug(title).lower()


def _link(panel, field, tab, variable):
    # Use the row tenant, not a possibly multi-tenant dashboard selection.
    url = (f"/d/{NAME}?dtab={_tab_route(tab)}&from=${{__from}}&to=${{__to}}"
           + "&${datasource:queryparam}&${loki_datasource:queryparam}"
           + "&var-tenant=${__data.fields.tenant_id:percentencode}"
           + f"&var-{variable}=${{__value.raw:percentencode}}")
    _override(panel, field, "links", [{"title": f"Open {tab}", "url": url}])


def _override(panel, field, prop, value):
    panel["fieldConfig"]["overrides"].append({
        "matcher": {"id": "byName", "options": field},
        "properties": [{"id": prop, "value": value}],
    })


def _agg(b, metric, *, keys=(), match="", op="", window=RATE, aggregate="sum"):
    name = b.cat.metric(metric).prom
    expr = f'{{{TENANT_SEL}{"," + match if match else ""}}}'
    term = name + expr
    if op == "increase":
        term = counter_increase(term, window)
    elif op:
        term = f"{op}({term}[{window}])"
    return f"{aggregate} by ({', '.join(('tenant_id', *keys))}) ({term})"


def _count(b, metric, **kw):
    """Whole events counted in the selected range."""
    return f"round({_agg(b, metric, op='increase', window='$__range', **kw)})"


def _slots(panel, *, bars=False, share=False):
    for target in panel["targets"]:
        target["interval"] = SLOT
    custom = panel["fieldConfig"]["defaults"].setdefault("custom", {})
    if bars:
        custom.update(drawStyle="bars", fillOpacity=80, lineWidth=1, stacking={"mode": "normal", "group": "A"})
    if share:
        panel["fieldConfig"]["defaults"].update(min=0, max=1)
    return panel


def _bars(b, title, metric, keys, desc, *, match=""):
    legend = " · ".join(["{{tenant_id}}", *("{{" + key + "}}" for key in keys)])
    panel = b.raw(title, [f"round({_agg(b, metric, keys=keys, match=match, op='increase', window='$__interval')})"],
                  unit="short", legends=[legend], desc=f"{desc} {SLOT_NOTE}".strip())
    return _slots(panel, bars=True)


def _share(numer, denom, *keys):
    join = f"on ({', '.join(('tenant_id', *keys))})"
    return f"((({numer}) or {join} (0 * ({denom}))) / ({denom})) and {join} (({denom}) > 0)"


def _stat(b, title, query, desc, unit="short", *, w=8, about=""):
    panel = b.raw(title, [query], viz="stat", unit=unit, desc=desc, w=w,
                  legends=["{{tenant_id}}"], about=about)
    panel["targets"][0].update(instant=True, range=False)
    return panel


def _pie(b, title, queries, legends, desc, *, donut=False):
    panel = b.raw(title, queries, viz="piechart", unit="short", desc=desc, legends=legends)
    for target in panel["targets"]:
        target.update(instant=True, range=False)
    panel["options"] = {"pieType": "donut" if donut else "pie",
                        "legend": {"showLegend": True, "placement": "right", "displayMode": "table"}}
    return panel


def _service_status(b, title, viz, w):
    expr = f'max by (tenant_id) ({b.cat.metric("m365.service_health.status").prom}{{{TENANT_SEL},{TEAMS_SERVICE}}})'
    desc = "Microsoft's declared status for the Microsoft Teams service, from the service-health collector."
    if viz == "stat":
        return _stat(b, title, expr, desc, None, w=w, about="m365.service_health.status")
    return b.raw(title, [expr], viz=viz, unit=None, desc=desc, w=w, legends=["{{tenant_id}}"],
                 about="m365.service_health.status")


def _verdict_coverage(b, noun, metric, share, *, scope=""):
    span = {"op": "increase", "window": "$__range"}
    observed = _agg(b, metric, match=scope, **span)

    def growth(verdict):
        match = f'{noun}_health=~"{verdict}"'
        return _agg(b, metric, match=f"{scope},{match}" if scope else match, **span)

    def count(expr):
        # No verdict series contributes zero only if this tenant's total exists.
        return f"(({expr}) or on (tenant_id) (0 * ({observed})))"

    classified = growth("good|poor")
    columns = {
        f"{share.title()} share": _share(growth(share), classified),
        "Classified": count(classified), "Observed": observed,
        **{verdict.title(): count(growth(verdict)) for verdict in ("good", "poor", "unclassified")},
    }
    # A Grafana table merge needs a tenant column in every result frame,
    # even if only unstamped series supply a share. Valid tenant IDs are GUIDs.
    scoped = [f'label_replace({expr}, "tenant_id", "(unlabelled)", "tenant_id", "^$")'
              for expr in columns.values()]
    panel = b.raw(f"Initial {noun} verdict coverage (processing time)", scoped, viz="table", unit="none", w=24, h=4,
                  desc=FIRST + " " + COUNT_NOTE + " Classified = good + poor; "
                       "the share is blank without a classified denominator. Counts are estimates. "
                       + ("The Site filter applies to streams only. " if scope else "")
                       + "Loki lists event-time versions, including later observations, not this population.")
    for target in panel["targets"]:
        target.update(instant=True, range=False, format="table")
    panel["transformations"] = [
        {"id": "merge", "options": {}},
        {"id": "organize", "options": {
            "excludeByName": {"Time": True},
            "renameByName": {f"Value #{target['refId']}": name for target, name in zip(panel["targets"], columns)},
        }},
    ]
    panel["fieldConfig"]["defaults"].update(decimals=2, noValue="No initial observations in range.")
    _override(panel, f"{share.title()} share", "unit", "percentunit")
    _override(panel, f"{share.title()} share", "noValue", "-")


def _client_legend(panel, *keys):
    # Lead with the comparison dimension. The abbreviated tenant is for display
    # only; it never replaces tenant_id in grouping or investigation links.
    for target in panel["targets"]:
        shortened = f'label_replace({target["expr"]}, "tenant_hint", "$1", "tenant_id", "^(.{{1,8}}).*$")'
        target["expr"] = f'label_replace({shortened}, "tenant_hint", "unlabelled", "tenant_id", "^$")'
        target["legendFormat"] = " · ".join("{{" + key + "}}" for key in (*keys, "tenant_hint"))


def overview(b):
    intro = b.text("Use **Call quality** and **Sites and network** for trends, then **Calls** and **Call detail** "
                   "for evidence. Counters use processing time; logs use call or stream start. "
                   "The same selection can cover different events on those clocks. "
                   "Caller endpoints are not necessarily call initiators. For missing signals, see **Collector health**.",
                   title="Teams call quality", h=3)
    intro["links"] = [{"title": tab, "url": f"/d/{NAME}?dtab={_tab_route(tab)}"
                       "&from=${__from}&to=${__to}&${__all_variables}"}
                      for tab in ("Call quality", "Service health")]
    _call_count_panels(b)
    increase = {"op": "increase", "window": "$__range"}
    good = _agg(b, "teams.calls", match='call_health="good"', **increase)
    classified = _agg(b, "teams.calls", match='call_health=~"good|poor"', **increase)
    _stat(b, "Good share of classified calls", _share(good, classified),
          FIRST + " See the coverage table below for the denominator and unclassified count.", "percentunit", w=6)
    _direct_routing_count_panels(b)
    _service_status(b, "Microsoft Teams service status", "stat", 6)
    _verdict_coverage(b, "call", "teams.calls", "good")
    _bars(b, "Calls by initial health", "teams.calls", ("call_health",), FIRST)
    _pie(b, "Calls by type in range", [_count(b, "teams.calls", keys=("type",))], ["{{tenant_id}} · {{type}}"],
         FIRST + " " + COUNT_NOTE, donut=True)
    flags = b.raw("Calls with PSTN, video or sharing in range", [
        _count(b, "teams.calls", match=f'{flag}="true"') for flag in ("has_pstn", "has_video", "has_sharing")
    ], viz="bargauge", unit="short", legends=["PSTN · {{tenant_id}}", "Video · {{tenant_id}}", "Sharing · {{tenant_id}}"],
        desc=FIRST + " A call can count in several bars. " + COUNT_NOTE)
    for target in flags["targets"]:
        target.update(instant=True, range=False)
    flags["options"].update(orientation="horizontal", namePlacement="left")
    platforms = b.raw("Recent client bucket counts by platform", [
        f'sum by (tenant_id, platform) ({b.cat.metric("teams.client_versions").prom}{{{TENANT_SEL}}})'],
        viz="bargauge", unit="short", legends=["{{tenant_id}} · {{platform}}"],
        desc="Initial call counts per client platform, product and version bucket, summed by platform. "
             "A call can contribute more than once to a platform. Latest 60 call-end minutes since process start.")
    _client_legend(platforms, "platform")
    platforms["description"] += " Tenant prefixes are display hints; inspect the series labels for full IDs."
    transitions = _bars(b, "Later call health transitions", "teams.call.health_transitions", ("from_health", "to_health"),
                        "Changes between successive accepted versions. Not a correction to the initial counts.")
    transitions["fieldConfig"]["defaults"]["noValue"] = "Requires two accepted versions with different verdicts."


def _measure(b, metric):
    return f"{b.cat.metric(metric).prom}_bucket{{{TENANT_SEL},{SITES}}}"


def quality(b):
    b.text("Stream counters use processing time and the first accepted complete call version. "
           "Loki evidence is dated by stream start and includes later versions. "
           "Use the **Site** dropdown to scope streams. Quantiles estimate values from histogram buckets.",
           title="Reading call quality", h=3)
    _verdict_coverage(b, "stream", "teams.streams", "poor", scope=SITES)
    failure_note = "Requires a Graph session or segment failure stage or reason. Direct Routing SIP outcomes are separate."
    failures = _stat(b, "Call failure evidence counted in range", _count(b, "teams.call.failures"),
                     "A call can count once per failure-stage and reason bucket, not once overall. " + COUNT_NOTE, w=6)
    failures["fieldConfig"]["defaults"]["noValue"] = failure_note
    # Range-wide means stay readable when calls are too sparse for the per-interval quantiles below.
    tenant = site_queries(b.cat, grown=True, window="$__range", site=SITES, group="tenant_id", mapped_only=False)
    for key, name, unit in (("rtt", "Mean audio round-trip time", "s"), ("jitter", "Mean audio jitter", "s"),
                            ("loss", "Mean audio packet loss", "percentunit")):
        _stat(b, f"{name} in range", tenant[key],
              "Mean of reported averages from measured audio streams in the selected sites. "
              "All sites includes unmapped streams. Uses histogram sums and sample counts.", unit, w=6)
    _bars(b, "Directional streams by media and verdict", "teams.streams", ("media", "stream_health"),
          "Directional streams by verdict. " + FIRST, match=SITES)
    slot = {"keys": ("media",), "op": "increase", "window": "$__interval"}
    _slots(b.raw("Poor-stream share by media", [_share(
        _agg(b, "teams.streams", match=f'{SITES},stream_health="poor"', **slot),
        _agg(b, "teams.streams", match=f'{SITES},stream_health=~"good|poor"', **slot), "media")],
          unit="percentunit", legends=["{{tenant_id}} · {{media}}"],
          desc="Poor among classified streams in each interval. Gaps mean no classified stream, not zero. "
               + SLOT_NOTE), share=True)
    for metric, name, unit in (("teams.stream.rtt", "Round-trip time", "s"),
                               ("teams.stream.jitter", "Jitter", "s"),
                               ("teams.stream.packet_loss", "Packet loss", "percentunit")):
        bucket = _measure(b, metric)
        grown = counter_increase(bucket, "$__interval")
        _slots(b.raw(f"{name} p50 and p95 by media", [
            f"histogram_quantile({q}, sum by (le, tenant_id, media) ({grown}))" for q in ("0.5", "0.95")
        ], unit=unit, legends=["{{tenant_id}} · {{media}} · p50", "{{tenant_id}} · {{media}} · p95"],
              desc="Per-stream averages reported by the endpoints, as bucketed quantiles across streams. " + SLOT_NOTE),
               share=unit == "percentunit")
        heat = b.raw(f"{name} distribution", [f"sum by (le) ({grown})"], viz="heatmap",
                     unit=unit, legends=["{{le}}"],
                     desc="How many directional streams fell in each bucket per interval, across the selected tenants. "
                          + SLOT_NOTE)
        heat["targets"][0]["format"] = "heatmap"
        heat["options"]["yAxis"] = {"unit": unit, **({"min": 0, "max": 1} if unit == "percentunit" else {})}
        _slots(heat)
    feedback = _bars(b, "Endpoint feedback", "teams.stream.feedback", ("media", "rating"),
                     "Explicit user ratings, counted once per reporting side, session and media.")
    feedback["fieldConfig"]["defaults"]["noValue"] = "Requires explicit user feedback."
    breakdown = _bars(b, "Calls with failure evidence", "teams.call.failures", ("failure_stage", "reason_bucket"),
                      "Graph session or segment failure evidence, once per call, stage and reason bucket.")
    breakdown["fieldConfig"]["defaults"]["noValue"] = failure_note
    for verdict in ("poor", "unclassified"):
        causes = _agg(b, "teams.streams", keys=("stream_health_cause",), match=f'{SITES},stream_health="{verdict}"',
                      op="increase", window="$__range")
        panel = _pie(b, f"{verdict.title()} stream causes", [f"({causes}) > 0"],
                     ["{{stream_health_cause}} · {{tenant_id}}"],
                     f"Primary cause bucket per {verdict} directional stream, by processing time. "
                     "Low packet utilisation is unclassified, not poor.")
        panel["fieldConfig"]["defaults"]["noValue"] = f"No {verdict} stream causes in range."
    clients = b.metric("teams.client_versions", title="Recently ended calls by client bucket",
                       by=["platform", "product_family", "version_bucket"],
                       desc="Calls in the latest 60 call-end minutes since process start. Client buckets overlap. "
                            "Tenant prefixes are display hints; inspect the series labels for full IDs.")
    _client_legend(clients, "platform", "product_family", "version_bucket")


def _site_link(panel):
    _link(panel, "site", "Calls", "site")


def _site_inventory(b):
    q = site_queries(b.cat, grown=True, window="$__range", site=SITES, mapped_only=False)
    span = {"keys": ("site",), "op": "increase", "window": "$__range", "match": SITES}
    streams = _agg(b, "teams.streams", **span)
    poor = _agg(b, "teams.streams", **{**span, "match": f'{SITES},stream_health="poor"'})
    measured = _agg(b, "teams.streams", **{**span, "match": f'{SITES},stream_health=~"good|poor"'})
    columns = (("Directional streams", f"round({streams})"), ("Poor share", _share(poor, measured, "site")),
               ("Mean RTT", q["rtt"]), ("Mean jitter", q["jitter"]), ("Mean loss", q["loss"]),
               ("TCP share", q["tcp"]))
    panel = b.raw("Site inventory", [expr for _, expr in columns], viz="table", unit="short", w=24, h=9,
                  desc="Every site value seen on a stream in range, including unmapped, overflow and other buckets. "
                       "Poor share counts classified streams; means are audio-only. A blank cell means no evidence. "
                       + FIRST)
    for target in panel["targets"]:
        target["format"] = "table"
    refs = [target["refId"] for target in panel["targets"]]
    panel["transformations"] = [
        {"id": "merge", "options": {}},
        {"id": "organize", "options": {
            "excludeByName": {"Time": True},
            "renameByName": {f"Value #{ref}": name for ref, (name, _) in zip(refs, columns)},
            "indexByName": {"tenant_id": 0, "site": 1},
        }},
    ]
    panel["options"]["sortBy"] = [{"displayName": "Directional streams", "desc": True}]
    for name, unit in (("Poor share", "percentunit"), ("Mean RTT", "s"), ("Mean jitter", "s"),
                       ("Mean loss", "percentunit"), ("TCP share", "percentunit")):
        _override(panel, name, "unit", unit)
    _link(panel, "site", "Calls", "site")


def _network_kpis(b):
    q = site_queries(b.cat, grown=True, window="$__range", site=SITES, group="tenant_id", mapped_only=False)
    wifi = _agg(b, "teams.streams", match=f'{SITES},connection_type="wifi"', op="increase", window="$__range")
    known = _agg(b, "teams.streams", match=f'{SITES},connection_type=~"wired|wifi|mobile|tunnel"',
                 op="increase", window="$__range")
    mapped = site_queries(b.cat, grown=True, window="$__range", site=SITES)
    note = " Every audio stream in range, including streams with no mapped site."
    _stat(b, "Sites with audio measurements", f"count by (tenant_id) ({mapped['rtt']})",
          "Mapped sites with at least one measured audio stream in range. Not the configured site count.", w=4)
    for key, name, unit in (("rtt", "Mean audio round-trip time", "s"), ("jitter", "Mean audio jitter", "s"),
                            ("loss", "Mean audio packet loss", "percentunit"), ("tcp", "Audio TCP share", "percentunit")):
        _stat(b, name, q[key], name + "." + note, unit, w=4)
    _stat(b, "Wi-Fi share of streams", _share(wifi, known),
          "Directional streams on Wi-Fi among known connection types." + note, "percentunit", w=4)


def sites(b):
    _network_kpis(b)
    queries = site_queries(b.cat, grown=True, window="$__range", site=SITES)
    status = compliance(queries, LOCAL, "<=")
    status_note = ("Local preset: mean audio jitter ≤ 30 ms, round-trip time ≤ 200 ms, "
                   "loss ≤ 2% and TCP share ≤ 1%. Only sites with all four measurements are evaluated. "
                   "This is not a verified network path or a count of all configured sites.")
    _pie(b, "Site compliance among evaluated sites", [
        f"count by (tenant_id) (({status}) == {value})" for value in (1, 0)
    ], ["{{tenant_id}} · meets preset", "{{tenant_id}} · misses preset"], status_note, donut=True)
    attention = b.raw("Measured sites missing the local preset", [f"({status}) == 0"],
                      viz="table", desc=status_note)
    _site_link(attention)
    base = {"keys": ("site",), "op": "increase", "window": "$__range"}
    named_site = f'{SITES},site!~"unmapped|overflow|other|"'
    poor = _agg(b, "teams.streams", match=f'{named_site},stream_health="poor"', **base)
    measured = _agg(b, "teams.streams", match=f'{named_site},stream_health=~"good|poor"', **base)
    attention = b.raw("Sites above 5% poor classified streams", [f"({_share(poor, measured, 'site')}) > 0.05"],
                      viz="table", unit="percentunit",
                      desc="Directional streams from initial versions. Unclassified streams and metric overflow sites are excluded.")
    _site_link(attention)
    _site_inventory(b)
    for side in ("caller", "callee"):
        site = f"{side}_site"
        lat, lon = f"{site}_latitude", f"{site}_longitude"
        panel = b.records(STREAM, f"Observed {side} sites", (site, f"{site}_country", lat, lon),
                          filters=[f(site, "nre", "unmapped|"), f(lat, "ne", ""), f(lon, "ne", "")],
                          desc="Location from the configured site mapping, when seen on a stream. Not the full configured inventory.")
        _link(panel, site, "Calls", "site")
        if side == "caller":
            # One side per query: a mapped coordinate is not a reflexive IP fix.
            map_panel = b.records(STREAM, "Mapped caller site locations", (site, lat, lon),
                                  filters=[f(lat, "ne", ""), f(lon, "ne", "")],
                                  desc="Observed caller-side site coordinates, not call endpoints. "
                                       "Compliance is shown separately; absence from this map proves nothing.")
            map_panel["type"] = "geomap"
            map_panel["transformations"].append(_convert((lat, lon), "number"))
            map_panel["options"] = {"view": {"id": "fit", "allLayers": True}, "layers": [{
                "type": "markers", "name": "Observed caller sites",
                "location": {"mode": "coords", "latitude": lat, "longitude": lon},
                "tooltip": True,
            }]}


def calls(b):
    b.text("The call table filters by health, type, modality, organiser UPN and minimum duration. "
           "Site is only recorded on stream sides. Use **Call IDs observed at the selected site** "
           "when a site is entered, then follow the call ID to details. The general call table is "
           "inactive during a site search. Site results match an optional user against either stream side; "
           "call health, type, modality and duration filters only apply to the general call table. "
           "Both views can show multiple versions.", title="How to search", h=5)
    site = _literal("site")
    general_calls = _require(f'{{{{if and .call_id (eq {site} "")}}}}yes{{{{end}}}}', ["call_id"],
                             "Show call-level rows only when a site search is not active")
    panel = b.records(CALL, "Call records", (
        "call_id", "version", "call_health", "call_type", "modalities", "participant_count",
        "organizer_user_principal_name", "duration_seconds", "start_time", "end_time",
    ), filters=[general_calls, _matches("health", "call_health"), _matches("call_type", "call_type"),
                _matches("modality", "modalities", json_list=True),
                _matches("user", "organizer_user_principal_name"), _duration()])
    _link(panel, "call_id", "Call detail", "call_id")
    panel = b.records(STREAM, "Call IDs observed at the selected site", (
        "call_id", "version", "stream_id", "caller_site", "callee_site", "media", "stream_health",
    ), filters=[f("call_id", "ne", ""), _matches("site", "caller_site", "callee_site", required=True),
                _matches("user", "caller_user_principal_name", "callee_user_principal_name")])
    _link(panel, "call_id", "Call detail", "call_id")


def _convert(fields, kind):
    return {"id": "convertFieldType", "options": {"conversions": [
        {"targetField": field, "destinationType": kind} for field in fields
    ]}}


def _detail_columns(panel, columns):
    panel["transformations"].append({"id": "organize", "options": {
        "indexByName": {key: i for i, key in enumerate((*columns, "Time", "tenant_id"))},
        "renameByName": {key: name for key, name in columns.items() if name},
    }})
    panel["fieldConfig"]["defaults"]["noValue"] = "Open or enter a call ID."


_VERDICT_UNITS = {
    "packets": ("packet_utilization",),
    "ms": ("average_rtt_ms", "average_jitter_ms"),
    "fraction (0-1)": ("average_packet_loss_rate", "post_fec_packet_loss_rate"),
    "% (0-100)": ("video_frame_loss_percent",),
    "fps": ("video_frame_rate",),
}


def _verdict_evidence(b, selected):
    metric = "stream_health_metric"
    tests = "".join('{{else if eq .' + metric + ' ' + ' '.join(f'"{name}"' for name in names) + '}}' + unit
                    for unit, names in _VERDICT_UNITS.items())
    unit = '{{if not .' + metric + '}}' + tests + '{{else}}unknown{{end}}'
    columns = {
        "stream_health": "Verdict", "stream_health_cause": "Cause", "media": "Media", "direction": "Direction",
        metric: "Metric", "stream_health_value": "Measured value", "stream_health_threshold": "Threshold",
        "g2o_units": "Units (value and threshold)", "version": "Version", "session_id": "Session",
        "segment_id": "Segment", "stream_id": "Stream",
    }
    fields = tuple(k for k in columns if k != "g2o_units")
    panel = b.records(STREAM, "Stream verdict evidence", fields, filters=selected,
                      desc="The collector sets the verdict. Low packet utilisation means unclassified, not poor. "
                           "Good streams and some unclassified streams have no threshold evidence.")
    # Keep the wire keys plus the derived units field, which is presentation only.
    stage = Raw(f'label_format g2o_units=`{unit}` | keep tenant_id, {", ".join(columns)}',
                keys=["tenant_id", *fields], reason="Show the wire units beside threshold values")
    panel["targets"][0]["expr"] = b._selector(STREAM, (*selected, stage))
    _detail_columns(panel, columns)


def _call_timeline(b, selected):
    # The state timeline takes its viewport from the dashboard time picker.
    # A separate link zooms only the timeline. Compute its range from call versions
    # AND stream intervals, not from a single call/stream row, to retain peers.
    clock = 'toDate "2006-01-02T15:04:05.999999999Z07:00"'
    order = Raw(f'label_format g2o_interval=`{{{{$start := {clock} .start_time}}}}'
                f'{{{{$end := {clock} .end_time}}}}'
                '{{if and (not $start.IsZero) (not $end.IsZero) (not ($end.Before $start))}}yes{{end}}`'
                ' | g2o_interval="yes" | drop g2o_interval', keys=["start_time", "end_time"],
                reason="Reject malformed or reversed source intervals rather than draw a false duration")
    timed = (*selected, f("start_time", "ne", ""), f("end_time", "ne", ""), order)
    bounds = b.records(CALL, "Call bounds and timeline zoom", ("start_time", "end_time"), filters=timed, h=4,
                       desc="Open the stream timeline in a new tab. Bounds use the selected call's dated versions "
                            "and plotted stream peers in this search, padded by one second. "
                            "The investigation window on this tab does not change. Zoom requires a tenant ID; "
                            "unlabelled rows are still visible in the All-tenant evidence.")
    # Fixed millisecond padding preserves endpoints at the query boundary and lets
    # a zero-duration observation stay visible. No time is invented for absent bounds.
    pad = Raw('label_format g2o_scope=tenant_id,'
              f' g2o_from=`{{{{sub (unixEpochMillis ({clock} .start_time)) 1000}}}}`,'
              f' g2o_to=`{{{{add (unixEpochMillis ({clock} .end_time)) 1000}}}}`'
              ' | keep g2o_scope, g2o_from, g2o_to', keys=["tenant_id", "start_time", "end_time"],
              reason="Project padded numeric epoch bounds for the time picker")
    bounds["targets"] = [
        {**b._loki_query(b._selector(event, (*timed, f("tenant_id", "ne", ""), pad)), ref=ref),
         "maxLines": RECORD_LIMIT}
        for ref, event in zip("AB", (CALL, STREAM))
    ]
    bounds["description"] = bounds["description"].replace(
        ROW_NOTE, f" Up to {RECORD_LIMIT} recent rows from each source; not a census.")
    bounds["transformations"][0]["options"]["keepTime"] = False
    bounds["transformations"].extend([
        _convert(("g2o_from", "g2o_to"), "number"),
        {"id": "merge", "options": {}},
        {"id": "groupBy", "options": {"fields": {
            "g2o_scope": {"operation": "groupby", "aggregations": []},
            "g2o_from": {"operation": "aggregate", "aggregations": ["min"]},
            "g2o_to": {"operation": "aggregate", "aggregations": ["max"]},
        }}},
    ])
    _detail_columns(bounds, {"g2o_from (min)": "From (padded)", "g2o_to (max)": "To (padded)", "g2o_scope": "Tenant"})
    bounds["options"]["sortBy"] = []
    bounds["fieldConfig"]["defaults"]["noValue"] = "No dated bounds. Open or enter a call ID."
    for field in ("From (padded)", "To (padded)"):
        _override(bounds, field, "unit", "dateTimeAsIso")
    _override(bounds, "Tenant", "links", [])

    keys = ("tenant_id", "version", "direction", "media", "session_id", "segment_id", "stream_id")
    timeline = b.records(STREAM, "Dated stream intervals", ("start_time", "end_time", "stream_health"),
                         filters=timed, desc="One verdict per dated directional stream, not a verdict history. "
                         "Stream bounds can fall back to source segment dates. Use the bounds link to see the "
                         "whole observed span without narrowing this search.")
    parts = ('v{{.version}}', '{{.direction | default "unknown direction"}}', '{{.media}}',
             '{{.session_id | default "?"}}/{{.segment_id | default "?"}}/{{.stream_id | default "?"}}',
             '{{.tenant_id | default "unlabelled"}}')
    lane = Raw('label_format g2o_lane=`' + ' · '.join(parts) + '`', keys=keys,
               reason="Label individual lanes even when Graph omits an identifier")
    # Project only the timeline fields so no other string becomes a state series.
    timeline["targets"][0]["expr"] = b._selector(STREAM, (*timed, lane, Raw(
        "keep g2o_lane, start_time, end_time, stream_health", keys=["start_time", "end_time", "stream_health"],
        reason="Project state timeline data without plotting other string attributes")))
    timeline["type"] = "state-timeline"
    timeline["options"] = {"mergeValues": False, "showValue": "auto", "rowHeight": 0.8, "perPage": 10,
                           "tooltip": {"mode": "single"}, "legend": {"showLegend": False}}
    timeline["transformations"][0]["options"]["keepTime"] = False
    timeline["transformations"].extend([
        _convert(("start_time", "end_time"), "time"),
        {"id": "organize", "options": {"indexByName": {"start_time": 0, "end_time": 1, "stream_health": 2}}},
        {"id": "calculateField", "options": {"mode": "index", "alias": "Observation"}},
        {"id": "partitionByValues", "options": {"fields": ["g2o_lane", "Observation"], "keepFields": False}},
    ])
    timeline["fieldConfig"]["defaults"].update(displayName="${__field.labels.g2o_lane}",
                                                custom={"axisWidth": 220},
                                                noValue="No dated streams. Open or enter a call ID.")
    bounds["fieldConfig"]["defaults"]["links"] = [{
        "title": "Open stream timeline at call bounds",
        "url": (f"/d/{NAME}?dtab={_tab_route('Call detail')}&viewPanel={timeline['id']}&"
                'from=${__data.fields["From (padded)"].numeric}&to=${__data.fields["To (padded)"].numeric}'
                "&${datasource:queryparam}&${loki_datasource:queryparam}&${call_id:queryparam}"
                "&var-tenant=${__data.fields.Tenant.text:percentencode}"),
        "targetBlank": True,
    }]


def detail(b):
    selected = [_matches("call_id", "call_id", required=True)]
    b.text("Open a call from **Calls** or **Users**, or select its tenant and enter a call ID. "
           "Compare matching versions. Use **Call bounds and timeline zoom** to inspect dated streams in a new tab. "
           "Blank fields are unavailable, not good verdicts.", title="Read the evidence", h=3)
    header = {
        "version": "Version", "call_health": "Verdict", "start_time": "Call start (UTC)", "end_time": "Call end (UTC)",
        "duration_seconds": "Duration (s)", "poor_stream_count": "Poor streams", "worst_rtt_ms": "Worst RTT (ms)",
        "worst_jitter_ms": "Worst jitter (ms)", "worst_packet_loss_rate": "Worst loss (fraction)",
        "dominant_transport": "Dominant transport", "shared_reflexive_ip": "Shared reflexive IP", "participant_apps": "Apps",
        "call_id": "Call ID",
    }
    panel = b.records(CALL, "Call verdict and worst observed metrics by version", tuple(header), filters=selected, h=5,
                      desc="Source start and end per version. Shared reflexive IP suggests a common breakout, not a proven path.")
    _detail_columns(panel, header)
    _call_timeline(b, selected)
    _verdict_evidence(b, selected)
    streams = {
        "version": "Version", "media": "Media", "direction": "Direction", "stream_health": "Verdict",
        "average_rtt_ms": "RTT (ms)", "average_jitter_ms": "Jitter (ms)", "average_packet_loss_rate": "Loss (fraction)",
        "caller_user_principal_name": "Caller UPN", "caller_impact": "Caller impact",
        "callee_user_principal_name": "Callee UPN", "callee_impact": "Callee impact",
        "start_time": "Stream start (UTC)", "end_time": "Stream end (UTC)", "session_id": "Session",
        "segment_id": "Segment", "stream_id": "Stream", "session_failure_stage": "Session failure stage",
        "session_failure_reason": "Session failure reason", "segment_failure_stage": "Segment failure stage",
        "segment_failure_reason": "Segment failure reason",
    }
    panel = b.records(STREAM, "Directional streams", tuple(streams), filters=selected,
                      desc="Caller and callee are the reported media endpoints, not the full meeting roster. "
                           "Impact labels follow the direction of a poor stream; they do not assign fault.")
    _detail_columns(panel, streams)
    for side, extra in (("caller", ("platform", "product_family", "client_version", "device_name")), ("callee", ())):
        common = {"version": "Version", "direction": "Direction", "stream_id": "Stream",
                  "session_id": "Session", "segment_id": "Segment"}
        endpoint = {f"{side}_{key}": key.replace("_", " ").capitalize() for key in (
            "user_principal_name", "identity_kind", "id", "impact", "connection_type", "transport_protocol", *extra,
            "device", "cpu_insufficient", "device_glitch", "low_speech_signal", "wifi_with_issue", "user_agent")}
        panel = b.records(STREAM, f"Reported {side} endpoint", (*endpoint, *common), filters=selected,
                          desc="Device JSON may carry audio capture and render data. "
                               "Callee platform and client version are not catalogued.")
        _detail_columns(panel, {**endpoint, **common})
        network = {f"{side}_{key}": key.replace("_", " ").capitalize() for key in (
            "site", "ip_address", "ip_class", "reflexive_ip_address", "relay_ip_address", "relay_address_present",
            "asn", "asn_organization", "id")}
        panel = b.records(STREAM, f"Reported {side} addresses and ASN", (*network, *common), filters=selected,
                          desc="ASN is optional reflexive address enrichment. Relay allocations do not prove relay use.")
        _detail_columns(panel, {**network, **common})
    trace = b.records(STREAM, "Reported caller trace hops", (
        "version", "stream_id", "caller_trace_route_hops", "caller_trace_route_hops_omitted",
    ), filters=[*selected, f("caller_trace_route_hops", "ne", "")],
       desc="No trace reported for this call if empty. Missing hops do not establish a direct path.")
    trace["fieldConfig"]["defaults"]["noValue"] = "No trace reported for the selected call."
    bots = b.records(STREAM, "Application and bot evidence", (
        "version", "stream_id", "caller_identity_kind", "callee_identity_kind",
        "callee_app_id", "callee_bot_role",
    ), filters=[*selected, Raw('caller_identity_kind="app" or callee_identity_kind="app" or callee_bot_role!=""',
                              keys=["caller_identity_kind", "callee_identity_kind", "callee_bot_role"],
                              reason="Either side may report an application identity")],
       desc="Application identity kinds and observed callee bot roles, not a count of all bots or attendees. "
            "Caller app ID and bot role are not catalogued.")
    bots["fieldConfig"]["defaults"]["noValue"] = "No application or bot evidence for the selected call."

    roster = {"version": "Version", "participant_id": "Roster row ID", "identity_kind": "Identity kind",
              "id": "Identity ID", "display_name": "Display name", "user_principal_name": "UPN"}
    # Use a fresh deep-link ID without moving the existing panel sequence.
    panel = b.records("teams.call_participant", "Participant roster by call version", tuple(roster),
                      filters=selected, panel_id=1001,
                      desc="Graph roster observations for accepted versions, dated at call start. "
                           "Roster row and identity IDs are separate. This is not a join to media endpoints, "
                           "participant join times or quality impact, and is not an atomic source snapshot.")
    _detail_columns(panel, roster)
    panel["fieldConfig"]["defaults"]["noValue"] = "No roster rows visible. Select a tenant and a call ID."


def users(b):
    b.text("Choose a UPN below or enter an exact **User UPN**. The lists show the most recent dated observation "
           "in each source's sample, per tenant and exact UPN. A UPN can occur in several lists. "
           "These are observed stream sides and organisers, not a meeting roster or a ranking. "
           "A user's presence on a stream does not establish impact or fault.", title="Investigate one user", h=4)
    for event, side, title in ((STREAM, "caller", "Observed caller UPNs"),
                               (STREAM, "callee", "Observed callee UPNs"),
                               (CALL, "organizer", "Observed organiser UPNs")):
        key = f"{side}_user_principal_name"
        panel = b.records(event, title, (key,), h=6,
                          filters=[f("tenant_id", "ne", ""), f("start_time", "ne", ""), f(key, "ne", "")],
                          desc="One row per tenant and recorded UPN from the recent dated log sample. "
                               "Unlabelled tenants and unreported UPNs are not listed.")
        panel["transformations"].append({"id": "groupBy", "options": {"fields": {
            "tenant_id": {"operation": "groupby"}, key: {"operation": "groupby"},
            "Time": {"operation": "aggregate", "aggregations": ["max"]},
        }}})
        panel["options"]["sortBy"] = [{"displayName": "Last observed", "desc": True}]
        _override(panel, "Time (max)", "displayName", "Last observed")
        panel["fieldConfig"]["defaults"]["noValue"] = "No dated UPN observations with a tenant label in range."
        _link(panel, key, "Users", "user")

    scopes = ("caller_identity_scope", "callee_identity_scope")
    # Backward compatibility: absence of the enum on old records is unknown,
    # regardless of the old boolean, user ID, site or connection information.
    show_unknown = Raw("label_format " + ", ".join(f'{key}=`{{{{ .{key} | default "unknown" }}}}`' for key in scopes),
                       keys=scopes, reason="Show unknown on historical records without a scope")
    panel = b.records(STREAM, "Recent stream observations for the selected user", (
        "call_id", "version", "stream_id", "direction", "caller_user_principal_name", "callee_user_principal_name",
        *scopes, "caller_platform", "caller_transport_protocol", "callee_transport_protocol", "stream_health",
    ), filters=[f("call_id", "ne", ""),
                _matches("user", "caller_user_principal_name", "callee_user_principal_name", required=True),
                show_unknown],
       desc="Scope compares a reported UPN with the configured domains. Unknown is not external; "
            "it includes an unavailable UPN, an unconfigured rule set or an older record without scope. "
            "Direction describes the stream, not who is at fault.")
    _link(panel, "call_id", "Call detail", "call_id")
    panel = b.records(CALL, "Recent calls organised by the selected user", (
        "call_id", "version", "organizer_user_principal_name", "call_type", "call_health", "duration_seconds",
    ), filters=[_matches("user", "organizer_user_principal_name", required=True)])
    _link(panel, "call_id", "Call detail", "call_id")


_EVENT_COUNT_NOTE = ("Exact for keyed Loki records visible in the selected event-time range, not a source census. "
                     "Late records can change the count. Narrow the range if Loki reaches its series limit.")
_ESTIMATE_NOTE = ("Estimated counter growth from exported metric samples in the selected collection-time range. "
                  "Includes the first value of series with no usable baseline at range start; missing samples "
                  "can distort the estimate. It is not an event-time count.")
_DIRECT_ROUTING_CLASSIFICATION = ("Answered means Graph reports successful_call=true, even with SIP 403, which still "
                                  "counts in the 4xx class. Otherwise SIP 486 or 600 is busy. Other explicit "
                                  "failures or SIP 4xx to 6xx are failed; the rest are unknown.")


def _keyed_event_count(b, title, event, keys, desc, *, filters, w):
    group = ("tenant_id", *keys)
    columns = ", ".join(group)
    keep = Raw(f"keep {columns}", keys=group, reason="Project only the identity columns before counting")
    sel = b._selector(event, [*filters, keep], by=list(keys))
    # Instant Loki queries expand $__auto to the whole selected range. The
    # inner sum collapses repeat deliveries of an identity across streams.
    expr = f"count by (tenant_id) (sum by ({columns}) (count_over_time({sel} [$__auto])))"
    panel = b._viz_panel("stat", title, [], "none",
                         f"{desc} {_EVENT_COUNT_NOTE} Needs Loki.", w, 8)
    panel["datasource"] = LOKI_DS
    panel["targets"] = [b._loki_query(expr, legend="{{tenant_id}}", query_type="instant")]
    panel["fieldConfig"]["defaults"].update(decimals=0, noValue=NO_LOKI)
    return panel


def _counter_estimate(b, title, metric, desc, *, w, unit="none", decimals=1):
    panel = _stat(b, title, _agg(b, metric, op="increase", window="$__range"),
                  f"{desc} {_ESTIMATE_NOTE}", unit=unit, w=w)
    panel["fieldConfig"]["defaults"]["decimals"] = decimals
    return panel


def _call_count_panels(b, *, w=8):
    keyed = f("call_id", "ne", "")
    _keyed_event_count(b, "Unique call IDs (event time)", CALL, ("call_id",),
                       "Distinct call IDs per tenant by call start time.", filters=[keyed], w=w)
    _keyed_event_count(b, "Call versions (event time)", CALL, ("call_id", "version"),
                       "Distinct call ID and version pairs per tenant by call start time.",
                       filters=[keyed, f("version", "ne", "")], w=w)
    _counter_estimate(b, "Calls (collection-time estimate)", "teams.calls", FIRST, w=w)


def _direct_routing_count_panels(b, *, w=12):
    _keyed_event_count(b, "Direct Routing attempts (event time)", "teams.direct_routing_call", ("id",),
                       "Distinct Direct Routing row IDs per tenant. A row takes its start, invite or failure "
                       "time, in that order.", filters=[f("id", "ne", "")], w=w)
    _counter_estimate(b, "Direct Routing attempts (collection-time estimate)", "teams.direct_routing.calls",
                      "Newly accepted Direct Routing report attempts, including unkeyed rows.", w=w)


def phone(b):
    either_id = Raw("id != `` or call_id != ``", keys=["id", "call_id"],
                    reason="A PSTN source row can be keyed by either ID and its start time")
    _keyed_event_count(b, "PSTN report rows (event time)", "teams.pstn_call", ("id", "call_id", "start_time"),
                       "Distinct PSTN row ID, PSTN call ID and start time tuples per tenant, with at least one ID. "
                       "Row IDs can be shared; this is not a count of unique Teams calls.",
                       filters=[either_id, f("start_time", "ne", "")], w=8)
    _counter_estimate(b, "PSTN report rows (collection-time estimate)", "teams.pstn.calls",
                      "Newly accepted PSTN report rows, including unkeyed rows.", w=8)
    _counter_estimate(b, "PSTN connected minutes (collection-time estimate)", "teams.pstn.minutes",
                      "Reported non-negative durations of newly accepted PSTN rows with a duration.",
                      unit="suffix: min", decimals=2, w=8)
    _direct_routing_count_panels(b)
    _bars(b, "Direct Routing attempts by trunk and SIP outcome", "teams.direct_routing.calls",
          ("trunk_fqdn", "sip_class", "outcome"), _DIRECT_ROUTING_CLASSIFICATION)
    trunk = b.metric("teams.direct_routing.network_effectiveness_ratio", title="Latest exported Direct Routing effectiveness",
                     by=["trunk_fqdn"], desc="Each sample reflects the most recent available poll value, not a ratio "
                     "over the selected range. Lookback can repeat a value between observations. Per trunk, the "
                     "numerator is answered plus busy attempts. The denominator is all "
                     "newly accepted attempts, including unknowns, not all attempts made. "
                     "No new attempts means no new ratio. This is not an SBC health check or proof of connected "
                     "media. " + _DIRECT_ROUTING_CLASSIFICATION)
    trunk["fieldConfig"]["defaults"].update(unit="percentunit", min=0, max=1)
    trunk["fieldConfig"]["defaults"]["custom"].update(spanNulls=False, showPoints="always")
    b.records("teams.direct_routing_poll", "Direct Routing effectiveness counts by poll", (
        "trunk_fqdn", "effective_attempts", "poll_attempts", "source_success_sip_4xx",
    ), desc="Each dated row is a successful poll with new attempts for this trunk. Effective is the numerator, "
            "poll attempts is the denominator, and source success with SIP 4xx is a subset of effective. "
            "Rows are poll-time evidence, not call start times or a range-wide rate.")
    b.records("teams.pstn_call", "PSTN call records", ("id", "call_id", "call_type", "connectivity_type",
              "duration_seconds", "call_duration_source", "usage_country_code", "tenant_country_code",
              "connection_charge", "currency", "start_time", "end_time"),
              desc="PSTN, Direct Routing and Graph call detail IDs are source-scoped, not join keys.")
    b.records("teams.direct_routing_call", "Direct Routing records", (
        "id", "trunk_fqdn", "successful_call", "final_sip_code", "final_sip_code_phrase", "duration_seconds",
        "start_time", "invite_time", "failure_time",
    ), desc="Source success and the final SIP code are independent evidence. Compare the timestamps where a start is absent.")


def voice_apps(b):
    b.text("This tab needs the optional **teams.voice_apps** collector. Queue and attendant labels are resource GUIDs. "
           "The Loki summaries use event time. The share, denominator and wait panels use processing time. "
           "An unkeyed queue observation can repeat across polls; it is evidence, not a distinct leg.",
           title="Before you read this tab", h=4)
    cq = "teams.call_queue_call"
    vaac = [f("ingest_transport", "eq", "vaac")]
    keyed = [*vaac, f("queue", "ne", ""), f("dialog_id", "ne", "")]
    unkeyed = [*vaac, Raw("queue=`` or dialog_id=``", keys=["queue", "dialog_id"],
                         reason="Either missing part makes a queue observation unkeyed")]
    queue_legend = "{{tenant_id}} · {{queue}}"

    def log_count(title, filters, keys, legend, desc, *, distinct=False):
        keep = Raw("keep " + ", ".join(keys), keys=keys,
                   reason="Discard unrelated per-record labels before counting")
        sel = b._selector(cq, [*filters, keep], by=keys)
        expr = f"sum by ({', '.join(keys)}) (count_over_time({sel} [$__range]))"
        if distinct:
            expr = f"count by (tenant_id, queue) ({expr})"
        panel = b._viz_panel("stat", title, [], "short", desc + " Requires the Loki datasource.", 12, 5)
        panel["datasource"] = LOKI_DS
        panel["targets"] = [b._loki_query(expr, legend=legend, query_type="instant")]
        panel["options"].update(graphMode="none", textMode="value_and_name")
        panel["fieldConfig"]["defaults"]["noValue"] = NO_LOKI

    log_count("Distinct keyed queue legs in range", keyed, ("tenant_id", "queue", "dialog_id"), queue_legend,
              "One leg per tenant, queue ID and dialog ID in the selected event-time range. "
              "Includes keys with unknown results. Shorten the range if Loki reaches its series limit.", distinct=True)
    log_count("Call queue observations in range", vaac, ("tenant_id",), "{{tenant_id}}",
              "Counts stored Loki observations, including unkeyed rows that can repeat across polls. "
              "This is not a count of calls or distinct legs.")

    shares = ("answer_share", "abandon_share")
    counts = ("known_result_legs", "answered_legs", "abandoned_legs")
    panel = b.records("teams.call_queue_batch", "Call queue outcomes by saved batch", ("queue", *counts, *shares),
                      filters=vaac, desc="Counts and shares come from a single saved batch per queue. "
                      "Zero known results means both shares are undefined. No row means no saved observation "
                      "is visible, not zero calls. Dates show processing time, not call time.")
    panel["transformations"].append(_convert((*counts, *shares), "number"))
    for share in shares:
        _override(panel, share, "unit", "percentunit")

    wait = b.cat.metric("teams.call_queue.wait_time").prom
    buckets = counter_increase(f'{wait}_bucket{{{TENANT_SEL}}}', "$__interval")
    samples = counter_increase(f'{wait}_count{{{TENANT_SEL}}}', "$__interval")
    for percentile, q in ((50, 0.5), (95, 0.95)):
        _slots(b.raw(f"Call queue wait time p{percentile}", [
            f"histogram_quantile({q}, sum by (le, tenant_id, queue) ({buckets}))"], unit="s", w=8,
            legends=[queue_legend],
            desc="Bucketed quantile of admitted queue waits. Read the observation count beside it. " + SLOT_NOTE))
    _slots(b.raw("Admitted queue wait observations", [f"sum by (tenant_id, queue) ({samples})"], unit="short", w=8,
                 legends=[queue_legend], desc="Sample count from the same histogram and interval as p50 and p95. "
                 "Estimated from scraped counter samples, not from Loki rows. " + SLOT_NOTE))
    _bars(b, "Auto attendant call legs by outcome", "teams.auto_attendant.calls", ("auto_attendant", "voice_outcome"),
          "Auto attendant call legs by bounded outcome.")
    queue_fields = ("queue", "dialog_id", "call_queue_identity", "result", "call_queue_final_state_action",
                    "call_queue_duration_seconds", "call_queue_agent_count", "agent_name", "start_date_time", "end_date_time")
    b.records(cq, "Keyed call queue observations", queue_fields, filters=keyed,
              desc="Rows with both a queue ID and a dialog ID. The summary above counts distinct keys.")
    b.records(cq, "Unkeyed call queue observations", queue_fields, filters=unkeyed,
              desc="The queue ID, dialog ID or both are absent or invalid. These rows can repeat across polls "
                   "and do not count as legs.")
    b.records("teams.auto_attendant_call", "Auto attendant legs", (
        "auto_attendant", "auto_attendant_identity", "result", "auto_attendant_transfer_action",
        "auto_attendant_call_flow", "auto_attendant_chain_duration_seconds", "start_date_time", "end_date_time",
    ))
    diagnostic = b.raw("Call queue share gauges (export diagnostics)", [
        f'{b.cat.metric(f"teams.call_queue.{outcome}_rate").prom}{{{TENANT_SEL}}}'
        for outcome in ("answer", "abandon")
    ], unit="percentunit", w=24, h=5, legends=[f"{outcome} · {queue_legend}" for outcome in ("Answer", "Abandon")],
       desc="Independent gauge series can be stale or clipped. Use the saved batches above for shares with "
            "their matching denominator.")
    diagnostic["fieldConfig"]["defaults"].update(min=0, max=1)


def inventory(b):
    numbers = b.cat.metric("m365.teams.phone_numbers.total").prom
    users = b.cat.metric("m365.teams.user_configuration.users").prom
    _stat(b, "Unassigned phone numbers", _agg(b, "m365.teams.phone_numbers.unassigned"),
          "Numbers in the tenant inventory with no user or voice application assignment.")
    _stat(b, "Enterprise Voice enabled users", f'sum by (tenant_id) ({users}{{{TENANT_SEL},enterprise_voice_enabled="true"}})',
          "Teams user configurations with Enterprise Voice enabled.")
    _stat(b, "Teams user configurations", _agg(b, "m365.teams.user_configuration.users"),
          "All configurations returned, including resource accounts and ineligible users.")
    keys = ("capability", "number_type", "assignment_status", "activation_state")
    b.raw("Phone numbers by capability and assignment", [
        f"sum by (tenant_id, {', '.join(keys)}) ({numbers}{{{TENANT_SEL}}})"], viz="table",
        desc="A number can support several capabilities, so do not add the capability rows together.")
    b.raw("User configurations by account type", [
        f"sum by (tenant_id, account_type, enterprise_voice_enabled) ({users}{{{TENANT_SEL}}})"], viz="table",
        desc="Voice enablement by Teams account type. Telephone numbers and effective policies are not mapped.")
    b.metric("m365.teams.phone_numbers.total", title="Phone numbers over time by assignment",
             by=["assignment_status", "number_type"],
             desc="Summed across capability buckets, which overlap: read the trend, not the total.")
    b.metric("m365.teams.phone_numbers.unassigned", title="Unassigned phone numbers over time", viz="timeseries")
    b.records("m365.teams.phone_number", "Phone number inventory", (
        "telephone_number", "number_type", "assignment_status", "activation_state", "capabilities",
        "city", "country_code", "number_source",
    ), desc="One row per number per poll; the newest poll is first.")
    b.records("m365.teams.user_configuration", "Teams user configurations", (
        "user_principal_name", "account_type", "enterprise_voice_enabled", "feature_types", "modified_date_time",
    ), desc="One row per user configuration per poll; the newest poll is first.")


def usage(b):
    b.text("Usage comes from Microsoft's Teams usage reports, which refresh daily and trail the report date. "
           "Platform and activity groups overlap: a user can count in several, so never add them into a "
           "unique-user total.", title="Reading usage", h=3)
    activity = b.cat.metric("m365.teams_usage.activity.users").prom
    b.metric("teams.device_usage.users", title="Teams users by platform (D7)", by=["platform"],
             desc="From the Teams usage report. A user may appear on several platforms; do not sum them.")
    b.raw("Users by activity on the latest report day", [
        f'sum by (tenant_id, activity) ({activity}{{{TENANT_SEL},days_ago="0"}})'],
        legends=["{{tenant_id}} · {{activity}}"],
        desc="days_ago=0 is the newest report date in the download, not today.")
    _stat(b, "Report names concealed", _agg(b, "m365.teams_usage.names_concealed", aggregate="max"),
          "1 means Microsoft conceals user, group and site names in reports, so identifier joins are not guaranteed. "
          "Absent means the setting is unknown.")
    _stat(b, "Teams in the tenant", _agg(b, "m365.teams.total"), "All teams, any visibility.")
    _stat(b, "Ownerless teams", _agg(b, "m365.teams.ownerless.total"),
          "Teams with no owner, excluding archived teams.")
    _stat(b, "Teams with guests", _agg(b, "m365.teams.with_guests.total"), "Teams with at least one guest member.")
    b.metric("m365.teams.total", title="Teams by visibility", by=["visibility"])
    b.metric("m365.teams.membership.total", title="Team memberships by role", by=["role"])
    b.metric("m365.teams.channels.total", title="Channels by membership type", by=["membership_type", "is_archived"])
    b.metric("m365.teams.installed_apps.total", title="Installed apps by distribution",
             by=["distribution_method", "has_rsc_permissions"])


def service(b):
    _service_status(b, "Microsoft Teams service status", "stat", 8)
    _service_status(b, "Microsoft Teams service status over time", "state-timeline", 16)


def _latest_labels(candidates, key, conflict_labels):
    """Keep labels of the newest timestamp per identity, or an explicit conflict."""
    newest = f"max by ({key}) ({candidates})"
    latest = f"(({candidates}) == on ({key}) group_left () ({newest}))"
    tie = f"(count by ({key}) ({latest}) > 1)"
    conflict = f"(({newest}) and on ({key}) {tie})"
    for name, value in conflict_labels.items():
        conflict = f'label_replace({conflict}, "{name}", "{value}", "{name}", "^$")'
    return f"(({latest} unless on ({key}) {tie}) or {conflict})"


def _issue_summary(b, title, expr, columns, value_name, unit, desc, empty):
    panel = b._viz_panel("table", title, [], unit, desc + _loki_note(), 24, 7)
    panel["datasource"] = LOKI_DS
    panel["targets"] = [b._loki_query(expr, query_type="instant")]
    panel["fieldConfig"]["defaults"]["noValue"] = empty
    # Loki returns one instant sample per series. Reduce makes a row from
    # each series and its labels, without joining on display text or nulls.
    panel["transformations"] = [
        {"id": "reduce", "options": {"reducers": ["last"], "mode": "seriesToRows", "labelsToFields": True}},
        {"id": "organize", "options": {"excludeByName": {"Field": True},
                                       "indexByName": {name: i for i, name in enumerate((*columns, "Last"))},
                                       "renameByName": {"Last": value_name}}},
    ]
    panel["options"]["sortBy"] = [{"displayName": value_name, "desc": True}]
    if "title" in columns:
        _override(panel, "title", "custom.wrapText", True)
    for kind in ("string", "number"):
        panel["fieldConfig"]["overrides"].append({"matcher": {"id": "byType", "options": kind},
                                                   "properties": [{"id": "noValue", "value": ""}]})


def issues(b):
    identity = ("tenant_id", "id")
    key = ", ".join(identity)
    teams_only = f("service", "eq", "Microsoft Teams")
    keyed = [teams_only, f("id", "ne", "")]
    open_only = b._selector(ISSUE, filters=[*keyed, f("is_resolved", "eq", "false"), Raw(
        f"keep {key}", keys=identity, reason="Discard mutable metadata before counting keyed observations")],
        by=list(identity))
    count = f"sum by ({key}) (count_over_time({open_only} [$__range]))"
    _issue_summary(b, "Distinct Teams issues observed open in range", count, identity,
                   "Polls seen open", "short",
                   "One row per tenant and issue ID. Counts stored open observations in the selected range, "
                   "not currently open issues. Missing IDs are left in the history only.",
                   "No keyed Teams issues were observed open in this range. Check the Loki datasource and service-health collector.")
    fields = (*identity, "title", "status", "classification", "is_resolved")
    grouped = ", ".join(fields)
    observed = b._selector(ISSUE, filters=[*keyed, f("is_resolved", "re", "true|false"), Raw(
        f"keep {grouped} | label_format g2o_issue_ms=`{{{{ __timestamp__ | unixEpochMillis }}}}` | unwrap g2o_issue_ms",
        keys=fields, reason="Compare the log event timestamps while retaining the latest row's display labels")])
    candidates = f"max_over_time({observed} [$__range]) by ({grouped})"
    _issue_summary(b, "Latest Teams issue observations in range",
                   _latest_labels(candidates, key, {"status": "Conflicting observations"}),
                   fields, "Observation time", "dateTimeAsIso",
                   "Latest stored event per tenant and issue ID in the selected range. Open rows use poll time; "
                   "resolutions use Microsoft's end time. If different display details share the latest millisecond, "
                   "read the dated history below. This is not a current open-issue inventory.",
                   "No keyed Teams issue observations in this range. This does not show whether any issue is currently open.")
    for title, resolved in (("Teams issue observations while open", "false"), ("Teams resolution events", "true")):
        panel = b.records(ISSUE, title, ("id", "title", "classification", "status", "impact_description",
                          "description", "last_modified_date_time", "end_date_time"),
                          filters=[f("service", "eq", "Microsoft Teams"), f("is_resolved", "eq", resolved)],
                          desc="Requires the service-health collector. This is history, not a current-state join: "
                               "an open observation can also have a later resolution. No resolution row is not proof an issue remains open.")
        _override(panel, "description", "custom.cellOptions", {"type": "markdown"})
        for field in ("impact_description", "description"):
            _override(panel, field, "custom.inspect", True)
        panel["options"]["cellHeight"] = "lg"
        if resolved == "true":
            panel["fieldConfig"]["defaults"]["noValue"] = (
                "No Teams resolution events in this range. A closure is recorded only for a previously observed open issue. "
                "Check the Loki datasource and service-health collector; no row does not prove the issue is still open.")


def _availability(b, selector):
    metric = b.cat.metric("graph2otel.collector.availability").prom
    key = "tenant_id, collector, collector_transport"
    # An instant selector sees the last sample of *each* series, possibly from
    # a replaced process or state. Compare their real sample timestamps, not
    # the gauge (always 1) or the instant query's evaluation timestamp.
    stamp = f"timestamp({metric}{{{TENANT_SEL},{selector}}})"
    by_state = f"max by ({key}, state, reason) ({stamp})"
    # Identical state/reason samples collapse above. At exactly equal times a
    # conflicting tuple has no provable winner, regardless of severity.
    expr = "1000 * " + _latest_labels(by_state, key, {"state": "unknown", "reason": "timestamp_tie"})
    panel = b.raw("Signal availability", [expr], viz="table", w=24, h=8,
                  desc="Newest exported state and reason per tenant, collector and collector transport at the "
                       "selected end time, within the datasource's instant lookback. Compare these columns with "
                       "availability.state, availability.reason and availability.transport in the poller's "
                       "admin /api/status.json. Admin is live; this table can lag the snapshot refresh and export. "
                       "If the newest samples have the same timestamp but disagree, the state is unknown. "
                       "Healthy, empty means the run succeeded without fetching rows, not disabled or failed.")
    panel["fieldConfig"]["defaults"]["noValue"] = (
        "Availability unknown: no recent snapshot sample at the selected end time. "
        "Check the tenant, Prometheus datasource and exporter; this is not evidence of a disabled collector.")
    panel["fieldConfig"]["overrides"] = [
        _value_mapping("state", {**AVAILABILITY_STATES, "unknown": {"text": "Unknown"}}),
        _value_mapping("reason", {**AVAILABILITY_REASONS, "timestamp_tie": {"text": "Latest samples disagree"}}),
    ]
    _override(panel, "Value", "unit", "dateTimeAsIso")
    _override(panel, "Value", "displayName", "Last exported sample")


def health(b):
    selector = f'collector=~`{COLLECTORS}|m365[.]collaboration_activity`'
    _availability(b, selector)
    name = b.cat.metric("graph2otel.collector.expected_interval").prom
    series = f"{name}{{{TENANT_SEL},{selector}}}"
    stamp = f"timestamp({series})"
    key = "tenant_id, collector"
    # Compare the sample times first: a retired instance's longer interval
    # may still be in lookback. Only agree on a value at the newest time.
    latest = f"({series} and ({stamp} == on ({key}) group_left () max by ({key}) ({stamp})))"
    cadence = f"max by ({key}) ({latest}) == min by ({key}) ({latest})"
    panel = b.raw("Scheduled collector interval", [cadence], viz="table", unit="s", w=24, h=7,
                  desc="Latest exported scheduler interval (admin interval_seconds), when newest samples agree. "
                       "Cadence, last success and checkpoint metrics identify only tenant and collector, not transport. "
                       "Compare against availability, but do not read these metrics as per-transport results.")
    panel["fieldConfig"]["defaults"]["noValue"] = "No recent interval sample, or newest samples disagree."
    for metric, title in (("graph2otel.collector.watermark_timestamp", "Window watermark lag"),
                          ("graph2otel.scrape.staleness", "Time since last successful scrape")):
        q = _agg(b, metric, keys=("collector",), match=selector, aggregate="max")
        b.raw(title, [f"time() - ({q})" if "watermark" in metric else q],
              unit="s", legends=["{{tenant_id}} · {{collector}}"],
              desc=("Age of the durable event-time cursor (admin checkpoint watermark for window collectors). "
                    "A successful quiet window can still advance its cursor. Missing is not zero lag."
                    if "watermark" in metric else
                    "Compare with the scheduled collector interval. Until the first success this counts from "
                    "process start. Admin staleness instead measures time since the last attempt. "
                    "Missing is not zero staleness."))
    throttle = b.raw("Teams Graph throttle response rate", [_agg(b, "graph2otel.throttle.count", keys=("workload",),
                     match='workload=~"teams-call-records|teams-phone"', op="rate")],
                     legends=["{{tenant_id}} · {{workload}}"],
                     desc="Only the Teams-specific call records and phone workload buckets. Shared reporting "
                          "and other Graph workloads cannot be attributed to Teams here. An empty plot may mean "
                          "no throttles or too few samples to calculate a rate; it is not a health verdict.")
    throttle["fieldConfig"]["defaults"]["noValue"] = (
        "No Teams throttle rate samples. There may have been no throttle responses, or too few counter samples. "
        "This does not establish zero throttling or collector health.")
    skipped = b.metric("teams.call.metrics_skipped", title="Call versions skipped by metrics admission rate",
                       by=["reason_bucket"],
                       desc="Rate of versions skipped by metrics admission, not a measure of Graph collection failure. "
                            "An empty plot may mean no skipped versions, no calls or too few counter samples.")
    skipped["fieldConfig"]["defaults"]["noValue"] = (
        "No admission-skip rate samples. There may have been no skipped versions, no calls, or too few "
        "counter samples. Use Signal availability for the collector's last reported state.")


def practices(b):
    q = site_queries(b.cat, grown=True, window="$__interval", site=SITES)
    label = ["{{tenant_id}} · {{site}}"]
    _slots(b.raw("Audio TCP share by site", [q["tcp"]], unit="percentunit", legends=label,
           desc="Observed sender TCP among known TCP or UDP audio streams. TCP can be expected; "
                "a high share is a prompt to check, not proof of blocked ports. " + SLOT_NOTE), share=True)
    b.text("Check the [Microsoft Teams network guidance](https://learn.microsoft.com/microsoftteams/prepare-network) "
           "and allow Microsoft’s documented Teams UDP ports where required. "
           "Version buckets do not establish whether a client is outdated. No bounded poor-device or relay-use "
           "share is emitted. The endpoint matrix shows observed CPU and glitch flags, and relay allocation is not use.",
           title="What the signals can establish", h=5, w=12)
    for key, name, unit in (("jitter", "Mean audio jitter by site", "s"), ("rtt", "Mean audio round-trip time by site", "s"),
                             ("loss", "Mean audio loss fraction by site", "percentunit")):
        _slots(b.raw(name, [q[key]], unit=unit, legends=label, desc="Mapped sites only. " + SLOT_NOTE))
    dims = {"keys": ("site",), "op": "increase", "window": "$__interval"}
    wifi = _agg(b, "teams.streams", match=f'{SITES},connection_type="wifi"', **dims)
    known = _agg(b, "teams.streams", match=f'{SITES},connection_type=~"wired|wifi|mobile|tunnel"', **dims)
    _slots(b.raw("Wi-Fi share of observed connection types by site", [_share(wifi, known, "site")],
           unit="percentunit", legends=label,
           desc="Directional streams from first accepted versions, not a share of users or calls. "
                "Unknown connection types are excluded. " + SLOT_NOTE), share=True)


def sites_and_network(b):
    sites(b)
    practices(b)


def service_health(b):
    service(b)
    issues(b)
    b.metric("m365.service_health.issues.total", title="Service issues by classification and status (all services)",
             by=["classification", "status"],
             desc="Counts expanded issues returned for all Microsoft 365 services, including any resolved rows "
                  "the source returns. This metric does not carry a service label.")
    b.metric("m365.service_health.services.total", title="Services by status (all services)", by=["status"],
             desc="Fleet context across Microsoft 365 services, not limited to Teams.")


def admin_config(b):
    b.text("Auto attendant, call queue, network topology, Direct Routing gateway and IP phone "
           "configuration from the Teams admin API. Each object is a log twin with a config_sha256 "
           "that changes when its exported configuration changes.",
           title="Teams admin configuration", h=3, w=24)
    b.metric("teams.call_queue.count", title="Call queues by routing method", by=["routing_method"],
             desc="Queues with a missing or unrecognised routing method count under unknown.")
    b.metric("teams.network_subnet.csv_coverage", title="Teams subnets by sites CSV coverage", by=["coverage"])
    b.metric("teams.pstn_gateway.count", title="Direct Routing gateways by enabled", by=["enabled"],
             desc="Configured Direct Routing gateways (SBCs) by whether they are enabled. Per-gateway "
                  "configuration is in the teams.pstn_gateway log twins.")


CALLS_EMPTY = "Teams publishes a call record after the call ends, sometimes hours later."
TABS = (
    ("Overview", overview, CALLS_EMPTY),
    ("Call quality", quality, "Stream metrics need completed call records with media streams. " + CALLS_EMPTY),
    ("Sites and network", sites_and_network,
     "Site panels need call records and a site mapping (tenants[].teams.sites_file)."),
    ("Calls", calls, "No call record matched the filters in this range. " + CALLS_EMPTY),
    ("Call detail", detail, "Enter a call ID, or follow one from Calls or Users."),
    ("Users", users, "Enter an exact user UPN in User UPN."),
    ("PSTN and Direct Routing", phone,
     "PSTN and Direct Routing records appear after calls end; healthy_empty means the source answered with no rows."),
    ("Auto attendant and call queue", voice_apps, "Needs the optional teams.voice_apps collector, off by default."),
    ("Phone inventory", inventory, "Needs the teams.phone_numbers and teams.user_configuration collectors."),
    ("Configuration", admin_config, "Needs tenants[].teams.admin_api.enabled, off by default."),
    ("Usage", usage, "Usage reports refresh daily; the first values follow the first report poll."),
    ("Service health", service_health,
     "Needs the m365.servicehealth collector. No issue rows means no Teams issue was observed in range."),
    ("Collector health", health, "No collector census for this tenant: check that graph2otel is exporting."),
)


def build(cat):
    b = TeamsBuilder(NAME, "graph2otel Teams", "Microsoft Teams call, site and service health. "
                     "Generated from grafana/boards/teams.py.", ["graph2otel", "teams", "generated"], cat)
    for name, label, desc in (
        ("call_id", "Call ID", "Required on Call detail; follows links from call or stream rows."),
        ("site", "Site search", "Exact configured name, either stream side. Used by the Calls site results only."),
        ("user", "User UPN", "Exact observed UPN; call rows check organiser, stream rows check either side."),
        ("health", "Call health", "Exact emitted value (good, poor, or unclassified). Blank means all."),
        ("call_type", "Call type", "Exact Graph type, e.g. peerToPeer or groupCall. Blank means all."),
        ("modality", "Modality", "Exact Graph modality token, e.g. audio or video. Blank means all."),
        ("min_seconds", "Minimum duration (seconds)", "Whole seconds. Blank means all, including unknown duration."),
    ):
        b.text_variable(name, label, description=desc)
    manifest = b.render([b.tab(title, add, empty) for title, add, empty in TABS])
    return b, manifest


def coverage_violations(cat, manifest):
    """Teams metrics, and the Teams-profile m365 ones, must reach a placed Teams panel."""
    # Self-observability metrics such as graph2otel.api.unexpected are shared
    # across collectors and belong to Collector health, not this coverage set.
    needed = {m.name for m in cat.metrics.values()
              if m.domain == "teams" or (m.domain != "graph2otel" and any(
                  p == prefix.rstrip("/") or p.startswith(prefix) for p in m.packages for prefix in TEAMS_PACKAGES))}
    covered = set()
    for name in v2.placed_element_names(manifest):
        element = manifest["spec"]["elements"].get(name)
        if element is None:
            continue  # handled by the layout gate
        for target in element["spec"]["data"]["spec"]["queries"]:
            query = target["spec"]["query"]
            if query["group"] == "prometheus":
                covered |= cat.metrics_referenced_by(query["spec"]["expr"])
    return [f"Teams dashboard is missing metric {name}" for name in sorted(needed - covered)]
