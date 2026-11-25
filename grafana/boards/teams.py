"""Separate Teams investigation dashboard, assembled from the signal catalogue."""

from builder import LOKI_DS, NO_LOKI, NO_METRIC, RATE, TENANT_SEL, Builder
from logquery import Raw, f
import v2

from .teams_quality import LOCAL, compliance, site_queries

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
        return v2.leaf(title, [v2.rowspec("", self._panels[start:])])

    def records(self, event, title, fields, *, filters=(), desc="", h=9):
        # Loki exposes structured metadata in its per-row labels frame column.
        # The keep stage is also catalog-gated, not a parser for the log body.
        columns = ("tenant_id", *fields)
        keep = Raw("keep " + ", ".join(columns), keys=columns,
                   reason="Project the structured metadata columns used in the table")
        panel = self.logs(event, title, [*filters, keep], desc + ROW_NOTE, h=h)
        panel["type"] = "table"
        panel["targets"][0]["maxLines"] = RECORD_LIMIT
        panel["options"] = {"showHeader": True, "sortBy": [{"displayName": "Time", "desc": True}]}
        panel["transformations"] = [
            {"id": "extractFields", "options": {"source": "labels", "format": "json",
                                               "replace": True, "keepTime": True}},
        ]
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


def _link(panel, field, tab, variable):
    # Use the row tenant, not a possibly multi-tenant dashboard selection.
    url = (f"/d/{NAME}?dtab={v2.slug(tab)}&from=${{__from}}&to=${{__to}}"
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
    if op:
        term = f"{op}({term}[{window}])"
    return f"{aggregate} by ({', '.join(('tenant_id', *keys))}) ({term})"


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
    return b.raw(title, [expr], unit=None, desc=desc, w=w, legends=["{{tenant_id}}"],
                 about="m365.service_health.status")


def overview(b):
    b.text("Start with **Call quality** and **Sites and network**, then use **Calls** and **Call detail** "
           "for the evidence. Home and site metrics describe first accepted complete versions. "
           "Log timestamps are source timestamps; metric counters and rates follow collection time. "
           "Unique callers are not available as a bounded aggregate; endpoint rows are not a substitute. "
           "A panel that says **No data yet** is not a health verdict: check **Collector health**.",
           title="Teams call quality", h=4)
    increase = {"op": "increase", "window": "$__range"}
    total = _agg(b, "teams.calls", **increase)
    good = _agg(b, "teams.calls", match='call_health="good"', **increase)
    classified = _agg(b, "teams.calls", match='call_health=~"good|poor"', **increase)
    _stat(b, "Calls counted in range", total, FIRST + " " + COUNT_NOTE, w=6)
    _stat(b, "Good share of classified calls", _share(good, classified),
          FIRST + " Unclassified calls are excluded. No classified observations means no percentage.",
          "percentunit", w=6)
    _stat(b, "Direct Routing attempts in range", _agg(b, "teams.direct_routing.calls", **increase),
          "Attempts through your own session border controllers. " + COUNT_NOTE, w=6)
    _service_status(b, "Microsoft Teams service status", "stat", 6)
    b.metric("teams.calls", title="Call rate by initial health", by=["call_health"], desc=FIRST)
    b.metric("teams.call.health_transitions", title="Later call health transition rate",
             by=["from_health", "to_health"],
             desc="Changes between successive accepted versions. Not a signed correction to the initial counts.")


def _measure(b, metric):
    return f"{b.cat.metric(metric).prom}_bucket{{{TENANT_SEL},{SITES}}}"


def quality(b):
    b.text("Directional media streams from the first accepted complete version of each call, filtered by "
           "the Site dropdown. Quantiles are estimated from histogram buckets, so they are bounded by "
           "the bucket edges. The distributions combine the selected tenants.",
           title="Reading call quality", h=3)
    span = {"op": "increase", "window": "$__range"}
    poor = _agg(b, "teams.streams", match=f'{SITES},stream_health="poor"', **span)
    classified = _agg(b, "teams.streams", match=f'{SITES},stream_health=~"good|poor"', **span)
    _stat(b, "Directional streams counted in range", _agg(b, "teams.streams", match=SITES, **span),
          FIRST + " " + COUNT_NOTE)
    _stat(b, "Poor share of classified streams", _share(poor, classified),
          FIRST + " Unclassified streams are excluded. No classified streams means no percentage.",
          "percentunit")
    _stat(b, "Calls with failure evidence in range", _agg(b, "teams.call.failures", **span),
          "Calls whose sessions or segments reported a failure stage. " + COUNT_NOTE)
    b.raw("Stream verdict rate by media", [_agg(b, "teams.streams", keys=("media", "stream_health"),
          match=SITES, op="rate")], legends=["{{tenant_id}} · {{media}} · {{stream_health}}"],
          desc="Directional streams by verdict. " + FIRST)
    rate = {"keys": ("media",), "op": "increase", "window": RATE}
    b.raw("Poor-stream share by media", [_share(
        _agg(b, "teams.streams", match=f'{SITES},stream_health="poor"', **rate),
        _agg(b, "teams.streams", match=f'{SITES},stream_health=~"good|poor"', **rate), "media")],
          unit="percentunit", legends=["{{tenant_id}} · {{media}}"],
          desc="Poor among classified streams in each interval. Gaps mean no classified stream, not zero.")
    for metric, name, unit in (("teams.stream.rtt", "Round-trip time", "s"),
                               ("teams.stream.jitter", "Jitter", "s"),
                               ("teams.stream.packet_loss", "Packet loss", "percentunit")):
        bucket = _measure(b, metric)
        b.raw(f"{name} p50 and p95 by media", [
            f"histogram_quantile({q}, sum by (le, tenant_id, media) (rate({bucket}[{RATE}])))" for q in ("0.5", "0.95")
        ], unit=unit, legends=["{{tenant_id}} · {{media}} · p50", "{{tenant_id}} · {{media}} · p95"],
              desc="Per-stream averages reported by the endpoints, as bucketed quantiles across streams.")
        heat = b.raw(f"{name} distribution", [f"sum by (le) (increase({bucket}[{RATE}]))"], viz="heatmap",
                     unit=unit, legends=["{{le}}"],
                     desc="How many directional streams fell in each bucket per interval, across the selected tenants.")
        heat["targets"][0]["format"] = "heatmap"
    b.metric("teams.stream.feedback", title="Endpoint feedback rate", by=["media", "rating"])
    b.metric("teams.call.failures", title="Call failure evidence rate", by=["failure_stage", "reason_bucket"])
    _pie(b, "Poor stream causes", [_agg(b, "teams.streams", keys=("stream_health_cause",),
         match=f'{SITES},stream_health="poor"', op="increase", window="$__range")],
         ["{{tenant_id}} · {{stream_health_cause}}"],
         "Reported primary cause bucket per poor directional stream, not proof of a network fault.")
    b.metric("teams.client_versions", title="Recently ended calls by client bucket",
             by=["platform", "product_family", "version_bucket"],
             desc="Calls in the latest 60 call-end minutes since process start. Client buckets overlap.")


def _site_link(panel):
    panel["transformations"] = [
        {"id": "labelsToFields", "options": {"mode": "columns"}},
        {"id": "merge", "options": {}},
    ]
    _link(panel, "site", "Calls", "site")


def sites(b):
    queries = site_queries(b.cat, window="$__range", site=SITES)
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
        "call_id", "version", "call_health", "call_type", "modalities",
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


def detail(b):
    selected = [_matches("call_id", "call_id", required=True)]
    b.text("Open a call from **Calls**, or select its tenant and enter a call ID. "
           "Compare like versions. Missing fields mean unavailable observations; they do not indicate a good endpoint. "
           "Relay addresses are allocations, not proof of relay use. Trace rows are reported hops only.",
           title="Read the evidence", h=4)
    b.records(CALL, "Call verdict and worst observed metrics by version", (
        "call_id", "version", "call_health", "poor_stream_count", "worst_rtt_ms", "worst_jitter_ms",
        "worst_packet_loss_rate", "shared_reflexive_ip", "participant_apps",
    ), filters=selected)
    b.records(STREAM, "Poor-stream threshold evidence", (
        "version", "session_id", "segment_id", "stream_id", "media", "direction",
        "stream_health_cause", "stream_health_metric", "stream_health_value", "stream_health_threshold",
    ), filters=[*selected, f("stream_health_metric", "ne", "")],
       desc="Value and threshold are in the units of the named metric; not all verdicts have threshold evidence.")
    b.records(STREAM, "Directional streams", (
        "version", "session_id", "segment_id", "stream_id", "media", "direction", "start_time", "end_time",
        "stream_health", "average_rtt_ms", "average_jitter_ms", "average_packet_loss_rate",
        "session_failure_stage", "session_failure_reason", "segment_failure_stage", "segment_failure_reason",
    ), filters=selected)
    # Only real intervals. An absent end must not paint a stream continuing to now.
    keys = ("version", "session_id", "segment_id", "stream_id", "direction")
    timeline = b.records(STREAM, "Dated stream intervals", (*keys, "start_time", "end_time", "stream_health"),
                         filters=[*selected, f("start_time", "ne", ""), f("end_time", "ne", "")],
                         desc="Whole-stream labels, not changing verdicts within the stream.")
    timeline["type"] = "state-timeline"
    timeline["options"] = {"mergeValues": False, "showValue": "auto"}
    timeline["transformations"][0]["options"]["keepTime"] = False
    timeline["transformations"].extend([
        _convert(("start_time", "end_time"), "time"),
        {"id": "organize", "options": {"indexByName": {"start_time": 0, "end_time": 1, "stream_health": 2}}},
        {"id": "partitionByValues", "options": {"fields": ["tenant_id", *keys], "keepFields": False}},
    ])
    for side, extra in (("caller", ("platform", "product_family", "client_version", "device_name")), ("callee", ())):
        b.records(STREAM, f"Reported {side} endpoint", ("version", "stream_id", "direction", *(
            f"{side}_{key}" for key in (*extra, "device", "cpu_insufficient", "device_glitch",
                                        "connection_type", "user_agent")),
        ), filters=selected, desc="Device JSON may carry audio capture and render data. "
                                "Callee platform and client version are not catalogued.")
        b.records(STREAM, f"Reported {side} addresses and ASN", ("version", "stream_id", "direction", *(
            f"{side}_{key}" for key in ("ip_address", "ip_class", "reflexive_ip_address", "relay_ip_address",
                                        "relay_address_present", "asn", "asn_organization", "site")),
        ), filters=selected, desc="Optional ASN enrichment describes a qualifying reflexive address, not a hop. "
                                "Private/shared status describes the reported address only.")
    b.records(STREAM, "Reported caller trace hops", (
        "version", "stream_id", "caller_trace_route_hops", "caller_trace_route_hops_omitted",
    ), filters=[*selected, f("caller_trace_route_hops", "ne", "")],
       desc="The capped source trace where available. Missing hops do not establish a direct path.")
    b.records(STREAM, "Application and bot evidence", (
        "version", "stream_id", "caller_identity_kind", "callee_identity_kind",
        "callee_app_id", "callee_bot_role",
    ), filters=[*selected, Raw('caller_identity_kind="app" or callee_identity_kind="app" or callee_bot_role!=""',
                              keys=["caller_identity_kind", "callee_identity_kind", "callee_bot_role"],
                              reason="Either side may report an application identity")],
       desc="Application identity kinds and observed callee bot roles, not a count of all bots or attendees. "
            "Caller app ID and bot role are not catalogued.")


def users(b):
    b.text("Enter an exact UPN to find dated endpoints and calls organised by that user. "
           "A user can appear on both stream sides or across versions. No poor-call ranking is available: "
           "ranking a limited record view would not rank the tenant.", title="Investigate one user", h=4)
    panel = b.records(STREAM, "Recent stream observations for the selected user", (
        "call_id", "version", "stream_id", "caller_user_principal_name", "callee_user_principal_name",
        "caller_platform", "caller_transport_protocol", "callee_transport_protocol", "stream_health",
    ), filters=[f("call_id", "ne", ""),
                _matches("user", "caller_user_principal_name", "callee_user_principal_name", required=True)])
    _link(panel, "call_id", "Call detail", "call_id")
    panel = b.records(CALL, "Recent calls organised by the selected user", (
        "call_id", "version", "organizer_user_principal_name", "call_type", "call_health", "duration_seconds",
    ), filters=[_matches("user", "organizer_user_principal_name", required=True)])
    _link(panel, "call_id", "Call detail", "call_id")


def phone(b):
    for metric, title in (("teams.pstn.calls", "PSTN calls in range"),
                          ("teams.pstn.minutes", "PSTN connected minutes in range"),
                          ("teams.direct_routing.calls", "Direct Routing attempts in range")):
        _stat(b, title, _agg(b, metric, op="increase", window="$__range"), COUNT_NOTE)
    b.metric("teams.direct_routing.calls", title="Direct Routing attempt rate by trunk and SIP outcome",
             by=["trunk_fqdn", "sip_class", "outcome"])
    b.metric("teams.direct_routing.network_effectiveness_ratio", title="Trunk effectiveness in latest successful poll",
             by=["trunk_fqdn"], desc="Share of new attempts that answered or reached a busy user in the latest successful poll.")
    b.records("teams.pstn_call", "PSTN call records", ("id", "call_id", "call_type", "connectivity_type",
              "duration_seconds", "start_time", "end_time"),
              desc="Phone log IDs are not assumed to name Graph call detail records.")
    b.records("teams.direct_routing_call", "Direct Routing records", (
        "id", "trunk_fqdn", "final_sip_code", "final_sip_code_phrase", "successful_call", "duration_seconds",
    ))


def voice_apps(b):
    b.text("This tab needs the optional **teams.voice_apps** collector, which reads Teams voice analytics and is "
           "off unless enabled for the tenant. Queue and attendant labels are resource GUIDs. Queue shares describe "
           "newly observed legs with known results, not intervals of event time.", title="Before you read this tab", h=3)
    b.metric("teams.call_queue.answer_rate", title="Call queue answer share", by=["queue"])
    b.metric("teams.call_queue.abandon_rate", title="Call queue abandon share", by=["queue"])
    b.metric("teams.call_queue.wait_time", title="Call queue wait time p95", by=["queue"])
    b.metric("teams.call_queue.wait_time", title="Call queue wait time p50", by=["queue"], quantile=0.5)
    b.metric("teams.auto_attendant.calls", by=["auto_attendant", "voice_outcome"])
    b.records("teams.call_queue_call", "Call queue legs", (
        "queue", "call_queue_identity", "result", "call_queue_final_state_action", "call_queue_duration_seconds",
        "call_queue_agent_count", "agent_name", "start_date_time", "end_date_time",
    ), desc="Caller and agent identities are kept in the log rows only.")
    b.records("teams.auto_attendant_call", "Auto attendant legs", (
        "auto_attendant", "auto_attendant_identity", "result", "auto_attendant_transfer_action",
        "auto_attendant_call_flow", "auto_attendant_chain_duration_seconds", "start_date_time", "end_date_time",
    ))


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
    table = b.raw("Phone numbers by capability and assignment", [
        f"sum by (tenant_id, {', '.join(keys)}) ({numbers}{{{TENANT_SEL}}})"], viz="table",
        desc="A number can support several capabilities, so do not add the capability rows together.")
    table["transformations"] = [{"id": "labelsToFields", "options": {"mode": "columns"}}]
    table = b.raw("User configurations by account type", [
        f"sum by (tenant_id, account_type, enterprise_voice_enabled) ({users}{{{TENANT_SEL}}})"], viz="table",
        desc="Voice enablement by Teams account type. Telephone numbers and effective policies are not mapped.")
    table["transformations"] = [{"id": "labelsToFields", "options": {"mode": "columns"}}]
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
    _service_status(b, "Microsoft Teams service status over time", "timeseries", 16)
    b.metric("m365.service_health.issues.total", title="Open service issues by classification (all services)",
             by=["classification", "status"],
             desc="Counts every Microsoft 365 service: the issue count carries no service label.")
    b.metric("m365.service_health.services.total", title="Services by status (all services)", by=["status"])


def issues(b):
    for title, resolved in (("Teams issue observations while open", "false"), ("Teams resolution events", "true")):
        panel = b.records(ISSUE, title, ("id", "title", "classification", "status", "impact_description",
                          "description", "last_modified_date_time", "end_date_time"),
                          filters=[f("service", "eq", "Microsoft Teams"), f("is_resolved", "eq", resolved)],
                          desc="Requires the service-health collector. This is history, not a current-state join: "
                               "an open observation can also have a later resolution. No resolution row is not proof an issue remains open.")
        _override(panel, "description", "custom.cellOptions", {"type": "markdown"})
        panel["options"]["cellHeight"] = "lg"


def health(b):
    b.availability(COLLECTORS)
    selector = f'collector=~`{COLLECTORS}`'
    for metric, title in (("graph2otel.collector.watermark_timestamp", "Window watermark lag"),
                          ("graph2otel.scrape.staleness", "Time since last successful scrape")):
        q = _agg(b, metric, keys=("collector",), match=selector, aggregate="max")
        b.raw(title, [f"time() - ({q})" if "watermark" in metric else q],
              unit="s", legends=["{{tenant_id}} · {{collector}}"],
              desc=("Only window collectors that emit a watermark are shown. Missing is not zero lag."
                    if "watermark" in metric else
                    "Until the first successful run, staleness counts from process start. Missing is not zero staleness."))
    b.raw("Teams Graph throttle response rate", [_agg(b, "graph2otel.throttle.count", keys=("workload",),
          match='workload=~"teams-call-records|teams-phone"', op="rate")],
          legends=["{{tenant_id}} · {{workload}}"],
          desc="These two Graph workload buckets are Teams-specific. Shared reporting and other Graph workloads cannot be attributed to Teams here.")
    for metric, title, by in (
        ("teams.call.metrics_skipped", "Call versions skipped by metrics admission rate", ["reason_bucket"]),
    ):
        b.metric(metric, title=title, by=by)


def practices(b):
    q = site_queries(b.cat, site=SITES)
    label = ["{{tenant_id}} · {{site}}"]
    b.raw("Audio TCP share by site", [q["tcp"]], unit="percentunit", legends=label,
          desc="Observed sender TCP among known TCP or UDP audio streams. TCP can be expected; "
               "a high share is a prompt to check, not proof of blocked ports.")
    b.text("Check the [Microsoft Teams network guidance](https://learn.microsoft.com/microsoftteams/prepare-network) "
           "and allow Microsoft’s documented Teams UDP ports where required. "
           "Version buckets do not establish whether a client is outdated. No bounded poor-device or relay-use "
           "share is emitted. The endpoint matrix shows observed CPU and glitch flags, and relay allocation is not use.",
           title="What the signals can establish", h=5, w=12)
    for key, name, unit in (("jitter", "Mean audio jitter", "s"), ("rtt", "Mean audio round-trip time", "s"),
                             ("loss", "Mean audio loss fraction", "percentunit")):
        b.raw(name, [q[key]], unit=unit, legends=label)
    dims = {"keys": ("site",), "op": "increase"}
    wifi = _agg(b, "teams.streams", match=f'{SITES},connection_type="wifi"', **dims)
    known = _agg(b, "teams.streams", match=f'{SITES},connection_type=~"wired|wifi|mobile|tunnel"', **dims)
    b.raw("Wi-Fi share of observed connection types", [_share(wifi, known, "site")],
          unit="percentunit", legends=label,
          desc="Directional streams from first accepted versions, not a share of users or calls. Unknown connection types are excluded.")


def sites_and_network(b):
    sites(b)
    practices(b)


def service_health(b):
    service(b)
    issues(b)


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
