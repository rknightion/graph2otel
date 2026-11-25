"""The Teams call-quality signal slice of the Microsoft 365 board."""

from builder import RATE, TENANT_SEL

# Both presets compare fractions and seconds. The stricter numbers come from
# Microsoft's client-to-network-edge optimal targets, not a measurement of which
# route these calls used. Microsoft gives no TCP-share target in that table.
EDGE_REFERENCE = (
    "https://learn.microsoft.com/skypeforbusiness/optimizing-your-network/"
    "network-performance-requirements"
)
LOCAL = {"jitter": 0.030, "rtt": 0.200, "loss": 0.02, "tcp": 0.01}
EDGE = {"jitter": 0.003, "rtt": 0.060, "loss": 0.005}
_GROUP = "tenant_id, site"
_SITE = 'site!~"unmapped|overflow|other|"'


def site_queries(cat, tenant=TENANT_SEL, window=RATE, site=""):
    """Return four measurement queries. A site with no evidence is absent.

    `site` is one more label matcher, such as a site template variable.
    """
    scope = f"{tenant},{_SITE}" + (f",{site}" if site else "")

    def increase(name, select):
        return f"sum by ({_GROUP}) (increase({name}{{{scope},{select}}}[{window}]))"

    def ratio(numer, denom):
        return f"(({numer}) / ({denom})) and on ({_GROUP}) (({denom}) > 0)"

    def mean(metric):
        base = cat.metric(metric).prom
        select = 'media="audio",direction=~"caller_to_callee|callee_to_caller"'
        return ratio(increase(f"{base}_sum", select), increase(f"{base}_count", select))

    transport = cat.metric("teams.stream.transport").prom
    known = increase(transport, 'transport=~"tcp|udp"')
    tcp = increase(transport, 'transport="tcp"')
    return {
        "jitter": mean("teams.stream.jitter"),
        "rtt": mean("teams.stream.rtt"),
        "loss": mean("teams.stream.packet_loss"),
        # No TCP in a site with measured UDP is a real zero. Missing evidence
        # for both protocols is not a zero and is removed by ratio().
        "tcp": ratio(f"({tcp}) or on ({_GROUP}) (0 * ({known}))", known),
    }


def compliance(queries, thresholds, compare):
    """1 means all measured targets pass; no series means incomplete evidence."""
    return f" * on ({_GROUP}) ".join(
        f"(({queries[key]}) {compare} bool {threshold})" for key, threshold in thresholds.items()
    )


def add(b):
    b.row("Teams call quality")
    for title, metric, by in (
        ("Call rate by initial health", "teams.calls", ["call_health"]),
        ("Call health transition rate", "teams.call.health_transitions", ["from_health", "to_health"]),
        ("Stream rate by media and health", "teams.streams", ["media", "stream_health"]),
        ("Endpoint feedback rate", "teams.stream.feedback", ["media", "rating"]),
        ("Rate of calls with failure evidence", "teams.call.failures", ["failure_stage", "reason_bucket"]),
        ("Recently ended calls by client bucket", "teams.client_versions", ["platform", "product_family", "version_bucket"]),
        ("Rate of call versions skipped by metric admission", "teams.call.metrics_skipped", ["reason_bucket"]),
    ):
        b.metrics([metric], title=title, by=by, viz="timeseries")

    b.row("Teams site network measurements")
    queries = site_queries(b.cat)
    legend = ["{{tenant_id}} · {{site}}"]
    for key, name, unit in (
        ("jitter", "Mean audio jitter", "s"), ("rtt", "Mean audio round-trip time", "s"),
        ("loss", "Mean audio packet loss", "percentunit"), ("tcp", "Audio TCP share of known protocols", "percentunit"),
    ):
        b.raw(name, [queries[key]], unit=unit, legends=legend)
    b.raw("Site compliance: local preset", [compliance(queries, LOCAL, "<=")], unit="short", legends=legend,
          desc="1 = all pass: jitter 30 ms, RTT 200 ms, loss 2%, TCP share 1%. No result means missing evidence. "
               "Check series clipping before interpreting compliance.")
    b.raw("Site compliance: published client-to-edge reference", [compliance(queries, EDGE, "<")], unit="short",
          legends=legend, desc="1 = all pass: jitter below 3 ms, RTT below 60 ms, loss below 0.5%. "
          "No published TCP share target. This compares call observations, not a verified edge route. " + EDGE_REFERENCE)
