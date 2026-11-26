"""Offline rule firing check: python3 grafana/tests/teams_promtool.py (needs promtool).

Project the generated instant query, final numeric comparator, hold time and
routable labels into real Prometheus alert rules. This exercises PromQL and
pending/firing, not Grafana's datasource, expression engine or routing.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_rules as rules  # noqa: E402


def test_cases():
    cases = []

    def series(metric, tenant, values, **labels):
        selector = ",".join(f'{key}={json.dumps(value)}'
                            for key, value in {"tenant_id": tenant, **labels}.items())
        return {"series": f"{metric}{{{selector}}}", "values": values}

    def counter(metric, tenant, increment, **labels):
        return series(metric, tenant, f"0+{increment}x12", **labels)

    def case(uid, fixtures, labels):
        cases.append((f"g2o-teams-{uid}", fixtures, labels))

    calls = "teams_calls_total"
    case("healthy-call-share-low", [
        counter(calls, "fixture-bad", 5, call_health="poor"),
        counter(calls, "fixture-good", 5, call_health="good"),
        counter(calls, "fixture-good", 100, call_health="unclassified"),
        counter(calls, "fixture-quiet", 1, call_health="poor"),
        counter(calls, "", 5, call_health="poor"),
        counter("teams_call_health_transitions_total", "fixture-good", 100,
                from_health="good", to_health="poor"),
    ], {"tenant_id": "fixture-bad"})

    def network(tenant, site, jitter, *, loss=True):
        dims = {"media": "audio", "direction": "caller_to_callee", "site": site}
        observations = {"jitter_seconds": jitter, "rtt_seconds": 0.05}
        if loss:
            observations["packet_loss"] = 0.001
        fixtures = []
        for kind, mean in observations.items():
            metric = f"teams_stream_{kind}"
            fixtures += [counter(f"{metric}_sum", tenant, mean * 10, **dims),
                         counter(f"{metric}_count", tenant, 10, **dims)]
        return fixtures + [counter("teams_stream_transport_total", tenant, 10,
                                   site=site, transport="udp")]

    case("site-network-noncompliant", [
        *network("fixture-bad", "Lab", 0.08),
        *network("fixture-good", "Lab", 0.01),
        *network("fixture-bad", "Annex", 0.01),
        *network("fixture-incomplete", "Lab", 0.08, loss=False),
        *network("fixture-bad", "overflow", 0.08),
    ], {"tenant_id": "fixture-bad", "site": "Lab"})

    def stream(tenant, health, count, site="Lab"):
        return counter("teams_streams_total", tenant, count, site=site,
                       media="audio", direction="caller_to_callee", stream_health=health)

    case("site-poor-stream-share-high", [
        stream("fixture-bad", "poor", 2), stream("fixture-bad", "good", 8),
        stream("fixture-bad", "unclassified", 100),
        stream("fixture-good", "good", 100), stream("fixture-good", "poor", 1),
        stream("fixture-bad", "good", 10, "Annex"),
        stream("fixture-overflow", "poor", 10, "overflow"),
        stream("fixture-quiet", "poor", 1),
    ], {"tenant_id": "fixture-bad", "site": "Lab"})

    trunk = "trunk.example.invalid"

    def attempts(tenant, host, outcome, sip, volume):
        return counter("teams_direct_routing_calls_total", tenant, volume,
                       trunk_fqdn=host, outcome=outcome, sip_class=sip)

    def effectiveness(tenant, host, ratio):
        return series("teams_direct_routing_network_effectiveness_ratio", tenant,
                      f"{ratio}+0x12", trunk_fqdn=host)

    case("trunk-effectiveness-low", [
        effectiveness("fixture-bad", trunk, 0.5),
        attempts("fixture-bad", trunk, "failed", "4xx", 10),
        effectiveness("fixture-good", trunk, 0.99),
        attempts("fixture-good", trunk, "answered", "2xx", 10),
        effectiveness("fixture-quiet", trunk, 0),
        attempts("fixture-quiet", trunk, "failed", "4xx", 1),
        effectiveness("fixture-bad", "other", 0),
        attempts("fixture-bad", "other", "failed", "4xx", 10),
    ], {"tenant_id": "fixture-bad", "trunk_fqdn": trunk})
    case("trunk-sip-5xx-high", [
        attempts("fixture-bad", trunk, "failed", "5xx", 5),
        attempts("fixture-bad", trunk, "answered", "2xx", 5),
        attempts("fixture-good", trunk, "failed", "5xx", 1),
        attempts("fixture-good", trunk, "failed", "4xx", 30),
        attempts("fixture-no-5xx", trunk, "answered", "2xx", 20),
        attempts("fixture-bad", "unknown", "failed", "5xx", 10),
        attempts("fixture-quiet", trunk, "failed", "5xx", 1),
    ], {"tenant_id": "fixture-bad", "trunk_fqdn": trunk})
    return cases


def stale_scenarios(uid, doc_rule):
    """Gate and arrival cases for g2o-teams-call-records-stale.

    promtool time zero is Thursday 1970-01-01 00:00 UTC. Eval at 6d14h is
    Wednesday 14:00; 2d14h is Saturday 14:00. The counter ramps and then stays
    flat, ending eight hours before the evaluation, so it was seen within 12h
    and not within 4h. Only the ramp's end is pinned; leading gaps are absent
    samples, so the series does not exist before it.
    """
    step_minutes = 5

    def steps(hours):
        return hours * 60 // step_minutes

    def scenario(eval_hours, series_values, exp):
        series = [{"series": f'teams_calls_total{{tenant_id="{t}",call_health="good"}}',
                   "values": v} for t, v in series_values.items()]
        return {"interval": "5m", "input_series": series, "alert_rule_test": [
            {"eval_time": f"{eval_hours}h", "alertname": uid,
             "exp_alerts": [{"exp_labels": {"tenant_id": t} | doc_rule["labels"]}
                            for t in exp]}]}

    def stopped(eval_hours, quiet_hours, ramp_hours=2):
        # absent, ramp up, then flat until past the evaluation time
        lead = steps(eval_hours - quiet_hours - ramp_hours)
        return f"_x{lead} 0+1x{steps(ramp_hours)} {steps(ramp_hours)}x{steps(quiet_hours + 24)}"

    wednesday, saturday = 6 * 24 + 14, 2 * 24 + 14
    out = []
    for eval_hours, fires in ((wednesday, True), (saturday, False)):
        out.append(scenario(eval_hours, {
            "fixture-stale": stopped(eval_hours, 8),
            "fixture-fresh": stopped(eval_hours, 1),
            "fixture-old": stopped(eval_hours, 20),
        }, ["fixture-stale"] if fires else []))
    # Wednesday 20:00 is outside the 12:00 to 18:00 gate.
    out.append(scenario(6 * 24 + 20, {"fixture-stale": stopped(6 * 24 + 20, 8)}, []))
    # A tenant whose counter never existed does not alert.
    out.append(scenario(wednesday, {}, []))
    return out


def project(generated, uid):
    doc = rules.to_app_platform(generated[uid], rules.ALERT_GROUP,
                                rules.GROUP_INTERVAL, 0)["spec"]
    source = doc["expressions"]
    a, b, c = (source[ref]["model"] for ref in "ABC")
    assert a["instant"] and not a["range"], uid
    evaluator = c["conditions"][0]["evaluator"]
    comparison = {"lt": "<", "gt": ">"}[evaluator["type"]]
    expr = f'({a["expr"]}) {comparison} {evaluator["params"][0]}'
    return doc, {"alert": uid, "expr": expr, "for": doc.get("for", "0s"),
                 "labels": doc["labels"]}


def main():
    generated = {r["uid"]: r for r in rules.RULES}
    alert_rules = []
    scenarios = []
    for uid, fixtures, expected in test_cases():
        doc = rules.to_app_platform(generated[uid], rules.ALERT_GROUP,
                                    rules.GROUP_INTERVAL, 0)["spec"]
        source = doc["expressions"]
        a, b, c = (source[ref]["model"] for ref in "ABC")
        assert a["instant"] and not a["range"], uid
        assert b["type"] == "reduce" and b["reducer"] == "last" and b["expression"] == "A", uid
        assert source["C"]["source"] and c["expression"] == "B", uid
        assert doc["noDataState"] == "Ok", uid
        evaluator = c["conditions"][0]["evaluator"]
        comparison = {"lt": "<", "gt": ">"}[evaluator["type"]]
        expr = f'({a["expr"]}) {comparison} {evaluator["params"][0]}'
        alert_rules.append({"alert": uid, "expr": expr, "for": doc.get("for", "0s"),
                            "labels": doc["labels"]})
        for series, labels in ((fixtures, [{"exp_labels": expected | doc["labels"]}]), ([], [])):
            scenarios.append({"interval": "5m", "input_series": series, "alert_rule_test": [
                {"eval_time": "50m", "alertname": uid, "exp_alerts": labels},
            ]})
    stale_uid = "g2o-teams-call-records-stale"
    stale_doc, stale_rule = project(generated, stale_uid)
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "rules.yml").write_text(json.dumps({"groups": [{
            "name": rules.ALERT_GROUP, "interval": rules.GROUP_INTERVAL, "rules": alert_rules,
        }]}), encoding="utf-8")
        (root / "test.yml").write_text(json.dumps({"rule_files": ["rules.yml"],
            "evaluation_interval": rules.GROUP_INTERVAL, "tests": scenarios}), encoding="utf-8")
        subprocess.run(["promtool", "test", "rules", "test.yml"], cwd=root, check=True, timeout=30)
        # The stale rule needs days of simulated time to reach weekday hours, so
        # it runs alone, apart from the 50m scenarios above.
        (root / "stale_rules.yml").write_text(json.dumps({"groups": [{
            "name": rules.ALERT_GROUP, "interval": rules.GROUP_INTERVAL,
            "rules": [stale_rule]}]}), encoding="utf-8")
        (root / "stale_test.yml").write_text(json.dumps({"rule_files": ["stale_rules.yml"],
            "evaluation_interval": rules.GROUP_INTERVAL,
            "tests": stale_scenarios(stale_uid, stale_doc)}), encoding="utf-8")
        subprocess.run(["promtool", "test", "rules", "stale_test.yml"], cwd=root, check=True,
                       timeout=300)
    print(f"{len(alert_rules)} Prometheus rules: adverse, healthy and no-data controls passed")


if __name__ == "__main__":
    main()
