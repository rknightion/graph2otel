"""Offline evidence for the Teams investigation panels, using the shipped manifest."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel-teams.json"


def panels():
    return [element["spec"] for element in json.loads(DASHBOARD.read_text())["spec"]["elements"].values()]


def panel(title):
    for candidate in panels():
        if candidate["title"] == title:
            return candidate
    raise AssertionError(f"Missing panel: {title}")


def query_models(panel):
    return [q["spec"]["query"]["spec"] for q in panel["data"]["spec"]["queries"]]


def verdict_panel():
    [evidence] = [p for p in panels() if any("stream_health_threshold" in q["expr"] for q in query_models(p))]
    return evidence


class TeamsInvestigationTests(unittest.TestCase):
    def test_fraction_axes_use_physical_bounds(self):
        for title in ("Packet loss p50 and p95 by media", "Poor-stream share by media"):
            defaults = panel(title)["vizConfig"]["spec"]["fieldConfig"]["defaults"]
            with self.subTest(title=title):
                self.assertEqual((defaults.get("min"), defaults.get("max"), defaults["unit"]),
                                 (0, 1, "percentunit"))
        y_axis = panel("Packet loss distribution")["vizConfig"]["spec"]["options"].get("yAxis", {})
        self.assertEqual((y_axis.get("min"), y_axis.get("max"), y_axis.get("unit")), (0, 1, "percentunit"))

    def test_threshold_evidence_preserves_all_verdicts_and_units(self):
        evidence = verdict_panel()
        self.assertNotIn("Poor", evidence["title"])
        expr = query_models(evidence)[0]["expr"]
        self.assertRegex(expr, r"keep [^|]*\bstream_health\b")
        self.assertNotIn('stream_health_metric!=', expr)
        self.assertIn('g2o_units=', expr)
        self.assertIn('stream_health_value', expr)
        self.assertIn('stream_health_threshold', expr)

    def test_call_bounds_pivot_is_separate_from_discovery_queries(self):
        bounds = panel("Call bounds and timeline zoom")
        timeline = panel("Dated stream intervals")
        link = bounds["vizConfig"]["spec"]["fieldConfig"]["defaults"]["links"][0]
        self.assertTrue(link["targetBlank"], "opening the timeline must not change the discovery window")
        self.assertIn(f"&viewPanel={timeline['id']}&", link["url"])
        self.assertIn('from=${__data.fields["From (padded)"].numeric}', link["url"])
        self.assertIn('to=${__data.fields["To (padded)"].numeric}', link["url"])
        self.assertIn('var-tenant=${__data.fields.Tenant.text:percentencode}', link["url"])
        queries = query_models(bounds)
        self.assertEqual(len(queries), 2, "need bounds from call versions and all plotted stream peers")
        self.assertIn('event_name=`teams.call`', queries[0]["expr"])
        self.assertIn('event_name=`teams.call_stream`', queries[1]["expr"])
        self.assertEqual(queries[1]["maxLines"], query_models(timeline)[0]["maxLines"])
        for q in queries:
            self.assertIn('| tenant_id!=``', q["expr"], "an unlabelled row must not offer an All-tenant zoom")
        for q in [*queries, *query_models(timeline)]:
            self.assertNotRegex(q["expr"], r'\| (?:version|direction|session_id|stream_id)=')

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool for offline PromQL fixture")
    def test_coverage_evaluates_initial_populations_and_absent_denominators(self):
        for noun, metric, health, share in (
                ("call", "teams_calls_total", "call_health", "Good"),
                ("stream", "teams_streams_total", "stream_health", "Poor")):
            with self.subTest(population=noun):
                summary = panel(f"Initial {noun} verdict coverage (processing time)")
                renames = next(t["spec"]["options"]["renameByName"]
                               for t in summary["data"]["spec"]["transformations"] if t["group"] == "organize")

                def series(tenant, verdict, value, site="selected", *, population=(noun, metric, health)):
                    entity, metric_name, verdict_label = population
                    scope = "" if entity == "call" else f',site="{site}"'
                    tenant_label = f'tenant_id="{tenant}",' if tenant else ""
                    return {"series": f'{metric_name}{{{tenant_label}{verdict_label}="{verdict}"{scope}}}',
                            "values": f"_x10 {value}x4"}

                input_series = [series(None, "good", 3), series(None, "unclassified", 2),
                                series("mixed", "good", 4), series("mixed", "poor", 4),
                                series("mixed", "unclassified", 16), series("only-unclassified", "unclassified", 8),
                                series("no-poor", "good", 6), series("quiet", "good", 0)]
                if noun == "stream":
                    input_series += [series("mixed", "poor", 90, "excluded")]
                expected = {
                    "(unlabelled)": {"Good": 3, "Poor": 0, "Unclassified": 2, "Classified": 3, "Observed": 5,
                                     f"{share} share": 1 if share == "Good" else 0},
                    "mixed": {"Good": 4, "Poor": 4, "Unclassified": 16, "Classified": 8, "Observed": 24,
                              f"{share} share": .5},
                    "only-unclassified": {"Good": 0, "Poor": 0, "Unclassified": 8, "Classified": 0, "Observed": 8},
                    "no-poor": {"Good": 6, "Poor": 0, "Unclassified": 0, "Classified": 6, "Observed": 6,
                                f"{share} share": 1 if share == "Good" else 0},
                    "quiet": {"Good": 0, "Poor": 0, "Unclassified": 0, "Classified": 0, "Observed": 0},
                }
                queries = query_models(summary)
                columns = {renames[f"Value #{q['refId']}"] for q in queries}
                self.assertEqual(columns, set(expected["mixed"]))
                checks = []
                for query in queries:
                    self.assertTrue(query["instant"] and not query["range"])
                    column = renames[f"Value #{query['refId']}"]
                    expr = (query["expr"].replace("$__range", "10m").replace("$tenant", ".*")
                            .replace("$sites", "selected"))
                    checks.append({"expr": expr, "eval_time": "14m", "exp_samples": [
                        {"labels": f'{{tenant_id="{tenant}"}}', "value": values[column]}
                        for tenant, values in expected.items() if column in values]})
                self.assert_promql(input_series, checks)

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool for offline PromQL fixture")
    def test_packet_loss_quantiles_for_zero_only_and_low_loss_streams(self):
        series = [{"series": f'teams_stream_packet_loss_bucket{{tenant_id="{tenant}",site="selected",'
                             f'media="audio",le="{limit}"}}', "values": f"_x10 {count}x4"}
                  for tenant in ("zero-only", "low-loss")
                  for limit, count in (("0", 20 if tenant == "zero-only" else 0), ("0.001", 20), ("+Inf", 20))]
        checks = []
        for query in query_models(panel("Packet loss p50 and p95 by media")):
            expr = (query["expr"].replace("$__interval", "10m").replace("$tenant", ".*")
                    .replace("$sites", "selected"))
            checks.append({"expr": expr, "eval_time": "14m", "exp_samples": [
                {"labels": '{tenant_id="zero-only",media="audio"}', "value": 0},
                {"labels": '{tenant_id="low-loss",media="audio"}',
                 "value": .0005 if "p50" in query["legendFormat"] else .00095},
            ]})
        self.assert_promql(series, checks)

    def assert_promql(self, series, checks):
        test = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": series,
                                                           "promql_expr_test": checks}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "investigation.yml"
            path.write_text(json.dumps(test))
            run = subprocess.run(["promtool", "test", "rules", str(path)],
                                 capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


@unittest.skipUnless(shutil.which("logcli") or os.environ.get("TEAMS_LOGCLI_DOCKER") == "1",
                     "needs logcli or TEAMS_LOGCLI_DOCKER=1 with a cached grafana/logcli:3.6.7 image")
class TeamsInvestigationLogQLTests(unittest.TestCase):
    def query(self, target, records, fields, *, call):
        runner = ["logcli"] if shutil.which("logcli") else [
            "docker", "run", "--rm", "-i", "--network", "none", "--pull=never", "grafana/logcli:3.6.7"]
        rendered = (target["expr"].replace('{service_name="graph2otel"}', '{source="logcli"} | json', 1)
                    .replace("$tenant", "fixture-tenant").replace("${call_id:percentencode}", quote(call, safe="")))
        # stdin mode has no wire metadata and prints no labels. The JSON stage
        # loads the same keys; reading them back tests the production pipeline.
        rendered += " | line_format `" + "\t".join("{{." + name + "}}" for name in fields) + "`"
        run = subprocess.run([*runner, "query", "--stdin", "--quiet", "--output=raw", rendered],
                             input="\n".join(json.dumps(row) for row in records) + "\n",
                             capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return [line.split("\t") for line in run.stdout.splitlines()]

    def test_verdict_rows_keep_low_packets_and_reported_units(self):
        good = "fixture / good"
        poor = "fixture / poor"
        records = [
            (good, "good", "", "", "", ""),
            (good, "unclassified", "low_packet_utilisation", "packet_utilization", "0", "500"),
            (poor, "poor", "jitter", "average_jitter_ms", "31", "30"),
            (poor, "poor", "frame_rate", "video_frame_rate", "0", "7"),
            (poor, "poor", "post_fec_loss", "post_fec_packet_loss_rate", "0.5", "0.15"),
            (poor, "poor", "frame_loss", "video_frame_loss_percent", "51", "50"),
            (poor, "unclassified", "no_metrics", "", "", ""),
        ]
        fields = ("stream_health", "stream_health_cause", "stream_health_metric", "stream_health_value",
                  "stream_health_threshold")
        rows = [{"event_name": "teams.call_stream", "tenant_id": "fixture-tenant", "call_id": call,
                 **dict(zip(fields, values))} for call, *values in records]
        target = query_models(verdict_panel())[0]
        for call, units in ((good, ["", "packets"]), (poor, ["ms", "fps", "fraction (0-1)", "% (0-100)", ""])):
            selected = [values for key, *values in records if key == call]
            self.assertCountEqual(self.query(target, rows, (*fields, "g2o_units"), call=call),
                                  [[*row, unit] for row, unit in zip(selected, units)])
        self.assertEqual(self.query(target, rows, fields, call=""), [])

    def test_call_bounds_include_peer_intervals_outside_one_call_version(self):
        base = {"tenant_id": "fixture-tenant", "call_id": "fixture-call"}
        records = []
        for event, version, start, end, direction in (
                ("teams.call", "1", "05.021", "11.999", ""),
                ("teams.call", "2", "06", "12", ""),
                ("teams.call_stream", "1", "03", "08", "callerToCallee"),
                ("teams.call_stream", "2", "10", "14", "calleeToCaller"),
                ("teams.call_stream", "2", "09", "07", "calleeToCaller"),
                ("teams.call_stream", "2", "12", "", "calleeToCaller")):
            records.append({**base, "event_name": event, "version": version, "direction": direction,
                            "start_time": f"2026-01-01T00:00:{start}Z", "media": "audio", "stream_health": "good",
                            "end_time": f"2026-01-01T00:00:{end}Z" if end else ""})
        targets = query_models(panel("Call bounds and timeline zoom"))
        columns = ("g2o_scope", "g2o_from", "g2o_to")
        bounds = [self.query(q, records, columns, call="fixture-call") for q in targets]
        self.assertCountEqual(bounds[0], [["fixture-tenant", "1767225604021", "1767225612999"],
                                         ["fixture-tenant", "1767225605000", "1767225613000"]])
        self.assertCountEqual(bounds[1], [["fixture-tenant", "1767225602000", "1767225609000"],
                                         ["fixture-tenant", "1767225609000", "1767225615000"]])
        timeline = query_models(panel("Dated stream intervals"))[0]
        self.assertCountEqual(self.query(timeline, records, ("g2o_lane", "stream_health"), call="fixture-call"), [
            ["v1 · callerToCallee · audio · ?/?/? · fixture-tenant", "good"],
            ["v2 · calleeToCaller · audio · ?/?/? · fixture-tenant", "good"],
        ])
