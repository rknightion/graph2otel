"""Offline checks of the generated Sites and network panels."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel-teams.json"


class TeamsSitesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = json.loads(MANIFEST.read_text())["spec"]
        cls.panels = {e["spec"]["title"]: e["spec"] for e in spec["elements"].values()}

    def queries(self, title):
        return [q["spec"]["query"]["spec"] for q in self.panels[title]["data"]["spec"]["queries"]]

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool for offline PromQL fixture")
    def test_measured_sites_include_jitter_only_but_not_mapping_buckets(self):
        series = []

        def observation(metric, tenant, site, labels, value):
            series.append({"series": f'{metric}{{tenant_id="{tenant}",site="{site}",{labels}}}',
                           "values": f"_x4 {value}"})

        audio = 'media="audio",direction="caller_to_callee"'
        for tenant, site, value in (("fixture-a", "selected", 2), ("fixture-a", "elsewhere", 1),
                                    ("fixture-a", "overflow", 3), ("fixture-b", "unmapped", 4)):
            observation("teams_streams_total", tenant, site, audio, value)
            observation("teams_stream_jitter_seconds_count", tenant, site, audio, value)
            observation("teams_stream_jitter_seconds_sum", tenant, site, audio, value * 0.01)

        expr = self.queries("Sites with audio measurements")[0]["expr"]
        tests = [{"expr": expr.replace("$tenant", ".*").replace("$__range", "5m").replace("$sites", selected),
                  "eval_time": "5m", "exp_samples": [{"labels": f'{{tenant_id="{tenant}"}}', "value": count}
                     for tenant, count in expected]}
                 for selected, expected in ((".*", (("fixture-a", 2), ("fixture-b", 0))),
                                             ("selected", (("fixture-a", 1),)), ("absent", ()))]
        self.check_promql(series, tests)

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool for offline PromQL fixture")
    def test_assessment_counts_missing_evidence_separately_from_failures(self):
        series = []

        def record(metric, tenant, site, labels, value):
            series.append({"series": f'{metric}{{tenant_id="{tenant}",site="{site}",{labels}}}',
                           "values": f"_x4 {value}"})

        audio = 'media="audio",direction="caller_to_callee"'
        # The same site label in another tenant has no protocol evidence.
        for tenant, site, verdict, jitter, transport in (
            ("fixture-a", "both", "good", 0.01, "udp"),
            ("fixture-a", "slow", "poor", 0.06, "udp"),
            ("fixture-b", "both", "unclassified", 0.01, None),
            ("fixture-b", "unmapped", "poor", 0.06, "tcp"),
        ):
            record("teams_streams_total", tenant, site, audio + f',stream_health="{verdict}"', 1)
            for metric, value in (("jitter_seconds", jitter), ("rtt_seconds", 0.1), ("packet_loss", 0)):
                record(f"teams_stream_{metric}_sum", tenant, site, audio, value)
                record(f"teams_stream_{metric}_count", tenant, site, audio, 1)
            if transport:
                record("teams_stream_transport_total", tenant, site, f'transport="{transport}"', 1)

        coverage = self.panels["Site assessment coverage"]
        organize = next(t for t in coverage["data"]["spec"]["transformations"] if t["group"] == "organize")
        columns = organize["spec"]["options"]["renameByName"]
        expected = {"Preset evaluated": (2, 0), "Audio sites not evaluated": (0, 1), "Missed preset": (1, 0),
                    "Sites with classified streams": (2, 0), "Above 5% poor": (1, 0)}
        tests = []
        for target in coverage["data"]["spec"]["queries"]:
            spec = target["spec"]
            values = expected.pop(columns[f"Value #{spec['refId']}"])
            tests.append({"expr": spec["query"]["spec"]["expr"].replace("$tenant", ".*")
                          .replace("$sites", ".*").replace("$__range", "5m"), "eval_time": "5m",
                          "exp_samples": [{"labels": f'{{g2o_scope="fixture-{t}|",tenant_id="fixture-{t}"}}', "value": value}
                                          for t, value in zip("ab", values)]})
        self.assertFalse(expected, "all coverage counts must be visible")
        self.check_promql(series, tests)

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool for offline PromQL fixture")
    def test_inventory_omits_idle_rows_and_does_not_invent_clipped_breakdowns(self):
        base = 'teams_streams_total{tenant_id="fixture",site="%s",media="%s",stream_health="%s",connection_type="%s"}'
        series = [
            {"series": base % ("idle", "audio", "good", "wifi"), "values": "7x6"},
            {"series": base % ("measured", "audio", "good", "wifi"), "values": "_x4 2"},
            # The limiter drops every non-tenant dimension into its other bucket.
            {"series": base % ("other", "other", "other", "other"), "values": "_x4 6"},
        ]
        inventory = self.panels["Site inventory"]
        organize = next(t for t in inventory["data"]["spec"]["transformations"] if t["group"] == "organize")
        columns = organize["spec"]["options"]["renameByName"]
        expected = {"Directional streams": {"measured": 2, "other": 6}, "Classified streams": {"measured": 2},
                    "Unclassified streams": {"measured": 0}, "Audio streams": {"measured": 2},
                    "Streams with known connection type": {"measured": 2}}
        tests = []
        for target in self.queries("Site inventory"):
            column = columns[f"Value #{target['refId']}"]
            if column not in expected:
                continue
            tests.append({"expr": target["expr"].replace("$tenant", ".*").replace("$sites", ".*")
                          .replace("$__range", "5m"), "eval_time": "5m", "exp_samples": [
                              {"labels": f'{{g2o_scope="fixture|{site}",site="{site}",tenant_id="fixture"}}', "value": value}
                              for site, value in expected.pop(column).items()]})
        self.assertFalse(expected)
        self.check_promql(series, tests)

    def test_inventory_buckets_do_not_link_as_named_sites(self):
        overrides = self.panels["Site inventory"]["vizConfig"]["spec"]["fieldConfig"]["overrides"]
        self.assertFalse(any(p["id"] == "links" and p.get("value")
                             for o in overrides for p in o["properties"]))

    def test_observations_keep_named_sites_even_without_coordinates(self):
        for side in ("caller", "callee"):
            title = f"Observed {side} sites"
            query, = self.queries(title)
            self.assertIn(f'| {side}_site!~`unmapped|`', query["expr"])
            self.assertNotIn("latitude", query["expr"])
            self.assertNotIn("longitude", query["expr"])
            transforms = self.panels[title]["data"]["spec"]["transformations"]
            group = next(t["spec"]["options"]["fields"] for t in transforms if t["group"] == "groupBy")
            self.assertEqual({k for k, v in group.items() if v["operation"] == "groupby"},
                             {"tenant_id", f"{side}_site"})
            self.assertEqual(set(group["Time"]["aggregations"]), {"count", "max"})

    def check_promql(self, series, tests):
        fixture = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": series,
                                                               "promql_expr_test": tests}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sites.yaml"
            path.write_text(json.dumps(fixture))  # JSON is valid YAML.
            result = subprocess.run(["promtool", "test", "rules", str(path)], capture_output=True, text=True,
                                    timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_loss_is_a_fraction_with_a_bounded_axis(self):
        panel = self.panels["Mean audio loss fraction by site"]
        defaults = panel["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual((defaults.get("unit"), defaults.get("min"), defaults.get("max")),
                         ("percentunit", 0, 1))
