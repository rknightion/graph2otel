"""Exercise the shipped Teams health queries against synthetic data."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel-teams.json"


def _tab(title):
    spec = json.loads(DASHBOARD.read_text())["spec"]
    tab = next(tab for tab in spec["layout"]["spec"]["tabs"] if tab["spec"]["title"] == title)
    return [spec["elements"][item["spec"]["element"]["name"]]["spec"]
            for row in tab["spec"]["layout"]["spec"]["rows"]
            for item in row["spec"]["layout"]["spec"]["items"]]


class TeamsHealthTests(unittest.TestCase):
    def test_service_health_shows_teams_evidence_before_fleet_context(self):
        panels = _tab("Service health")
        fleet, teams = [], []
        for i, panel in enumerate(panels):
            queries = [t["spec"]["query"] for t in panel["data"]["spec"]["queries"]]
            if any('service="Microsoft Teams"' in q["spec"]["expr"] or q["group"] == "loki" for q in queries):
                teams.append(i)
            elif queries:
                fleet.append(i)
        self.assertTrue(teams and fleet)
        self.assertLess(max(teams), min(fleet))


    def test_latest_issue_table_keeps_identity_and_observation_time(self):
        panel = next(p for p in _tab("Service health") if p["title"] == "Latest Teams issue observations in range")
        data = panel["data"]["spec"]
        self.assertEqual(data["queries"][0]["spec"]["query"]["spec"]["queryType"], "instant")
        self.assertEqual(panel["vizConfig"]["spec"]["fieldConfig"]["defaults"]["unit"], "dateTimeAsIso")
        reduce = next(t for t in data["transformations"] if t["group"] == "reduce")
        self.assertTrue(reduce["spec"]["options"]["labelsToFields"])
        organize = next(t for t in data["transformations"] if t["group"] == "organize")
        self.assertLessEqual({"tenant_id", "id", "title", "status"}, organize["spec"]["options"]["indexByName"].keys())

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool")
    def test_cadence_uses_newest_sample_and_does_not_guess_at_ties(self):
        panel = next(p for p in _tab("Collector health") if p["title"] == "Scheduled collector interval")
        query = panel["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]
        self.assertTrue(query["instant"] and not query["range"])
        expr = query["expr"].replace("$tenant", ".*")
        metric = "graph2otel_collector_expected_interval_seconds"
        label = lambda tenant: '{tenant_id="' + tenant + '",collector="teams.call_records"}'
        series = lambda t, instance: metric + label(t)[:-1] + ',instance="' + instance + '"}'
        sample = lambda tenant, value: {"labels": label(tenant), "value": value}
        test = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": [
            {"series": series("a", "old"), "values": "600"},
            {"series": series("a", "new"), "values": "_ _ 60 _ 60"},
            {"series": series("a", "tie"), "values": "_ _ _ _ 75"},
            {"series": series("b", "third"), "values": "_ _ _ 120"},
        ], "promql_expr_test": [
            {"expr": expr, "eval_time": "3m", "exp_samples": [sample("a", 60), sample("b", 120)]},
            {"expr": expr, "eval_time": "4m", "exp_samples": [sample("b", 120)]},
            {"expr": expr, "eval_time": "10m", "exp_samples": []},
        ]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cadence.yaml"
            path.write_text(json.dumps(test))
            run = subprocess.run(["promtool", "test", "rules", str(path)], capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool")
    def test_availability_selects_latest_sample_in_instant_lookback(self):
        panel = next(p for p in _tab("Collector health") if p["title"] == "Signal availability")
        query = panel["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]
        self.assertTrue(query["instant"])
        self.assertFalse(query["range"])
        self.assertEqual(query["format"], "table")
        value_props = [prop for override in panel["vizConfig"]["spec"]["fieldConfig"]["overrides"]
                       if override["matcher"]["options"] == "Value" for prop in override["properties"]]
        self.assertIn({"id": "unit", "value": "dateTimeAsIso"}, value_props)
        expr = query["expr"].replace("$tenant", ".*")

        def labels(tenant="a", transport="graph", state="starting", reason="no_completed_run",
                   collector="teams.call_records", **extra):
            fields = dict(tenant_id=tenant, collector=collector, collector_transport=transport,
                          state=state, reason=reason, **extra)
            return "{" + ",".join(f'{key}="{value}"' for key, value in fields.items() if value) + "}"

        # Old Healthy remains inside the five-minute lookback after the new
        # instance first exports Starting. The new instance then becomes Healthy.
        # Neither a higher value nor a status order can decide which is newer.
        before = labels(state="healthy", reason="success", instance="old")
        starting = labels(instance="new")
        after = labels(state="healthy", reason="success", instance="new")
        # Two export replicas of the same state do not make a conflict. Two
        # different reasons at the same timestamp do, even for the same state.
        replica = labels(state="healthy", reason="success", instance="replica")
        conflict = labels(state="healthy", reason="transport_fallback", instance="other")
        blob = labels(transport="blob", state="healthy_empty", reason="empty")
        other_tenant = labels(tenant="b")
        marker = labels(tenant="c", state="healthy", reason="success")
        other_collector = labels(collector="m365.collaboration_activity", state="healthy", reason="success")
        unlabelled = labels(tenant="")
        data = [(before, "1 1 _ _ _ _ _ _ _ _ _"), (starting, "_ _ 1 _ _ _ _ _ _ _ _"),
                (after, "_ _ _ _ 1 _ 1 _ _ 1 _"), (replica, "_ _ _ _ 1 _ _ _ _ _ _"),
                (conflict, "_ _ _ _ _ _ 1 _ _ _ _"), (blob, "_ _ 1 1 1 _ 1 _ _ 1 _"),
                (other_tenant, "_ _ _ 1 1 _ 1 _ _ 1 _"), (marker, "1 stale _ _ _ _ _ _ _ _ _"),
                (other_collector, "_ _ _ 1 stale _ _ _ _ _ _"), (unlabelled, "_ _ _ 1 stale _ _ _ _ _ _")]

        def sample(key, minute):
            return {"labels": key, "value": minute * 60_000}

        test = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": [
            {"series": "graph2otel_collector_availability" + key, "values": values} for key, values in data
        ], "promql_expr_test": [
            {"expr": expr, "eval_time": "3m", "exp_samples": [
                sample(labels(), 2), sample(blob, 3), sample(other_tenant, 3),
                sample(other_collector, 3), sample(unlabelled, 3)]},
            {"expr": expr, "eval_time": "5m", "exp_samples": [
                sample(labels(state="healthy", reason="success"), 4), sample(blob, 4), sample(other_tenant, 4)]},
            {"expr": expr, "eval_time": "7m", "exp_samples": [
                sample(labels(state="unknown", reason="timestamp_tie"), 6), sample(blob, 6), sample(other_tenant, 6)]},
            {"expr": expr, "eval_time": "11m", "exp_samples": [
                sample(labels(state="healthy", reason="success"), 9), sample(blob, 9), sample(other_tenant, 9)]},
            {"expr": expr, "eval_time": "15m", "exp_samples": []},
        ]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "availability.yaml"
            path.write_text(json.dumps(test))  # JSON is also YAML.
            run = subprocess.run(["promtool", "test", "rules", str(path)], capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
