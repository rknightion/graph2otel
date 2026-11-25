"""Contracts on the separate generated Teams dashboard."""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import catalog
import v2
from boards import teams
from boards.teams_quality import counter_increase


DASHBOARDS = Path(__file__).resolve().parents[2] / "dashboards"


class TeamsDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = DASHBOARDS / "graph2otel-teams.json"
        cls.manifest = json.loads(path.read_text()) if path.is_file() else None

    def panels_by_tab(self):
        spec = self.manifest["spec"]
        return {
            tab["spec"]["title"]: [spec["elements"][name]["spec"] for name in v2.placed_element_names({
                "spec": {"layout": {"spec": {"tabs": [tab]}}}
            })]
            for tab in spec["layout"]["spec"]["tabs"]
        }

    def test_separate_dashboard_has_reachable_investigation_tabs(self):
        path = DASHBOARDS / "graph2otel-teams.json"
        self.assertTrue(path.is_file(), "Teams needs its own generated dashboard")
        manifest = json.loads(path.read_text())
        self.assertEqual(manifest["metadata"]["name"], "graph2otel-teams")
        tabs = manifest["spec"]["layout"]["spec"]["tabs"]
        self.assertEqual([tab["spec"]["title"] for tab in tabs], [
            "Overview", "Call quality", "Sites and network", "Calls", "Call detail", "Users",
            "PSTN and Direct Routing", "Auto attendant and call queue", "Phone inventory",
            "Configuration", "Usage", "Service health", "Collector health",
        ])
        for tab in tabs:
            self.assertNotIn("conditionalRendering", tab["spec"])
        graph = json.loads((DASHBOARDS / "graph2otel.json").read_text())
        self.assertEqual(graph["metadata"]["name"], "graph2otel")

    def test_site_and_call_links_keep_the_row_tenant_and_time(self):
        tabs = self.panels_by_tab()
        destinations = {v2.slug(title).lower(): title for title in tabs}
        routes = set()
        for source, panels in tabs.items():
            for panel in panels:
                field_config = panel["vizConfig"]["spec"].get("fieldConfig", {})
                for override in field_config.get("overrides", []):
                    field = override["matcher"]["options"]
                    for prop in override["properties"]:
                        if prop["id"] != "links":
                            continue
                        for link in prop["value"]:
                            replacements = {
                                "__from": "100", "__to": "200",
                                "__data.fields.tenant_id:percentencode": "example-tenant",
                                "__value.raw:percentencode": quote("Sample / `?&=Site", safe=""),
                                "datasource:queryparam": "var-datasource=example-prom",
                                "loki_datasource:queryparam": "var-loki_datasource=example-logs",
                            }
                            url = re.sub(r"\$\{([^}]+)\}", lambda m: replacements[m[1]], link["url"])
                            parts = urlsplit(url)
                            self.assertEqual(parts.path, "/d/graph2otel-teams")
                            query = parse_qs(parts.query)
                            slug = query["dtab"][0]
                            self.assertIn(slug, destinations)
                            target = destinations[slug]
                            variable = {
                                "call_id": "call_id", "site": "site", "caller_site": "site", "callee_site": "site",
                                "caller_user_principal_name": "user", "callee_user_principal_name": "user",
                                "organizer_user_principal_name": "user",
                            }[field]
                            self.assertEqual(query[f"var-{variable}"], ["Sample / `?&=Site"])
                            self.assertEqual(query["var-tenant"], ["example-tenant"])
                            self.assertEqual(query["from"] + query["to"], ["100", "200"])
                            self.assertEqual(query["var-datasource"], ["example-prom"])
                            self.assertEqual(query["var-loki_datasource"], ["example-logs"])
                            routes.add((source, target, variable))
        self.assertEqual(routes, {
            ("Sites and network", "Calls", "site"), ("Calls", "Call detail", "call_id"),
            ("Users", "Call detail", "call_id"), ("Users", "Users", "user"),
        })

    def test_panel_navigation_uses_the_routes_grafana_writes(self):
        tabs = self.panels_by_tab()
        overview = next(p for p in tabs["Overview"] if p["title"] == "Teams call quality")
        self.assertEqual({parse_qs(urlsplit(link["url"]).query)["dtab"][0] for link in overview["links"]},
                         {"call-quality", "service-health"})
        bounds = next(p for p in tabs["Call detail"] if p["title"] == "Call bounds and timeline zoom")
        links = bounds["vizConfig"]["spec"]["fieldConfig"]["defaults"]["links"]
        self.assertEqual(parse_qs(urlsplit(links[0]["url"]).query)["dtab"], ["call-detail"])

    def test_users_index_requires_dated_tenant_scoped_upns(self):
        indexed = set()
        for panel in self.panels_by_tab()["Users"]:
            transforms = {t["group"]: t["spec"]["options"]
                          for t in panel["data"]["spec"]["transformations"]}
            if "groupBy" not in transforms:
                continue
            grouping = transforms["groupBy"]["fields"]
            upn = next(key for key in grouping if key.endswith("_user_principal_name"))
            self.assertEqual({k for k, v in grouping.items() if v["operation"] == "groupby"}, {"tenant_id", upn})
            self.assertEqual(grouping["Time"]["aggregations"], ["max"])
            targets = panel["data"]["spec"]["queries"]
            self.assertEqual(len(targets), 1)
            query = targets[0]["spec"]["query"]
            self.assertEqual(query["group"], "loki")
            self.assertEqual(query["spec"]["queryType"], "range")
            self.assertGreater(query["spec"]["maxLines"], 0)
            expr = query["spec"]["expr"]
            self.assertIn('tenant_id=~"$tenant"', expr)
            self.assertIn('| tenant_id!=``', expr)
            self.assertIn(f'| {upn}!=``', expr)
            self.assertIn('| start_time!=``', expr)
            self.assertNotIn('${user:percentencode}', expr)
            links = panel["vizConfig"]["spec"]["fieldConfig"]["overrides"]
            self.assertTrue(any(o["matcher"]["options"] == upn and
                                any(p["id"] == "links" for p in o["properties"]) for o in links))
            indexed.add(upn)
        self.assertEqual(indexed, {
            "caller_user_principal_name", "callee_user_principal_name", "organizer_user_principal_name",
        })

    def test_users_stream_search_displays_unknown_scope_without_guessing(self):
        queries = [q["spec"]["query"]["spec"]["expr"]
                   for panel in self.panels_by_tab()["Users"] for q in panel["data"]["spec"]["queries"]]
        selected = [expr for expr in queries if 'event_name=`teams.call_stream`' in expr
                    and '${user:percentencode}' in expr]
        self.assertEqual(len(selected), 1)
        expr = selected[0]
        keep = expr.rsplit(" | keep ", 1)[1].split(", ")
        for side in ("caller", "callee"):
            scope = f"{side}_identity_scope"
            self.assertIn(scope, keep)
            self.assertIn(f'{scope}=`{{{{ .{scope} | default "unknown" }}}}`', expr)
            self.assertNotIn(f"{side}_is_internal", expr)

    def test_query_boundaries_on_a_teams_only_stack(self):
        for tab, panels in self.panels_by_tab().items():
            for panel in panels:
                for target in panel["data"]["spec"]["queries"]:
                    query = target["spec"]["query"]
                    expr = query["spec"]["expr"]
                    with self.subTest(tab=tab, panel=panel["title"]):
                        if query["group"] == "prometheus":
                            self.assertEqual(query["datasource"]["name"], "${datasource}")
                            self.assertIn('tenant_id=~"$tenant"', expr)
                            self.assertNotIn("topk(", expr)
                            continue
                        self.assertEqual(query["group"], "loki")
                        self.assertEqual(query["datasource"]["name"], "${loki_datasource}")
                        # A metric query wraps the selector; the selector itself is the contract.
                        match = re.search(
                            r'(?:^|\()\{service_name="graph2otel"\} \| event_name=`([^`]+)` \| tenant_id=~"\$tenant"', expr)
                        self.assertIsNotNone(match, expr)
                        event = match[1]
                        self.assertTrue(event.startswith("teams.") or event in {
                            "m365.service_health_issue", "m365.teams.phone_number", "m365.teams.user_configuration",
                            "m365.teams.phone_inventory_snapshot"})
                        if event == "m365.teams.phone_inventory_snapshot":
                            self.assertEqual(tab, "Phone inventory")
                        if tab == "Service health":
                            self.assertEqual(event, "m365.service_health_issue")
                            self.assertIn('| service=`Microsoft Teams`', expr)
                            if panel["title"] == "Latest Teams issue observations in range":
                                self.assertIn('| is_resolved=~`true|false`', expr)
                            else:
                                self.assertRegex(expr, r'\| is_resolved=`(true|false)`')
                        if tab == "Calls":
                            self.assertIn('${site:percentencode}', expr)
                            if event == "teams.call":
                                self.assertIn('eq "${site:percentencode}" ""', expr)
                            else:
                                self.assertIn('.caller_site', expr)
                                self.assertIn('.callee_site', expr)
                        if tab == "Call detail":
                            self.assertIn('${call_id:percentencode}', expr)
                            self.assertIn('""}}' + '{{else}}', expr)  # blank never emits the pass label
                        else:
                            self.assertNotIn('${call_id:percentencode}', expr)

    def prom_exprs(self, tab):
        return [target["spec"]["query"]["spec"]["expr"]
                for panel in self.panels_by_tab()[tab]
                for target in panel["data"]["spec"]["queries"]
                if target["spec"]["query"]["group"] == "prometheus"]

    def test_call_quality_plots_each_stream_measure_as_quantiles_and_a_distribution(self):
        panels = self.panels_by_tab()["Call quality"]
        for name in ("teams_stream_jitter_seconds", "teams_stream_rtt_seconds", "teams_stream_packet_loss"):
            with self.subTest(metric=name):
                quantiles = {q for expr in self.prom_exprs("Call quality")
                             for q in re.findall(r"histogram_quantile\((0\.\d+), [^\n]*" + name + "_bucket", expr)}
                self.assertEqual(quantiles, {"0.5", "0.95"})
                heatmaps = [p for p in panels if p["vizConfig"]["group"] == "heatmap"
                            and any(name + "_bucket" in t["spec"]["query"]["spec"]["expr"]
                                    for t in p["data"]["spec"]["queries"])]
                self.assertEqual(len(heatmaps), 1, "one bucket distribution per measure")
                target = heatmaps[0]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]
                self.assertEqual(target["format"], "heatmap")
                self.assertIn("by (le)", target["expr"])

    def test_site_labelled_metrics_follow_the_site_variable(self):
        variables = {v["spec"]["name"]: v for v in self.manifest["spec"]["variables"]}
        sites = variables["sites"]
        self.assertEqual(sites["kind"], "QueryVariable")
        self.assertTrue(sites["spec"]["includeAll"] and sites["spec"]["multi"])
        self.assertEqual(sites["spec"]["allValue"], ".*")
        self.assertIn("teams_streams_total", sites["spec"]["query"]["spec"]["query"])
        self.assertIn('tenant_id=~"$tenant"', sites["spec"]["query"]["spec"]["query"])
        cat = catalog.load()
        sited = {m.prom for m in cat.metrics.values() if m.domain == "teams" and "site" in m.keys}
        self.assertGreaterEqual(len(sited), 5)
        pattern = re.compile(r"(" + "|".join(sorted(sited)) + r")(?:_bucket|_sum|_count)?\{([^}]*)\}")
        seen = 0
        for tab in self.panels_by_tab():
            for expr in self.prom_exprs(tab):
                for name, selector in pattern.findall(expr):
                    seen += 1
                    with self.subTest(tab=tab, metric=name):
                        self.assertIn('site=~"$sites"', selector)
        self.assertGreater(seen, 20)

    def test_data_panels_say_no_data_yet_instead_of_looking_broken(self):
        for tab, panels in self.panels_by_tab().items():
            for panel in panels:
                if panel["vizConfig"]["group"] == "text":
                    continue
                with self.subTest(tab=tab, panel=panel["title"]):
                    note = panel["vizConfig"]["spec"]["fieldConfig"]["defaults"]["noValue"]
                    self.assertTrue(note.startswith("No data yet."), note)
                    self.assertGreater(len(note), len("No data yet. "))

    def test_teams_counts_keep_the_first_value_of_a_new_counter_series(self):
        # Plain increase() drops the first sample of a series born in the window,
        # which on a sparse Teams counter is most of the data.
        counters = {m.prom for m in catalog.load().metrics.values()
                    if m.domain == "teams" and m.kind in ("sum", "histogram")}
        checked = 0
        for tab in self.panels_by_tab():
            for expr in self.prom_exprs(tab):
                for name in re.findall(r"\bincrease\(([a-z_]+)\{", expr):
                    base = re.sub(r"_(bucket|sum|count)$", "", name)
                    if base not in counters and name not in counters:
                        continue
                    checked += 1
                    with self.subTest(tab=tab, metric=name):
                        self.assertRegex(expr, r"unless " + name + r"\{[^}]*\} offset ")
                if tab != "Collector health":
                    with self.subTest(tab=tab, expr=expr[:80]):
                        self.assertNotRegex(expr, r"\brate\(teams_", "sparse Teams counters are counted, not rated")
        self.assertGreater(checked, 30)

    @unittest.skipUnless(shutil.which("promtool"), "needs promtool")
    def test_counter_increase_counts_a_series_born_inside_the_window(self):
        expr = f'round(sum by (k) ({counter_increase("m", "10m")}))'
        test = {
            "evaluation_interval": "1m",
            "tests": [{
                "interval": "1m",
                "input_series": [
                    {"series": 'm{k="born"}', "values": "_x10 1 1 2 2 2"},
                    {"series": 'm{k="single"}', "values": "_x14 3"},
                    {"series": 'm{k="old"}', "values": "5x9 6 6 7 7 7"},
                    {"series": 'm{k="reset"}', "values": "4x9 1 1 2 2 2"},
                ],
                "promql_expr_test": [{"expr": expr, "eval_time": "14m", "exp_samples": [
                    {"labels": '{k="born"}', "value": 2},
                    {"labels": '{k="single"}', "value": 3},
                    {"labels": '{k="old"}', "value": 2},
                    {"labels": '{k="reset"}', "value": 2},
                ]}],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counter_test.yaml"
            path.write_text(json.dumps(test))  # JSON is valid YAML
            run = subprocess.run(["promtool", "test", "rules", str(path)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_empty_notes_stay_readable(self):
        for tab, panels in self.panels_by_tab().items():
            for panel in panels:
                group = panel["vizConfig"]["group"]
                field_config = panel["vizConfig"]["spec"].get("fieldConfig", {})
                with self.subTest(tab=tab, panel=panel["title"]):
                    if group == "stat":
                        # A long sentence shrinks to illegible text in a stat.
                        self.assertEqual(field_config["defaults"]["noValue"], teams.STAT_NO_VALUE)
                        self.assertIn("If it is empty:", panel["description"])
                    loki = any(q["spec"]["query"]["group"] == "loki" for q in panel["data"]["spec"]["queries"])
                    if group == "table" and loki and not any(
                            t["group"] == "reduce" for t in panel["data"]["spec"]["transformations"]):
                        # A missing attribute is a blank cell, not the empty-panel note.
                        blank = {o["matcher"]["options"] for o in field_config["overrides"]
                                 if o["matcher"]["id"] == "byType"
                                 and {"id": "noValue", "value": ""} in o["properties"]}
                        self.assertEqual(blank, {"string", "number"})

    def test_prometheus_tables_are_one_frame(self):
        graph = json.loads((DASHBOARDS / "graph2otel.json").read_text())
        seen = 0
        for manifest in (self.manifest, graph):
            for element in manifest["spec"]["elements"].values():
                panel = element["spec"]
                if panel["vizConfig"]["group"] != "table":
                    continue
                for target in panel["data"]["spec"]["queries"]:
                    query = target["spec"]["query"]
                    if query["group"] != "prometheus":
                        continue
                    seen += 1
                    with self.subTest(panel=panel["title"]):
                        # Without format=table each series is a frame behind a picker.
                        self.assertEqual(query["spec"].get("format"), "table")
                        self.assertTrue(query["spec"]["instant"])
        self.assertGreater(seen, 20)

    def test_coverage_fails_if_a_real_team_metric_has_no_placed_team_panel(self):
        cat = catalog.load()
        for name in ("teams.call.health_transitions", "m365.teams.phone_numbers.unassigned",
                     "m365.teams_usage.activity.users", "m365.service_health.status"):
            with self.subTest(metric=name):
                self.assert_coverage_catches_missing(cat, name)
        self.assertEqual(teams.coverage_violations(cat, self.manifest), [])

    def assert_coverage_catches_missing(self, cat, name):
        panel_names = {key for key, p in self.manifest["spec"]["elements"].items()
                       if any(name in cat.metrics_referenced_by(t["spec"]["query"]["spec"]["expr"])
                              for t in p["spec"]["data"]["spec"]["queries"])}
        self.assertTrue(panel_names, name)
        mutated = json.loads(json.dumps(self.manifest))
        for tab in mutated["spec"]["layout"]["spec"]["tabs"]:
            for row in tab["spec"]["layout"]["spec"]["rows"]:
                items = row["spec"]["layout"]["spec"]["items"]
                items[:] = [item for item in items if item["spec"]["element"]["name"] not in panel_names]
        self.assertIn(f"Teams dashboard is missing metric {name}", teams.coverage_violations(cat, mutated))
