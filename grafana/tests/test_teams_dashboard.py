"""Contracts on the separate generated Teams dashboard."""

import json
from pathlib import Path
import re
import unittest
from urllib.parse import parse_qs, quote, urlsplit

import catalog
import v2
from boards import teams


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
            "Home", "Sites", "Calls", "Call detail", "Users", "PSTN / Direct Routing",
            "Issues", "Health", "Best practices",
        ])
        for tab in tabs:
            self.assertNotIn("conditionalRendering", tab["spec"])
        graph = json.loads((DASHBOARDS / "graph2otel.json").read_text())
        self.assertEqual(graph["metadata"]["name"], "graph2otel")

    def test_site_and_call_links_keep_the_row_tenant_and_time(self):
        tabs = self.panels_by_tab()
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
                            target = next(tab for tab in tabs if v2.slug(tab) == query["dtab"][0])
                            variable = "call_id" if field == "call_id" else "site"
                            self.assertEqual(query[f"var-{variable}"], ["Sample / `?&=Site"])
                            self.assertEqual(query["var-tenant"], ["example-tenant"])
                            self.assertEqual(query["from"] + query["to"], ["100", "200"])
                            self.assertEqual(query["var-datasource"], ["example-prom"])
                            self.assertEqual(query["var-loki_datasource"], ["example-logs"])
                            routes.add((source, target, variable))
        self.assertEqual(routes, {
            ("Sites", "Calls", "site"), ("Calls", "Call detail", "call_id"),
            ("Users", "Call detail", "call_id"),
        })

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
                        match = re.match(
                            r'^\{service_name="graph2otel"\} \| event_name=`([^`]+)` \| tenant_id=~"\$tenant"', expr)
                        self.assertIsNotNone(match, expr)
                        event = match[1]
                        self.assertTrue(event.startswith("teams.") or event == "m365.service_health_issue")
                        if tab == "Issues":
                            self.assertEqual(event, "m365.service_health_issue")
                            self.assertIn('| service=`Microsoft Teams`', expr)
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

    def test_coverage_fails_if_a_real_team_metric_has_no_placed_team_panel(self):
        cat = catalog.load()
        name = "teams.call.health_transitions"
        panel_name = next(key for key, p in self.manifest["spec"]["elements"].items()
                          if any(name in cat.metrics_referenced_by(t["spec"]["query"]["spec"]["expr"])
                                 for t in p["spec"]["data"]["spec"]["queries"]))
        mutated = json.loads(json.dumps(self.manifest))
        for tab in mutated["spec"]["layout"]["spec"]["tabs"]:
            for row in tab["spec"]["layout"]["spec"]["rows"]:
                items = row["spec"]["layout"]["spec"]["items"]
                items[:] = [item for item in items if item["spec"]["element"]["name"] != panel_name]
        self.assertIn(f"Teams dashboard is missing metric {name}", teams.coverage_violations(cat, mutated))
