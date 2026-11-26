"""Usage panels keep report freshness and concealment separate from usage counts."""

import unittest

import build_dashboard


class TeamsUsageDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = build_dashboard.load_teams()
        spec = manifest["spec"]
        tab = next(t for t in spec["layout"]["spec"]["tabs"] if t["spec"]["title"] == "Usage")
        items = tab["spec"]["layout"]["spec"]["rows"][0]["spec"]["layout"]["spec"]["items"]
        cls.placed = [(item["spec"], spec["elements"][item["spec"]["element"]["name"]]["spec"])
                      for item in items]

    @staticmethod
    def queries(panel):
        return [q["spec"]["query"]["spec"] for q in panel["data"]["spec"]["queries"]]

    def test_each_plot_has_its_own_source_refresh_date(self):
        for period, metric in ((7, "teams_device_usage_users"), (30, "m365_teams_usage_activity_users")):
            with self.subTest(period=period):
                plot = next(item for item, panel in self.placed if any(
                    metric + "{" in q["expr"] for q in self.queries(panel)))
                matches = [(item, panel) for item, panel in self.placed if any(
                    "m365_teams_usage_report_refresh_timestamp_seconds{" in q["expr"]
                    and f'report_period="{period}"' in q["expr"] for q in self.queries(panel))]
                self.assertEqual(len(matches), 1, "each usage plot needs its own refresh-date panel")
                item, panel = matches[0]
                self.assertEqual(item["y"], plot["y"])
                self.assertGreater(item["x"], plot["x"])
                self.assertEqual(panel["vizConfig"]["group"], "stat")
                query, = self.queries(panel)
                self.assertTrue(query["instant"] and not query["range"])
                self.assertIn('tenant_id=~"$tenant"', query["expr"])

    def test_concealment_is_neither_a_count_nor_a_false_default(self):
        panel = next(panel for _, panel in self.placed
                     if any("m365_teams_usage_names_concealed_ratio{" in q["expr"] for q in self.queries(panel)))
        self.assertEqual(panel["vizConfig"]["spec"]["options"]["textMode"], "name")
        by_state = {q["legendFormat"].split(" · ")[-1]: q for q in self.queries(panel)}
        self.assertEqual(set(by_state), {"On", "Off", "Unknown"})
        for state, value in (("On", 1), ("Off", 0)):
            self.assertTrue(by_state[state]["expr"].endswith(f"== {value}"))
        unknown = by_state["Unknown"]["expr"]
        self.assertIn("unless on (tenant_id)", unknown)
        self.assertIn('collector="m365.teams_usage"', unknown)
        self.assertTrue(all(q["instant"] and not q["range"] for q in by_state.values()))
