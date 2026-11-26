"""The query and numeric display contracts of the Teams voice-app tab."""

import unittest

import v2
import build_dashboard


class TeamsVoiceAppsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = build_dashboard.load_teams()
        spec = manifest["spec"]
        tab = next(t for t in spec["layout"]["spec"]["tabs"] if t["spec"]["title"] == "Auto attendant and call queue")
        cls.panels = {panel["title"]: panel for panel in (
            spec["elements"][name]["spec"] for name in v2.placed_element_names({
                "spec": {"layout": {"spec": {"tabs": [tab]}}},
            })
        )}

    def query(self, title):
        return self.panels[title]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]

    def test_queue_outcomes_use_one_saved_batch_row_with_fraction_units(self):
        title = "Call queue outcomes by saved batch"
        panel = self.panels[title]
        self.assertEqual(len(panel["data"]["spec"]["queries"]), 1)
        expr = self.query(title)["expr"]
        self.assertIn('event_name=`teams.call_queue_batch`', expr)
        self.assertIn('keep tenant_id, queue, known_result_legs, answered_legs, abandoned_legs, answer_share, abandon_share',
                      expr)
        overrides = panel["vizConfig"]["spec"]["fieldConfig"]["overrides"]
        for share in ("answer_share", "abandon_share"):
            self.assertIn({"id": "unit", "value": "percentunit"}, next(
                override["properties"] for override in overrides if override["matcher"]["options"] == share))

    def test_admitted_wait_count_uses_the_quantiles_histogram_and_interval(self):
        count = self.query("Admitted queue wait observations")
        count_expr = count["expr"]
        self.assertIn("teams_call_queue_wait_time_seconds_count", count_expr)
        self.assertIn("sum by (tenant_id, queue)", count_expr)
        for q in ("p50", "p95"):
            quantile = self.query(f"Call queue wait time {q}")
            self.assertEqual(count["interval"], quantile["interval"])
            self.assertIn("[$__interval]", count_expr)
            self.assertIn("[$__interval]", quantile["expr"])
            self.assertIn("teams_call_queue_wait_time_seconds_bucket", quantile["expr"])

    def test_queue_summary_counts_keys_not_rows_and_unkeyed_rows_stay_visible(self):
        obs = self.query("Call queue observations in range")
        distinct = self.query("Distinct keyed queue legs in range")
        self.assertEqual(obs["queryType"], "instant")
        self.assertEqual(distinct["queryType"], "instant")
        self.assertIn("sum by (tenant_id) (count_over_time(", obs["expr"])
        self.assertNotIn("| queue!=``", obs["expr"])
        self.assertNotIn("| dialog_id!=``", obs["expr"])
        self.assertIn("count by (tenant_id, queue) (sum by (tenant_id, queue, dialog_id)", distinct["expr"])
        for key in ("queue", "dialog_id"):
            self.assertIn(f"| {key}!=``", distinct["expr"])
        self.assertIn("[$__range]", obs["expr"])
        self.assertIn("[$__range]", distinct["expr"])
        unkeyed = self.query("Unkeyed call queue observations")["expr"]
        self.assertIn("| queue=`` or dialog_id=``", unkeyed)
        self.assertIn("dialog_id", self.query("Keyed call queue observations")["expr"])
