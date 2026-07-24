"""Structural tests for the dashboard builder and its gates.

Standard-library ``unittest`` only, matching the repo's no-third-party-assertion
rule on the Go side. Run from grafana/:

    python3 -m unittest discover -s tests -t .

``make grafana-check`` runs them, so CI does too.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import catalog as catalog_mod  # noqa: E402
from builder import dumps, group_keys  # noqa: E402
from promname import prom_name  # noqa: E402

CAT = catalog_mod.load()
BUILT, COVERED, LOG_DOMAINS = build_dashboard.build_all(CAT)
WAIVERS = build_dashboard.load_waivers()


class TestPromName(unittest.TestCase):
    def test_reproduces_every_cataloged_prometheus_name(self):
        """Pins the Python derivation to the Go one over all 274 real metrics.

        The two exist because the catalog cannot see self-observability metrics
        emitted outside a collector package, so the board there derives its own
        names. This is what stops the two rules drifting apart silently.
        """
        for m in CAT.metrics.values():
            self.assertEqual(prom_name(m.name, m.unit, m.kind), m.prom, m.name)

    def test_annotation_units_add_no_suffix(self):
        self.assertEqual(prom_name("a.b", "{device}", "gauge"), "a_b")

    def test_dimensionless_gauge_gains_ratio_but_a_counter_gains_total(self):
        self.assertEqual(prom_name("a.b", "1", "gauge"), "a_b_ratio")
        self.assertEqual(prom_name("a.b", "1", "sum"), "a_b_total")

    def test_a_unit_word_already_in_the_name_is_not_appended_twice(self):
        self.assertEqual(prom_name("a.age_seconds", "s", "gauge"), "a_age_seconds")
        self.assertEqual(prom_name("a.days_until_expiry", "d", "gauge"),
                         "a_days_until_expiry")


class TestCoverageGate(unittest.TestCase):
    def test_every_cataloged_metric_is_panelled_or_waived(self):
        missing, stale, reasonless = build_dashboard.coverage(CAT, COVERED, WAIVERS)
        self.assertEqual(missing, [], "unpanelled catalog metrics")
        self.assertEqual(stale, [], "waivers for metrics that no longer exist")
        self.assertEqual(reasonless, [], "waivers with no reason")

    def test_an_unpanelled_metric_is_reported(self):
        """The gate must actually fail — a gate nobody has seen fail is a hope."""
        missing, _, _ = build_dashboard.coverage(
            CAT, COVERED - {"intune.devices.count"}, {})
        self.assertIn("intune.devices.count", missing)

    def test_a_waiver_excuses_an_unpanelled_metric(self):
        missing, _, _ = build_dashboard.coverage(
            CAT, COVERED - {"intune.devices.count"},
            {"intune.devices.count": "deliberately unpanelled for this test"})
        self.assertNotIn("intune.devices.count", missing)

    def test_a_waiver_for_a_metric_that_no_longer_exists_fails(self):
        _, stale, _ = build_dashboard.coverage(CAT, COVERED, {"gone.metric": "why"})
        self.assertEqual(stale, ["gone.metric"])

    def test_a_waiver_with_no_reason_fails(self):
        _, _, reasonless = build_dashboard.coverage(
            CAT, COVERED, {"intune.devices.count": "   "})
        self.assertEqual(reasonless, ["intune.devices.count"])

    def test_coverage_is_right_boundary_anchored(self):
        """A longer name must not credit a shorter one that prefixes it."""
        self.assertEqual(
            CAT.metrics_referenced_by("sum(intune_devices_overview_total{})"),
            {"intune.devices.overview.total"})

    def test_a_histogram_is_credited_through_its_bucket_series(self):
        self.assertIn(
            "intune.uxa.boot_time_ms",
            CAT.metrics_referenced_by("rate(intune_uxa_boot_time_ms_milliseconds_bucket{}[5m])"))


class TestLogPanels(unittest.TestCase):
    def test_every_domain_with_a_log_signal_has_a_log_panel(self):
        self.assertEqual(build_dashboard.log_coverage(CAT, LOG_DOMAINS), [])

    def test_no_stream_selector_on_an_attribute(self):
        """#90: {event_name="…"} matches zero rows, silently. Never ship one."""
        selector = re.compile(r"\{([^}]*)\}")
        for name, b in BUILT:
            for expr in b._loki_exprs:
                for inner in selector.findall(expr):
                    labels = re.findall(r"([a-z_][a-z0-9_]*)\s*[=!~]", inner)
                    self.assertEqual(
                        set(labels), {"service_name"},
                        f"{name}: LogQL stream selector on a non-stream label: {expr}")

    def test_logql_never_reaches_the_metric_coverage_corpus(self):
        """The two corpora must stay disjoint.

        If a LogQL string reached ``_exprs`` a metric name inside a log filter
        would credit a metric that has no metric panel at all — the coverage
        gate would then report coverage it does not have.
        """
        for name, b in BUILT:
            for expr in b._exprs:
                self.assertNotIn("service_name=", expr,
                                 f"{name}: LogQL leaked into the PromQL corpus: {expr}")
            self.assertEqual(set(b._exprs) & set(b._loki_exprs), set(), name)

    def test_a_board_declaring_log_panels_gets_a_loki_datasource_variable(self):
        for name, b in BUILT:
            if not b._loki_exprs:
                continue
            names = {v["name"] for v in b.variables()}
            self.assertIn("loki_datasource", names, name)

    def test_log_panels_declare_a_loki_datasource_and_degrade_honestly(self):
        for name, b in BUILT:
            for item in b._panels:
                spec = item.get("spec")
                if not spec or spec.get("datasource", {}).get("type") != "loki":
                    continue
                self.assertIn("Loki", spec.get("description", ""), f"{name}: {spec['title']}")
                self.assertIn("noValue", spec["fieldConfig"]["defaults"],
                              f"{name}: {spec['title']} shows 'No data' instead of an "
                              f"explanation when Loki is unset")


class TestStructure(unittest.TestCase):
    def test_panel_ids_are_unique_within_a_dashboard(self):
        for name, b in BUILT:
            ids = [p["id"] for p in b.render()["panels"]]
            self.assertEqual(len(ids), len(set(ids)), name)

    def test_panels_fit_the_24_column_grid(self):
        for name, b in BUILT:
            for p in b.render()["panels"]:
                g = p["gridPos"]
                self.assertLessEqual(g["x"] + g["w"], 24, f"{name}: {p.get('title')}")

    def test_dashboard_uids_are_unique(self):
        uids = [b.uid for _, b in BUILT]
        self.assertEqual(len(uids), len(set(uids)))

    def test_output_is_deterministic(self):
        again, _, _ = build_dashboard.build_all(CAT)
        for (n1, b1), (n2, b2) in zip(BUILT, again):
            self.assertEqual(n1, n2)
            self.assertEqual(dumps(b1.render()), dumps(b2.render()), n1)

    def test_committed_dashboards_are_not_stale(self):
        for out_name, b in BUILT:
            path = os.path.join(build_dashboard.OUT_DIR, out_name)
            with open(path) as f:
                self.assertEqual(f.read(), dumps(b.render()),
                                 f"{out_name} is stale — run `make dashboard`")

    def test_every_generated_file_is_valid_grafana_json(self):
        for out_name, _ in BUILT:
            with open(os.path.join(build_dashboard.OUT_DIR, out_name)) as f:
                d = json.load(f)
            self.assertTrue(d["uid"] and d["title"] and d["panels"])
            self.assertEqual(d["schemaVersion"], 39)

    def test_no_orphan_dashboard_files(self):
        """A renamed board must not leave its old JSON behind, unowned and stale."""
        expected = {out for _, out in build_dashboard.BOARDS}
        present = {f for f in os.listdir(build_dashboard.OUT_DIR) if f.endswith(".json")}
        self.assertEqual(present, expected)

    def test_group_keys_drops_an_id_that_has_a_name_twin(self):
        self.assertEqual(group_keys(["policy_id", "policy_name", "state"]),
                         ["policy_name", "state"])
        self.assertEqual(group_keys(["policy_id", "state"]), ["policy_id", "state"])


if __name__ == "__main__":
    unittest.main()
