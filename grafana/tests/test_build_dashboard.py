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
import build_rules  # noqa: E402
import catalog as catalog_mod  # noqa: E402
from builder import Builder, TENANT_SEL, dumps, group_keys  # noqa: E402
from promname import prom_name  # noqa: E402

CAT = catalog_mod.load()
SELF_OBS = {
    name: metric for name, metric in CAT.metrics.items()
    if metric.domain == catalog_mod.SELF_OBS_DOMAIN
}
BUILT, COVERED, LOG_DOMAINS = build_dashboard.build_all(CAT)
WAIVERS = build_dashboard.load_waivers()


class TestPromName(unittest.TestCase):
    def test_reproduces_every_cataloged_prometheus_name(self):
        """Pins the independent Python derivation to the Go rule over real metrics."""
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


class TestSelfObservabilityScopeGate(unittest.TestCase):
    def setUp(self):
        self.board = next(b for name, b in BUILT
                          if name == "graph2otel-self-observability.json")

    def test_every_generated_self_observability_metric_has_an_explicit_scope(self):
        self.assertEqual(
            {m.scope for m in SELF_OBS.values()},
            {catalog_mod.TENANT_SCOPE, catalog_mod.PROCESS_SCOPE},
        )

    def test_every_referenced_selfobs_metric_uses_its_declared_scope(self):
        """#284: a tenant selector on a process metric is an empty panel.

        Conversely, omitting it from a tenant metric blends tenants. The
        generated scope and the query must move together, so adding a new
        metric cannot silently pick whichever convention the author happened
        to copy.
        """
        referenced = set()
        for expr in self.board._exprs:
            for name in CAT.metrics_referenced_by(expr):
                metric = SELF_OBS.get(name)
                if metric is None:
                    continue
                referenced.add(metric.name)
                if metric.scope == catalog_mod.TENANT_SCOPE:
                    self.assertIn(TENANT_SEL, expr, f"{metric.name}: {expr}")
                else:
                    self.assertNotIn(TENANT_SEL, expr, f"{metric.name}: {expr}")
        self.assertEqual(referenced, set(SELF_OBS),
                         "generated self-observability metrics missing a panel")

    def test_process_total_is_declared_and_panelled_without_tenant_filter(self):
        metric = SELF_OBS["graph2otel.series.total"]
        self.assertEqual(metric.scope, catalog_mod.PROCESS_SCOPE)
        exprs = [
            expr for expr in self.board._exprs
            if metric.name in CAT.metrics_referenced_by(expr)
        ]
        self.assertEqual(len(exprs), 1)
        self.assertNotIn(TENANT_SEL, exprs[0])


class TestOutcomeAccountingPanels(unittest.TestCase):
    def setUp(self):
        board = next(b for name, b in BUILT
                     if name == "graph2otel-self-observability.json")
        self.panels = {
            item["spec"]["title"]: item["spec"]
            for item in board._panels
            if item.get("spec")
        }

    def test_record_outcomes_do_not_stack_overlapping_lifecycle_stages(self):
        panel = self.panels["Source-record rate by outcome"]
        self.assertNotIn(
            "stacking", panel["fieldConfig"]["defaults"]["custom"],
        )
        expr = panel["targets"][0]["expr"]
        self.assertIn("graph2otel_record_outcomes_total", expr)
        self.assertIn("outcome", expr)
        self.assertIn("ingest_transport", expr)

    def test_outcome_panels_preserve_tenant_identity(self):
        expected_groupings = {
            "Collector runs by reconciled result":
                "sum by (tenant_id, collector, ingest_transport, result)",
            "Source-record rate by outcome":
                "sum by (tenant_id, collector, ingest_transport, outcome)",
            "Dropped / errored source records":
                "sum by (tenant_id, collector, ingest_transport, outcome)",
            "Payload type mismatches":
                "sum by (tenant_id, collector, ingest_transport, field, "
                "expected_type, actual_type)",
        }
        for title, grouping in expected_groupings.items():
            with self.subTest(panel=title):
                panel = self.panels[title]
                self.assertIn(grouping, panel["targets"][0]["expr"])

    def test_event_lag_has_p50_and_p95_queries(self):
        panel = self.panels["Source-event lag at emission"]
        exprs = [target["expr"] for target in panel["targets"]]
        self.assertEqual(len(exprs), 2)
        self.assertTrue(any("histogram_quantile(0.50" in expr for expr in exprs))
        self.assertTrue(any("histogram_quantile(0.95" in expr for expr in exprs))
        self.assertTrue(all("graph2otel_event_lag_seconds_bucket" in expr for expr in exprs))
        self.assertTrue(all(
            "sum by (le, tenant_id, collector, ingest_transport)" in expr
            for expr in exprs
        ))
        self.assertTrue(all(
            "{{tenant_id}}" in target["legendFormat"]
            for target in panel["targets"]
        ))

    def test_loss_and_payload_drift_are_visible(self):
        self.assertIn("Dropped / errored source records", self.panels)
        self.assertIn("Payload type mismatches", self.panels)


class TestOTLPDeliveryPanels(unittest.TestCase):
    METRICS = {
        "graph2otel.otlp.delivery.degraded",
        "graph2otel.otlp.delivery.export_attempts",
        "graph2otel.otlp.delivery.export_successes",
        "graph2otel.otlp.delivery.export_failures",
        "graph2otel.otlp.delivery.force_flush_failures",
        "graph2otel.otlp.delivery.shutdown_failures",
    }

    def setUp(self):
        self.board = next(b for name, b in BUILT
                          if name == "graph2otel-self-observability.json")
        self.panels = {
            item["spec"]["title"]: item["spec"]
            for item in self.board._panels
            if item.get("spec")
        }

    def test_all_six_delivery_metrics_are_process_wide_and_panelled(self):
        referenced = set()
        for expr in self.board._exprs:
            names = CAT.metrics_referenced_by(expr) & self.METRICS
            if not names:
                continue
            referenced.update(names)
            self.assertNotIn(TENANT_SEL, expr)
            self.assertNotIn("$tenant", expr)
            self.assertNotIn("tenant_id", expr)
            self.assertNotIn("$collector", expr)
            self.assertNotIn("collector", expr)
        self.assertEqual(referenced, self.METRICS)
        self.assertTrue(all(
            SELF_OBS[name].scope == catalog_mod.PROCESS_SCOPE
            for name in self.METRICS
        ))

    def test_export_callback_rates_are_split_by_signal_and_unstacked(self):
        panel = self.panels["Exporter callback rates by signal"]
        exprs = [target["expr"] for target in panel["targets"]]
        self.assertEqual(len(exprs), 3)
        self.assertTrue(all(expr.startswith("sum by (signal) (rate(") for expr in exprs))
        self.assertEqual(
            {
                name
                for expr in exprs
                for name in CAT.metrics_referenced_by(expr)
            },
            {
                "graph2otel.otlp.delivery.export_attempts",
                "graph2otel.otlp.delivery.export_successes",
                "graph2otel.otlp.delivery.export_failures",
            },
        )
        self.assertNotIn("stacking", panel["fieldConfig"]["defaults"]["custom"])

    def test_flush_and_shutdown_failures_preserve_signal_identity(self):
        for title, metric_name in {
            "Force-flush failure rate by signal":
                "graph2otel.otlp.delivery.force_flush_failures",
            "Shutdown failure total by signal":
                "graph2otel.otlp.delivery.shutdown_failures",
        }.items():
            with self.subTest(panel=title):
                expr = self.panels[title]["targets"][0]["expr"]
                self.assertEqual(
                    CAT.metrics_referenced_by(expr),
                    {metric_name},
                )
                self.assertIn("by (signal)", expr)

    def test_no_delivery_alert_or_recording_rule_is_added(self):
        rendered = json.dumps({
            "alerts": build_rules.RULES,
            "recording": build_rules.RECORDING,
        })
        self.assertNotIn("graph2otel_otlp_delivery_", rendered)

    def test_docs_define_the_callback_boundary_and_local_fallbacks(self):
        path = os.path.join(os.path.dirname(GRAFANA), "docs", "signals.md")
        with open(path) as f:
            docs = re.sub(r"\s+", " ", f.read().lower().replace("**", ""))
        for phrase in [
            "exporter accepted",
            "not exactly-once",
            "not backend retention",
            "local writer",
            "admin status",
            "structured logs",
        ]:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, docs)


class TestCollectorAvailabilityPanels(unittest.TestCase):
    def setUp(self):
        board = next(b for name, b in BUILT
                     if name == "graph2otel-self-observability.json")
        self.board = board
        self.panels = {
            item["spec"]["title"]: item["spec"]
            for item in board._panels
            if item.get("spec")
        }
        self.availability = SELF_OBS["graph2otel.collector.availability"].prom

    def test_availability_backs_tenant_and_collector_variables(self):
        self.assertEqual(self.board.tenant_metric, self.availability)
        collector = next(v for v in self.board.variables() if v["name"] == "collector")
        self.assertEqual(
            collector["definition"],
            f'label_values({self.availability}{{tenant_id=~"$tenant"}}, collector)',
        )

    def test_current_state_table_preserves_every_availability_dimension(self):
        panel = self.panels["Current collector availability"]
        self.assertEqual(panel["type"], "table")
        self.assertEqual(
            panel["targets"][0]["expr"],
            f'max by (tenant_id, collector, collector_transport, state, reason) '
            f'({self.availability}{{tenant_id=~"$tenant",collector=~"$collector"}})',
        )

    def test_availability_state_counts_and_state_classes_are_visible(self):
        self.assertIn("Collector availability by state", self.panels)
        self.assertIn("Intentional collector absence", self.panels)
        self.assertIn("Collector availability failures", self.panels)
        self.assertIn("Subscription and capability limitations", self.panels)
        self.assertIn("non-failure", self.panels["Subscription and capability limitations"]["description"])

    def test_subscription_limitations_are_not_reported_as_failures(self):
        limitations = self.panels["Subscription and capability limitations"]
        limitation_exprs = [target["expr"] for target in limitations["targets"]]
        self.assertEqual(len(limitation_exprs), 2)
        self.assertIn('state="limited", reason="partial_license"', limitation_exprs[0])
        self.assertIn('state="blocked", reason="license_unavailable"', limitation_exprs[1])

        failures = self.panels["Collector availability failures"]
        failure_exprs = [target["expr"] for target in failures["targets"]]
        self.assertEqual(len(failure_exprs), 2)
        self.assertIn('state=~"degraded|failed|startup_failed"', failure_exprs[0])
        self.assertIn('state="blocked", reason="permission_denied"', failure_exprs[1])
        self.assertTrue(all('state=~"blocked|' not in expr for expr in failure_exprs))

    def test_availability_never_uses_record_ingest_transport_or_an_alert(self):
        availability_exprs = [
            expr for expr in self.board._exprs
            if self.availability in expr
        ]
        self.assertTrue(availability_exprs)
        self.assertTrue(all("ingest_transport" not in expr for expr in availability_exprs))
        for panel in self.panels.values():
            self.assertNotIn("alert", panel)


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
    def test_every_tenant_dropdown_metric_resolves_to_the_catalog(self):
        known = {metric.prom: metric for metric in CAT.metrics.values()}
        for out_name, board in BUILT:
            self.assertIn(
                board.tenant_metric,
                known,
                f"{out_name} tenant dropdown queries an uncataloged metric",
            )
            self.assertEqual(
                known[board.tenant_metric].scope,
                catalog_mod.TENANT_SCOPE,
                f"{out_name} tenant dropdown queries a process-scoped metric",
            )

    def test_process_metric_cannot_back_a_tenant_dropdown(self):
        metric = SELF_OBS["graph2otel.build_info"]
        with self.assertRaisesRegex(ValueError, "process-scoped"):
            Builder("test", "test", "", [], metric.prom, CAT)

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
