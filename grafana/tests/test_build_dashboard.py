"""Structural tests for the dashboard builder and its gates.

Standard-library ``unittest`` only, matching the repo's no-third-party-assertion
rule on the Go side. Run from grafana/:

    python3 -m unittest discover -s tests -t .

``make grafana-check`` runs them, so CI does too.

# The v2 single-dashboard shape (#399)

graph2otel moved from six Grafana v1 dashboards (one per domain, each its own
``Builder``) to ONE v2 "dynamic dashboard": one shared ``Builder`` accumulates
every domain's panels, ``build_dashboard.build_all`` returns
``(builder, domain_tabs, log_domains)``, and ``domain_tabs`` become nested
``TabsLayout`` tabs — Entra, Intune, Defender, M365, Purview, Self-obs — under
one ``TabsLayout`` root alongside the unconditional Overview tab.

Per-board access (``next(b for name, b in BUILT if name == "...")``) no longer
exists: there is one ``BUILDER`` and one assembled ``MANIFEST``. The helpers
below (``_domain_panel_ids`` / ``_domain_panels`` / ``_domain_prom_exprs`` /
``_domain_loki_exprs``) recover the old "this domain's panels/queries" scoping
by walking the v2 layout for one domain tab's placed elements and mapping them
back to the pre-translation v1 panel spec kept in ``PANEL_BY_ID`` — the shape
every assertion below still wants to inspect (``panel["targets"][0]["expr"]``,
``panel["fieldConfig"]``, etc.), since the v1 shape remains the generator's
internal intermediate representation (see ``v2.py``'s module docstring, #399
C3) and only the final translation step changes it.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import build_rules  # noqa: E402
import builder as builder_mod  # noqa: E402
import catalog as catalog_mod  # noqa: E402
import v2  # noqa: E402
from boards import common  # noqa: E402
from builder import (  # noqa: E402
    AVAILABILITY_REASONS,
    AVAILABILITY_STATES,
    Builder,
    DASHBOARD_NAME,
    LOKI_DATASOURCE_DEFAULT,
    LOKI_DATASOURCE_EXCLUDE_REGEX,
    PROM_DATASOURCE_DEFAULT,
    PROM_DATASOURCE_EXCLUDE_REGEX,
    TENANT_SEL,
    dumps,
    group_keys,
)
from promname import prom_name  # noqa: E402

CAT = catalog_mod.load()
SELF_OBS = {
    name: metric for name, metric in CAT.metrics.items()
    if metric.domain == catalog_mod.SELF_OBS_DOMAIN
}

# Assembled exactly the way build_dashboard.main() assembles it: build the
# estate, add the unconditional Overview tab, then render the one manifest.
BUILDER, DOMAIN_TABS, LOG_DOMAINS = build_dashboard.build_all(CAT)
COVERED = BUILDER._covered
WAIVERS = build_dashboard.load_waivers()
OVERVIEW_LEAF = build_dashboard.overview(BUILDER)
MANIFEST = BUILDER.render([OVERVIEW_LEAF, *DOMAIN_TABS])

# Every non-row panel's pre-translation v1 spec, by its numeric id — ids are
# unique across the whole estate (one shared Builder), so this is a safe map.
PANEL_BY_ID = {
    item["spec"]["id"]: item["spec"]
    for item in BUILDER._panels
    if not item.get("row")
}
DOMAIN_TAB_BY_TITLE = {tab["spec"]["title"]: tab for tab in DOMAIN_TABS}


def _domain_panel_ids(tab: dict) -> set:
    """Every panel id actually placed under one domain tab's layout.

    Wraps the one tab in a throwaway single-tab manifest shell so
    ``v2.placed_element_names`` — the same walk the real coverage gate uses —
    can be reused here instead of a second hand-rolled layout walk.
    """
    shell = {"spec": {"layout": {"kind": "TabsLayout", "spec": {"tabs": [tab]}}}}
    return {int(name.removeprefix("panel-"))
            for name in v2.placed_element_names(shell)}


def _domain_panel_list(tab: dict) -> list:
    """Every placed panel's v1 spec under one domain tab, id order.

    A list, not a dict-by-title: some assertions below need to count how many
    panels share a title (a real duplicate would be a bug), and a dict would
    silently collapse duplicates and hide exactly that bug.
    """
    return [PANEL_BY_ID[i] for i in sorted(_domain_panel_ids(tab)) if i in PANEL_BY_ID]


def _domain_panels(tab: dict) -> dict:
    """One domain's panels keyed by title, for the (already-unique) direct
    ``panels["Some Title"]`` lookups most assertions want."""
    return {panel["title"]: panel for panel in _domain_panel_list(tab)}


def _domain_prom_exprs(tab: dict) -> list:
    """Every PromQL expression among one domain's placed panels.

    Mirrors the old per-board ``Builder._exprs`` (Prometheus-only, never
    LogQL) now that all domains share one builder and one ``_exprs`` list.
    """
    return [
        target["expr"]
        for panel in _domain_panel_list(tab)
        for target in panel.get("targets", [])
        if target.get("datasource", {}).get("type") == "prometheus"
    ]


def _domain_loki_exprs(tab: dict) -> list:
    """Every LogQL expression among one domain's placed panels."""
    return [
        target["expr"]
        for panel in _domain_panel_list(tab)
        for target in panel.get("targets", [])
        if target.get("datasource", {}).get("type") == "loki"
    ]


def _all_grid_items(tabs: list):
    """Every ``GridLayoutItem`` anywhere under a list of tabs, depth-first.

    A tab's layout is either a nested ``TabsLayout`` (a domain tab holding
    leaves) or a ``RowsLayout`` (a leaf tab holding rows of a grid) — this
    walks either shape down to the grid items themselves.
    """
    for tab in tabs:
        layout = tab["spec"].get("layout", {})
        if layout.get("kind") == "TabsLayout":
            yield from _all_grid_items(layout["spec"]["tabs"])
        elif layout.get("kind") == "RowsLayout":
            for row in layout["spec"]["rows"]:
                grid = row["spec"].get("layout", {})
                if grid.get("kind") == "GridLayout":
                    yield from grid["spec"]["items"]


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
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]

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
        for expr in _domain_prom_exprs(self.tab):
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
        exprs = [
            expr for expr in _domain_prom_exprs(self.tab)
            if metric.name in CAT.metrics_referenced_by(expr)
        ]
        self.assertEqual(len(exprs), 1)
        self.assertNotIn(TENANT_SEL, exprs[0])


class TestTenantPreservingQueries(unittest.TestCase):
    AGGREGATION = re.compile(
        r"\b(?:sum|avg|max|min|count)\s*"
        r"(?:by\s*\((?P<group>[^)]*)\))?\s*\("
    )

    def _builder(self):
        # uid/tenant_metric are gone from Builder.__init__ (#399): the tenant
        # dropdown is now derived from the one estate-wide
        # Builder.TENANT_SOURCE_METRIC, not passed in per instance.
        return Builder(
            name="tenant-test",
            title="tenant test",
            description="",
            tags=[],
            catalog=CAT,
        )

    def _groups(self, expr):
        return [
            [] if match.group("group") is None else [
                key.strip() for key in match.group("group").split(",")
            ]
            for match in self.AGGREGATION.finditer(expr)
        ]

    def test_standard_metric_and_non_additive_queries_preserve_tenant(self):
        builder = self._builder()
        additive = builder.metric("intune.devices.count")
        non_additive = builder.metric("intune.compliance.policy.version")

        self.assertIn(
            "sum by (tenant_id, compliance_state, operating_system)",
            additive["targets"][0]["expr"],
        )
        self.assertEqual(
            additive["targets"][0]["legendFormat"],
            "{{tenant_id}} {{compliance_state}} {{operating_system}}",
        )
        self.assertIn(
            "avg by (tenant_id, policy_name)",
            non_additive["targets"][0]["expr"],
        )
        self.assertEqual(
            non_additive["targets"][0]["legendFormat"],
            "{{tenant_id}} {{policy_name}}",
        )

    def test_histogram_preserves_tenant_before_quantile(self):
        panel = self._builder().metric("intune.uxa.boot_time_ms")
        target = panel["targets"][0]
        self.assertIn(
            "sum by (le, tenant_id, restart_category)",
            target["expr"],
        )
        self.assertEqual(
            target["legendFormat"],
            "{{tenant_id}} {{restart_category}}",
        )

    def test_log_rate_and_topk_table_preserve_tenant(self):
        builder = self._builder()
        rate = builder.log_rate(
            "entra.signin",
            "Sign-ins",
            by=["status_error_code"],
        )
        table = builder.log_table(
            "intune.compliance_alert",
            "Compliance alerts",
            by=["alert_type"],
        )

        self.assertIn(
            "sum by (tenant_id, status_error_code)",
            rate["targets"][0]["expr"],
        )
        self.assertEqual(
            rate["targets"][0]["legendFormat"],
            "{{tenant_id}} {{status_error_code}}",
        )
        self.assertIn(
            "topk(20, sum by (tenant_id, alert_type)",
            table["targets"][0]["expr"],
        )
        self.assertEqual(
            table["targets"][0]["legendFormat"],
            "{{tenant_id}} {{alert_type}}",
        )

    def test_explicit_tenant_group_is_not_duplicated(self):
        builder = self._builder()
        rate = builder.log_rate(
            "entra.signin",
            "Sign-ins",
            by=["tenant_id", "status_error_code"],
        )
        table = builder.log_table(
            "intune.compliance_alert",
            "Compliance alerts",
            by=["tenant_id", "alert_type"],
        )

        self.assertIn(
            "sum by (tenant_id, status_error_code)",
            rate["targets"][0]["expr"],
        )
        self.assertNotIn(
            "tenant_id, tenant_id",
            rate["targets"][0]["expr"],
        )
        self.assertIn(
            "sum by (tenant_id, alert_type)",
            table["targets"][0]["expr"],
        )
        self.assertNotIn(
            "tenant_id, tenant_id",
            table["targets"][0]["expr"],
        )

    def test_two_tenant_fixture_keeps_every_query_shape_separable(self):
        builder = self._builder()
        panels = [
            builder.metric("intune.devices.count"),
            builder.metric("intune.uxa.boot_time_ms"),
            builder.log_rate(
                "entra.signin",
                "Sign-ins",
                by=["status_error_code"],
            ),
            builder.log_table(
                "intune.compliance_alert",
                "Compliance alerts",
                by=["alert_type"],
            ),
        ]
        raw_panel = _domain_panels(DOMAIN_TAB_BY_TITLE["Self-obs"])[
            "Scrape error rate by error type"
        ]
        panels.append(raw_panel)

        fixtures = [
            {
                "tenant_id": "tenant-a",
                "compliance_state": "compliant",
                "operating_system": "Windows",
            },
            {
                "tenant_id": "tenant-b",
                "compliance_state": "compliant",
                "operating_system": "Windows",
            },
        ]
        for panel in panels:
            with self.subTest(panel=panel["title"]):
                group = self._groups(panel["targets"][0]["expr"])[0]
                keys = {
                    tuple(record.get(label, "") for label in group)
                    for record in fixtures
                }
                self.assertEqual(len(keys), 2)

    def test_every_generated_tenant_aggregation_keeps_tenant_id(self):
        violations = []
        checked = 0
        for item in BUILDER._panels:
            panel = item.get("spec")
            if panel is None:
                continue
            for target in panel.get("targets", []):
                expr = target.get("expr", "")
                names = CAT.metrics_referenced_by(expr)
                scopes = {CAT.metric(name).scope for name in names}
                if catalog_mod.TENANT_SCOPE not in scopes:
                    continue
                checked += 1
                if catalog_mod.PROCESS_SCOPE in scopes:
                    violations.append(
                        f"{panel['title']}: mixes process and tenant metrics"
                    )
                    continue
                for group in self._groups(expr):
                    if "tenant_id" not in group:
                        violations.append(f"{panel['title']}: {expr}")
        # A gate that skips everything it should have inspected passes for
        # free (#399 C7) — prove the walk actually reached tenant-scoped
        # queries across the whole estate, not zero of them.
        self.assertGreater(checked, 100,
                            "expected many tenant-scoped queries across the estate")
        self.assertEqual(violations, [], "\n".join(violations[:20]))

    def test_every_generated_tenant_series_has_an_explicit_tenant_legend(self):
        violations = []
        checked = 0
        for item in BUILDER._panels:
            panel = item.get("spec")
            if panel is None or panel["type"] not in {
                "timeseries", "stat", "bargauge"
            }:
                continue
            for target in panel.get("targets", []):
                names = CAT.metrics_referenced_by(target.get("expr", ""))
                if not any(
                    CAT.metric(name).scope == catalog_mod.TENANT_SCOPE
                    for name in names
                ):
                    continue
                checked += 1
                if "{{tenant_id}}" not in target.get("legendFormat", ""):
                    violations.append(
                        f"{panel['title']}: {target.get('expr', '')}"
                    )
        self.assertGreater(checked, 50,
                            "expected many tenant-scoped series-carrying panels")
        self.assertEqual(violations, [], "\n".join(violations[:20]))

    def test_process_scoped_query_does_not_gain_tenant_identity(self):
        panel = self._builder().metric("graph2otel.series.total")
        target = panel["targets"][0]
        self.assertNotIn("tenant_id", target["expr"])
        self.assertNotIn("legendFormat", target)


class TestOutcomeAccountingPanels(unittest.TestCase):
    def setUp(self):
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]
        self.panels = _domain_panels(self.tab)

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
            "Collector run rate by reconciled result":
                "sum by (tenant_id, collector, ingest_transport, result)",
            "Source-record rate by outcome":
                "sum by (tenant_id, collector, ingest_transport, outcome)",
            "Dropped / errored source-record rate":
                "sum by (tenant_id, collector, ingest_transport, outcome)",
            "Payload type-mismatch rate":
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
        self.assertIn("Dropped / errored source-record rate", self.panels)
        self.assertIn("Payload type-mismatch rate", self.panels)


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
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]
        self.panels = _domain_panels(self.tab)

    def test_all_six_delivery_metrics_are_process_wide_and_panelled(self):
        referenced = set()
        for expr in _domain_prom_exprs(self.tab):
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

    def test_a_delivery_alert_states_its_self_reporting_blind_spot(self):
        """Superseded #421. This gate used to forbid a delivery alert outright.

        The reason it existed is real and is preserved below: the delivery
        metrics travel through the METRICS exporter, so they can be unobservable
        in the backend at exactly the moment metrics delivery is failing. A rule
        built on them therefore cannot be the metrics-path watchdog, and the
        original gate stopped anyone believing otherwise.

        What the blanket ban ALSO stopped was the case that actually happened.
        #419 lost log records to per-entry HTTP 400s for days, visible only in
        container logs, while ``export_failures{signal="logs"}`` recorded them
        perfectly — the metrics path was healthy throughout, so the failure was
        queryable the whole time. A partial metrics-side rejection reports itself
        for the same reason: the accepted batches carry the counter.

        So the ban is narrowed to what its reason supports. A delivery rule is
        allowed, and MUST carry the blind spot in its own description, because
        the failure mode this gate was built around is a responder trusting the
        rule's silence. Recording rules were retired entirely by #297, so RULES
        is the whole generated rule surface.
        """
        delivery = [r for r in build_rules.RULES
                    if "graph2otel_otlp_delivery_" in json.dumps(r)]
        for rule in delivery:
            with self.subTest(uid=rule["uid"]):
                description = rule["annotations"]["description"]
                self.assertIn(
                    "cannot be the metrics-path watchdog", description,
                    f"{rule['uid']}: a delivery rule must state that its own evidence "
                    "travels through the metrics exporter, so silence from it is not "
                    "proof that delivery is healthy",
                )

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


class TestCapacityAndCostPanels(unittest.TestCase):
    def setUp(self):
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]
        self.panels = _domain_panels(self.tab)

    def test_exact_collector_volume_preserves_bounded_attribution(self):
        source = self.panels[
            "Exact source-record rate by collector and traffic class"
        ]
        self.assertIn(
            "sum by (tenant_id, collector, ingest_transport, traffic_class)",
            source["targets"][0]["expr"],
        )
        self.assertIn(
            "graph2otel_ingest_source_records_total",
            source["targets"][0]["expr"],
        )
        self.assertIn("exact", source["description"].lower())

        points = self.panels[
            "Exact emitted-point rate by collector, signal and traffic class"
        ]
        self.assertIn(
            "sum by (tenant_id, collector, ingest_transport, signal, traffic_class)",
            points["targets"][0]["expr"],
        )
        self.assertIn(
            "graph2otel_ingest_emitted_points_total",
            points["targets"][0]["expr"],
        )
        self.assertIn("after the central limiter", points["description"].lower())

    def test_exact_transport_panels_are_process_wide_and_preserve_signal(self):
        expected = {
            "Exact transmitted OTLP payload rate by signal":
                "graph2otel_otlp_transmitted_payload_bytes_total",
            "Exact exporter retry rate by signal":
                "graph2otel_otlp_retry_attempts_total",
        }
        for title, metric in expected.items():
            with self.subTest(panel=title):
                panel = self.panels[title]
                expr = panel["targets"][0]["expr"]
                self.assertIn(metric, expr)
                self.assertIn("sum by (signal) (rate(", expr)
                self.assertNotIn(TENANT_SEL, expr)
                self.assertNotIn("$tenant", expr)
                self.assertNotIn("tenant_id", expr)
                self.assertNotIn("$collector", expr)
                self.assertNotIn("collector", expr)

    def test_transport_byte_panel_states_the_exact_boundary(self):
        desc = self.panels[
            "Exact transmitted OTLP payload rate by signal"
        ]["description"].lower()
        self.assertIn("post-compression", desc)
        self.assertIn("excludes", desc)
        self.assertIn("framing", desc)

    def test_cost_panel_is_explicitly_estimated_and_optional(self):
        title = "Estimated projected collector cost (configured period)"
        panel = self.panels[title]
        self.assertIn("estimated", title.lower())
        self.assertIn("estimate, not invoice", panel["description"].lower())
        self.assertIn(
            "max by (tenant_id, collector, ingest_transport, currency, "
            "price_version, attribution)",
            panel["targets"][0]["expr"],
        )
        self.assertIn(
            "graph2otel_ingest_cost_projected",
            panel["targets"][0]["expr"],
        )
        self.assertIn('attribution="estimated"', panel["targets"][0]["expr"])
        self.assertNotIn("budget", panel["targets"][0]["expr"].lower())

    def test_capacity_and_cost_add_no_alert_rule(self):
        rendered = json.dumps({"alerts": build_rules.RULES})
        for metric in [
            "graph2otel_ingest_source_records",
            "graph2otel_ingest_emitted_points",
            "graph2otel_otlp_transmitted_payload",
            "graph2otel_otlp_retry_attempts",
            "graph2otel_ingest_cost_projected",
        ]:
            with self.subTest(metric=metric):
                self.assertNotIn(metric, rendered)


class TestCollectorAvailabilityPanels(unittest.TestCase):
    def setUp(self):
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]
        self.panels = _domain_panels(self.tab)
        self.availability = SELF_OBS["graph2otel.collector.availability"].prom

    def test_availability_backs_tenant_and_collector_variables(self):
        # One estate-wide tenant dropdown now (Builder.TENANT_SOURCE_METRIC),
        # not a per-board tenant_metric.
        self.assertEqual(BUILDER.tenant_metric, self.availability)
        collector = next(
            v for v in BUILDER.variables() if v["spec"]["name"] == "collector"
        )
        self.assertEqual(
            collector["spec"]["query"]["spec"]["query"],
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
            expr for expr in _domain_prom_exprs(self.tab)
            if self.availability in expr
        ]
        self.assertTrue(availability_exprs)
        self.assertTrue(all("ingest_transport" not in expr for expr in availability_exprs))
        for panel in self.panels.values():
            self.assertNotIn("alert", panel)


class TestExecutiveHealthSummary(unittest.TestCase):
    EXPECTED_DRILLDOWNS = {
        "Current source collection failures": "Collector availability failures",
        "Known source-to-emitter record loss": "Dropped / errored source-record rate",
        "Current exporter callback degradation":
            "Current exporter degradation by signal",
        "Checkpoint persistence failures": "Checkpoint persist error rate",
        "Source-event emission lag": "Source-event lag at emission",
        "Series clipped last interval": "Series clipped, by mode (process-wide)",
        "Microsoft API assumption violations":
            "Microsoft API drift rate — a response no longer matches what a collector expects",
        "Maximum reported throttle consumption":
            "Graph-reported throttle budget consumed",
    }

    def setUp(self):
        self.tab = DOMAIN_TAB_BY_TITLE["Self-obs"]
        self.panels = _domain_panels(self.tab)

    def test_summary_is_the_first_leaf_tab(self):
        """The executive summary is Self-obs's first LEAF TAB now, not the
        first "row" panel in a single scrolling page (#399: one b.row() call
        becomes one leaf tab). Panel declaration order — which the numeric
        ids encode — still proves the summary panels are built, and placed,
        before the detail panels they drill down into.
        """
        leaves = self.tab["spec"]["layout"]["spec"]["tabs"]
        self.assertEqual(leaves[0]["spec"]["title"],
                         "Executive health and data-loss summary")
        self.assertLess(
            self.panels["Current source collection failures"]["id"],
            self.panels["Current exporter degradation by signal"]["id"],
        )

    def test_summary_keeps_failure_dimensions_separate(self):
        self.assertEqual(
            set(self.EXPECTED_DRILLDOWNS),
            set(self.panels) & set(self.EXPECTED_DRILLDOWNS),
        )
        queries = {
            title: self.panels[title]["targets"][0]["expr"]
            for title in self.EXPECTED_DRILLDOWNS
        }
        self.assertIn(
            'state=~"degraded|failed|startup_failed"',
            queries["Current source collection failures"],
        )
        self.assertIn(
            'state="blocked",reason="permission_denied"',
            queries["Current source collection failures"].replace(" ", ""),
        )
        self.assertIn(
            'outcome=~"dropped|errored"',
            queries["Known source-to-emitter record loss"],
        )
        self.assertIn("$__range", queries["Known source-to-emitter record loss"])
        self.assertIn(
            "graph2otel_otlp_delivery_degraded_ratio",
            queries["Current exporter callback degradation"],
        )
        self.assertIn(
            "graph2otel_checkpoint_persist_errors_total",
            queries["Checkpoint persistence failures"],
        )
        self.assertIn(
            "graph2otel_event_lag_seconds_bucket",
            queries["Source-event emission lag"],
        )
        self.assertIn(
            "histogram_quantile(0.95",
            queries["Source-event emission lag"],
        )
        self.assertIn(
            "graph2otel_series_clipped",
            queries["Series clipped last interval"],
        )
        self.assertIn(
            "graph2otel_api_unexpected_total",
            queries["Microsoft API assumption violations"],
        )
        self.assertIn(
            "graph2otel_throttle_limit_percentage_percent",
            queries["Maximum reported throttle consumption"],
        )

    def test_healthy_empty_and_intentional_absence_are_not_source_failures(self):
        expr = self.panels[
            "Current source collection failures"
        ]["targets"][0]["expr"]
        for value in [
            "healthy_empty",
            "disabled",
            "covered",
            "limited",
            "partial_license",
            "license_unavailable",
        ]:
            with self.subTest(value=value):
                self.assertNotIn(value, expr)

    def test_delivery_and_readiness_boundaries_are_explicit(self):
        delivery = self.panels[
            "Current exporter callback degradation"
        ]["description"].lower()
        self.assertIn("exporter accepted", delivery)
        self.assertIn("not backend retention", delivery)
        self.assertIn("not exactly-once", delivery)

        boundary = self.panels["What this summary cannot prove"]["options"][
            "content"
        ].lower()
        for phrase in [
            "/readyz",
            "admin status",
            "dependency-free liveness",
            "latched readiness",
            "metrics path",
        ]:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, boundary)

    def test_every_verdict_has_a_resolving_same_dashboard_drilldown(self):
        for title, expected_target in self.EXPECTED_DRILLDOWNS.items():
            with self.subTest(panel=title):
                links = self.panels[title]["fieldConfig"]["defaults"]["links"]
                self.assertEqual(len(links), 1)
                url = links[0]["url"]
                self.assertTrue(url.startswith(f"/d/{DASHBOARD_NAME}?viewPanel="))
                self.assertIn("from=${__from}", url)
                self.assertIn("to=${__to}", url)
                self.assertIn("${__all_variables}", url)
                target_id = int(re.search(r"viewPanel=(\d+)", url).group(1))
                self.assertIn(target_id, PANEL_BY_ID)
                self.assertEqual(PANEL_BY_ID[target_id]["title"], expected_target)

    def test_summary_no_data_is_neutral_not_green(self):
        for title in self.EXPECTED_DRILLDOWNS:
            panel = self.panels[title]
            self.assertEqual(panel["type"], "table", title)
            no_value = panel["fieldConfig"]["defaults"]["noValue"].lower()
            self.assertIn("unknown", no_value)
            self.assertIn("not a green verdict", no_value)


class TestDomainAvailabilityPresentation(unittest.TestCase):
    DOMAIN_PATTERNS = {
        "Intune": r"intune\..+",
        "Entra": r"entra\..+",
        "M365": r"m365\..+",
        "Defender": r"(?:defender|mdca)\..+",
        "Purview": r"purview\..+",
    }

    def test_new_board_must_declare_availability_ownership(self):
        module = SimpleNamespace(
            __name__="boards.test_missing_availability",
            DOMAIN="Test",
            DESCRIPTION="",
            SECTIONS=[],
            LOGS=[],
        )
        builder = Builder("test", "test", "", [], CAT)
        with self.assertRaisesRegex(ValueError, "AVAILABILITY_PATTERN"):
            common.add(builder, module)

    def test_each_domain_board_has_one_truthful_availability_table(self):
        availability = SELF_OBS["graph2otel.collector.availability"].prom
        for domain_name, pattern in self.DOMAIN_PATTERNS.items():
            tab = DOMAIN_TAB_BY_TITLE[domain_name]
            with self.subTest(board=domain_name):
                panels = [
                    p for p in _domain_panel_list(tab)
                    if p["title"] == "Signal availability"
                ]
                self.assertEqual(len(panels), 1)
                panel = panels[0]
                self.assertEqual(panel["type"], "table")
                self.assertEqual(panel["gridPos"], {})
                self.assertIn(
                    "max by (tenant_id, collector, collector_transport, state, reason)",
                    panel["targets"][0]["expr"],
                )
                self.assertIn(availability, panel["targets"][0]["expr"])
                self.assertIn(TENANT_SEL, panel["targets"][0]["expr"])
                self.assertIn(
                    f'collector=~"{pattern}"',
                    panel["targets"][0]["expr"],
                )
                no_value = panel["fieldConfig"]["defaults"]["noValue"].lower()
                self.assertIn("unknown", no_value)
                self.assertIn("does not mean disabled", no_value)

    def test_availability_table_maps_the_complete_bounded_state_set(self):
        expected = {
            "disabled",
            "blocked",
            "covered",
            "starting",
            "healthy_empty",
            "healthy",
            "limited",
            "degraded",
            "failed",
            "startup_failed",
        }
        for domain_name in self.DOMAIN_PATTERNS:
            tab = DOMAIN_TAB_BY_TITLE[domain_name]
            panel = next(
                p for p in _domain_panel_list(tab)
                if p["title"] == "Signal availability"
            )
            override = next(
                item for item in panel["fieldConfig"]["overrides"]
                if item["matcher"] == {"id": "byName", "options": "state"}
            )
            mapping = next(
                prop["value"][0]["options"]
                for prop in override["properties"]
                if prop["id"] == "mappings"
            )
            self.assertEqual(set(mapping), expected, domain_name)
            self.assertTrue(all("color" not in value for value in mapping.values()))

    def test_mappings_cover_the_generated_go_contract(self):
        path = os.path.join(os.path.dirname(GRAFANA), "docs", "collectors.md")
        with open(path) as f:
            availability_section = f.read().split(
                "## Collector availability", 1
            )[1].split("\n## ", 1)[0]
        pairs = re.findall(
            r"^\| `([^`]+)` \| `([^`]+)` \|$",
            availability_section,
            re.MULTILINE,
        )
        self.assertTrue(pairs)
        self.assertEqual(set(AVAILABILITY_STATES), {state for state, _ in pairs})
        self.assertEqual(set(AVAILABILITY_REASONS), {reason for _, reason in pairs})

    def test_distinct_empty_and_failure_reasons_are_documented(self):
        required = {
            "transport_not_configured",
            "experimental_not_enabled",
            "high_volume_not_enabled",
            "disabled_by_config",
            "covered_by_alternative",
            "partial_license",
            "license_unavailable",
            "empty",
            "permission_denied",
            "source_error",
            "startup_failed",
        }
        for domain_name in self.DOMAIN_PATTERNS:
            tab = DOMAIN_TAB_BY_TITLE[domain_name]
            panel = next(
                p for p in _domain_panel_list(tab)
                if p["title"] == "Signal availability"
            )
            text = panel["description"] + json.dumps(
                panel["fieldConfig"]["overrides"]
            )
            for reason in required:
                with self.subTest(board=domain_name, reason=reason):
                    self.assertIn(reason, text)

    def test_metric_empty_state_is_neutral_and_never_green(self):
        checked = 0
        for domain_name in self.DOMAIN_PATTERNS:
            tab = DOMAIN_TAB_BY_TITLE[domain_name]
            for panel in _domain_panel_list(tab):
                if panel.get("datasource", {}).get("type") != "prometheus":
                    continue
                if panel["title"] == "Signal availability":
                    continue
                checked += 1
                with self.subTest(board=domain_name, panel=panel["title"]):
                    no_value = panel["fieldConfig"]["defaults"]["noValue"].lower()
                    self.assertIn("check signal availability", no_value)
                    self.assertIn("not evidence", no_value)
                    if panel["type"] == "stat":
                        self.assertEqual(panel["options"]["colorMode"], "none")
        self.assertGreater(checked, 50,
                            "expected many prometheus metric panels across domains")


class TestLogPanels(unittest.TestCase):
    def test_every_domain_with_a_log_signal_has_a_log_panel(self):
        self.assertEqual(build_dashboard.log_coverage(CAT, LOG_DOMAINS), [])

    def test_no_stream_selector_on_an_attribute(self):
        """#90: {event_name="…"} matches zero rows, silently. Never ship one."""
        selector = re.compile(r"\{([^}]*)\}")
        checked = 0
        for expr in BUILDER._loki_exprs:
            for inner in selector.findall(expr):
                checked += 1
                labels = re.findall(r"([a-z_][a-z0-9_]*)\s*[=!~]", inner)
                self.assertEqual(
                    set(labels), {"service_name"},
                    f"LogQL stream selector on a non-stream label: {expr}")
        self.assertGreater(checked, 0, "expected at least one LogQL selector")

    def test_logql_never_reaches_the_metric_coverage_corpus(self):
        """The two corpora must stay disjoint.

        If a LogQL string reached ``_exprs`` a metric name inside a log filter
        would credit a metric that has no metric panel at all — the coverage
        gate would then report coverage it does not have.
        """
        for expr in BUILDER._exprs:
            self.assertNotIn("service_name=", expr,
                             f"LogQL leaked into the PromQL corpus: {expr}")
        self.assertEqual(set(BUILDER._exprs) & set(BUILDER._loki_exprs), set())

    def test_the_estate_declares_a_loki_datasource_variable_when_it_has_log_panels(self):
        # There is one shared Builder for the whole estate now, not one per
        # board (#399), so "a board declaring log panels gets a loki
        # variable" collapses to one estate-wide check: the estate does have
        # LogQL panels, so it must declare the loki_datasource variable.
        self.assertTrue(BUILDER._loki_exprs, "expected LogQL panels in the estate")
        names = {v["spec"]["name"] for v in BUILDER.variables()}
        self.assertIn("loki_datasource", names)

    def test_log_panels_declare_a_loki_datasource_and_degrade_honestly(self):
        checked = 0
        for item in BUILDER._panels:
            spec = item.get("spec")
            if not spec or spec.get("datasource", {}).get("type") != "loki":
                continue
            checked += 1
            self.assertIn("Loki", spec.get("description", ""), spec["title"])
            self.assertIn("noValue", spec["fieldConfig"]["defaults"],
                          f"{spec['title']} shows 'No data' instead of an "
                          f"explanation when Loki is unset")
        self.assertGreater(checked, 0, "expected at least one Loki panel")


class TestDatasourceVariableDefaults(unittest.TestCase):
    """#295: a first render on a Grafana Cloud stack must land on
    graph2otel's actual Mimir/Loki datasources, not whatever the stack's
    own default happens to resolve to. On m7kni that default is the ML
    Prometheus forecast proxy and the alert-state-history Loki datasource —
    both empty for graph2otel, so every dashboard opened blank.

    Fix: save a portable Grafana Cloud default as `current` (maintainer
    decision, issue comment 2026-07-27) while keeping the variables
    selectable `type: datasource` dropdowns for other stacks.

    One shared Builder for the whole estate now (#399), so this is one
    dashboard-wide check rather than a loop over per-board variable sets.
    """

    def _variables(self):
        return {v["spec"]["name"]: v for v in BUILDER.variables()}

    def test_the_dashboard_pins_the_prometheus_datasource_default(self):
        var = self._variables()["datasource"]
        self.assertEqual(var["kind"], "DatasourceVariable")
        self.assertEqual(var["spec"]["pluginId"], "prometheus")
        self.assertEqual(var["spec"]["hide"], "dontHide")
        self.assertEqual(
            var["spec"]["current"],
            {"text": PROM_DATASOURCE_DEFAULT, "value": PROM_DATASOURCE_DEFAULT},
        )

    def test_the_dashboard_pins_the_loki_datasource_default(self):
        var = self._variables()["loki_datasource"]
        self.assertEqual(var["kind"], "DatasourceVariable")
        self.assertEqual(var["spec"]["pluginId"], "loki")
        self.assertEqual(var["spec"]["hide"], "dontHide")
        self.assertEqual(
            var["spec"]["current"],
            {"text": LOKI_DATASOURCE_DEFAULT, "value": LOKI_DATASOURCE_DEFAULT},
        )

    def test_the_datasource_variable_declares_the_prometheus_exclusion_regex(self):
        self.assertEqual(
            self._variables()["datasource"]["spec"]["regex"],
            PROM_DATASOURCE_EXCLUDE_REGEX,
        )

    def test_the_loki_variable_declares_the_loki_exclusion_regex(self):
        self.assertEqual(
            self._variables()["loki_datasource"]["spec"]["regex"],
            LOKI_DATASOURCE_EXCLUDE_REGEX,
        )

    def test_prometheus_exclusion_regex_hides_the_ml_and_usage_datasources(self):
        """Live-verified 2026-07-27 against the m7kni Grafana Cloud stack
        (`gcx datasources list --context cloud`): `grafanacloud-ml-metrics`
        (the ML forecast Prometheus proxy) and `grafanacloud-usage` (Grafana
        Cloud billing/usage metrics) are both ``type: prometheus`` near-misses
        that must never be the resolved default. This is the exact pattern
        Grafana's own Cloud Connections plugin already ships on live
        Alloy-mixin dashboards on that same stack for the same purpose.
        """
        self.assertIsNone(re.match(PROM_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-ml-metrics"))
        self.assertIsNone(re.match(PROM_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-usage"))
        self.assertIsNotNone(re.match(PROM_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-prom"))
        self.assertIsNotNone(
            re.match(PROM_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-robknight-prom"))

    def test_loki_exclusion_regex_hides_alert_history_and_usage_insights(self):
        """Live-verified 2026-07-27 against the m7kni Grafana Cloud stack:
        `grafanacloud-alert-state-history` and `grafanacloud-usage-insights`
        (uids) — whose display names are
        `grafanacloud-robknight-alert-state-history` /
        `grafanacloud-robknight-usage-insights` — are both ``type: loki``
        near-misses that must never be the resolved default.
        """
        self.assertIsNone(
            re.match(LOKI_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-alert-state-history"))
        self.assertIsNone(
            re.match(LOKI_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-usage-insights"))
        self.assertIsNone(re.match(
            LOKI_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-robknight-alert-state-history"))
        self.assertIsNone(re.match(
            LOKI_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-robknight-usage-insights"))
        self.assertIsNotNone(re.match(LOKI_DATASOURCE_EXCLUDE_REGEX, "grafanacloud-logs"))


class TestStructure(unittest.TestCase):
    def test_the_tenant_dropdown_metric_resolves_to_the_catalog_and_is_tenant_scoped(self):
        # One estate-wide tenant dropdown now (#399), not one per board, so
        # this folds the old per-board "resolves to the catalog" check and
        # the old "a process metric cannot back it" constructor-raises check
        # into a single assertion against the one dropdown metric: it must
        # resolve to a real, tenant-scoped catalog entry.
        known = {metric.prom: metric for metric in CAT.metrics.values()}
        self.assertIn(BUILDER.tenant_metric, known)
        self.assertEqual(known[BUILDER.tenant_metric].scope, catalog_mod.TENANT_SCOPE)

    def test_a_process_scoped_metric_cannot_back_the_tenant_dropdown(self):
        # The test above asserts the current metric is tenant-scoped; this one
        # asserts the GUARD still exists. Without it, someone could repoint
        # TENANT_SOURCE_METRIC at a process-scoped metric and the dropdown would
        # silently never populate — label_values on a metric with no tenant_id
        # label returns nothing, which looks identical to "no tenants yet".
        process_metric = next(
            (name for name, metric in CAT.metrics.items()
             if metric.scope != catalog_mod.TENANT_SCOPE),
            None,
        )
        self.assertIsNotNone(process_metric, "catalog has no process-scoped metric")
        original = builder_mod.TENANT_SOURCE_METRIC
        builder_mod.TENANT_SOURCE_METRIC = process_metric
        try:
            with self.assertRaises(ValueError):
                Builder(name="x", title="t", description="d", tags=[], catalog=CAT)
        finally:
            builder_mod.TENANT_SOURCE_METRIC = original

    def test_panel_ids_are_unique_within_the_dashboard(self):
        ids = [item["spec"]["id"] for item in BUILDER._panels if not item.get("row")]
        self.assertEqual(len(ids), len(set(ids)))

    def test_panels_fit_the_24_column_grid(self):
        items = list(_all_grid_items(MANIFEST["spec"]["layout"]["spec"]["tabs"]))
        self.assertGreater(len(items), 0)
        for item in items:
            spec = item["spec"]
            self.assertLessEqual(spec["x"] + spec["width"], 24, spec)

    def test_dashboard_name_is_graph2otel(self):
        # metadata.name is the v2 identity; there is no top-level uid and no
        # per-domain uid to check for uniqueness against (#399).
        self.assertEqual(MANIFEST["metadata"]["name"], "graph2otel")

    def test_output_is_deterministic(self):
        builder2, tabs2, _ = build_dashboard.build_all(CAT)
        manifest2 = builder2.render([build_dashboard.overview(builder2), *tabs2])
        self.assertEqual(dumps(MANIFEST), dumps(manifest2))

    def test_committed_dashboard_is_not_stale(self):
        path = os.path.join(build_dashboard.OUT_DIR, build_dashboard.OUT_FILE)
        with open(path) as f:
            self.assertEqual(f.read(), dumps(MANIFEST),
                             f"{build_dashboard.OUT_FILE} is stale — run "
                             "`python3 build_dashboard.py`")

    def test_the_generated_file_is_valid_v2_dashboard_json(self):
        path = os.path.join(build_dashboard.OUT_DIR, build_dashboard.OUT_FILE)
        with open(path) as f:
            d = json.load(f)
        self.assertEqual(d["apiVersion"], v2.API_VERSION)
        self.assertEqual(d["kind"], v2.KIND)
        self.assertTrue(d["metadata"]["name"])
        self.assertTrue(d["spec"]["title"])
        self.assertTrue(d["spec"]["elements"])

    def test_no_orphan_dashboard_files(self):
        """One dashboard file now, not six — a leftover old-named file would
        be an orphan, unowned and stale."""
        present = {f for f in os.listdir(build_dashboard.OUT_DIR) if f.endswith(".json")}
        self.assertEqual(present, {build_dashboard.OUT_FILE})

    def test_group_keys_drops_an_id_that_has_a_name_twin(self):
        self.assertEqual(group_keys(["policy_id", "policy_name", "state"]),
                         ["policy_name", "state"])
        self.assertEqual(group_keys(["policy_id", "state"]), ["policy_id", "state"])


if __name__ == "__main__":
    unittest.main()
