"""Tests for #309's policy-free dashboard performance baseline.

#399 migrated the estate from six v1 dashboards to one v2 manifest. The v1
keys this harness used to read (``panels``, ``uid``, ``title``, ``time``,
``refresh``, per-panel ``targets``) do not exist in v2, so a hand-written v1
fixture would stay green over a harness measuring nothing — exactly the bug
that migration silently introduced. To make that impossible, the static
fixture here is the REAL manifest, built by calling the real generator
(``build_dashboard.build_all`` + ``v2``), so it cannot drift from what
``dashboards/graph2otel.json`` actually contains. A separate test asserts a
v1-shaped document is rejected outright, not measured as zeros.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import performance_baseline  # noqa: E402
import catalog as catalog_mod  # noqa: E402
import v2  # noqa: E402
from build_dashboard import build_all, overview  # noqa: E402

# Floors measured against the real generated estate (#309): 348 panels, 7
# top-level tabs, 60 leaves. Kept comfortably below the live count so the
# test does not become a second copy of the coverage gate, but high enough
# that a harness returning near-zero counts cannot pass.
MIN_PANELS = 300
MIN_TABS = 7
MIN_LEAVES = 50
MIN_ROWS = 50
MIN_TARGETS = 300
MIN_EXPRESSION_BYTES = 20000


def _build_real_manifest() -> dict:
    """Build the real v2 manifest the same way ``build_dashboard.py`` does.

    Calling the actual generator rather than hand-writing a v2-shaped dict
    means this fixture cannot drift from the real dashboard shape the way the
    old hand-written v1 fixture drifted from reality after #399.
    """
    cat = catalog_mod.load()
    b, domain_tabs, _log_domains = build_all(cat)
    manifest = b.render([overview(b), *domain_tabs])
    violations = list(b.violations) + v2.manifest_violations(manifest)
    assert not violations, f"real manifest has build violations: {violations}"
    return manifest


class TestStaticAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = _build_real_manifest()

    def test_v1_shaped_document_is_rejected_not_measured_as_zeros(self):
        # This is the regression test for the exact bug #399 introduced: the
        # old harness read v1-only keys and silently reported panels=0,
        # targets=0, uid=None over a v2 manifest instead of failing. A
        # v1-shaped document must now be refused outright.
        v1_dashboard = {
            "uid": "test-board",
            "title": "Test",
            "time": {"from": "now-6h", "to": "now"},
            "refresh": "5m",
            "panels": [
                {
                    "id": 2,
                    "type": "timeseries",
                    "targets": [{"expr": "up", "instant": True}],
                },
            ],
        }
        with self.assertRaises(performance_baseline.OperationalError):
            performance_baseline.analyze_dashboard(v1_dashboard, "dashboards/test.json")

    def test_missing_v2_structure_is_rejected(self):
        not_quite_v2 = {
            "apiVersion": "dashboard.grafana.app/v2",
            "kind": "Dashboard",
            "metadata": {"name": "test"},
            "spec": {"title": "Test"},  # no elements, no layout
        }
        with self.assertRaises(performance_baseline.OperationalError):
            performance_baseline.analyze_dashboard(not_quite_v2, "dashboards/test.json")

    def test_counts_the_real_generated_estate_above_a_realistic_floor(self):
        # Asserting > 0 would still pass over a harness that measures the
        # wrong field and happens to find one stray value. The floors below
        # are calibrated to the real dashboard's actual shape, so a harness
        # that silently regresses to near-zero counts (the #399 bug) fails
        # here even if every field happens to be individually non-zero.
        result = performance_baseline.analyze_dashboard(self.manifest, "graph2otel.json")

        self.assertEqual(result["name"], "graph2otel")
        self.assertEqual(result["title"], "graph2otel")
        self.assertGreaterEqual(result["panels"], MIN_PANELS)
        self.assertGreaterEqual(result["tabs"], MIN_TABS)
        self.assertGreaterEqual(result["leaves"], MIN_LEAVES)
        self.assertGreaterEqual(result["rows"], MIN_ROWS)
        self.assertGreaterEqual(result["query_panels"], MIN_PANELS - 20)
        self.assertGreaterEqual(result["targets"], MIN_TARGETS)
        self.assertGreaterEqual(result["expression_bytes"], MIN_EXPRESSION_BYTES)
        self.assertGreater(result["unique_expressions"], 0)
        # range + instant + unknown must account for every counted target —
        # no target silently falls outside all three buckets.
        self.assertEqual(
            result["range_targets"] + result["instant_targets"]
            + result["unknown_mode_targets"],
            result["targets"],
        )
        self.assertIn("from", result["default_time"])
        self.assertIn("to", result["default_time"])
        self.assertIsNotNone(result["auto_refresh"])

    def test_paths_are_reported_in_stable_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, dashboard_name in (("z.json", "z"), ("a.json", "a")):
                doc = _minimal_v2_manifest(dashboard_name, expr="shared")
                with open(os.path.join(tmp, name), "w") as f:
                    json.dump(doc, f)
            receipt = performance_baseline.static_receipt([
                os.path.join(tmp, "z.json"),
                os.path.join(tmp, "a.json"),
            ])
        self.assertEqual(
            [item["name"] for item in receipt["dashboards"]],
            ["a", "z"],
        )
        self.assertEqual(receipt["totals"]["unique_expressions"], 1)
        self.assertEqual(receipt["repeated_expressions"], {"shared": 2})


def _minimal_v2_manifest(name: str, *, expr: str) -> dict:
    """The smallest legitimate v2 manifest, for tests that only need identity
    and multi-file aggregation behaviour, not the full real estate."""
    element_name, element = v2.panel_element(
        {
            "id": 1,
            "type": "timeseries",
            "title": name,
            "targets": [{
                "refId": "A",
                "expr": expr,
                "instant": True,
                "range": False,
                "datasource": {"type": "prometheus", "uid": "${datasource}"},
            }],
        },
        12, 8,
    )
    row = v2.rowspec("", [{"w": 12, "h": 8, "spec": {"id": 1}}])
    leaf = v2.leaf("Overview", [row])
    return v2.manifest(
        name=name,
        title=name,
        description="",
        tags=[],
        variables=[],
        elements={element_name: element},
        tabs=[leaf],
    )


class TestLiveSnapshot(unittest.TestCase):
    def test_snapshot_is_fixed_serial_temporary_and_redacts_values(self):
        variables = {
            "datasource": "private-prom",
            "tenant": "private-tenant",
        }
        calls = []
        output_dirs = []

        def fake_run(args, **kwargs):
            calls.append(args)
            output_dir = args[args.index("--output-dir") + 1]
            output_dirs.append(output_dir)
            with open(os.path.join(output_dir, "board.png"), "wb") as f:
                f.write(b"png-bytes")
            self.assertEqual(kwargs["cwd"], output_dir)
            return mock.Mock(returncode=0, stdout="[]", stderr="")

        with (
            mock.patch.object(
                performance_baseline.subprocess, "run", side_effect=fake_run
            ),
            mock.patch.object(
                performance_baseline.time, "perf_counter",
                side_effect=[10.0, 12.5],
            ),
        ):
            result = performance_baseline.snapshot_once(
                "graph2otel",
                "m7kni",
                variables,
                since="6h",
                width=1920,
                height=1080,
                theme="dark",
                timezone="UTC",
            )

        self.assertEqual(result["elapsed_seconds"], 2.5)
        self.assertEqual(result["png_bytes"], 9)
        self.assertEqual(
            result["variable_names"], ["datasource", "tenant"]
        )
        self.assertNotIn("private-prom", json.dumps(result))
        self.assertNotIn("private-tenant", json.dumps(result))
        args = calls[0]
        self.assertIn("--concurrency", args)
        self.assertEqual(args[args.index("--concurrency") + 1], "1")
        self.assertIn("--since", args)
        self.assertIn("--width", args)
        self.assertIn("--height", args)
        self.assertFalse(os.path.exists(output_dirs[0]))

    def test_snapshot_failure_redacts_runtime_values(self):
        completed = mock.Mock(
            returncode=1,
            stdout="",
            stderr="tenant private-tenant failed",
        )
        with mock.patch.object(
            performance_baseline.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(
                performance_baseline.OperationalError, r"<redacted>"
            ) as caught:
                performance_baseline.snapshot_once(
                    "graph2otel", "m7kni", {"tenant": "private-tenant"}
                )
        self.assertNotIn("private-tenant", str(caught.exception))


# Real gcx 404 shape for an absent dashboard, live-measured 2026-07-27 against
# grafana.m7kni.com via `gcx dashboards get <nonexistent-name> --context
# grafana.m7kni.com -o json` (read-only; no dashboard was created, updated, or
# deleted). Also live-verified the same day: `gcx dashboards snapshot
# <nonexistent-name>` does NOT fail — it exits 0 and silently renders
# Grafana's own "Dashboard not found" page as a PNG, which is why absence must
# be checked with `dashboards get` BEFORE snapshotting rather than inferred
# from the snapshot command's own exit code or output.
GCX_404_STDOUT = (
    '{"type":"gcx.error","schema_version":"1","error":{"summary":"404 NotFound",'
    '"details":"dashboards.dashboard.grafana.app \\"graph2otel\\" not found"}}'
)


class TestDashboardExists(unittest.TestCase):
    def test_present_dashboard_returns_true(self):
        completed = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(
            performance_baseline.subprocess, "run", return_value=completed
        ) as run:
            self.assertTrue(
                performance_baseline.dashboard_exists("graph2otel", "m7kni")
            )
        args = run.call_args.args[0]
        self.assertEqual(
            args,
            ["gcx", "dashboards", "get", "graph2otel", "--context", "m7kni",
             "-o", "json"],
        )

    def test_absent_dashboard_returns_false_not_a_failure(self):
        completed = mock.Mock(returncode=1, stdout=GCX_404_STDOUT, stderr="")
        with mock.patch.object(
            performance_baseline.subprocess, "run", return_value=completed
        ):
            self.assertFalse(
                performance_baseline.dashboard_exists("graph2otel", "m7kni")
            )

    def test_non_404_failure_raises_operational_error(self):
        completed = mock.Mock(
            returncode=1,
            stdout=(
                '{"type":"gcx.error","schema_version":"1","error":'
                '{"summary":"Unauthorized","details":"token rejected"}}'
            ),
            stderr="",
        )
        with mock.patch.object(
            performance_baseline.subprocess, "run", return_value=completed
        ):
            with self.assertRaises(performance_baseline.OperationalError):
                performance_baseline.dashboard_exists("graph2otel", "m7kni")

    def test_cannot_execute_gcx_raises_operational_error(self):
        with mock.patch.object(
            performance_baseline.subprocess, "run",
            side_effect=OSError("no such file"),
        ):
            with self.assertRaises(performance_baseline.OperationalError):
                performance_baseline.dashboard_exists("graph2otel", "m7kni")


class TestLiveBaselineSkipsAbsentDashboard(unittest.TestCase):
    def _receipt(self):
        return {
            "dashboards": [{"name": "graph2otel", "source": "graph2otel.json"}],
        }

    def test_absent_dashboard_is_skipped_cleanly_not_measured_as_a_failure(self):
        with (
            mock.patch.object(
                performance_baseline, "dashboard_exists", return_value=False
            ),
            mock.patch.object(
                performance_baseline, "snapshot_once"
            ) as snapshot_once,
        ):
            receipt = performance_baseline.add_live_baseline(
                self._receipt(), "m7kni", {}, repeat=1, since="6h",
                width=1920, height=1080, theme="dark", timezone="UTC",
            )
        snapshot_once.assert_not_called()
        entry = receipt["live"]["dashboards"][0]
        self.assertEqual(entry["status"], "skipped_absent")
        self.assertEqual(entry["name"], "graph2otel")
        self.assertIn("not present", entry["message"])
        self.assertNotIn("attempts", entry)

    def test_present_dashboard_is_measured_normally(self):
        attempt = {"status": "measured", "elapsed_seconds": 1.0, "png_bytes": 10,
                   "variable_names": []}
        with (
            mock.patch.object(
                performance_baseline, "dashboard_exists", return_value=True
            ),
            mock.patch.object(
                performance_baseline, "snapshot_once", return_value=attempt
            ) as snapshot_once,
        ):
            receipt = performance_baseline.add_live_baseline(
                self._receipt(), "m7kni", {}, repeat=2, since="6h",
                width=1920, height=1080, theme="dark", timezone="UTC",
            )
        self.assertEqual(snapshot_once.call_count, 2)
        entry = receipt["live"]["dashboards"][0]
        self.assertEqual(entry["status"], "measured")
        self.assertEqual(len(entry["attempts"]), 2)


class TestEvaluateBudget(unittest.TestCase):
    def _measured_receipt(self, elapsed_values):
        return {
            "live": {
                "dashboards": [{
                    "name": "graph2otel",
                    "status": "measured",
                    "attempts": [
                        {"elapsed_seconds": v} for v in elapsed_values
                    ],
                }],
            },
        }

    def _absent_receipt(self):
        return {
            "live": {
                "dashboards": [{
                    "name": "graph2otel",
                    "status": "skipped_absent",
                    "message": "dashboard 'graph2otel' is not present",
                }],
            },
        }

    def test_no_live_lane_is_not_applicable(self):
        result = performance_baseline.evaluate_budget({}, None)
        self.assertEqual(result["status"], "not_applicable")

    def test_no_budget_configured_is_a_clean_pass(self):
        # #309's whole point: never guess this number from n=1. Unset must
        # never read as a failure of any kind.
        receipt = self._measured_receipt([5.0])
        result = performance_baseline.evaluate_budget(receipt, None)
        self.assertEqual(result["status"], "not_configured")
        self.assertIsNone(result["budget_seconds"])

    def test_within_budget(self):
        receipt = self._measured_receipt([1.0, 2.0])
        result = performance_baseline.evaluate_budget(receipt, 5.0)
        self.assertEqual(result["status"], "within_budget")
        self.assertEqual(result["breaches"], [])

    def test_breach_is_detected_and_named(self):
        receipt = self._measured_receipt([1.0, 9.0])
        result = performance_baseline.evaluate_budget(receipt, 5.0)
        self.assertEqual(result["status"], "breached")
        self.assertEqual(len(result["breaches"]), 1)
        self.assertEqual(result["breaches"][0]["name"], "graph2otel")
        self.assertEqual(result["breaches"][0]["elapsed_seconds"], 9.0)

    def test_no_measurements_is_not_a_failure_even_with_a_budget_set(self):
        # An absent dashboard produces zero attempts. A budget breach check
        # over zero attempts must not silently read as "within budget" —
        # that would claim a measurement that never happened.
        receipt = self._absent_receipt()
        result = performance_baseline.evaluate_budget(receipt, 5.0)
        self.assertEqual(result["status"], "no_measurements")


if __name__ == "__main__":
    unittest.main()
