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


if __name__ == "__main__":
    unittest.main()
