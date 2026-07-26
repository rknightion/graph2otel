"""Tests for #309's policy-free dashboard performance baseline."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import performance_baseline  # noqa: E402


class TestStaticAnalysis(unittest.TestCase):
    def test_counts_queries_rows_modes_and_repeated_expressions(self):
        dashboard = {
            "uid": "test-board",
            "title": "Test",
            "time": {"from": "now-6h", "to": "now"},
            "refresh": "5m",
            "panels": [
                {"id": 1, "type": "row", "collapsed": False, "panels": []},
                {
                    "id": 2,
                    "type": "timeseries",
                    "targets": [
                        {"expr": "up", "instant": False, "range": True},
                        {"expr": "up", "instant": True, "range": False},
                    ],
                },
                {
                    "id": 3,
                    "type": "table",
                    "targets": [{
                        "expr": '{service_name="graph2otel"}',
                        "queryType": "range",
                    }],
                },
                {
                    "id": 4,
                    "type": "row",
                    "collapsed": True,
                    "panels": [{
                        "id": 5,
                        "type": "stat",
                        "targets": [{"expr": "vector(1)", "instant": True}],
                    }],
                },
            ],
        }
        result = performance_baseline.analyze_dashboard(
            dashboard, "dashboards/test.json"
        )
        self.assertEqual(result["panels"], 5)
        self.assertEqual(result["rows"], 2)
        self.assertEqual(result["collapsed_rows"], 1)
        self.assertEqual(result["expanded_rows"], 1)
        self.assertEqual(result["query_panels"], 3)
        self.assertEqual(result["targets"], 4)
        self.assertEqual(result["range_targets"], 2)
        self.assertEqual(result["instant_targets"], 2)
        self.assertEqual(result["unique_expressions"], 3)
        self.assertEqual(result["repeated_expressions"], {"up": 2})
        self.assertEqual(result["default_time"], {"from": "now-6h", "to": "now"})
        self.assertEqual(result["refresh"], "5m")

    def test_paths_are_reported_in_stable_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, uid in (("z.json", "z"), ("a.json", "a")):
                with open(os.path.join(tmp, name), "w") as f:
                    json.dump({
                        "uid": uid,
                        "title": uid,
                        "panels": [{
                            "type": "timeseries",
                            "targets": [{"expr": "shared", "instant": True}],
                        }],
                    }, f)
            receipt = performance_baseline.static_receipt([
                os.path.join(tmp, "z.json"),
                os.path.join(tmp, "a.json"),
            ])
        self.assertEqual(
            [item["uid"] for item in receipt["dashboards"]],
            ["a", "z"],
        )
        self.assertEqual(receipt["totals"]["unique_expressions"], 1)
        self.assertEqual(receipt["repeated_expressions"], {"shared": 2})


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
                "board",
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
                    "board", "m7kni", {"tenant": "private-tenant"}
                )
        self.assertNotIn("private-tenant", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
