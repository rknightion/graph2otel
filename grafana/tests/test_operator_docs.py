"""Drift gates for generated observability inventory in operator docs."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
REPO = os.path.dirname(GRAFANA)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import build_rules  # noqa: E402
import catalog as catalog_mod  # noqa: E402


class TestOperatorObservabilityInventory(unittest.TestCase):
    def test_full_check_runs_the_grafana_asset_gate(self):
        result = subprocess.run(
            ["make", "--no-print-directory", "-n", "check"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn(
            "cd grafana && python3 build_dashboard.py --check",
            result.stdout,
        )
        self.assertIn(
            "cd grafana && python3 build_rules.py --check",
            result.stdout,
        )
        self.assertIn(
            "cd grafana && python3 -m unittest discover -s tests -t . -q",
            result.stdout,
        )

    def test_deployment_reference_matches_generated_asset_counts(self):
        docs_path = os.path.join(REPO, "docs", "deploying-observability.md")
        with open(docs_path, encoding="utf-8") as f:
            docs = f.read()
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()

        dashboards, _, _ = build_dashboard.build_all(catalog_mod.load())
        dashboard_count = len(dashboards)
        alert_count = len(build_rules.RULES)
        recording_count = len(build_rules.RECORDING)
        expected = (
            f"{dashboard_count} dashboards, "
            f"{alert_count} alert rules, and "
            f"{recording_count} recording rules"
        )
        self.assertIn(expected, docs)
        self.assertIn(expected, readme)
        self.assertIn(
            f"| `dashboards/` | {dashboard_count} dashboards (**generated**)",
            docs,
        )
        self.assertIn(
            f"| `alerts/` | {alert_count} alert rules (**generated**)",
            docs,
        )
        self.assertIn(
            f"| `recording-rules/` | {recording_count} recording rules (**generated**)",
            docs,
        )


if __name__ == "__main__":
    unittest.main()
