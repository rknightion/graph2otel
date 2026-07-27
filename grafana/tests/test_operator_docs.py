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

import build_rules  # noqa: E402
import v2  # noqa: E402


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

        # One v2 dashboard covers the whole estate (#399), so this count is 1 and
        # the sentence has to read "1 dashboard" — an f-string that always says
        # "dashboards" would force the docs to say "1 dashboards".
        dashboard_count = 1
        alert_count = len(build_rules.RULES)
        recording_count = len(build_rules.RECORDING)
        noun = "dashboard" if dashboard_count == 1 else "dashboards"
        expected = (
            f"{dashboard_count} {noun}, "
            f"{alert_count} alert rules, and "
            f"{recording_count} recording rules"
        )
        self.assertIn(expected, docs)
        self.assertIn(expected, readme)
        self.assertIn(
            f"| `dashboards/` | {dashboard_count} {noun} (**generated**)",
            docs,
        )
        # The generator really does emit exactly that many files, so the prose
        # cannot drift from the build.
        self.assertEqual(
            sorted(os.listdir(os.path.join(REPO, "dashboards"))),
            ["graph2otel.json"],
        )
        # v2 needs Grafana 13+, and the docs must say so rather than leaving an
        # operator to discover it from a broken import.
        self.assertIn(v2.MIN_GRAFANA_VERSION, docs)
        self.assertIn(v2.MIN_GRAFANA_VERSION, readme)
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
