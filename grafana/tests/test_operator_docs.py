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
        check = subprocess.run(
            ["just", "--show", "check"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("gen-check", check.stdout)

        generated_assets = subprocess.run(
            ["just", "--show", "gen-check"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("grafana-check", generated_assets.stdout)

        result = subprocess.run(
            ["just", "--show", "grafana-check"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn(
            "python3 build_dashboard.py --check",
            result.stdout,
        )
        self.assertIn(
            "python3 build_rules.py --check",
            result.stdout,
        )
        self.assertIn(
            "python3 -m unittest discover -s tests -t . -q",
            result.stdout,
        )

    def test_deployment_reference_matches_generated_asset_counts(self):
        docs_path = os.path.join(REPO, "docs", "deploying-observability.md")
        with open(docs_path, encoding="utf-8") as f:
            docs = f.read()
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()

        dashboard_files = sorted(os.listdir(os.path.join(REPO, "dashboards")))
        dashboard_count = len(dashboard_files)
        alert_count = len(build_rules.RULES)
        noun = "dashboard" if dashboard_count == 1 else "dashboards"
        detection_count = len(build_rules.DETECTIONS)
        expected = (
            f"{dashboard_count} {noun}, "
            f"{alert_count} alert rules, and "
            f"{detection_count} paused detection examples"
        )
        self.assertIn(expected, docs)
        self.assertIn(expected, readme)
        self.assertIn(
            f"| `dashboards/` | {dashboard_count} {noun} (Graph **generated**, Teams hand-maintained)",
            docs,
        )
        # Both stable dashboard identities must remain documented.
        self.assertEqual(dashboard_files, ["graph2otel-teams.json", "graph2otel.json"])
        for filename in dashboard_files:
            self.assertIn(f"`dashboards/{filename}`", docs)
        # v2 needs Grafana 13+, and the docs must say so rather than leaving an
        # operator to discover it from a broken import.
        self.assertIn(v2.MIN_GRAFANA_VERSION, docs)
        self.assertIn(v2.MIN_GRAFANA_VERSION, readme)
        self.assertIn(
            f"| `alerts/rules/` | {alert_count} alert rules (**generated**)",
            docs,
        )
        # #294: one representation only, and the generator really does emit
        # exactly one manifest per rule, so the prose cannot drift from the build.
        self.assertEqual(
            len(os.listdir(os.path.join(REPO, "alerts", "rules"))),
            alert_count + detection_count,
        )
        self.assertIn("rules.alerting.grafana.app/v0alpha1", docs)
        # #297 retired both recording rules. The reference may explain the
        # retirement (it does, and should), but must not advertise a directory
        # that no longer exists or carry a count that can drift.
        self.assertNotIn("`recording-rules/`", docs)
        self.assertNotIn("recording-rules/intune", docs)
        self.assertNotIn("recording rules (**generated**)", docs)
        self.assertIn("ships **no recording rules**", docs)


if __name__ == "__main__":
    unittest.main()
