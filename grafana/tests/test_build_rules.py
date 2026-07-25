"""Structural tests for the alert + recording rule builder and its gates (#219).

Standard-library ``unittest`` only, matching the repo's no-third-party-
assertion rule on the Go side (and ``test_build_dashboard.py``'s own
convention). Auto-discovered by:

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

import build_rules  # noqa: E402
import catalog as catalog_mod  # noqa: E402

CAT = catalog_mod.load()

# uid -> expected isPaused, derived from alerts/README.md's own designation of
# each rule as "(primary)"/"default-enabled" (isPaused: false) vs "(companion)"
# (isPaused: true) in doc blocks 1-5.
EXPECTED_PAUSED = {
    "g2o-entra-cred-expiry-critical": False,        # primary, doc block 1
    "g2o-entra-cred-expiry-warning": True,           # companion
    "g2o-intune-apple-token-expiry-critical": True,  # companion
    "g2o-intune-cert-expiry-critical": True,         # companion
    "g2o-intune-compliance-ratio-low": False,        # primary, doc block 2
    "g2o-intune-compliance-noncompliant-spike": True,  # companion
    "g2o-collector-staleness": False,                # primary, doc block 3
    "g2o-checkpoint-persist-errors": True,           # companion
    "g2o-record-integrity-loss": False,               # primary, doc block 6
    "g2o-payload-type-mismatch": True,                # companion, doc block 6
    "g2o-throttle-saturation": False,                # primary, doc block 4
    "g2o-throttle-budget-consumption": True,         # companion
    "g2o-mdca-uploads-stopped": False,               # default-enabled, doc block 5
    "g2o-mdca-parse-failing": False,                 # default-enabled, doc block 5
}


class TestRuleIdentity(unittest.TestCase):
    def test_no_duplicate_uid(self):
        uids = [r["uid"] for r in build_rules.RULES]
        self.assertEqual(len(uids), len(set(uids)), uids)

    def test_matches_the_expected_paused_set(self):
        """Covers both directions: nothing missing, nothing extra."""
        self.assertEqual({r["uid"] for r in build_rules.RULES}, set(EXPECTED_PAUSED))

    def test_ispaused_matches_alerts_readme(self):
        actual = {r["uid"]: r["isPaused"] for r in build_rules.RULES}
        self.assertEqual(actual, EXPECTED_PAUSED)

    def test_fourteen_alert_rules_two_recording_rules(self):
        self.assertEqual(len(build_rules.RULES), 14)
        self.assertEqual(len(build_rules.RECORDING), 2)


class TestPipelineShape(unittest.TestCase):
    def test_every_alert_rule_is_a_valid_abc_pipeline(self):
        for r in build_rules.RULES:
            ref_ids = [n["refId"] for n in r["data"]]
            self.assertEqual(ref_ids, ["A", "B", "C"], r["uid"])
            self.assertEqual(r["condition"], "C", r["uid"])
            a, b, c = r["data"]
            self.assertEqual(a["model"]["datasource"]["type"], "prometheus", r["uid"])
            self.assertEqual(b["model"]["type"], "reduce", r["uid"])
            self.assertEqual(b["model"]["expression"], "A", r["uid"])
            self.assertEqual(c["model"]["type"], "threshold", r["uid"])
            self.assertEqual(c["model"]["expression"], "B", r["uid"])

    def test_every_recording_rule_records_from_a_single_query_node(self):
        for fname, r in build_rules.RECORDING:
            self.assertEqual(r["condition"], "A", fname)
            self.assertEqual([n["refId"] for n in r["data"]], ["A"], fname)
            self.assertEqual(r["record"]["from"], "A", fname)
            self.assertEqual(r["data"][0]["model"]["datasource"]["type"], "loki", fname)


class TestReverseValidation(unittest.TestCase):
    def test_every_rule_metric_token_resolves(self):
        violations = build_rules.reverse_validate(CAT, build_rules.RULES)
        self.assertEqual(violations, [])

    def test_an_unresolvable_token_is_reported(self):
        """The gate must actually fail — a gate nobody has seen fail is a hope."""
        bogus = [{
            "uid": "test-bogus-rule",
            "data": [{
                "model": {
                    "datasource": {"type": "prometheus"},
                    "expr": "sum(graph2otel_this_metric_does_not_exist_total)",
                }
            }],
        }]
        violations = build_rules.reverse_validate(CAT, bogus)
        self.assertEqual(len(violations), 1)
        self.assertIn("test-bogus-rule", violations[0])
        self.assertIn("graph2otel_this_metric_does_not_exist_total", violations[0])

    def test_throttle_limit_percentage_bug_is_fixed(self):
        """#219: the shipped rule queried a metric name that cannot exist —
        the unit is '%', so OTLP normalization appends _percent."""
        rule = next(r for r in build_rules.RULES
                    if r["uid"] == "g2o-throttle-budget-consumption")
        expr = rule["data"][0]["model"]["expr"]
        self.assertIn("graph2otel_throttle_limit_percentage_percent", expr)
        # The wrong (pre-#219) name is a PREFIX of the fixed one, so a plain
        # assertNotIn would false-fail; require it never appears un-suffixed.
        self.assertIsNone(re.search(r"graph2otel_throttle_limit_percentage(?!_percent)", expr))

    def test_record_integrity_alert_uses_only_dropped_and_errored_outcomes(self):
        rule = next(r for r in build_rules.RULES
                    if r["uid"] == "g2o-record-integrity-loss")
        expr = rule["data"][0]["model"]["expr"]
        self.assertIn('outcome=~"dropped|errored"', expr)
        self.assertIn("increase(graph2otel_record_outcomes_total", expr)
        self.assertIn("tenant_id, collector, ingest_transport", expr)

    def test_every_recording_rule_event_name_resolves(self):
        # _record() already calls cat.log() at build time (KeyError on a typo);
        # this re-asserts the event names it validated are real, current ones.
        for fname, r in build_rules.RECORDING:
            event = r["data"][0]["model"]["expr"]
            # event_name is backtick-quoted in the LogQL; every RECORDING event
            # used here is a literal we control, so just confirm it is cataloged.
            found = [e for e in CAT.logs if f"`{e}`" in event]
            self.assertEqual(len(found), 1, f"{fname}: {event}")
            self.assertIn(found[0], CAT.logs, fname)


class TestNoRecordingMetricCollision(unittest.TestCase):
    def test_recording_rule_metric_does_not_collide_with_a_catalog_metric(self):
        catalog_proms = {m.prom for m in CAT.metrics.values()}
        for fname, r in build_rules.RECORDING:
            self.assertNotIn(r["record"]["metric"], catalog_proms, fname)


class TestStaleness(unittest.TestCase):
    def test_committed_alerts_yaml_is_not_stale(self):
        with open(build_rules.ALERTS_PATH, "rb") as f:
            committed = f.read()
        self.assertEqual(committed, build_rules.render_alerts(build_rules.RULES),
                         "alerts/graph2otel-alerts.yaml is stale — run `make rules`")

    def test_committed_recording_rules_are_not_stale(self):
        rendered = build_rules.render_recording(build_rules.RECORDING)
        for fname, data in rendered.items():
            path = os.path.join(build_rules.RECORDING_DIR, fname)
            with open(path, "rb") as f:
                committed = f.read()
            self.assertEqual(committed, data, f"{fname} is stale — run `make rules`")

    def test_output_is_deterministic(self):
        self.assertEqual(build_rules.render_alerts(build_rules.RULES),
                         build_rules.render_alerts(build_rules.RULES))


class TestYamlRoundTrips(unittest.TestCase):
    def test_alerts_yaml_round_trips_through_pyyaml(self):
        """Best-effort: PyYAML is NOT a build/CI dependency (pure-stdlib
        generator, no setup-python step — see Makefile / ci.yml), so this
        skips rather than fails when it is unavailable."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed — not a dependency of this repo")
        doc = yaml.safe_load(build_rules.render_alerts(build_rules.RULES))
        self.assertEqual(doc["apiVersion"], 1)
        rules = doc["groups"][0]["rules"]
        self.assertEqual(len(rules), 14)
        uids = {r["uid"] for r in rules}
        self.assertEqual(uids, set(EXPECTED_PAUSED))


class TestRecordingRulesAreValidJson(unittest.TestCase):
    def test_every_recording_rule_file_is_valid_json_with_expected_shape(self):
        for fname, _ in build_rules.RECORDING:
            path = os.path.join(build_rules.RECORDING_DIR, fname)
            with open(path) as f:
                d = json.load(f)
            self.assertIn("record", d)
            self.assertTrue(d["title"])
            self.assertEqual(d["folderUID"], "efskohpc18lj4b")
            self.assertEqual(d["ruleGroup"], "blob-derived")


if __name__ == "__main__":
    unittest.main()
