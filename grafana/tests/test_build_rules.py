"""Structural tests for the alert rule builder and its gates (#219).

Standard-library ``unittest`` only, matching the repo's no-third-party-
assertion rule on the Go side (and ``test_build_dashboard.py``'s own
convention). Auto-discovered by:

    python3 -m unittest discover -s tests -t .

``make grafana-check`` runs them, so CI does too.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

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

    def test_fourteen_alert_rules_and_no_recording_rules(self):
        self.assertEqual(len(build_rules.RULES), 14)


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



class TestEvaluatorErrorState(unittest.TestCase):
    def test_every_alert_treats_evaluator_errors_as_errors(self):
        for rule in build_rules.RULES:
            self.assertEqual(rule["execErrState"], "Error", rule["uid"])

    def test_ok_evaluator_state_requires_a_documented_waiver(self):
        args = (
            "test-evaluator-waiver",
            "Evaluator waiver",
            "vector(1)",
            "gt",
            [0],
            "0s",
            {"severity": "warning"},
            "summary",
            "description",
            True,
        )
        with self.assertRaisesRegex(ValueError, "waiver"):
            build_rules._alert(*args, exec_err_state="OK")

        waived = build_rules._alert(
            *args,
            exec_err_state="OK",
            exec_err_waiver="The datasource is deliberately optional.",
        )
        self.assertEqual(waived["execErrState"], "OK")
        self.assertEqual(
            waived["annotations"]["exec_error_waiver"],
            "The datasource is deliberately optional.",
        )

    def test_no_data_state_remains_independent(self):
        staleness = next(
            r for r in build_rules.RULES
            if r["uid"] == "g2o-collector-staleness"
        )
        healthy_empty = next(
            r for r in build_rules.RULES
            if r["uid"] == "g2o-throttle-saturation"
        )
        self.assertEqual(staleness["noDataState"], "Alerting")
        self.assertEqual(healthy_empty["noDataState"], "OK")
        self.assertEqual(staleness["execErrState"], "Error")
        self.assertEqual(healthy_empty["execErrState"], "Error")


class TestCollectorStalenessIsIntervalAware(unittest.TestCase):
    """#299: replace the fixed 3600s placeholder with a per-collector ratio
    against the scheduler's own effective interval, at the maintainer-approved
    3x multiplier. Modifies the EXISTING g2o-collector-staleness rule in place
    (TestRuleIdentity.test_fourteen_alert_rules_and_no_recording_rules already
    pins the rule count at 14 — this must not add a 15th)."""

    def _rule(self):
        return next(r for r in build_rules.RULES if r["uid"] == "g2o-collector-staleness")

    def _expr(self):
        return self._rule()["data"][0]["model"]["expr"]

    def test_expr_divides_staleness_by_the_scheduler_s_effective_interval(self):
        expr = self._expr()
        self.assertIn(build_rules._m("graph2otel.scrape.staleness"), expr)
        self.assertIn(build_rules._m("graph2otel.collector.expected_interval"), expr)
        self.assertIn("/", expr)

    def test_threshold_is_the_approved_3x_multiplier_not_a_fixed_second_count(self):
        threshold_node = self._rule()["data"][2]["model"]
        condition = threshold_node["conditions"][0]
        self.assertEqual(condition["evaluator"]["type"], "gt")
        self.assertEqual(condition["evaluator"]["params"], [3])
        # The old fixed-seconds placeholder must not survive anywhere in the
        # expr — a leftover comparison to 3600 would silently coexist with the
        # new ratio and nobody would notice which one actually gates the rule.
        self.assertNotIn("3600", self._expr())

    def test_expr_groups_both_sides_by_tenant_and_collector_so_the_ratio_is_one_to_one(self):
        expr = self._expr()
        self.assertEqual(expr.count("by (tenant_id, collector)"), 2)

    def test_annotation_no_longer_claims_a_missing_series_means_the_process_died(self):
        """The issue's own evidence: 'the annotation ... misstates how Grafana
        handles one missing multidimensional series versus an entirely empty
        query.' A single collector's series disappearing (deregistered,
        deliberately removed) does not make Grafana's multi-series alert
        evaluation empty as long as another collector's series still matches —
        that alert INSTANCE simply stops existing; noDataState is a
        whole-query condition, not a per-series one."""
        description = self._rule()["annotations"]["description"]
        self.assertNotIn("or that collector was removed", description)

    def test_annotation_documents_the_removed_collector_outcome_explicitly(self):
        description = self._rule()["annotations"]["description"]
        self.assertIn("removed", description)
        self.assertIn("3x", description)


class TestCollectorStalenessRatioGrafanaSemantics(unittest.TestCase):
    """Acceptance criterion 2 (#299): one missing series and all series
    missing behave differently under Grafana's real per-series alert
    evaluation, and the rule's noDataState choice only makes sense against
    that real behavior — so pin it here rather than trust prose alone.

    Grafana evaluates a multi-dimensional rule's threshold PER label
    combination the query actually returns; noDataState fires only when the
    whole evaluation returns zero rows, never for one missing combination
    among several. This models that vector-matching arithmetic directly
    (dividing two label-keyed fixtures, as PromQL's `/` on identically-labeled
    vectors does) rather than asserting prose.
    """

    @staticmethod
    def _ratio_rows(staleness, expected_interval):
        """One-to-one vector match on (tenant_id, collector), mirroring what
        `max by (tenant_id, collector) (A) / max by (tenant_id, collector) (B)`
        does when both sides carry exactly those two labels: a row survives
        only where BOTH sides have a value for that exact key."""
        return {
            key: staleness[key] / expected_interval[key]
            for key in staleness
            if key in expected_interval
        }

    def test_one_collector_s_series_disappearing_leaves_the_others_evaluable(self):
        staleness = {
            ("tenant-a", "entra.domains"): 30.0,
            ("tenant-a", "intune.devices"): 200.0,
        }
        expected_interval = {
            ("tenant-a", "entra.domains"): 300.0,
            ("tenant-a", "intune.devices"): 3600.0,
        }
        full = self._ratio_rows(staleness, expected_interval)
        self.assertEqual(len(full), 2)

        # entra.domains is deregistered: BOTH of its series disappear (the
        # scheduler no longer ticks it, so neither scrape.staleness nor
        # expected_interval is emitted for it again) — the deliberately
        # removed collector's own explicit, non-accidental outcome.
        del staleness[("tenant-a", "entra.domains")]
        del expected_interval[("tenant-a", "entra.domains")]
        after_removal = self._ratio_rows(staleness, expected_interval)

        # The query still returns a row for the surviving collector — Grafana
        # evaluates it exactly as before. Only the removed collector's OWN
        # alert instance disappears; it does not become a "no data" firing,
        # and no other collector's evaluation is disturbed.
        self.assertEqual(set(after_removal), {("tenant-a", "intune.devices")})
        self.assertNotIn(("tenant-a", "entra.domains"), after_removal)

    def test_every_collector_s_series_disappearing_is_the_only_true_empty_query(self):
        staleness = {("tenant-a", "entra.domains"): 30.0}
        expected_interval = {("tenant-a", "entra.domains"): 300.0}
        self.assertEqual(len(self._ratio_rows(staleness, expected_interval)), 1)

        # The whole tenant's self-obs pipeline goes dark (process died, or —
        # degenerate case — its only collector was removed): now the query
        # legitimately returns zero rows, which is the one case
        # noDataState=Alerting is meant to catch.
        staleness.clear()
        expected_interval.clear()
        self.assertEqual(self._ratio_rows(staleness, expected_interval), {})


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


class TestStaleness(unittest.TestCase):


    def test_output_is_deterministic(self):
        self.assertEqual(build_rules.render_app_platform(),
                         build_rules.render_app_platform())


class TestYamlRoundTrips(unittest.TestCase):
    def test_every_manifest_round_trips_through_pyyaml(self):
        """Best-effort: PyYAML is NOT a build/CI dependency (pure-stdlib
        generator, no setup-python step — see Makefile / ci.yml), so this skips
        rather than fails when it is unavailable. It still matters, because the
        generator emits YAML with its own yamlify() and a real parser is the only
        thing that proves the output is valid YAML rather than merely
        plausible-looking text."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed — not a dependency of this repo")
        rendered = build_rules.render_app_platform()
        self.assertEqual(len(rendered), 19)
        uids = set()
        for fname, data in rendered.items():
            doc = yaml.safe_load(data)
            self.assertEqual(doc["kind"], "AlertRule", fname)
            self.assertEqual(doc["apiVersion"], build_rules.APP_PLATFORM_API)
            uids.add(doc["metadata"]["name"])
        expected = {r["uid"] for r in build_rules.RULES}
        expected |= {r["uid"] for r in build_rules.DETECTIONS}
        self.assertEqual(uids, expected)


class TestRoutableLabelContract(unittest.TestCase):
    """#293/#296: graph2otel ships alert *rules* only, no routing — so every
    generated rule instead carries a stable, documented, routable label set
    an operator writes their own notification-policy route against.
    pipeline/severity/source/category are mandatory; component is optional
    and only present on the two Intune credential rules that need a finer
    distinction than the frozen `source` domain enum allows."""

    def test_every_rule_has_the_four_mandatory_labels_non_empty(self):
        for rule in build_rules.RULES:
            labels = rule["labels"]
            for key in ("pipeline", "severity", "source", "category"):
                self.assertIn(key, labels, f"{rule['uid']}: missing {key}")
                self.assertTrue(labels[key], f"{rule['uid']}: empty {key}")

    def test_pipeline_is_the_constant_graph2otel_on_every_rule(self):
        for rule in build_rules.RULES:
            self.assertEqual(rule["labels"]["pipeline"], "graph2otel", rule["uid"])

    def test_severity_source_category_values_are_in_their_closed_sets(self):
        for rule in build_rules.RULES:
            labels = rule["labels"]
            self.assertIn(labels["severity"], build_rules.SEVERITY_VALUES, rule["uid"])
            self.assertIn(labels["source"], build_rules.SOURCE_VALUES, rule["uid"])
            self.assertIn(labels["category"], build_rules.CATEGORY_VALUES, rule["uid"])

    def test_component_present_only_on_the_two_intune_credential_rules(self):
        expected = {
            "g2o-intune-apple-token-expiry-critical": "apple-token",
            "g2o-intune-cert-expiry-critical": "certificate",
        }
        for rule in build_rules.RULES:
            uid = rule["uid"]
            if uid in expected:
                self.assertEqual(rule["labels"].get("component"), expected[uid], uid)
            else:
                self.assertNotIn("component", rule["labels"], uid)

    def test_component_values_are_in_their_closed_set(self):
        for rule in build_rules.RULES:
            component = rule["labels"].get("component")
            if component is not None:
                self.assertIn(component, build_rules.COMPONENT_VALUES, rule["uid"])

    def test_validate_labels_rejects_a_rule_missing_pipeline(self):
        bogus = [{
            "uid": "test-missing-pipeline",
            "labels": {"severity": "warning", "source": "entra", "category": "compliance"},
        }]
        violations = build_rules.validate_labels(bogus)
        self.assertEqual(len(violations), 1)
        self.assertIn("test-missing-pipeline", violations[0])
        self.assertIn("pipeline", violations[0])

    def test_validate_labels_rejects_out_of_set_severity_source_category(self):
        bogus = [{
            "uid": "test-bad-values",
            "labels": {
                "pipeline": "graph2otel",
                "severity": "critical",
                "source": "not-a-real-domain",
                "category": "not-a-real-category",
            },
        }]
        violations = build_rules.validate_labels(bogus)
        self.assertEqual(len(violations), 2)
        joined = " ".join(violations)
        self.assertIn("source", joined)
        self.assertIn("category", joined)

    def test_validate_labels_rejects_out_of_set_component(self):
        bogus = [{
            "uid": "test-bad-component",
            "labels": {
                "pipeline": "graph2otel",
                "severity": "warning",
                "source": "intune",
                "category": "compliance",
                "component": "not-a-real-component",
            },
        }]
        violations = build_rules.validate_labels(bogus)
        self.assertEqual(len(violations), 1)
        self.assertIn("component", violations[0])

    def test_validate_labels_accepts_the_real_rule_set(self):
        self.assertEqual(build_rules.validate_labels(build_rules.RULES), [])


class TestNoRoutingAssetsShipped(unittest.TestCase):
    """#293/#296: no contact point, notification policy, or route ships in
    this repository, in any form, under alerts/. A real content check on
    committed YAML/JSON top-level keys, not a filename convention."""

    def test_committed_alert_files_carry_no_routing_keys(self):
        violations = build_rules.routing_asset_violations(
            [build_rules.ALERTS_DIR])
        self.assertEqual(violations, [])

    def test_alerts_directory_contains_exactly_the_expected_entries(self):
        # An allowlist, not a convention: a new file under alerts/ has to be
        # added here deliberately, which is how a stray contact-point or policy
        # bundle gets noticed. Generated manifests live one level down in
        # alerts/rules/ and are covered by the staleness/orphan gate.
        actual = set(os.listdir(build_rules.ALERTS_DIR))
        self.assertEqual(actual, {"rules", "README.md"})

    def test_the_gate_actually_rejects_a_synthetic_offending_document(self):
        """A gate nobody has seen fail is a hope, not a gate (same framing as
        TestReverseValidation.test_an_unresolvable_token_is_reported above)."""
        with tempfile.TemporaryDirectory() as tmp:
            offending = os.path.join(tmp, "sneaky-notification-policy.yaml")
            with open(offending, "w", encoding="utf-8") as f:
                f.write(
                    "apiVersion: 1\n"
                    "\n"
                    "contactPoints:\n"
                    "  - orgId: 1\n"
                    "    name: sneaky\n"
                    "\n"
                    "policies:\n"
                    "  - orgId: 1\n"
                    "    receiver: sneaky\n"
                )
            violations = build_rules.routing_asset_violations([tmp])
        self.assertEqual(len(violations), 1)
        self.assertIn("sneaky-notification-policy.yaml", violations[0])
        self.assertIn("contactPoints", violations[0])
        self.assertIn("policies", violations[0])

    def test_a_clean_alert_rule_json_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean = os.path.join(tmp, "clean.json")
            with open(clean, "w", encoding="utf-8") as f:
                json.dump({"title": "x", "record": {"metric": "y"}}, f)
            violations = build_rules.routing_asset_violations([tmp])
        self.assertEqual(violations, [])


class TestDetectionExamples(unittest.TestCase):
    """The portable detection pack (#300).

    These are adapted from detections running on a real tenant. Two properties
    make them safe to ship publicly and they are both enforced here rather than
    trusted: nothing tenant-specific is in them, and every one is paused.
    """

    def test_every_detection_is_paused(self):
        """#375's binding rule: unmeasured detections ship paused.

        None of these thresholds has been measured on more than one tenant. A
        detection that fires on correct data is worse than no detection, because
        it teaches responders to ignore the channel.
        """
        for rule in build_rules.DETECTIONS:
            self.assertTrue(rule["isPaused"], rule["uid"])

    def test_every_detection_names_the_measurement_it_needs(self):
        """A paused rule with no stated unblock condition is a rule nobody can
        ever safely enable — the same failure as a waiver with no reason."""
        for rule in build_rules.DETECTIONS:
            tuning = rule["annotations"].get("tuning_required", "")
            self.assertTrue(tuning.strip(), rule["uid"])

    def test_a_detection_without_a_tuning_note_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            build_rules._loki_alert(
                "x", "t", "sum(count_over_time({service_name=\"graph2otel\"} [5m]))",
                "gt", [0],
                {"severity": "critical", "source": "entra",
                 "category": "identity-threat"},
                "s", "d", tuning="   ")

    def test_every_field_a_detection_filters_on_exists_in_the_catalog(self):
        """A LogQL filter on an attribute graph2otel does not emit matches zero
        rows silently, forever (#90). For a detection that is the worst possible
        failure: it looks installed and healthy while unable to ever fire."""
        self.assertEqual(build_rules.validate_detection_fields(build_rules.CAT), [])

    def test_every_detection_query_uses_the_only_correct_stream_selector(self):
        """service_name is the sole stream label. An attribute in the stream
        selector is the #90 trap."""
        checked = 0
        for rule in build_rules.DETECTIONS:
            expr = rule["data"][0]["model"]["expr"]
            self.assertNotIn("{event_name=", expr, rule["uid"])
            self.assertIn('{service_name="graph2otel"}', expr, rule["uid"])
            checked += 1
        self.assertGreater(checked, 0)

    def test_detections_carry_the_frozen_routable_label_contract(self):
        self.assertEqual(build_rules.validate_labels(build_rules.DETECTIONS), [])

    def test_no_detection_carries_a_tenant_specific_identifier(self):
        """The three per-service-principal rules on the source tenant hardcode
        application GUIDs and private network addresses. They are deliberately
        not ported. This asserts none of that shape leaked into the ones that
        were: a GUID, a dotted IPv4 literal, or an IPv6 prefix.
        """
        guid = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
        ipv4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        ipv6 = re.compile(r"\b[0-9a-f]{1,4}:[0-9a-f:]{2,}::?/\d{1,3}")
        for rule in build_rules.DETECTIONS:
            blob = json.dumps(rule)
            self.assertIsNone(guid.search(blob), f"{rule['uid']} carries a GUID")
            self.assertIsNone(ipv4.search(blob), f"{rule['uid']} carries an IPv4")
            self.assertIsNone(ipv6.search(blob), f"{rule['uid']} carries an IPv6")

    def test_detections_ship_in_a_separate_group_from_the_health_rules(self):
        """Different group and folder. graph2otel-alerts means 'is graph2otel
        working'; mixing tenant-security detections into it would blur what an
        operator agrees to when they provision it."""
        manifests = build_rules.render_app_platform()
        for rule in build_rules.DETECTIONS:
            doc = manifests[f"{rule['uid']}.yaml"].decode()
            self.assertIn(build_rules.DETECTION_GROUP, doc, rule["uid"])
            self.assertNotIn(build_rules.ALERT_GROUP, doc, rule["uid"])
        for rule in build_rules.RULES:
            doc = manifests[f"{rule['uid']}.yaml"].decode()
            self.assertIn(build_rules.ALERT_GROUP, doc, rule["uid"])
            self.assertNotIn(build_rules.DETECTION_GROUP, doc, rule["uid"])

    def test_every_detection_manifest_on_disk_is_current(self):
        rendered = build_rules.render_app_platform()
        for rule in build_rules.DETECTIONS:
            fname = f"{rule['uid']}.yaml"
            with open(os.path.join(build_rules.RULES_DIR, fname), "rb") as f:
                self.assertEqual(f.read(), rendered[fname], fname)


class TestSecondDetectionWave(unittest.TestCase):
    """#313: six further portable detections, and the hunting-query library.

    The five #300 detections cover privileged directory change, unresolved
    security alert, active security incident, interactive sign-in anomaly and a
    Graph 403 burst. Everything added here has to be genuinely DIFFERENT from
    those — a near-duplicate of a shipped rule is worse than shipping fewer,
    because it doubles the pages for one event while looking like coverage.

    So the assertions below are about distinctness and about grounding, not about
    prose: each new detection must key on an (event, attribute) pair no shipped
    rule already keys on, and every hunt must name the paused detection whose
    measurement it produces.
    """

    WAVE_TWO = {
        "g2o-detect-exchange-inbox-rule-change",
        "g2o-detect-mailbox-permission-grant",
        "g2o-detect-identity-risk-detection",
        "g2o-detect-workload-identity-risk",
        "g2o-detect-legacy-auth-signin",
        "g2o-detect-mail-remediation-failed",
    }

    def _detection(self, uid):
        return next(r for r in build_rules.DETECTIONS if r["uid"] == uid)

    def test_the_six_new_detections_ship(self):
        uids = {r["uid"] for r in build_rules.DETECTIONS}
        self.assertTrue(self.WAVE_TWO <= uids, sorted(self.WAVE_TWO - uids))
        self.assertEqual(len(build_rules.DETECTIONS), 11)

    def test_each_new_detection_queries_a_distinct_event_attribute_pair(self):
        """The whole point of the wave: no new rule may re-ask a shipped rule's
        question. Derived from the rendered query text, so it cannot disagree
        with what the rule evaluates."""
        pairs = {}
        for rule in build_rules.DETECTIONS:
            expr = rule["data"][0]["model"]["expr"]
            events = set(re.findall(r"event_name=`([^`]+)`", expr))
            attrs = set(re.findall(r"\|\s*([a-z_][a-z0-9_]*)\s*(?:=~|!~|=|!=)\s*`",
                                   expr)) - {"event_name"}
            pairs[rule["uid"]] = {(e, a) for e in events for a in attrs}
        for uid in sorted(self.WAVE_TWO):
            mine = pairs[uid]
            self.assertTrue(mine, uid)
            for other, theirs in pairs.items():
                if other == uid or other in self.WAVE_TWO:
                    continue
                self.assertFalse(
                    mine <= theirs,
                    f"{uid} asks the same (event, attribute) question as {other}")

    def test_the_new_detections_spread_across_more_than_one_source_domain(self):
        sources = {self._detection(uid)["labels"]["source"]
                   for uid in self.WAVE_TWO}
        self.assertGreaterEqual(len(sources), 3, sources)

    def test_the_mail_remediation_rule_requires_the_attribute_to_be_present(self):
        """A negative label filter matches a record that lacks the label at all:
        LogQL compares a missing structured-metadata key as the empty string, so
        `action_result!~"success"` alone would fire on every record that simply
        has no action_result. The presence term is what stops that."""
        expr = self._detection(
            "g2o-detect-mail-remediation-failed")["data"][0]["model"]["expr"]
        self.assertIn("action_result=~`.+`", expr)
        self.assertIn("action_result!~", expr)

    def test_every_new_detection_regex_is_case_insensitive(self):
        """Every value these rules match on is a Microsoft-documented spelling
        that this project has NOT measured on the wire for that exact field. A
        case-sensitive regex on an unverified spelling is a query that matches
        zero rows silently — the #90 failure at value level rather than key
        level."""
        for uid in sorted(self.WAVE_TWO):
            expr = self._detection(uid)["data"][0]["model"]["expr"]
            for value in re.findall(r"[=!]~`([^`]+)`", expr):
                if value == ".+":
                    continue
                self.assertTrue(value.startswith("(?i)"),
                                f"{uid}: regex {value!r} is case-sensitive")

    def test_every_hunt_validates_through_the_typed_filter_contract(self):
        """The hunts are built by the same _sel() path as the detections, so a
        misspelled filter or group key in a DOCUMENTED query fails CI too. A
        hunting library nobody validates is a page of queries that quietly
        return nothing."""
        self.assertTrue(build_rules.HUNTS)
        self.assertEqual(build_rules.validate_detection_fields(build_rules.CAT), [])

    def test_every_hunt_query_is_the_only_correct_stream_selector(self):
        for hunt in build_rules.HUNTS:
            query = build_rules.hunt_query(hunt)
            self.assertIn('{service_name="graph2otel"}', query, hunt["title"])
            self.assertNotIn("{event_name=", query, hunt["title"])

    def test_every_hunt_states_the_question_and_what_it_unblocks(self):
        """A hunt with no stated purpose is a query, not a hunt. `unblocks` may
        be empty only when the hunt answers a standalone question rather than
        producing a paused rule's missing measurement."""
        uids = {r["uid"] for r in build_rules.DETECTIONS}
        for hunt in build_rules.HUNTS:
            self.assertTrue(hunt["question"].strip(), hunt["title"])
            self.assertTrue(hunt["look_for"].strip(), hunt["title"])
            for uid in hunt["unblocks"]:
                self.assertIn(uid, uids, hunt["title"])

    def test_every_hunt_query_appears_verbatim_on_the_docs_page(self):
        """The page is hand-written prose around generated queries. Asserting the
        exact rendered string is what stops a hand-copied query drifting from the
        validated one — a drifted copy is unvalidated, and looks identical."""
        with open(build_rules.HUNTS_DOC, encoding="utf-8") as fh:
            page = fh.read()
        for hunt in build_rules.HUNTS:
            self.assertIn(build_rules.hunt_query(hunt), page, hunt["title"])
            self.assertIn(hunt["title"], page, hunt["title"])

    def test_every_paused_detection_has_a_hunt_that_measures_it(self):
        """The commitment this wave makes: every paused rule names a measurement
        in tuning_required, and the hunting page carries the query that produces
        it. A named measurement with no way to take it is a rule nobody can
        enable."""
        measured = {uid for hunt in build_rules.HUNTS for uid in hunt["unblocks"]}
        for rule in build_rules.DETECTIONS:
            self.assertIn(rule["uid"], measured, rule["uid"])


class TestRecordingRulesAreRetired(unittest.TestCase):
    """#297: both Loki recording rules are retired, on measured evidence.

    They recorded no series for 30+ days while reporting health=ok, because a
    1h *event-time* window can never overlap a blob-derived source whose
    records are 3.3-7.0 days old (median 5.97, n=223). Nothing consumed their
    output; a LogQL `count by` over the log twin answers the same question with
    no materialized series. See docs/derived-metrics.md for the full reasoning.

    These assertions exist so the retirement cannot be undone by accident. A
    deliberate reintroduction has to delete this class, which is the point.
    """

    def test_no_recording_rule_directory_is_committed(self):
        self.assertFalse(
            os.path.isdir(os.path.join(build_rules.REPO, "recording-rules")),
            "recording-rules/ is retired (#297) — a recording rule over a "
            "blob-derived stream is structurally incapable of matching its "
            "own data",
        )

    def test_the_builder_declares_no_recording_rules(self):
        for gone in ("RECORDING", "RECORDING_DIR", "render_recording",
                     "_record", "_recording_expr", "recording_rule_orphans"):
            self.assertFalse(
                hasattr(build_rules, gone),
                f"build_rules.{gone} survived the #297 retirement",
            )

    def test_no_committed_asset_declares_a_recording_rule(self):
        """A gate on the outcome, not on a precondition: any committed YAML or
        JSON carrying a top-level Grafana `record` block would be a recording
        rule under a different name."""
        offenders = []
        for dirpath, dirnames, fnames in os.walk(build_rules.REPO):
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "__pycache__", "node_modules",
                                        "third_party", ".superpowers", "testdata"}]
            for fname in fnames:
                if not fname.endswith((".yaml", ".yml", ".json")):
                    continue
                path = os.path.join(dirpath, fname)
                if "record" in build_rules._top_level_keys(path):
                    offenders.append(os.path.relpath(path, build_rules.REPO))
        self.assertEqual(offenders, [])

    def test_the_retirement_reason_is_documented_where_a_reader_will_look(self):
        path = os.path.join(build_rules.REPO, "docs", "derived-metrics.md")
        with open(path, encoding="utf-8") as f:
            doc = f.read()
        self.assertIn("#297", doc)
        self.assertIn("retired", doc.lower())


if __name__ == "__main__":
    unittest.main()


class TestAppPlatformProjection(unittest.TestCase):
    """#294: the deployable representation is App Platform
    `rules.alerting.grafana.app/v0alpha1` AlertRule manifests, one YAML per
    rule, pushed by stable `metadata.name` with create-or-update semantics.

    Every field shape asserted here was measured off the live wire on
    2026-07-27 by reading an existing rule back with
    `gcx resources get alertrules.v0alpha1.rules.alerting.grafana.app/<uid>`
    and then pushing a projected manifest and reading it back again. It is a
    frozen contract, not an inference from documentation — the classic
    `apiVersion: 1` file-provisioning bundles this replaces were rejected with
    HTTP 400 when posted as individual objects.
    """

    def _project(self, uid="g2o-collector-staleness"):
        rule = next(r for r in build_rules.RULES if r["uid"] == uid)
        return build_rules.to_app_platform(
            rule, group="graph2otel-alerts", interval="5m", index=6)

    def test_identity_is_the_stable_uid_as_metadata_name(self):
        m = self._project()
        self.assertEqual(m["apiVersion"], "rules.alerting.grafana.app/v0alpha1")
        self.assertEqual(m["kind"], "AlertRule")
        self.assertEqual(m["metadata"]["name"], "g2o-collector-staleness")

    def test_group_and_index_are_metadata_labels(self):
        labels = self._project()["metadata"]["labels"]
        self.assertEqual(labels["grafana.com/group"], "graph2otel-alerts")
        self.assertEqual(labels["grafana.com/group-index"], "6")

    def test_folder_is_a_loud_substitution_token_not_a_guess(self):
        """A folder UID is stack-specific, so a public repository cannot know
        it. Measured 2026-07-27: pushing an unresolvable folder UID fails with
        `403 Forbidden` and creates nothing, so an unsubstituted token fails
        VISIBLY. Omitting the annotation instead would silently file every rule
        in the General folder, which is the failure mode worth avoiding."""
        annotations = self._project()["metadata"]["annotations"]
        self.assertEqual(annotations["grafana.app/folder"],
                         build_rules.FOLDER_TOKEN)
        self.assertIn("REPLACE", build_rules.FOLDER_TOKEN)

    def test_expressions_are_a_map_keyed_by_refid_not_a_data_list(self):
        exprs = self._project()["spec"]["expressions"]
        self.assertEqual(sorted(exprs), ["A", "B", "C"])

    def test_the_condition_node_is_marked_source_true(self):
        """`condition: "C"` has no App Platform equivalent — the condition is
        identified by `source: true` on that expression instead."""
        exprs = self._project()["spec"]["expressions"]
        self.assertTrue(exprs["C"]["source"])
        self.assertNotIn("source", exprs["A"])
        self.assertNotIn("source", exprs["B"])
        self.assertNotIn("condition", self._project()["spec"])

    def test_durations_are_go_duration_strings_not_second_counts(self):
        spec = self._project()["spec"]
        self.assertEqual(spec["expressions"]["A"]["relativeTimeRange"],
                         {"from": "1h0m0s", "to": "0s"})
        self.assertEqual(spec["for"], "5m0s")

    def test_only_datasource_backed_nodes_carry_a_datasource_and_time_range(self):
        """Expression nodes (`__expr__`) carry neither on the wire."""
        exprs = self._project()["spec"]["expressions"]
        self.assertEqual(exprs["A"]["datasourceUID"], "grafanacloud-prom")
        for ref in ("B", "C"):
            self.assertNotIn("datasourceUID", exprs[ref])
            self.assertNotIn("relativeTimeRange", exprs[ref])

    def test_group_interval_becomes_a_per_rule_trigger(self):
        self.assertEqual(self._project()["spec"]["trigger"], {"interval": "5m"})

    def test_evaluator_states_labels_and_annotations_survive(self):
        spec = self._project()["spec"]
        self.assertEqual(spec["execErrState"], "Error")
        self.assertEqual(spec["noDataState"], "Alerting")
        self.assertEqual(spec["labels"]["pipeline"], "graph2otel")
        self.assertIn("runbook_url", spec["annotations"])

    def test_paused_is_carried_for_every_paused_rule(self):
        for rule in build_rules.RULES:
            m = build_rules.to_app_platform(
                rule, group="graph2otel-alerts", interval="5m", index=0)
            self.assertEqual(m["spec"]["paused"], rule["isPaused"], rule["uid"])
        for rule in build_rules.DETECTIONS:
            m = build_rules.to_app_platform(
                rule, group="graph2otel-detections", interval="5m", index=0)
            self.assertTrue(m["spec"]["paused"], rule["uid"])

    def test_every_rule_and_detection_gets_one_committed_manifest(self):
        rendered = build_rules.render_app_platform()
        expected = {f"{r['uid']}.yaml" for r in build_rules.RULES}
        expected |= {f"{r['uid']}.yaml" for r in build_rules.DETECTIONS}
        self.assertEqual(set(rendered), expected)
        self.assertEqual(len(rendered), 19)

    def test_committed_manifests_are_not_stale(self):
        for fname, data in build_rules.render_app_platform().items():
            path = os.path.join(build_rules.RULES_DIR, fname)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), data,
                                 f"{fname} is stale — run `make rules`")

    def test_no_classic_file_provisioning_bundle_is_committed(self):
        """#294: one representation only. A committed `apiVersion: 1` +
        `groups:` bundle was measured to be rejected with HTTP 400 when posted
        as an individual object, and keeping it alongside the App Platform
        manifests would be two generated representations to gate and drift."""
        for dirpath, dirnames, fnames in os.walk(build_rules.ALERTS_DIR):
            for fname in fnames:
                if not fname.endswith((".yaml", ".yml")):
                    continue
                keys = build_rules._top_level_keys(os.path.join(dirpath, fname))
                self.assertNotIn("groups", keys, fname)
                self.assertIn("apiVersion", keys, fname)
        self.assertFalse(hasattr(build_rules, "render_alerts"))
        self.assertFalse(hasattr(build_rules, "render_detections"))

    def test_ok_states_are_spelled_Ok_not_OK(self):
        """Measured 2026-07-27: 18 of 19 rules were rejected with
        `403 Forbidden: spec.noDataState: Invalid value: "OK": value is not one
        of the allowed values ["NoData","Ok","Alerting","KeepLast"]`. The classic
        file-provisioning API accepted `OK`, so this is a genuine representation
        difference between the two APIs, and no documentation mentions it."""
        healthy_empty = next(r for r in build_rules.RULES
                             if r["uid"] == "g2o-throttle-saturation")
        self.assertEqual(healthy_empty["noDataState"], "OK")
        m = build_rules.to_app_platform(
            healthy_empty, group="graph2otel-alerts", interval="5m", index=0)
        self.assertEqual(m["spec"]["noDataState"], "Ok")

    def test_no_manifest_carries_the_rejected_spelling(self):
        for fname, data in build_rules.render_app_platform().items():
            text = data.decode()
            self.assertNotIn('noDataState: "OK"', text, fname)
            self.assertNotIn('execErrState: "OK"', text, fname)

    def test_go_duration_omits_leading_zero_units(self):
        """Go's own time.Duration.String() format, measured off the wire. The
        obvious `HhMmSs` implementation emits `0h5m0s`, which reads back as
        `5m0s` and reported all 11 deployed rules as divergent on nothing."""
        self.assertEqual(build_rules.go_duration(0), "0s")
        self.assertEqual(build_rules.go_duration(30), "30s")
        self.assertEqual(build_rules.go_duration(300), "5m0s")
        self.assertEqual(build_rules.go_duration(900), "15m0s")
        self.assertEqual(build_rules.go_duration(3600), "1h0m0s")
        self.assertEqual(build_rules.go_duration(5400), "1h30m0s")

    def test_a_zero_for_is_omitted_rather_than_spelled(self):
        """The server drops `for: 0m0s`, so emitting it makes every
        instant-firing rule permanently divergent and buries real drift."""
        instant = next(r for r in build_rules.RULES
                       if build_rules.parse_duration(r["for"]) == 0)
        m = build_rules.to_app_platform(
            instant, group="graph2otel-alerts", interval="5m", index=0)
        self.assertNotIn("for", m["spec"])

    def test_a_nonzero_for_is_carried(self):
        m = self._project()          # g2o-collector-staleness, for: 5m
        self.assertEqual(m["spec"]["for"], "5m0s")

    def test_parse_duration_refuses_to_guess(self):
        """An unparseable `for` silently becoming 0 would turn a 5-minute alert
        into an instant one."""
        self.assertEqual(build_rules.parse_duration("1h30m"), 5400)
        for bad in ("", "soon", "5", "5 minutes", "-5m"):
            with self.assertRaises(ValueError, msg=bad):
                build_rules.parse_duration(bad)

    def test_expression_nodes_carry_the_defaults_the_server_fills_in(self):
        """The server stores `intervalMs`/`maxDataPoints` on every expression
        node, including the reduce/threshold nodes the canonical rule dicts omit
        them on. Emitting them keeps the read-back free of normalization."""
        exprs = self._project()["spec"]["expressions"]
        for ref in ("A", "B", "C"):
            self.assertEqual(exprs[ref]["model"]["intervalMs"], 1000, ref)
            self.assertEqual(exprs[ref]["model"]["maxDataPoints"], 43200, ref)
