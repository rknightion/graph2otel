"""Offline contract tests for the read-only Grafana semantic canary (#308)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build_rules  # noqa: E402
import semantic_canary  # noqa: E402


PROM_UID = "test-prom"
LOKI_UID = "test-loki"
CONTEXT = "test"


def _manifest(*probes):
    return {"schema": 1, "probes": list(probes)}


def _query_probe(**overrides):
    probe = {
        "id": "availability",
        "kind": "promql",
        "datasource": "prometheus",
        "query": "graph2otel_collector_availability",
        "empty": "required_nonempty",
        "required_labels": ["tenant_id"],
    }
    probe.update(overrides)
    return probe


class TestManifest(unittest.TestCase):
    def test_loads_closed_schema(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(_manifest(_query_probe()), f)
            f.flush()
            loaded = semantic_canary.load_manifest(f.name)
        self.assertEqual(loaded["schema"], 1)

    def test_rejects_unknown_probe_fields(self):
        with self.assertRaisesRegex(semantic_canary.ManifestError, "unknown"):
            semantic_canary.validate_manifest(
                _manifest(_query_probe(shell="curl example.invalid"))
            )

    def test_rejects_rule_without_stable_uid(self):
        with self.assertRaisesRegex(semantic_canary.ManifestError, "uid"):
            semantic_canary.validate_manifest(_manifest({
                "id": "rule",
                "kind": "rule_health",
                "datasource": "prometheus",
                "folder_uid": "graph2otel",
            }))


class TestResultClassification(unittest.TestCase):
    def test_required_nonempty_fails_on_empty_success(self):
        result = semantic_canary.classify_query(
            _query_probe(),
            {"status": "success", "data": {"result": []}},
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["outcome"], "unexpected_empty")

    def test_empty_allowed_passes_on_empty_success(self):
        result = semantic_canary.classify_query(
            _query_probe(empty="empty_allowed"),
            {"status": "success", "data": {"result": []}},
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["outcome"], "healthy_empty")

    def test_missing_required_label_fails(self):
        result = semantic_canary.classify_query(
            _query_probe(required_labels=["tenant_id", "collector"]),
            {
                "status": "success",
                "data": {"result": [{"metric": {"tenant_id": "tenant-a"}}]},
            },
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["outcome"], "missing_labels")
        self.assertEqual(result["missing_labels"], ["collector"])

    def test_labelled_prometheus_result_passes(self):
        result = semantic_canary.classify_query(
            _query_probe(required_labels=["tenant_id", "collector"]),
            {
                "status": "success",
                "data": {"result": [{
                    "metric": {"tenant_id": "tenant-a", "collector": "entra.users"},
                    "value": [1, "1"],
                }]},
            },
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["outcome"], "nonempty")
        self.assertEqual(result["series"], 1)

    def test_labelled_loki_result_passes(self):
        result = semantic_canary.classify_query(
            _query_probe(kind="logql", datasource="loki"),
            {
                "status": "success",
                "data": {"result": [{
                    "stream": {"tenant_id": "tenant-a"},
                    "values": [[1, "1"]],
                }]},
            },
        )
        self.assertEqual(result["status"], "passed")

    def test_backend_error_never_passes_as_empty(self):
        result = semantic_canary.classify_query(
            _query_probe(empty="empty_allowed"),
            {"status": "error", "error": "parse error"},
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["outcome"], "query_error")


class TestDatasourceAndRuleHealth(unittest.TestCase):
    def test_wrong_datasource_type_fails(self):
        result = semantic_canary.classify_datasource(
            "prometheus",
            {"spec": {"type": "loki"}},
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["outcome"], "wrong_type")

    def test_rule_must_be_healthy_and_evaluated(self):
        probe = {
            "id": "staleness-rule",
            "kind": "rule_health",
            "datasource": "prometheus",
            "folder_uid": "graph2otel",
            "uid": "g2o-collector-staleness",
        }
        failed = semantic_canary.classify_rule(
            probe,
            [{"rules": [{
                "uid": probe["uid"],
                "health": "error",
                "lastEvaluation": "2026-07-26T19:00:00Z",
                "queriedDatasourceUIDs": [PROM_UID],
            }]}],
            PROM_UID,
        )
        self.assertEqual(failed["outcome"], "evaluator_error")

        never = semantic_canary.classify_rule(
            probe,
            [{"rules": [{
                "uid": probe["uid"],
                "health": "ok",
                "lastEvaluation": "",
                "queriedDatasourceUIDs": [PROM_UID],
            }]}],
            PROM_UID,
        )
        self.assertEqual(never["outcome"], "never_evaluated")

        passed = semantic_canary.classify_rule(
            probe,
            [{"rules": [{
                "uid": probe["uid"],
                "health": "ok",
                "lastEvaluation": "2026-07-26T19:00:00Z",
                "queriedDatasourceUIDs": [PROM_UID],
            }]}],
            PROM_UID,
        )
        self.assertEqual(passed["status"], "passed")


class TestSuiteCommands(unittest.TestCase):
    def test_suite_preflights_and_runs_exact_read_only_gcx_commands(self):
        manifest = _manifest(
            _query_probe(),
            _query_probe(
                id="logs",
                kind="logql",
                datasource="loki",
                query='sum(count_over_time({service_name="graph2otel"}[1h]))',
                empty="empty_allowed",
                required_labels=[],
                since="1h",
                step="5m",
            ),
            {
                "id": "rule",
                "kind": "rule_health",
                "datasource": "prometheus",
                "folder_uid": "graph2otel",
                "uid": "g2o-collector-staleness",
            },
        )
        calls = []

        def fake_invoke(args):
            calls.append(args)
            if args[1:3] == ["datasources", "get"]:
                uid = args[3]
                return {"spec": {"type": "prometheus" if uid == PROM_UID else "loki"}}
            if args[1:3] == ["metrics", "query"]:
                return {
                    "status": "success",
                    "data": {"result": [{"metric": {"tenant_id": "tenant-a"}}]},
                }
            if args[1:3] == ["logs", "query"]:
                return {"status": "success", "data": {"result": []}}
            if args[1:4] == ["alert", "rules", "list"]:
                return [{"rules": [{
                    "uid": "g2o-collector-staleness",
                    "health": "ok",
                    "lastEvaluation": "2026-07-26T19:00:00Z",
                    "queriedDatasourceUIDs": [PROM_UID],
                }]}]
            self.fail(f"unexpected command: {args}")

        receipt = semantic_canary.run_suite(
            manifest,
            CONTEXT,
            {"prometheus": PROM_UID, "loki": LOKI_UID},
            fake_invoke,
        )

        self.assertEqual(receipt["status"], "passed")
        self.assertEqual([probe["id"] for probe in receipt["probes"]],
                         ["availability", "logs", "rule"])
        self.assertEqual(calls[0], [
            "gcx", "datasources", "get", PROM_UID,
            "--context", CONTEXT, "-o", "json",
        ])
        self.assertIn([
            "gcx", "logs", "query", "--context", CONTEXT,
            "-d", LOKI_UID,
            'sum(count_over_time({service_name="graph2otel"}[1h]))',
            "--since", "1h", "--step", "5m", "-o", "json",
        ], calls)
        self.assertIn([
            "gcx", "alert", "rules", "list", "--context", CONTEXT,
            "--folder", "graph2otel", "--limit", "0", "-o", "json",
        ], calls)

    def test_backend_parse_failure_is_a_semantic_probe_failure(self):
        def fake_invoke(args):
            if args[1:3] == ["datasources", "get"]:
                return {"spec": {"type": "prometheus"}}
            raise semantic_canary.QueryError("Invalid PromQL query: parse error")

        receipt = semantic_canary.run_suite(
            _manifest(_query_probe()),
            CONTEXT,
            {"prometheus": PROM_UID},
            fake_invoke,
        )
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["probes"][0]["outcome"], "query_error")


class TestGCXFailureBoundary(unittest.TestCase):
    def test_promql_parse_error_is_recognized(self):
        completed = mock.Mock(
            returncode=1,
            stdout="",
            stderr="Error: Invalid PromQL query\nparse error",
        )
        with (
            mock.patch.object(
                semantic_canary.subprocess, "run", return_value=completed
            ),
            self.assertRaises(semantic_canary.QueryError),
        ):
            semantic_canary.invoke_gcx([
                "gcx", "metrics", "query", "sum(", "-o", "json",
            ])

    def test_auth_or_transport_error_remains_operational(self):
        completed = mock.Mock(
            returncode=1,
            stdout="",
            stderr="authentication failed",
        )
        with (
            mock.patch.object(
                semantic_canary.subprocess, "run", return_value=completed
            ),
            self.assertRaises(semantic_canary.OperationalError),
        ):
            semantic_canary.invoke_gcx([
                "gcx", "metrics", "query", "up", "-o", "json",
            ])


class TestCommittedManifest(unittest.TestCase):
    @staticmethod
    def _manifest():
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "spec",
            "grafana-semantic-canary.json",
        )
        return semantic_canary.load_manifest(path)

    def test_committed_manifest_is_valid(self):
        manifest = self._manifest()
        self.assertGreaterEqual(len(manifest["probes"]), 6)

    def test_recording_probes_match_generated_source(self):
        probes = {probe["id"]: probe for probe in self._manifest()["probes"]}
        compliance = dict(build_rules.RECORDING)[
            "intune-compliance-alert-count.json"
        ]
        self.assertEqual(
            probes["compliance-alert-log"]["query"],
            compliance["data"][0]["model"]["expr"],
        )
        self.assertEqual(
            probes["compliance-alert-recording"]["query"],
            compliance["record"]["metric"],
        )

    def test_alert_query_and_uid_match_generated_source(self):
        probes = {probe["id"]: probe for probe in self._manifest()["probes"]}
        staleness = next(
            rule for rule in build_rules.RULES
            if rule["uid"] == "g2o-collector-staleness"
        )
        self.assertEqual(
            probes["collector-staleness-query"]["query"],
            staleness["data"][0]["model"]["expr"],
        )
        self.assertEqual(
            probes["collector-staleness-rule-health"]["uid"],
            staleness["uid"],
        )

    def test_tenant_scoped_canaries_require_tenant_id(self):
        for probe in self._manifest()["probes"]:
            if probe["kind"] in {"promql", "logql"}:
                self.assertIn("tenant_id", probe["required_labels"], probe["id"])


if __name__ == "__main__":
    unittest.main()
