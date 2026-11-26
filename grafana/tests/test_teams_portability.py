"""The hand-maintained Teams dashboard stays importable on any stack."""

import json
import re
import unittest

import build_dashboard


def datasource_refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "datasource":
                yield value
            yield from datasource_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from datasource_refs(value)


class TeamsPortabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_dashboard.load_teams()

    def test_identity_is_unchanged(self):
        self.assertEqual(self.manifest["metadata"]["name"], "graph2otel-teams")
        self.assertEqual(self.manifest["spec"]["title"], "graph2otel Teams")

    def test_datasource_variables_default_to_grafana_cloud(self):
        variables = {v["spec"]["name"]: v for v in self.manifest["spec"]["variables"]}
        for name, plugin, default in (("datasource", "prometheus", "grafanacloud-prom"),
                                      ("loki_datasource", "loki", "grafanacloud-logs")):
            with self.subTest(variable=name):
                variable = variables[name]
                self.assertEqual(variable["kind"], "DatasourceVariable")
                self.assertEqual(variable["spec"]["pluginId"], plugin)
                self.assertEqual(variable["spec"]["current"]["value"], default)

    def test_every_datasource_is_a_variable_reference(self):
        refs = list(datasource_refs(self.manifest["spec"]))
        self.assertGreater(len(refs), 100)
        for ref in refs:
            with self.subTest(ref=ref):
                value = ref.get("uid", ref.get("name")) if isinstance(ref, dict) else ref
                self.assertIn(value, ("${datasource}", "${loki_datasource}"))

    def test_no_hard_coded_datasource_uid(self):
        text = json.dumps(self.manifest)
        self.assertEqual(re.findall(r'"uid": "(?!\$\{)[^"]*"', text), [])


if __name__ == "__main__":
    unittest.main()
