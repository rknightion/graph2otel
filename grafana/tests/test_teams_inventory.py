"""Offline query contracts for the rendered Teams Phone inventory tab."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import catalog
import v2
from boards import teams


def inventory_panels(cat):
    _, manifest = teams.build(cat)
    tab = next(tab for tab in manifest["spec"]["layout"]["spec"]["tabs"]
               if tab["spec"]["title"] == "Phone inventory")
    names = v2.placed_element_names({"spec": {"layout": {"spec": {"tabs": [tab]}}}})
    return {manifest["spec"]["elements"][name]["spec"]["title"]:
            manifest["spec"]["elements"][name]["spec"] for name in names}


@unittest.skipUnless(shutil.which("promtool"), "needs promtool to execute the rendered queries")
class TeamsInventoryTests(unittest.TestCase):
    def test_current_counts_exclude_removed_buckets_and_previous_assignments(self):
        cat = catalog.load()
        panels = inventory_panels(cat)
        numbers = cat.metric("m365.teams.phone_numbers.total").prom
        users = cat.metric("m365.teams.user_configuration.users").prom

        def series(metric, tenant, values, **labels):
            labels = {"tenant_id": tenant, **labels}
            selector = ",".join(f'{key}="{value}"' for key, value in labels.items())
            return {"series": f"{metric}{{{selector}}}", "values": values}

        def number(tenant, assignment, kind, values):
            return series(numbers, tenant, values, assignment_status=assignment,
                          number_type=kind, capability="userAssignment", activation_state="activated")

        def user(tenant, account, voice, values):
            return series(users, tenant, values, account_type=account, enterprise_voice_enabled=voice)

        # Both old buckets are still inside Prometheus lookback. A direct
        # routing number changed assignment and the only calling plan number
        # disappeared. The other tenant did not export at the same time.
        fixtures = [number("one", "unassigned", "directRouting", "1 _ _"),
                    number("one", "unassigned", "callingPlan", "1 _ _"),
                    number("one", "userAssigned", "directRouting", "_ 1 1"),
                    number("two", "unassigned", "directRouting", "1 1 _"),
                    user("one", "resourceAccount", "true", "1 _ _"),
                    user("one", "user", "true", "2 3 3"),
                    user("two", "user", "false", "2 2 _")]

        def query(title, samples):
            spec, = (target["spec"]["query"]["spec"] for target in panels[title]["data"]["spec"]["queries"])
            return {"expr": spec["expr"].replace("$tenant", ".*"),
                    "eval_time": "2m", "exp_samples": samples}

        def sample(value, **labels):
            return {"labels": "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}", "value": value}

        def bucket(tenant, status):
            return sample(1, tenant_id=tenant, capability="userAssignment", number_type="directRouting",
                          assignment_status=status, activation_state="activated")

        checks = [query("Phone numbers by capability and assignment", [bucket("one", "userAssigned"),
                                                                       bucket("two", "unassigned")]),
                  query("Teams user configurations", [sample(3, tenant_id="one"), sample(2, tenant_id="two")]),
                  query("Enterprise Voice enabled users", [sample(3, tenant_id="one"), sample(0, tenant_id="two")])]
        self.assert_queries(fixtures, checks)

    def test_empty_policy_export_replaces_old_policy_values_in_lookback(self):
        cat = catalog.load()
        metric = cat.metric("m365.teams.user_configuration.effective_policy_assignments").prom
        title = "Reported effective policy assignments"
        spec, = [target["spec"]["query"]["spec"]
                 for target in inventory_panels(cat)[title]["data"]["spec"]["queries"]]
        expr = spec["expr"].replace("$tenant", ".*")
        buckets = {"TeamsCallingPolicy": 3, "OnlineVoiceRoutingPolicy": 2, "unknown": 1}
        fixtures = [{"series": f'{metric}{{tenant_id="fixture",policy_type="{kind}"}}', "values": f"{old} 0 _"}
                    for kind, old in buckets.items()]
        self.assert_queries(fixtures, [{"expr": expr, "eval_time": when, "exp_samples": [
            {"labels": f'{{tenant_id="fixture",policy_type="{kind}"}}', "value": old if when == "0m" else 0}
            for kind, old in buckets.items()]} for when in ("0m", "2m")])

    def test_last_reported_poll_finish_does_not_infer_success(self):
        cat = catalog.load()
        panels = inventory_panels(cat)
        timestamp = cat.metric("graph2otel.scrape.last_timestamp").prom
        success = cat.metric("graph2otel.scrape.success").prom
        numbers, users = "teams.phone_numbers", "teams.user_configuration"
        # Independently exported success and finish samples can be mixed:
        # the failed finish at 120 has the previous success flag alongside it.
        fixtures = [{"series": f'{metric}{{tenant_id="{tenant}",collector="{collector}"}}', "values": values}
                    for tenant, collector, finished, results in (
                        ("one", numbers, "_ 60 120 180", "_ 1 1 0"),
                        ("one", users, "_ 60 120 180", "_ 0 0 0"),
                        ("two", numbers, "_ 60 120 180", "_ 0 0 0"),
                    ) for metric, values in ((timestamp, finished), (success, results))]
        panel = panels.get("Last reported inventory poll finish")
        self.assertIsNotNone(panel, "the inventory tab must not claim a successful poll from independent samples")
        spec, = (target["spec"]["query"]["spec"] for target in panel["data"]["spec"]["queries"])
        self.assertTrue(spec["instant"])
        self.assertNotIn(success, spec["expr"], "success and finish gauges are not atomic")
        self.assert_queries(fixtures, [{
            "expr": spec["expr"].replace("$tenant", ".*").replace("$__range", "3m").replace("${__from}", "0"),
            "eval_time": "3m", "exp_samples": [
                {"labels": f'{{tenant_id="{tenant}",collector="{collector}"}}', "value": 180000}
                for tenant, collector in (("one", numbers), ("one", users), ("two", numbers))
            ],
        }])

    def assert_queries(self, fixtures, checks):
        test = {"evaluation_interval": "1m", "tests": [{"interval": "1m", "input_series": fixtures,
                                                        "promql_expr_test": checks}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "teams_inventory_test.yaml"
            path.write_text(json.dumps(test), encoding="utf-8")
            run = subprocess.run(["promtool", "test", "rules", str(path)],
                                 capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
