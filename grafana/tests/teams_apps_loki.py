"""Offline app inventory check: python3 grafana/tests/teams_apps_loki.py.

Uses the cached grafana/loki:3.6.7 image and synthetic structured metadata.
"""

import json
import time
import unittest
from contextlib import ExitStack
from urllib.parse import urlencode

from teams_service_loki import DASHBOARD, _loki


class TeamsAppQueryTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        spec = json.loads(DASHBOARD.read_text())["spec"]
        usage = next(tab["spec"] for tab in spec["layout"]["spec"]["tabs"] if tab["spec"]["title"] == "Usage")
        rows = usage["layout"]["spec"]["rows"]
        panels = [spec["elements"][item["spec"]["element"]["name"]]["spec"]
                  for row in rows for item in row["spec"]["layout"]["spec"]["items"]]
        [cls.panel] = [panel for panel in panels if panel["title"] == "Latest Teams app observations in range"]
        [target] = cls.panel["data"]["spec"]["queries"]
        cls.target = target["spec"]["query"]["spec"]
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.request = staticmethod(stack.enter_context(_loki()))
        cls.at = time.time_ns() // 1_000_000 * 1_000_000

        def row(seconds, tenant="a", team="T1", app="A1", offset_ns=0, **metadata):
            labels = {"event_name": "m365.teams_app", "app_display_name": "Same name", **metadata}
            labels.update({key: val for key, val in zip(("tenant_id", "team_id", "app_id"), (tenant, team, app))
                           if val is not None})
            # Distinct bodies prevent Loki collapsing equal-time entries in the same stream
            # before their structured metadata reaches the query.
            return [str(cls.at + seconds * 1_000_000_000 + offset_ns), json.dumps(labels, sort_keys=True), labels]

        entries = [
            row(-70, team="outside-range"),
            row(-55, app_display_name="Old name", distribution_method="store", rsc_permissions="[old]"),
            row(-45, team="T2"),
            row(-40, team="T2"),
            row(-30, tenant="b"),
            row(-25, tenant="ab"),
            row(-20, distribution_method="sideloaded"),
            row(-20, distribution_method="sideloaded"),  # Same displayed details, not a conflict.
            row(-15, app="A2", has_rsc_permissions="true", rsc_permissions="[one]"),
            row(-15, app="A2", has_rsc_permissions="true", rsc_permissions="[two]"),
            row(-15, app="A3", has_rsc_permissions="false"),
            row(-15, app="A3", offset_ns=1),  # Same displayed millisecond; absent does not mean false.
            row(-12, tenant=None), row(-11, team=None), row(-10, app=""),
            row(-9, event_name="other.event"),
            row(1, app_display_name="After range"),
        ]
        # Make identical evidence appear on a second stream as well.
        cls.request("/loki/api/v1/push", {"streams": [
            {"stream": {"service_name": "graph2otel"}, "values": entries},
            {"stream": {"service_name": "graph2otel", "partition": "two"}, "values": [entries[7]]},
        ]})

    def instant(self, tenants):
        self.assertEqual(self.target["queryType"], "instant")
        expr = self.target["expr"].replace("$tenant", tenants).replace("$__range", "1m")
        result = json.loads(self.request("/loki/api/v1/query?" + urlencode({"query": expr, "time": str(self.at)})))
        return [(item["metric"], float(item["value"][1])) for item in result["data"]["result"]]

    def test_latest_app_observations_preserve_exact_identity_without_inventing_metadata(self):
        viz = self.panel["vizConfig"]
        self.assertEqual(viz["group"], "table")
        self.assertEqual(viz["spec"]["fieldConfig"]["defaults"]["unit"], "dateTimeAsIso")

        def sample(offset, tenant, team, app, **details):
            return ({"tenant_id": tenant, "team_id": team, "app_id": app, **details},
                    self.at // 1_000_000 + offset * 1000)

        tenant_a = [
            sample(-20, "a", "T1", "A1", app_display_name="Same name", distribution_method="sideloaded"),
            sample(-40, "a", "T2", "A1", app_display_name="Same name"),
            sample(-15, "a", "T1", "A2", observation_status="Conflicting observations"),
            sample(-15, "a", "T1", "A3", observation_status="Conflicting observations"),
        ]
        self.assertCountEqual(self.instant("a"), tenant_a)
        self.assertCountEqual(self.instant(".*"), tenant_a + [
            sample(-30, "b", "T1", "A1", app_display_name="Same name"),
            sample(-25, "ab", "T1", "A1", app_display_name="Same name"),
        ])


if __name__ == "__main__":
    unittest.main()
