"""Offline query check: python3 grafana/tests/teams_service_loki.py.

Requires the cached grafana/loki:3.6.7 image. Uses a disposable localhost Loki
and synthetic structured metadata, never a configured datasource.
"""

import json
import subprocess
import tempfile
import time
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel-teams.json"


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=15).stdout.strip()


@contextmanager
def _loki():
    container = _docker("create", "--pull=never", "-p", "127.0.0.1::3100", "--tmpfs", "/loki:uid=10001",
                        "grafana/loki:3.6.7", "-config.file=/etc/loki/local-config.yaml",
                        "-ingester.min-ready-duration=0s")
    try:
        with tempfile.TemporaryFile() as logs, subprocess.Popen(
            ["docker", "start", "--attach", container], stdout=logs, stderr=logs, stdin=subprocess.DEVNULL,
        ) as server:
            try:
                opener = build_opener(ProxyHandler({}))  # no workstation proxy

                def request(path, data=None):
                    payload = json.dumps(data).encode() if data is not None else None
                    req = Request(address + path, data=payload, headers={"Content-Type": "application/json"})
                    with opener.open(req, timeout=5) as response:
                        return response.read()

                # The ingester may return 503 while joining its local ring.
                deadline = time.monotonic() + 25
                while True:
                    try:
                        address = "http://" + _docker("port", container, "3100/tcp")
                        request("/ready")
                        break
                    except (OSError, subprocess.CalledProcessError) as exc:
                        if isinstance(exc, HTTPError):
                            exc.close()
                        if time.monotonic() >= deadline or server.poll() is not None:
                            logs.seek(0)
                            raise RuntimeError(logs.read().decode(errors="replace"))
                        time.sleep(0.25)
                yield request
            finally:
                _docker("rm", "--force", container)
                server.wait(timeout=5)
    finally:
        subprocess.run(["docker", "rm", "--force", container], capture_output=True, check=False, timeout=15)


def _query(title):
    panel = next(p["spec"] for p in json.loads(DASHBOARD.read_text())["spec"]["elements"].values()
                 if p["spec"]["title"] == title)
    return panel["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]


class TeamsIssueQueries(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.request = staticmethod(stack.enter_context(_loki()))
        cls.at = time.time_ns() // 1_000_000 * 1_000_000

        def row(offset, tenant, issue_id, title, status, resolved="false", service="Microsoft Teams", **extra):
            return [str(cls.at + offset * 1_000_000_000), f"Observation {offset}: {status}", {
                "tenant_id": tenant, "id": issue_id, "title": title, "status": status, "service": service,
                "is_resolved": resolved, "event_name": "m365.service_health_issue", "classification": "incident",
                **extra,
            }]

        entries = [row(-70, "a", "X", "Old title", "investigating"),  # outside range
                   row(-50, "a", "X", "Old title", "investigating"),
                   row(-40, "a", "X", "New title", "serviceDegradation"),
                   row(-30, "b", "X", "Another tenant", "investigating"),
                   row(-25, "a", "", "No ID", "investigating"),
                   row(-20, "a", "Y", "Other service", "investigating", service="Exchange Online"),
                   row(-11, "a", "Z", "Tied title", "investigating"),
                   row(-11, "a", "Z", "Tied title", "serviceDegradation"),
                   row(-10, "a", "X", "Closed title", "resolved", resolved="true", description="Final post")]
        cls.request("/loki/api/v1/push", {"streams": [{"stream": {"service_name": "graph2otel"}, "values": entries}]})

    def instant(self, title):
        target = _query(title)
        self.assertEqual(target["queryType"], "instant")
        expr = target["expr"].replace("$tenant", ".*").replace("$__range", "1m")
        result = json.loads(self.request("/loki/api/v1/query?" + urlencode({"query": expr, "time": str(self.at)})))
        return [(item["metric"], float(item["value"][1])) for item in result["data"]["result"]]

    def test_open_poll_counts_group_by_tenant_and_id_only(self):
        self.assertCountEqual(self.instant("Distinct Teams issues observed open in range"), [
            ({"tenant_id": "a", "id": "X"}, 2), ({"tenant_id": "b", "id": "X"}, 1), ({"tenant_id": "a", "id": "Z"}, 2),
        ])

    def test_latest_observation_keeps_one_real_record_per_issue_or_marks_a_tie(self):
        self.assertCountEqual(self.instant("Latest Teams issue observations in range"), [
            ({"tenant_id": "a", "id": "X", "title": "Closed title", "status": "resolved",
              "classification": "incident", "is_resolved": "true"}, self.at / 1_000_000 - 10_000),
            ({"tenant_id": "b", "id": "X", "title": "Another tenant", "status": "investigating",
              "classification": "incident", "is_resolved": "false"}, self.at / 1_000_000 - 30_000),
            ({"tenant_id": "a", "id": "Z", "status": "Conflicting observations"}, self.at / 1_000_000 - 11_000),
        ])

    def test_history_keeps_both_titles_and_statuses_and_resolved_text(self):
        def history(title):
            target = _query(title)
            self.assertEqual(target["queryType"], "range")
            expr = target["expr"].replace("$tenant", "a")
            query = urlencode({"query": expr, "start": str(self.at - 60_000_000_000), "end": str(self.at),
                               "limit": target["maxLines"]})
            result = json.loads(self.request("/loki/api/v1/query_range?" + query))
            return [series["stream"] for series in result["data"]["result"]
                    for _ in series["values"] if series["stream"].get("id") == "X"]

        self.assertCountEqual([(row["title"], row["status"]) for row in history("Teams issue observations while open")],
                              [("Old title", "investigating"), ("New title", "serviceDegradation")])
        self.assertEqual([(row["title"], row["description"]) for row in history("Teams resolution events")],
                         [("Closed title", "Final post")])


if __name__ == "__main__":
    unittest.main()
