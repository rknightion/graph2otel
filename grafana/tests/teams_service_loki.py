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
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel-teams.json"


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=15).stdout.strip()


@contextmanager
def _loki(*limits):
    container = _docker("create", "--pull=never", "-p", "127.0.0.1::3100", "--tmpfs", "/loki:uid=10001",
                        "grafana/loki:3.6.7", "-config.file=/etc/loki/local-config.yaml",
                        "-ingester.min-ready-duration=0s", *limits)
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


def _queries(title):
    for element in json.loads(DASHBOARD.read_text())["spec"]["elements"].values():
        panel = element["spec"]
        if panel["title"] == title:
            return [q["spec"]["query"]["spec"] for q in panel["data"]["spec"]["queries"]]
    raise AssertionError(f"Missing dashboard panel: {title}")


def _query(title):
    return _queries(title)[0]


def _interpolate(target, tenant, **inputs):
    expr = target["expr"].replace("$tenant", tenant).replace("$__range", "1m")
    for name, value in inputs.items():
        expr = expr.replace("${" + name + ":percentencode}", quote(value, safe=""))
    return expr


def _instant(request, expr, at):
    result = json.loads(request("/loki/api/v1/query?" + urlencode({"query": expr, "time": str(at)})))
    return [(item["metric"], float(item["value"][1])) for item in result["data"]["result"]]


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
                   row(-50, "a", "X", "Old title", "investigating", last_modified_date_time="2020-01-01T00:00:00Z"),
                   row(-40, "a", "X", "New title", "serviceDegradation", last_modified_date_time="2020-01-01T00:00:00Z"),
                   row(-30, "b", "X", "Another tenant", "investigating"),
                   row(-25, "a", "", "No ID", "investigating"),
                   row(-23, "", "X", "No tenant", "investigating"),
                   row(-22, "a", "R", "Resolution only", "resolved", resolved="true"),
                   row(-20, "a", "Y", "Other service", "investigating", service="Exchange Online"),
                   row(-11, "a", "Z", "Tied title", "investigating"),
                   row(-11, "a", "Z", "Tied title", "serviceDegradation"),
                   row(-10, "a", "X", "Closed title", "resolved", resolved="true", description="Final post")]
        cls.request("/loki/api/v1/push", {"streams": [{"stream": {"service_name": "graph2otel"}, "values": entries}]})

    def instant(self, title):
        target = _query(title)
        self.assertEqual(target["queryType"], "instant")
        return _instant(self.request, _interpolate(target, ".*"), self.at)

    def test_open_poll_counts_group_by_tenant_and_id_only(self):
        self.assertCountEqual(
            [(labels, value) for labels, value in self.instant("Visible open observations by Teams issue")
             if labels.get("g2o_measure") == "Returned open polls"],
            [({"tenant_id": tenant, "id": issue_id, "g2o_measure": "Returned open polls"}, count)
             for tenant, issue_id, count in (("a", "X", 2), ("b", "X", 1), ("a", "Z", 2))],
        )

    def test_open_observation_bounds_exclude_resolutions_and_use_exact_identity(self):
        rows = self.instant("Visible open observations by Teams issue")
        self.assertCountEqual(
            [(labels.get("tenant_id"), labels.get("id"), labels["g2o_measure"], value)
             for labels, value in rows if labels.get("g2o_measure") in ("Earliest returned open", "Latest returned open")],
            [(tenant, issue_id, column, self.at // 1_000_000 + offset * 1000)
             for tenant, issue_id, first, last in (("a", "X", -50, -40), ("b", "X", -30, -30), ("a", "Z", -11, -11))
             for column, offset in (("Earliest returned open", first), ("Latest returned open", last))],
        )

    def test_latest_observation_keeps_one_real_record_per_issue_or_marks_a_tie(self):
        self.assertCountEqual(self.instant("Latest Teams issue observations in range"), [
            ({"tenant_id": "a", "id": "X", "title": "Closed title", "status": "resolved",
              "classification": "incident", "is_resolved": "true"}, self.at / 1_000_000 - 10_000),
            ({"tenant_id": "b", "id": "X", "title": "Another tenant", "status": "investigating",
              "classification": "incident", "is_resolved": "false"}, self.at / 1_000_000 - 30_000),
            ({"id": "X", "title": "No tenant", "status": "investigating",
              "classification": "incident", "is_resolved": "false"}, self.at / 1_000_000 - 23_000),
            ({"tenant_id": "a", "id": "R", "title": "Resolution only", "status": "resolved",
              "classification": "incident", "is_resolved": "true"}, self.at / 1_000_000 - 22_000),
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


class TeamsExactSiteQueries(unittest.TestCase):
    def test_counts_one_population_without_using_the_recent_table_cap(self):
        target = _query("Visible call evidence at the selected site")
        self.assertEqual(target["queryType"], "instant")
        site = "Fixture / `?&=site"
        user = "fixture+caller@example.com"
        at = time.time_ns()

        def row(offset_ms, tenant="a", call_id="X", version="1", **changes):
            fields = {"event_name": "teams.call_stream", "tenant_id": tenant, "call_id": call_id,
                      "version": version, "caller_site": site, "callee_user_principal_name": user, "stream_id": "one"}
            return [str(at + offset_ms * 1_000_000), f"Stored stream observation {offset_ms}", {**fields, **changes}]

        # More matching rows than the 250-row evidence table can show; these
        # are repeated observations of the same call version, not new versions.
        entries = [row(-40_000 + i) for i in range(251)] + [
            row(-30_000, version="2", callee_site=site),  # both sides match, one observation
            row(-29_000, call_id="Y", caller_site="unmapped", callee_site=site,
                callee_user_principal_name="", caller_user_principal_name=user, stream_id=""),
            row(-20_000, tenant="ab"),  # same call/version but another tenant
            row(-19_000, tenant="", call_id="Unlabelled"),
            row(-18_000, call_id="No version", version=""),
            row(-17_000, call_id=""),
            row(-16_000, call_id="Prefix", caller_site=site + "."),
            row(-15_000, call_id="Other user", callee_user_principal_name=user.upper()),
            row(-14_000, call_id="Unknown site", caller_site="unmapped"),
            row(-13_000, call_id="Near a matching stream", event_name="teams.call"),
            row(-61_000, call_id="Outside range"),
        ]
        with _loki() as request:
            request("/loki/api/v1/push", {"streams": [{"stream": {"service_name": "graph2otel"}, "values": entries}]})

            def counts(selected_site=site, tenant=".*", selected_user=user):
                expr = _interpolate(target, tenant, site=selected_site, user=selected_user)
                return _instant(request, expr, at)

            def expected(tenant, *values):
                return [({"tenant_id": tenant, "g2o_measure": measure}, value) for measure, value in zip(
                    ("Returned distinct call IDs", "Returned distinct call versions", "Returned stream observations"),
                    values)]

            self.assertCountEqual(counts(), [*expected("a", 2, 3, 253), *expected("ab", 1, 1, 1)])
            self.assertCountEqual(counts(tenant="a"), expected("a", 2, 3, 253))
            self.assertCountEqual(counts(tenant="a", selected_user=""), expected("a", 3, 4, 254))
            self.assertEqual(counts(selected_site=""), [])
            self.assertEqual(counts(selected_site="unmapped"), [])
            self.assertEqual(counts(selected_site=site.upper()), [])

            # The existing recent evidence remains available, including a row
            # without a version and the unlabelled result without a link field.
            def evidence(query):
                expr = _interpolate(query, ".*", site=site, user=user)
                params = urlencode({"query": expr, "start": str(at - 60_000_000_000), "end": str(at),
                                    "limit": query["maxLines"]})
                result = json.loads(request("/loki/api/v1/query_range?" + params))
                return [series["stream"] for series in result["data"]["result"] for _ in series["values"]]

            labelled, unlabelled = map(evidence, _queries("Call IDs observed at the selected site"))
            self.assertEqual(len(labelled), 250)
            self.assertIn(("a", "No version"), [(row["tenant_id"], row["call_id"]) for row in labelled])
            self.assertEqual([row["g2o_unlabelled_call_id"] for row in unlabelled], ["Unlabelled"])
            self.assertNotIn("call_id", unlabelled[0])

    def test_series_limit_returns_an_error_not_partial_counts(self):
        target = _query("Visible call evidence at the selected site")
        at = time.time_ns()
        with _loki("-querier.max-query-series=5") as request:
            entries = [[str(at - 1_000_000_000), f"Observation from {tenant}", {
                "event_name": "teams.call_stream", "tenant_id": tenant, "call_id": "X", "version": "1",
                "callee_site": "Fixture site",
            }] for tenant in ("a", "b")]
            request("/loki/api/v1/push", {"streams": [{"stream": {"service_name": "graph2otel"}, "values": entries}]})
            with self.assertRaises(HTTPError) as rejected:
                _instant(request, _interpolate(target, ".*", site="Fixture site", user=""), at)
            with rejected.exception as error:
                self.assertIn(b"series (5) reached", error.read())
            counts = _instant(request, _interpolate(target, "a", site="Fixture site", user=""), at)
            self.assertCountEqual(counts, [({"tenant_id": "a", "g2o_measure": name}, 1) for name in (
                "Returned distinct call IDs", "Returned distinct call versions", "Returned stream observations",
            )])


class TeamsVisibleEvidenceLookback(unittest.TestCase):
    def test_silently_shortened_range_only_claims_returned_evidence(self):
        panels = {element['spec']['id']: element['spec']
                  for element in json.loads(DASHBOARD.read_text())['spec']['elements'].values()}
        issue, site = panels[122], panels[1042]
        with _loki('-querier.max-query-lookback=35s') as request:
            at = time.time_ns() // 1_000_000 * 1_000_000
            entries = []
            for tenant, offset, version in (('a', -50, '1'), ('a', -5, '2'), ('older', -50, '1')):
                stamp = str(at + offset * 1_000_000_000)
                entries.extend([
                    [stamp, f'Issue {tenant} {version}', {'tenant_id': tenant, 'id': 'X', 'service': 'Microsoft Teams',
                        'event_name': 'm365.service_health_issue', 'is_resolved': 'false'}],
                    [stamp, f'Stream {tenant} {version}', {'tenant_id': tenant, 'call_id': 'X', 'version': version,
                        'event_name': 'teams.call_stream', 'caller_site': 'Fixture site'}],
                ])
            request('/loki/api/v1/push', {'streams': [{'stream': {'service_name': 'graph2otel'}, 'values': entries}]})

            def read(panel, tenant):
                expr = _interpolate(_query(panel['title']), tenant, site='Fixture site', user='')
                path = '/loki/api/v1/query?' + urlencode({'query': expr, 'time': str(at)})
                payload = json.loads(request(path))
                self.assertEqual(payload['status'], 'success')
                self.assertFalse(payload.get('warnings'))
                return {entry['metric']['g2o_measure']: float(entry['value'][1]) for entry in payload['data']['result']}

            # An older-only tenant has no returned evidence, not zero activity.
            self.assertFalse(read(issue, 'older'))
            self.assertFalse(read(site, 'older'))
            issue_values, site_values = read(issue, 'a'), read(site, 'a')
            opened = (at - 5_000_000_000) / 1_000_000
            self.assertCountEqual(list(issue_values.values()), [1, opened, opened])
            self.assertCountEqual(list(site_values.values()), [1, 1, 1])
            # Nothing in either API response reveals the clipping. The
            # generated labels and empty states must carry the qualification.
            for panel in (issue, site):
                self.assertIn('silently shorten', panel['description'])
                no_value = panel['vizConfig']['spec']['fieldConfig']['defaults']['noValue']
                self.assertIn('returned', no_value)
                self.assertIn('not proof', no_value)
            self.assertEqual(issue_values, {'Returned open polls': 1, 'Earliest returned open': opened,
                                           'Latest returned open': opened})
            self.assertEqual(site_values, {'Returned distinct call IDs': 1, 'Returned distinct call versions': 1,
                                          'Returned stream observations': 1})


class TeamsNavigationEvidenceQueries(unittest.TestCase):
    def test_start_and_routing_navigation_show_scoped_source_rows(self):
        startup = _query("graph2otel process starts")
        polls = _query("Direct Routing effectiveness counts by poll")
        calls = _query("Direct Routing records")
        with _loki() as request:
            at = time.time_ns()

            def row(offset, event, tenant, **fields):
                stamp = str(at + offset * 1_000_000_000)
                return [stamp, f"Observation {offset}", {"event_name": event, "tenant_id": tenant, **fields}]

            start = row(-50, "graph2otel.startup", "a", version="v0.1.0", config_fingerprint="0123456789abcdef")
            start[1] = "graph2otel v0.1.0 started; config fingerprint 0123456789abcdef"
            conflict = row(-10, "teams.direct_routing_poll", "a", trunk_fqdn="trunk.example",
                           effective_attempts="1", poll_attempts="2", source_success_sip_4xx="1")
            clean = row(-9, "teams.direct_routing_poll", "a", trunk_fqdn="trunk.example",
                        effective_attempts="2", poll_attempts="2", source_success_sip_4xx="0")
            raw = row(-40, "teams.direct_routing_call", "a", id="routing-1", trunk_fqdn="trunk.example",
                      successful_call="true", final_sip_code="403")
            entries = [start, conflict, clean, raw,
                       row(-70, "graph2otel.startup", "a", version="outside-range"),
                       row(-39, "graph2otel.startup", "ab", version="other-tenant"),
                       row(-48, "teams.direct_routing_poll", "ab", trunk_fqdn="trunk.example",
                           effective_attempts="3", poll_attempts="3", source_success_sip_4xx="3"),
                       row(-7, "graph2otel.scrape", "a", version="not-a-start")]
            request("/loki/api/v1/push", {"streams": [{"stream": {"service_name": "graph2otel"}, "values": entries}]})

            def history(target):
                self.assertEqual(target["queryType"], "range")
                query = urlencode({"query": target["expr"].replace("$tenant", "a"), "start": str(at - 60_000_000_000),
                                   "end": str(at), "limit": target.get("maxLines", 250)})
                result = json.loads(request("/loki/api/v1/query_range?" + query))
                return [(stamp, body, stream["stream"]) for stream in result["data"]["result"]
                        for stamp, body in stream["values"]]

            def expected(entry):
                return entry[0], entry[1], {key: value for key, value in entry[2].items() if key != "event_name"}

            self.assertEqual([(stamp, body) for stamp, body, _ in history(startup)], [tuple(start[:2])])
            self.assertCountEqual(history(polls), [expected(conflict), expected(clean)])
            self.assertEqual(history(calls), [expected(raw)])


if __name__ == "__main__":
    unittest.main()
