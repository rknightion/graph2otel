"""Replay Loki responses through the read-only Teams Phone verifier command."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlencode


REPO = Path(__file__).resolve().parents[2]
START = 1700000000000000000
END = START + 100
NUMBERS = "teams.phone_numbers"
USERS = "teams.user_configuration"
RECEIPT = "m365.teams.phone_inventory_snapshot"
NUMBER = "m365.teams.phone_number"
USER = "m365.teams.user_configuration"
OLD = "0" * 32
NEW = "1" * 32
PROXY = "/api/datasources/proxy/uid/fixture-logs/loki/api/v1/query_range?"


def response(*streams):
    stats = {"summary": {"totalEntriesReturned": sum(len(s["values"]) for s in streams)}}
    return {"status": "success", "data": {"resultType": "streams", "result": streams, "stats": stats}}


def stream(at, event, tenant, **attrs):
    labels = {"service_name": "graph2otel", "event_name": event, **attrs}
    if tenant != "":
        labels["tenant_id"] = tenant
    return {"stream": labels, "values": [[str(START + at), "fixture body"]]}


def receipt(at, tenant, collector, snapshot, count):
    return stream(at, RECEIPT, tenant, collector=collector, snapshot_id=snapshot, entity_count=count)


def replay(tenant, event, scope_key, scope_value, limit, payload, exit_code=0, *, start=START, end=END):
    # Compare the wire query, not just outputs from a fake that returns rows
    # regardless of whether the verifier actually asked for that snapshot.
    query = (f'{{service_name="graph2otel"}} | event_name="{event}"'
             f' | tenant_id={json.dumps(tenant, ensure_ascii=False)}'
             f' | {scope_key}="{scope_value}"')
    path = PROXY + urlencode({"query": query, "start": start, "end": end,
                              "direction": "backward", "limit": limit})
    return {"path": path, "payload": payload, "exit_code": exit_code}


def markers(tenant, collector, *rows):
    return replay(tenant, RECEIPT, "collector", collector, 2, response(*rows))


def detail(tenant, event, snapshot, limit, *rows):
    return replay(tenant, event, "snapshot_id", snapshot, limit, response(*rows))


FAKE_GCX = '''
import json
import os
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

fixture = Path(os.environ["HOME"])
with (fixture / "calls").open("a") as log:
    print(json.dumps(sys.argv[1:]), file=log)
ctx, name, api, path, method, get, fmt, encoding = sys.argv[1:]
assert (ctx, name, api, method, get, fmt, encoding) == (
    "--context", "fixture-context", "api", "--method", "GET", "--output", "json")
assert "GRAFANA_SERVER" not in os.environ and "GRAFANA_TOKEN" not in os.environ
actual = urlsplit(path)
for replay in json.loads((fixture / "replays.json").read_text()):
    expected = urlsplit(replay["path"])
    if (actual.path, parse_qs(actual.query)) == (expected.path, parse_qs(expected.query)):
        print(json.dumps(replay["payload"]))
        if replay["exit_code"]:
            print("fixture private diagnostic", file=sys.stderr)
        sys.exit(replay["exit_code"])
sys.exit("unexpected query")
'''


class VerifyPhoneInventoryTest(unittest.TestCase):
    def run_cli(self, replays, *args, start=START, end=END):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            fake = scratch / "gcx"
            fake.write_text(f"#!{sys.executable}\n" + FAKE_GCX, encoding="utf-8")
            fake.chmod(0o700)
            (scratch / "replays.json").write_text(json.dumps(replays), encoding="utf-8")
            run = subprocess.run(
                ["just", "verify-phone-inventory", "--context", "fixture-context", "--datasource",
                 "fixture-logs", "--start-ns", str(start), "--end-ns", str(end), *args],
                cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10,
                env={"HOME": tmp, "PATH": tmp + os.pathsep + os.environ["PATH"],
                     "GRAFANA_SERVER": "unused", "GRAFANA_TOKEN": "unused"},
            )
            calls_file = scratch / "calls"
            calls = [json.loads(line)[3] for line in calls_file.read_text().splitlines()] if calls_file.exists() else []
        return run, calls

    def assert_calls(self, calls, replays):
        self.assertCountEqual(calls, [r["path"] for r in replays])

    def test_latest_exact_snapshot_replaces_history(self):
        # Two number detail rows were visible for the old poll. One number is
        # removed and the surviving number has a different assignment now.
        tenant = "fixture-a"
        replays = [
            markers(tenant, NUMBERS, receipt(11, tenant, NUMBERS, OLD, "2"),
                    receipt(51, tenant, NUMBERS, NEW, "1")),
            detail(tenant, NUMBER, NEW, 2,
                   stream(50, NUMBER, tenant, snapshot_id=NEW, id="fixture-survivor", assignment_status="userAssigned")),
        ]
        history = detail(tenant, NUMBER, OLD, 3,
                         stream(9, NUMBER, tenant, snapshot_id=OLD, id="fixture-removed"),
                         stream(10, NUMBER, tenant, snapshot_id=OLD, id="fixture-survivor", assignment_status="unassigned"))
        run, calls = self.run_cli([*replays, history], "--tenant", tenant, "--collector", NUMBERS)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {
            "tenant_index": 1, "collector": NUMBERS, "receipt_ns": str(START + 51),
            "entity_count": 1, "state": "verified_complete",
        })
        self.assert_calls(calls, replays)
        self.assertNotIn("fixture-survivor", run.stdout + run.stderr)

    def test_independent_scopes_late_detail_and_known_zero(self):
        a, b = 'fixture-"a', "fixture-b"
        an = stream(40, NUMBER, a, snapshot_id=NEW, id="fixture-number")
        au = stream(61, USER, a, snapshot_id=NEW, id="fixture-user")
        late = stream(62, USER, a, snapshot_id=NEW, id="fixture-late")
        bu = stream(81, USER, b, snapshot_id=NEW, id="fixture-user")
        before = detail(a, USER, NEW, 3, au)
        after = detail(a, USER, NEW, 3, au, late)
        replays = [
            markers(a, NUMBERS, receipt(41, a, NUMBERS, NEW, "1")), detail(a, NUMBER, NEW, 2, an),
            markers(a, USERS, receipt(63, a, USERS, NEW, "2")), before,
            markers(b, NUMBERS, receipt(25, b, NUMBERS, NEW, "1"), receipt(47, b, NUMBERS, OLD, "0")),
            detail(b, NUMBER, OLD, 1),
            markers(b, USERS, receipt(82, b, USERS, NEW, "1")), detail(b, USER, NEW, 2, bu),
        ]
        history = detail(b, NUMBER, NEW, 2, stream(24, NUMBER, b, snapshot_id=NEW, id="fixture-old"))
        for detail_replay, exit_code in ((before, 1), (after, 0)):
            with self.subTest(exit_code=exit_code):
                queries = [detail_replay if replay is before else replay for replay in replays]
                run, calls = self.run_cli([*queries, history], "--tenant", a, "--tenant", b)
                self.assertEqual(run.returncode, exit_code, run.stderr)
                self.assert_calls(calls, queries)
                reports = list(map(json.loads, run.stdout.splitlines()))
                self.assertEqual([(r["tenant_index"], r["collector"], r["receipt_ns"], r["entity_count"], r["state"])
                                  for r in reports], [
                    (1, NUMBERS, str(START + 41), 1, "verified_complete"),
                    (1, USERS, str(START + 63), 2, "not_proven_complete" if exit_code else "verified_complete"),
                    (2, NUMBERS, str(START + 47), 0, "verified_complete"),
                    (2, USERS, str(START + 82), 1, "verified_complete"),
                ])
                if exit_code:
                    self.assertEqual(reports[1]["reason"], "detail_count_mismatch")
                for private in (a, b, NEW, OLD, "fixture-late", "fixture-user"):
                    self.assertNotIn(private, run.stdout + run.stderr)

    def assert_unproven(self, replays, reason, at, count, *args, tenant="fixture-a", history=()):
        run, calls = self.run_cli([*replays, *history], "--tenant", tenant, "--collector", NUMBERS, *args)
        self.assertEqual(run.returncode, 1, (run.stdout, run.stderr))
        self.assert_calls(calls, replays)
        self.assertEqual(json.loads(run.stdout), {
            "tenant_index": 1, "collector": NUMBERS,
            "receipt_ns": str(START + at) if at is not None else None, "entity_count": count,
            "state": "not_proven_complete", "reason": reason,
        })
        self.assertEqual(run.stderr, "")

    def test_missing_tied_or_malformed_latest_receipt_does_not_use_older_detail(self):
        a = "fixture-a"
        older = receipt(21, a, NUMBERS, OLD, "0")
        latest = receipt(51, a, NUMBERS, NEW, "0")
        no_snapshot = receipt(51, a, NUMBERS, "", "0")
        no_count = receipt(51, a, NUMBERS, NEW, "0")
        del no_count["stream"]["entity_count"]
        for rows, reason, at in (
            ([], "no_receipt", None),
            ([latest, receipt(51, a, NUMBERS, OLD, "0")], "tied_latest_receipt", 51),
            ([older, no_snapshot], "malformed_receipt", 51),
            ([older, no_count], "malformed_receipt", 51),
            ([older, receipt(51, a, NUMBERS, NEW, "-1")], "malformed_receipt", 51),
            ([older, receipt(51, a, NUMBERS, NEW, "1.0")], "malformed_receipt", 51),
        ):
            with self.subTest(rows=rows):
                self.assert_unproven([markers(a, NUMBERS, *rows)], reason, at, None,
                                     history=[detail(a, NUMBER, OLD, 1), detail(a, NUMBER, NEW, 1)])

    def test_count_must_fit_with_an_extra_probe_row(self):
        a = ""  # Explicitly unlabelled; Loki omits tenant_id from the stream.
        latest = receipt(51, a, NUMBERS, NEW, "2")
        marker_query = markers(a, NUMBERS, latest)
        rows = detail(a, NUMBER, NEW, 3,
                      stream(49, NUMBER, a, snapshot_id=NEW, id="fixture-first"),
                      stream(50, NUMBER, a, snapshot_id=NEW, id="fixture-second"))
        self.assert_unproven([marker_query], "over_read_limit", 51, 2, "--read-limit", "2", tenant=a,
                             history=[rows])
        run, calls = self.run_cli([marker_query, rows], "--tenant", a, "--collector", NUMBERS, "--read-limit", "3")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_calls(calls, [marker_query, rows])
        self.assertEqual(json.loads(run.stdout)["state"], "verified_complete")

    def test_detail_requires_the_exact_unclipped_distinct_population(self):
        a = "fixture-a"
        marker_query = markers(a, NUMBERS, receipt(51, a, NUMBERS, NEW, "2"))
        first = stream(48, NUMBER, a, snapshot_id=NEW, id="fixture-first")
        second = stream(49, NUMBER, a, snapshot_id=NEW, id="fixture-second")
        third = stream(50, NUMBER, a, snapshot_id=NEW, id="fixture-third")
        # Two entries of one ID in one result stream still count as two rows.
        repeated = first | {"values": [*first["values"], *second["values"]]}
        for bad_rows, reason in (
            ([repeated], "missing_or_duplicate_id"),
            ([first, stream(49, NUMBER, a, snapshot_id=NEW)], "missing_or_duplicate_id"),
            ([first, stream(49, NUMBER, a, snapshot_id=NEW, id="fixture-second", attrs_truncated="true")],
             "clipped_detail"),
            ([first, stream(49, NUMBER, a, snapshot_id=OLD, id="fixture-second")], "detail_unexpected_scope"),
            ([first, stream(49, NUMBER, "fixture-b", snapshot_id=NEW, id="fixture-second")], "detail_unexpected_scope"),
            ([first, stream(49, USER, a, snapshot_id=NEW, id="fixture-second")], "detail_unexpected_scope"),
            ([first, stream(100, NUMBER, a, snapshot_id=NEW, id="fixture-second")], "detail_invalid_response"),
        ):
            with self.subTest(reason=reason, rows=bad_rows):
                self.assert_unproven([marker_query, detail(a, NUMBER, NEW, 3, *bad_rows)], reason, 51, 2)
        # Requesting only the declared count could look complete while hiding
        # the third row, even when the backend honours the requested cap.
        self.assert_unproven([marker_query, detail(a, NUMBER, NEW, 3, third, second, first)],
                             "detail_at_limit", 51, 2, history=[detail(a, NUMBER, NEW, 2, third, second)])
        # Zero is only verified after probing for a contradictory matching row.
        zero = markers(a, NUMBERS, receipt(51, a, NUMBERS, NEW, "0"))
        self.assert_unproven([zero, detail(a, NUMBER, NEW, 1, first)], "detail_at_limit", 51, 0)

    def test_partial_or_failed_reads_do_not_prove_even_zero(self):
        a = "fixture-a"
        marker_query = markers(a, NUMBERS, receipt(51, a, NUMBERS, NEW, "0"))
        for payload, code, reason in (
            (response() | {"warnings": ["fixture partial"]}, 0, "invalid_response"),
            ({"status": "success", "data": response()["data"] | {"nextCursor": "fixture cursor"}},
             0, "invalid_response"),
            (response() | {"status": "error", "error": "fixture private diagnostic"}, 0, "datasource_error"),
            (response(), 1, "datasource_error"),
        ):
            with self.subTest(payload=payload, code=code):
                read = replay(a, NUMBER, "snapshot_id", NEW, 1, payload, code)
                self.assert_unproven([marker_query, read], "detail_" + reason, 51, 0)

    def test_missing_tenant_does_not_query_an_ambient_scope(self):
        run, calls = self.run_cli([])
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertEqual(calls, [])

    def test_bounds_near_the_epoch_are_sent_as_nanoseconds(self):
        a = "fixture-a"
        # Loki reads a short integral time parameter as seconds. These two
        # nanosecond bounds differ by one ns and only the lower edge is included.
        marker = receipt(0, a, NUMBERS, NEW, "0")
        marker["values"][0][0] = "7"
        bounds = {"start": "00000000007", "end": "00000000008"}
        replays = [replay(a, RECEIPT, "collector", NUMBERS, 2, response(marker), **bounds),
                   replay(a, NUMBER, "snapshot_id", NEW, 1, response(), **bounds)]
        run, calls = self.run_cli(replays, "--tenant", a, "--collector", NUMBERS, start=7, end=8)
        self.assertEqual(run.returncode, 0, (run.stdout, run.stderr))
        self.assert_calls(calls, replays)
        self.assertEqual(json.loads(run.stdout)["receipt_ns"], "7")
