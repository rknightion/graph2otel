"""Verify visible Teams Phone completion receipts with read-only Loki queries."""

import argparse
import json
import os
import re
import subprocess
from urllib.parse import urlencode


RECEIPT_EVENT = "m365.teams.phone_inventory_snapshot"
DETAIL_EVENTS = {
    "teams.phone_numbers": "m365.teams.phone_number",
    "teams.user_configuration": "m365.teams.user_configuration",
}
MAX_TIMESTAMP = 2**63 - 1
MAX_ENTITY_COUNT = 2**64 - 1


class ReadbackError(Exception):
    """An untrusted or incomplete datasource response, with a public reason code."""


def decimal(value, maximum):
    """Accept only bounded, unsigned decimal strings from Loki and the CLI."""
    if (isinstance(value, str) and len(value) <= len(str(maximum))
            and re.fullmatch(r"[0-9]+", value) and int(value) <= maximum):
        return int(value)
    return None


def labels(value):
    if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
        raise ReadbackError("invalid_response")
    return value


def entries(doc, start, end, limit, scope):
    if not isinstance(doc, dict) or doc.get("status") != "success":
        raise ReadbackError("datasource_error")
    data = doc.get("data")
    if (doc.keys() - {"status", "data", "warnings"} or doc.get("warnings", []) != []
            or not isinstance(data, dict) or data.keys() - {"resultType", "result", "stats"}
            or data.get("resultType") != "streams" or not isinstance(data.get("result"), list)):
        # Only accept the standard streams envelope. Do not interpret a warning,
        # extension carrying a continuation, or other partial response as complete.
        raise ReadbackError("invalid_response")
    rows = []
    for stream in data["result"]:
        if (not isinstance(stream, dict) or stream.keys() != {"stream", "values"}
                or not isinstance(stream["values"], list) or not stream["values"]):
            raise ReadbackError("invalid_response")
        # The default Loki encoding puts structured metadata in stream labels.
        attrs = labels(stream["stream"])
        # An absent tenant_id is valid only for the explicit unlabelled scope.
        if (attrs.get("service_name") != "graph2otel" or attrs.get("__error__")
                or any(attrs.get(k, "") != v for k, v in scope.items())):
            raise ReadbackError("unexpected_scope")
        for entry in stream["values"]:
            if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[1], str):
                raise ReadbackError("invalid_response")
            at = decimal(entry[0], MAX_TIMESTAMP)
            if at is None or not start <= at < end or len(rows) == limit:
                raise ReadbackError("invalid_response")
            rows.append((at, attrs))
    return rows


def read_range(args, tenant, event, limit, **match):
    scope = {"event_name": event, "tenant_id": tenant, **match}
    query = '{service_name="graph2otel"}' + "".join(
        f" | {key}={json.dumps(value, ensure_ascii=False)}" for key, value in scope.items()
    )
    # Loki interprets short (ten or fewer digits) integral timestamps as seconds.
    params = urlencode({"query": query, "start": f"{args.start_ns:011d}", "end": f"{args.end_ns:011d}",
                        "direction": "backward", "limit": limit})
    path = f"/api/datasources/proxy/uid/{args.datasource}/loki/api/v1/query_range?{params}"
    # gcx otherwise lets GRAFANA_* override the selected context's destination
    # or auth. Use the operator's named context, not an ambient override.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GRAFANA_")}
    env.update(GCX_AGENT_MODE="0", GCX_TELEMETRY="disabled", GCX_NO_UPDATE_NOTIFIER="1")
    try:
        run = subprocess.run(
            ["gcx", "--context", args.context, "api", path, "--method", "GET", "--output", "json"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReadbackError("datasource_error") from exc
    # Do not relay request URLs, row data or errors that could contain them.
    if run.returncode != 0:
        raise ReadbackError("datasource_error")
    try:
        doc = json.loads(run.stdout)
    except (ValueError, RecursionError) as exc:
        raise ReadbackError("invalid_response") from exc
    return entries(doc, args.start_ns, args.end_ns, limit, scope)


def clipped(attrs):
    return attrs.get("attrs_truncated") not in (None, "false")


def verify(args, tenant_index, tenant, collector):
    result = {"tenant_index": tenant_index, "collector": collector, "receipt_ns": None,
              "entity_count": None, "state": "not_proven_complete"}

    def unproven(reason):
        return {**result, "reason": reason}

    try:
        markers = read_range(args, tenant, RECEIPT_EVENT, 2, collector=collector)
    except ReadbackError as exc:
        return unproven(f"receipt_{exc}")
    if not markers:
        return unproven("no_receipt")
    markers.sort(key=lambda row: row[0], reverse=True)
    at, receipt = markers[0]
    result["receipt_ns"] = str(at)
    if len(markers) == 2 and markers[1][0] == at:
        return unproven("tied_latest_receipt")
    snapshot = receipt.get("snapshot_id", "")
    count = decimal(receipt.get("entity_count"), MAX_ENTITY_COUNT)
    if not re.fullmatch(r"[0-9a-f]{32}", snapshot) or count is None or clipped(receipt):
        return unproven("malformed_receipt")
    result["entity_count"] = count
    if count + 1 > args.read_limit:
        return unproven("over_read_limit")
    try:
        detail = read_range(args, tenant, DETAIL_EVENTS[collector], count + 1, snapshot_id=snapshot)
    except ReadbackError as exc:
        return unproven(f"detail_{exc}")
    if len(detail) == count + 1:
        return unproven("detail_at_limit")
    if len(detail) != count:
        return unproven("detail_count_mismatch")
    ids = set()
    for _, row in detail:
        if clipped(row):
            return unproven("clipped_detail")
        entity = row.get("id", "")
        if not entity.strip() or entity in ids:
            return unproven("missing_or_duplicate_id")
        ids.add(entity)
    return {**result, "state": "verified_complete"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--context", required=True, help="configured gcx stack context")
    parser.add_argument("--datasource", required=True, help="Loki datasource UID in that stack")
    parser.add_argument("--tenant", required=True, action="append", help="exact tenant_id; repeat, or use '' for unlabelled")
    parser.add_argument("--collector", choices=DETAIL_EVENTS, action="append", help="repeat; default is both Phone collectors")
    parser.add_argument("--start-ns", required=True, help="inclusive absolute Unix time in nanoseconds")
    parser.add_argument("--end-ns", required=True, help="exclusive absolute Unix time in nanoseconds")
    parser.add_argument("--read-limit", default="251", help="maximum rows per query (default: %(default)s), including the extra probe row")
    args = parser.parse_args()
    args.start_ns = decimal(args.start_ns, MAX_TIMESTAMP)
    args.end_ns = decimal(args.end_ns, MAX_TIMESTAMP)
    args.read_limit = decimal(args.read_limit, 2**32 - 1)
    if args.start_ns is None or args.end_ns is None or not args.start_ns < args.end_ns:
        parser.error("absolute bounds must satisfy 0 <= start-ns < end-ns <= 2^63-1")
    if args.read_limit is None or args.read_limit < 2:
        parser.error("read-limit must be an integer from 2 to 2^32-1")
    if not args.context.strip() or not re.fullmatch(r"[A-Za-z0-9_-]+", args.datasource):
        parser.error("a non-empty context and a valid datasource UID are required")
    if len(set(args.tenant)) != len(args.tenant) or any(t and not t.isprintable() for t in args.tenant):
        parser.error("each tenant must be exact and unique; use an empty string only for an unlabelled scope")
    collectors = args.collector or DETAIL_EVENTS
    if len(set(collectors)) != len(collectors):
        parser.error("each collector may be given once")

    failed = False
    for index, tenant in enumerate(args.tenant, start=1):
        for collector in collectors:
            result = verify(args, index, tenant, collector)
            print(json.dumps(result), flush=True)
            failed |= result["state"] != "verified_complete"
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
