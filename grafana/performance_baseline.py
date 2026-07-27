#!/usr/bin/env python3
"""Measure graph2otel dashboard shape and optional live render latency (#309)."""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter


class OperationalError(RuntimeError):
    """A dashboard or live snapshot could not be measured."""


COUNT_FIELDS = (
    "panels",
    "tabs",
    "leaves",
    "rows",
    "collapsed_rows",
    "expanded_rows",
    "query_panels",
    "targets",
    "range_targets",
    "instant_targets",
    "unknown_mode_targets",
    "expression_bytes",
)


def _require_v2(doc: dict) -> None:
    """Reject a v1-shaped document loudly instead of measuring it as zeros.

    graph2otel moved from six v1 dashboards to one v2 manifest (#399). The v1
    keys this module used to read (``panels``, ``uid``, ``title``, ``time``,
    ``refresh``, per-panel ``targets``) do not exist in v2 — a v1-shaped
    document has none of them, so the old code silently reported
    ``panels: 0, targets: 0, uid: null`` instead of failing. That is exactly
    the bug this check exists to make impossible: a harness that measures
    nothing must error, not report a healthy-looking zero.
    """
    if doc.get("apiVersion") != "dashboard.grafana.app/v2" or doc.get("kind") != "Dashboard":
        raise OperationalError(
            "expected a dashboard.grafana.app/v2 Dashboard manifest, got "
            f"apiVersion={doc.get('apiVersion')!r} kind={doc.get('kind')!r} — "
            "this looks like a v1-shaped dashboard (#399 migrated the estate "
            "to v2; see grafana/v2.py). A v1 document has no spec.elements/"
            "spec.layout and must be rejected, not measured as all zeros."
        )
    spec = doc.get("spec")
    if not isinstance(spec, dict) or "elements" not in spec or "layout" not in spec:
        raise OperationalError(
            "v2 manifest is missing spec.elements or spec.layout — cannot "
            "measure a manifest with no panels or layout"
        )
    if "name" not in doc.get("metadata", {}):
        raise OperationalError("v2 manifest is missing metadata.name (the v2 identity)")


def _walk_v2_tabs(tabs: list):
    """Yield every ``TabsLayoutTab`` spec, depth-first (mirrors v2._walk_tabs).

    Written locally rather than imported from ``v2`` because that walker is a
    private (underscore-prefixed) helper not meant for outside callers; this
    module only needs read-only traversal, not v2's build-time invariants.
    """
    for tab in tabs:
        spec = tab["spec"]
        yield spec
        layout = spec.get("layout", {})
        if layout.get("kind") == "TabsLayout":
            yield from _walk_v2_tabs(layout["spec"]["tabs"])


def _rows_of(tab_spec: dict) -> list:
    layout = tab_spec.get("layout", {})
    if layout.get("kind") == "RowsLayout":
        return layout["spec"]["rows"]
    return []


def _analyze_dashboard(doc: dict, source: str) -> tuple:
    _require_v2(doc)
    spec = doc["spec"]
    elements = spec.get("elements", {})
    panels = list(elements.values())

    top_tabs = spec["layout"]["spec"]["tabs"]
    all_tab_specs = list(_walk_v2_tabs(top_tabs))
    # A "leaf" is a tab whose own content is rows of panels (v2.leaf()), as
    # opposed to a domain tab whose content is a nested TabsLayout of leaves
    # (v2.domain()). Topology (tabs/leaves) is a new, real dimension of the
    # estate's size that the old flat v1 panel list had no notion of.
    leaf_specs = [t for t in all_tab_specs if t.get("layout", {}).get("kind") == "RowsLayout"]
    rows = [row for leaf in leaf_specs for row in _rows_of(leaf)]

    query_panels = []
    expressions = []
    range_targets = 0
    instant_targets = 0
    unknown_targets = 0

    for panel in panels:
        panel_targets = []
        queries = panel.get("spec", {}).get("data", {}).get("spec", {}).get("queries", [])
        for query in queries:
            # The v1 target dict survives, minus its "datasource" key, at
            # query.spec.query.spec (see v2.panel_element/_query) — so the
            # same range/instant/queryType fields are read from there.
            target = query.get("spec", {}).get("query", {}).get("spec", {})
            expr = target.get("expr")
            if not isinstance(expr, str) or not expr:
                continue
            panel_targets.append(target)
            expressions.append(expr)
            if target.get("instant") is True:
                instant_targets += 1
            elif target.get("range") is True or target.get("queryType") == "range":
                range_targets += 1
            else:
                unknown_targets += 1
        if panel_targets:
            query_panels.append(panel)

    counts = Counter(expressions)
    repeated = {
        expr: count for expr, count in sorted(counts.items())
        if count > 1
    }
    time_settings = spec.get("timeSettings", {})
    result = {
        "source": source,
        # v2 has no top-level uid; metadata.name is the identity (#399).
        "name": doc["metadata"]["name"],
        "title": spec.get("title"),
        "default_time": {
            "from": time_settings.get("from"),
            "to": time_settings.get("to"),
        },
        "auto_refresh": time_settings.get("autoRefresh"),
        "panels": len(panels),
        "tabs": len(top_tabs),
        "leaves": len(leaf_specs),
        "rows": len(rows),
        "collapsed_rows": sum(bool(row["spec"].get("collapse")) for row in rows),
        "expanded_rows": sum(not bool(row["spec"].get("collapse")) for row in rows),
        "query_panels": len(query_panels),
        "targets": len(expressions),
        "range_targets": range_targets,
        "instant_targets": instant_targets,
        "unknown_mode_targets": unknown_targets,
        "unique_expressions": len(counts),
        "repeated_expressions": repeated,
        "expression_bytes": sum(len(expr.encode("utf-8")) for expr in expressions),
    }
    return result, expressions


def analyze_dashboard(doc: dict, source: str) -> dict:
    result, _ = _analyze_dashboard(doc, source)
    return result


def static_receipt(paths: list) -> dict:
    dashboards = []
    all_expressions = []
    for path in sorted(paths):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise OperationalError(f"cannot load dashboard {path}: {exc}") from exc
        dashboard, expressions = _analyze_dashboard(doc, os.path.basename(path))
        dashboards.append(dashboard)
        all_expressions.extend(expressions)
    if not dashboards:
        raise OperationalError("no dashboards selected")

    totals = {
        field: sum(item[field] for item in dashboards)
        for field in COUNT_FIELDS
    }
    totals["dashboards"] = len(dashboards)
    expression_counts = Counter(all_expressions)
    totals["unique_expressions"] = len(expression_counts)
    return {
        "schema": 1,
        "status": "measured",
        "dashboards": dashboards,
        "totals": totals,
        "repeated_expressions": {
            expr: count for expr, count in sorted(expression_counts.items())
            if count > 1
        },
    }


def _redact(text: str, values) -> str:
    for value in sorted(
            (str(value) for value in values if value),
            key=len,
            reverse=True):
        text = text.replace(value, "<redacted>")
    return text


def snapshot_once(dashboard_name: str, context: str, variables: dict,
                  *, since: str = "6h", width: int = 1920,
                  height: int = 1080, theme: str = "dark",
                  timezone: str = "UTC") -> dict:
    # gcx addresses a dashboard by its v2 metadata.name; there is no v1 uid
    # any more (#399).
    with tempfile.TemporaryDirectory(prefix="graph2otel-render-") as output_dir:
        args = [
            "gcx", "dashboards", "snapshot", dashboard_name,
            "--context", context,
            "--output-dir", output_dir,
            "--since", since,
            "--width", str(width),
            "--height", str(height),
            "--theme", theme,
            "--tz", timezone,
            "--concurrency", "1",
            "-o", "json",
        ]
        for name in sorted(variables):
            args.extend(["--var", f"{name}={variables[name]}"])

        started = time.perf_counter()
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                cwd=output_dir,
            )
        except OSError as exc:
            raise OperationalError(f"cannot execute gcx: {exc}") from exc
        elapsed = time.perf_counter() - started

        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            detail = _redact(detail, variables.values())
            raise OperationalError(
                f"gcx snapshot failed for {dashboard_name}: {detail or 'no diagnostic'}"
            )
        try:
            json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise OperationalError(
                f"gcx snapshot returned invalid JSON for {dashboard_name}"
            ) from exc

        png_bytes = sum(
            os.path.getsize(os.path.join(root, filename))
            for root, _, files in os.walk(output_dir)
            for filename in files
            if filename.lower().endswith(".png")
        )
        if png_bytes == 0:
            raise OperationalError(f"gcx snapshot produced no PNG for {dashboard_name}")
        return {
            "status": "measured",
            "elapsed_seconds": round(elapsed, 6),
            "png_bytes": png_bytes,
            "variable_names": sorted(variables),
        }


def add_live_baseline(receipt: dict, context: str, variables: dict,
                      *, repeat: int, since: str, width: int, height: int,
                      theme: str, timezone: str) -> dict:
    if repeat < 1:
        raise OperationalError("repeat must be at least 1")
    receipt["live"] = {
        "status": "measured",
        "parameters": {
            "repeat": repeat,
            "since": since,
            "width": width,
            "height": height,
            "theme": theme,
            "timezone": timezone,
            "concurrency": 1,
            "variable_names": sorted(variables),
        },
        "dashboards": [],
    }
    for dashboard in receipt["dashboards"]:
        # gcx addresses a dashboard by its v2 identity, metadata.name — there is
        # no v1 "uid" any more (#399).
        attempts = [
            snapshot_once(
                dashboard["name"],
                context,
                variables,
                since=since,
                width=width,
                height=height,
                theme=theme,
                timezone=timezone,
            )
            for _ in range(repeat)
        ]
        receipt["live"]["dashboards"].append({
            "name": dashboard["name"],
            "attempts": attempts,
        })
    return receipt


def _parse_variables(values: list) -> dict:
    variables = {}
    for value in values:
        if "=" not in value:
            raise OperationalError(f"invalid --var value: {value}")
        name, selected = value.split("=", 1)
        if not name or not selected:
            raise OperationalError("--var requires non-empty NAME=VALUE")
        variables[name] = selected
    return variables


def _default_dashboards() -> list:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return sorted(glob.glob(os.path.join(repo, "dashboards", "*.json")))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure generated dashboard shape and live render latency",
    )
    parser.add_argument("--dashboard", action="append", default=[])
    parser.add_argument("--live-context")
    parser.add_argument("--var", action="append", default=[])
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--since", default="6h")
    parser.add_argument("--width", type=int, default=1920)
    parser.add_argument("--height", type=int, default=1080)
    parser.add_argument("--theme", choices=("dark", "light"), default="dark")
    parser.add_argument("--timezone", default="UTC")
    args = parser.parse_args()

    raw_variable_values = [
        value.split("=", 1)[1]
        for value in args.var
        if "=" in value
    ]
    try:
        receipt = static_receipt(args.dashboard or _default_dashboards())
        variables = _parse_variables(args.var)
        if args.live_context:
            add_live_baseline(
                receipt,
                args.live_context,
                variables,
                repeat=args.repeat,
                since=args.since,
                width=args.width,
                height=args.height,
                theme=args.theme,
                timezone=args.timezone,
            )
    except OperationalError as exc:
        print(json.dumps({
            "schema": 1,
            "status": "operational_error",
            "error": _redact(str(exc), raw_variable_values),
        }, indent=2, sort_keys=True))
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
