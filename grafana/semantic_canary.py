#!/usr/bin/env python3
"""Run graph2otel's read-only Grafana semantic canary through gcx (#308)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys


class ManifestError(ValueError):
    """The committed probe manifest does not satisfy the closed schema."""


class OperationalError(RuntimeError):
    """gcx could not execute or returned an unreadable response."""


class QueryError(RuntimeError):
    """gcx reached the backend and the backend rejected query semantics."""


QUERY_FIELDS = {
    "id", "kind", "datasource", "query", "empty", "required_labels",
    "since", "step",
}
RULE_FIELDS = {"id", "kind", "datasource", "folder_uid", "uid"}
QUERY_KINDS = {"promql": "prometheus", "logql": "loki"}
EMPTY_POLICIES = {"required_nonempty", "empty_allowed"}


def validate_manifest(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise ManifestError("manifest must be an object")
    unknown = set(doc) - {"schema", "probes"}
    if unknown:
        raise ManifestError(f"manifest has unknown fields: {sorted(unknown)}")
    if doc.get("schema") != 1:
        raise ManifestError("manifest schema must be 1")
    probes = doc.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ManifestError("manifest probes must be a non-empty list")

    seen = set()
    for probe in probes:
        if not isinstance(probe, dict):
            raise ManifestError("every probe must be an object")
        kind = probe.get("kind")
        allowed = RULE_FIELDS if kind == "rule_health" else QUERY_FIELDS
        extra = set(probe) - allowed
        if extra:
            raise ManifestError(
                f"probe {probe.get('id', '?')} has unknown fields: {sorted(extra)}"
            )
        probe_id = probe.get("id")
        if not isinstance(probe_id, str) or not probe_id:
            raise ManifestError("every probe needs a non-empty id")
        if probe_id in seen:
            raise ManifestError(f"duplicate probe id: {probe_id}")
        seen.add(probe_id)

        if kind in QUERY_KINDS:
            if probe.get("datasource") != QUERY_KINDS[kind]:
                raise ManifestError(
                    f"probe {probe_id} datasource must be {QUERY_KINDS[kind]}"
                )
            if not isinstance(probe.get("query"), str) or not probe["query"]:
                raise ManifestError(f"probe {probe_id} needs a query")
            if probe.get("empty") not in EMPTY_POLICIES:
                raise ManifestError(f"probe {probe_id} has invalid empty policy")
            labels = probe.get("required_labels")
            if (not isinstance(labels, list)
                    or any(not isinstance(label, str) or not label
                           for label in labels)):
                raise ManifestError(
                    f"probe {probe_id} required_labels must be strings"
                )
            for field in ("since", "step"):
                if field in probe and (
                        not isinstance(probe[field], str) or not probe[field]):
                    raise ManifestError(
                        f"probe {probe_id} {field} must be a non-empty string"
                    )
        elif kind == "rule_health":
            if probe.get("datasource") not in {"prometheus", "loki"}:
                raise ManifestError(
                    f"probe {probe_id} needs a supported datasource"
                )
            if not isinstance(probe.get("folder_uid"), str) or not probe["folder_uid"]:
                raise ManifestError(f"probe {probe_id} needs a folder_uid")
            if not isinstance(probe.get("uid"), str) or not probe["uid"]:
                raise ManifestError(f"probe {probe_id} needs a stable uid")
        else:
            raise ManifestError(f"probe {probe_id} has unknown kind: {kind}")
    return doc


def load_manifest(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot load manifest {path}: {exc}") from exc
    return validate_manifest(doc)


def classify_datasource(expected: str, response: dict) -> dict:
    actual = response.get("spec", {}).get("type")
    if actual != expected:
        return {
            "status": "failed",
            "outcome": "wrong_type",
            "expected": expected,
            "actual": actual,
        }
    return {"status": "passed", "outcome": "matched", "type": actual}


def classify_query(probe: dict, response: dict) -> dict:
    result = {"id": probe["id"], "kind": probe["kind"]}
    if response.get("status") != "success":
        result.update({
            "status": "failed",
            "outcome": "query_error",
            "error": response.get("error") or response.get("message") or
                     "backend did not return success",
        })
        return result

    series = response.get("data", {}).get("result")
    if not isinstance(series, list):
        result.update({
            "status": "failed",
            "outcome": "invalid_response",
            "error": "data.result is not a list",
        })
        return result
    result["series"] = len(series)
    if not series:
        result.update({
            "status": ("passed" if probe["empty"] == "empty_allowed"
                       else "failed"),
            "outcome": ("healthy_empty" if probe["empty"] == "empty_allowed"
                        else "unexpected_empty"),
        })
        return result

    missing = set()
    for item in series:
        labels = item.get("metric")
        if labels is None:
            labels = item.get("stream")
        if not isinstance(labels, dict):
            labels = {}
        missing.update(
            label for label in probe["required_labels"] if label not in labels
        )
    if missing:
        result.update({
            "status": "failed",
            "outcome": "missing_labels",
            "missing_labels": sorted(missing),
        })
        return result

    result.update({"status": "passed", "outcome": "nonempty"})
    return result


def _rule_groups(response) -> list:
    if isinstance(response, list):
        return response
    if isinstance(response, dict) and isinstance(response.get("groups"), list):
        return response["groups"]
    return []


def classify_rule(probe: dict, response, datasource_uid: str) -> dict:
    result = {"id": probe["id"], "kind": probe["kind"]}
    matches = [
        rule
        for group in _rule_groups(response)
        for rule in group.get("rules", [])
        if rule.get("uid") == probe["uid"]
    ]
    if len(matches) != 1:
        result.update({
            "status": "failed",
            "outcome": "missing_rule" if not matches else "duplicate_rule",
            "matches": len(matches),
        })
        return result

    rule = matches[0]
    if str(rule.get("health", "")).lower() != "ok":
        result.update({
            "status": "failed",
            "outcome": "evaluator_error",
            "health": rule.get("health"),
        })
        return result
    if not rule.get("lastEvaluation"):
        result.update({
            "status": "failed",
            "outcome": "never_evaluated",
        })
        return result
    queried = rule.get("queriedDatasourceUIDs", [])
    if datasource_uid not in queried:
        result.update({
            "status": "failed",
            "outcome": "wrong_datasource",
            "queried_datasources": queried,
        })
        return result

    result.update({
        "status": "passed",
        "outcome": "healthy",
        "last_evaluation": rule["lastEvaluation"],
    })
    return result


def _query_command(probe: dict, context: str, datasource_uid: str) -> list:
    domain = "metrics" if probe["kind"] == "promql" else "logs"
    args = [
        "gcx", domain, "query", "--context", context,
        "-d", datasource_uid, probe["query"],
    ]
    if "since" in probe:
        args.extend(["--since", probe["since"]])
    if "step" in probe:
        args.extend(["--step", probe["step"]])
    args.extend(["-o", "json"])
    return args


def run_suite(manifest: dict, context: str, datasource_uids: dict,
              invoke) -> dict:
    validate_manifest(manifest)
    roles = [
        role for role in ("prometheus", "loki")
        if any(probe["datasource"] == role for probe in manifest["probes"])
    ]
    receipt = {
        "schema": 1,
        "context": context,
        "status": "passed",
        "datasources": [],
        "probes": [],
    }
    datasource_ok = {}
    for role in roles:
        uid = datasource_uids.get(role)
        if not uid:
            raise OperationalError(f"missing runtime datasource UID for {role}")
        response = invoke([
            "gcx", "datasources", "get", uid,
            "--context", context, "-o", "json",
        ])
        check = classify_datasource(role, response)
        check.update({"role": role, "uid": uid})
        receipt["datasources"].append(check)
        datasource_ok[role] = check["status"] == "passed"

    rule_cache = {}
    for probe in manifest["probes"]:
        role = probe["datasource"]
        if not datasource_ok[role]:
            result = {
                "id": probe["id"],
                "kind": probe["kind"],
                "status": "failed",
                "outcome": "datasource_preflight_failed",
            }
        elif probe["kind"] in QUERY_KINDS:
            try:
                response = invoke(
                    _query_command(probe, context, datasource_uids[role])
                )
            except QueryError as exc:
                result = {
                    "id": probe["id"],
                    "kind": probe["kind"],
                    "status": "failed",
                    "outcome": "query_error",
                    "error": str(exc),
                }
            else:
                result = classify_query(probe, response)
        else:
            folder_uid = probe["folder_uid"]
            if folder_uid not in rule_cache:
                rule_cache[folder_uid] = invoke([
                    "gcx", "alert", "rules", "list", "--context", context,
                    "--folder", folder_uid, "--limit", "0", "-o", "json",
                ])
            result = classify_rule(
                probe, rule_cache[folder_uid], datasource_uids[role]
            )
        receipt["probes"].append(result)

    if (any(item["status"] != "passed" for item in receipt["datasources"])
            or any(item["status"] != "passed" for item in receipt["probes"])):
        receipt["status"] = "failed"
    return receipt


def invoke_gcx(args: list) -> dict:
    try:
        completed = subprocess.run(
            args, check=False, capture_output=True, text=True,
        )
    except OSError as exc:
        raise OperationalError(f"cannot execute gcx: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        query_markers = (
            "Invalid PromQL query",
            "Invalid LogQL query",
            'invalid parameter "query"',
            "parse error",
        )
        if (len(args) > 2 and args[1] in {"metrics", "logs"}
                and any(marker in detail for marker in query_markers)):
            raise QueryError(detail or "backend rejected query")
        raise OperationalError(
            f"gcx exited {completed.returncode}: {detail or 'no diagnostic'}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise OperationalError("gcx returned invalid JSON") from exc


def _default_manifest() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "spec",
        "grafana-semantic-canary.json",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run graph2otel's read-only Grafana semantic canary",
    )
    parser.add_argument("--manifest", default=_default_manifest())
    parser.add_argument("--context", required=True)
    parser.add_argument("--prometheus-datasource", required=True)
    parser.add_argument("--loki-datasource", required=True)
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest)
        receipt = run_suite(
            manifest,
            args.context,
            {
                "prometheus": args.prometheus_datasource,
                "loki": args.loki_datasource,
            },
            invoke_gcx,
        )
    except (ManifestError, OperationalError) as exc:
        receipt = {
            "schema": 1,
            "context": args.context,
            "status": "operational_error",
            "error": str(exc),
        }
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
