#!/usr/bin/env python3
"""Build graph2otel's alert + recording rules, and gate their metric naming (#219).

    python3 build_rules.py            # write alerts/*.yaml + recording-rules/*.json
    python3 build_rules.py --check    # gate only, write nothing (CI)

Run from grafana/ (``make rules`` / ``make grafana-check`` do). Sibling of
``build_dashboard.py`` (#218) — same sys.path setup, same pure-stdlib
constraint (no PyYAML, no ``setup-python`` step in CI: see Makefile and
``.github/workflows/ci.yml``).

# What this generator is for

#218 shipped ``spec/signal-catalog.json`` and the dashboard builder that reads
it. #219's own comment on that issue found a shipped alert rule querying
``graph2otel_throttle_limit_percentage`` — a metric name that cannot exist,
because the metric's unit is ``%`` and OTLP->Prometheus normalization appends
``_percent``. The rule was ``isPaused: true``, so it had never evaluated and
nobody noticed. That is the alert-side twin of #218's dead dashboard panels:
invisible precisely because a hand-typed metric name is never checked against
what graph2otel actually emits.

So every rule's ``expr`` is assembled from the generated catalog lookup
(``_m()`` below), never a hand-typed literal — a wrong name is a
``KeyError`` at build time, same guarantee ``build_dashboard.py`` gives
dashboard panels. The reverse-validation gate below additionally scans the
rendered PromQL text itself, so a metric name that somehow bypassed the lookup
(pasted straight into an expr string) still fails the gate rather than
shipping silently paused.

# What stays hand-authored

``alerts/README.md`` carries the doc-block prose for every rule — what/why,
threshold rationale, false-positive notes, applicability. This generator does
not touch it and does not regenerate it; only the one bug this issue exists to
fix (the throttle metric name, in both the shipped ``expr``/description AND
the README) is corrected here, by hand, in the RULES list below.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import catalog as catalog_mod  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ALERTS_DIR = os.path.join(REPO, "alerts")
ALERTS_PATH = os.path.join(ALERTS_DIR, "graph2otel-alerts.yaml")
RECORDING_DIR = os.path.join(REPO, "recording-rules")

PROM_UID = "grafanacloud-prom"
LOKI_UID = "grafanacloud-logs"
EXPR_UID = "__expr__"

CAT = catalog_mod.load()

# ---------------------------------------------------------------------------
# the frozen routable label contract (#293/#296). graph2otel ships alert
# *rules* only — no contact point, notification policy, or route (see the
# repository-content gate below) — so this is the entire public interface an
# operator routes their own notification policy against.
#
# pipeline/severity/source/category are MANDATORY on every rule and non-empty.
# `source` is the DOMAIN (what an operator would send to a whole owning team),
# so it does not fragment per rule — do not add a value to it for a single
# rule's sake. `component` is OPTIONAL and carries a finer distinction than
# `source` allows for a small number of rules; only add a rule to the
# COMPONENT_VALUES set (and only set component=... on a rule) with the same
# care as extending SOURCE_VALUES — this is a frozen seam, not a place to
# silently rewrite a rule's meaning.
# ---------------------------------------------------------------------------

PIPELINE = "graph2otel"

SEVERITY_VALUES = {"critical", "warning"}

SOURCE_VALUES = {
    "entra", "intune", "m365", "purview", "defender", "mdca", "graph2otel",
}

CATEGORY_VALUES = {
    "credential-expiry", "compliance", "self-observability",
    "record-integrity", "throttle", "mdca-discovery",
}

# Optional fifth label. Only g2o-intune-apple-token-expiry-critical and
# g2o-intune-cert-expiry-critical carry it today — both are source=intune,
# and component is the only label distinguishing them from each other and
# from the other intune-sourced rules.
COMPONENT_VALUES = {"apple-token", "certificate"}


def _m(name: str) -> str:
    """A catalogued metric's Prometheus name. KeyError at build time on a typo."""
    return CAT.metric(name).prom


# ---------------------------------------------------------------------------
# tiny stdlib block-YAML emitter (no PyYAML — see the module docstring). Ported
# from ~/repos/tailscale2otel/deploy/alerts/gen/build_rules.py's yamlify(). All
# string scalars are double-quoted + escaped, which is always valid YAML and
# sidesteps block-scalar special-character rules.
# ---------------------------------------------------------------------------

def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return repr(v) if isinstance(v, float) else str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return '"%s"' % s


def yamlify(obj, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, dict) and v:
                lines.append("%s%s:" % (pad, k))
                lines.append(yamlify(v, indent + 1))
            elif isinstance(v, list) and v:
                lines.append("%s%s:" % (pad, k))
                lines.append(yamlify(v, indent + 1))
            elif isinstance(v, dict):
                lines.append("%s%s: {}" % (pad, k))
            elif isinstance(v, list):
                lines.append("%s%s: []" % (pad, k))
            else:
                lines.append("%s%s: %s" % (pad, k, _scalar(v)))
        return "\n".join(lines)
    if isinstance(obj, list):
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                block = yamlify(item, indent + 1).split("\n")
                stripped = block[0][(indent + 1) * 2:]
                block = ["%s- %s" % (pad, stripped)] + block[1:]
                lines.extend(block)
            else:
                lines.append("%s- %s" % (pad, _scalar(item)))
        return "\n".join(lines)
    return "%s%s" % (pad, _scalar(obj))


# ---------------------------------------------------------------------------
# rule pipeline nodes — the canonical Grafana 3-node shape: A (Prometheus
# query) -> B (reduce, last) -> C (threshold), condition: C. Matches what the
# Grafana UI itself produces, so rules round-trip through the UI/API.
# ---------------------------------------------------------------------------

def _ds(uid: str) -> dict:
    return {"type": "__expr__" if uid == EXPR_UID else "prometheus", "uid": uid}


def _query_node(expr: str, lookback: int = 3600) -> dict:
    return {
        "refId": "A",
        "relativeTimeRange": {"from": lookback, "to": 0},
        "datasourceUid": PROM_UID,
        "model": {
            "datasource": _ds(PROM_UID),
            "editorMode": "code",
            "expr": expr,
            "instant": False,
            "range": True,
            "intervalMs": 1000,
            "maxDataPoints": 43200,
            "refId": "A",
        },
    }


def _reduce_node() -> dict:
    return {
        "refId": "B",
        "relativeTimeRange": {"from": 0, "to": 0},
        "datasourceUid": EXPR_UID,
        "model": {
            "datasource": _ds(EXPR_UID),
            "expression": "A",
            "reducer": "last",
            "type": "reduce",
            "refId": "B",
        },
    }


def _threshold_node(op: str, params: list) -> dict:
    return {
        "refId": "C",
        "relativeTimeRange": {"from": 0, "to": 0},
        "datasourceUid": EXPR_UID,
        "model": {
            "datasource": _ds(EXPR_UID),
            "expression": "B",
            "type": "threshold",
            "conditions": [{
                "type": "query",
                "evaluator": {"type": op, "params": params},
                "operator": {"type": "and"},
                "query": {"params": ["C"]},
                "reducer": {"type": "last", "params": []},
            }],
            "refId": "C",
        },
    }


def _alert(uid: str, title: str, expr: str, op: str, params: list, for_: str,
           labels: dict, summary: str, description: str, is_paused: bool,
           no_data_state: str = "OK", exec_err_state: str = "Error",
           exec_err_waiver: str = "", component: str = "") -> dict:
    if exec_err_state == "OK" and not exec_err_waiver.strip():
        raise ValueError(f"{uid}: execErrState OK requires a documented waiver")
    annotations = {"summary": summary, "description": description}
    if exec_err_waiver:
        annotations["exec_error_waiver"] = exec_err_waiver
    # pipeline is the fixed ownership label on every rule (#293/#296) — every
    # caller gets it for free rather than repeating it at all 14 call sites.
    full_labels = dict(labels)
    full_labels["pipeline"] = PIPELINE
    if component:
        full_labels["component"] = component
    return {
        "uid": uid,
        "title": title,
        "condition": "C",
        "data": [_query_node(expr), _reduce_node(), _threshold_node(op, params)],
        "noDataState": no_data_state,
        "execErrState": exec_err_state,
        "for": for_,
        "labels": full_labels,
        "annotations": annotations,
        "isPaused": is_paused,
    }


# ---------------------------------------------------------------------------
# the 12 alert rules — ported 1:1 from the previously hand-authored
# alerts/graph2otel-alerts.yaml. The ONLY change from the hand-authored
# version: every metric name inside an expr is a catalog lookup
# (_m()) instead of a literal, which is what catches the
# graph2otel_throttle_limit_percentage bug below. uid, title, labels, for,
# isPaused and the summary/description prose are unchanged, except the one
# throttle-budget rule's description, corrected to name the real metric.
# ---------------------------------------------------------------------------

RULES = [
    # --- Credential & token expiry (alerts/README.md doc block 1) ----------
    _alert(
        "g2o-entra-cred-expiry-critical",
        "Entra app/SP credential expiring within 7 days",
        f'sum by (tenant_id, owner_type, credential_type) '
        f'({_m("entra.credentials.expiring.total")}{{expiry_bucket=~"lt_7d|expired"}})',
        "gt", [0], "15m",
        {"severity": "critical", "category": "credential-expiry", "source": "entra"},
        "{{ $labels.owner_type }} {{ $labels.credential_type }} credential(s) expiring "
        "within 7 days (tenant {{ $labels.tenant_id }})",
        "entra_credentials_expiring_total is non-zero in the lt_7d/expired buckets for "
        "tenant {{ $labels.tenant_id }}, owner_type={{ $labels.owner_type }}, "
        "credential_type={{ $labels.credential_type }} for 15m. Bucket-count based (never "
        "per-credential) — see README.md doc block 1 for the false-positive notes and the "
        "lt_30d warning-tier companion rule.",
        False,
    ),
    _alert(
        "g2o-entra-cred-expiry-warning",
        "Entra app/SP credential expiring within 30 days",
        f'sum by (tenant_id, owner_type, credential_type) '
        f'({_m("entra.credentials.expiring.total")}{{expiry_bucket="lt_30d"}})',
        "gt", [0], "15m",
        {"severity": "warning", "category": "credential-expiry", "source": "entra"},
        "{{ $labels.owner_type }} {{ $labels.credential_type }} credential(s) expiring "
        "within 30 days (tenant {{ $labels.tenant_id }})",
        "Companion to g2o-entra-cred-expiry-critical: earlier warning tier on the lt_30d "
        "bucket. Paused by default — enable once you've picked a rotation-lead-time that "
        "matches your tenant's actual credential renewal process.",
        True,
    ),
    _alert(
        "g2o-intune-apple-token-expiry-critical",
        "Intune Apple MDM token expiring soon",
        f'min by (tenant_id, type, token_name) '
        f'({_m("intune.apple_token.days_until_expiry")})',
        "lt", [14], "15m",
        {"severity": "critical", "category": "credential-expiry",
         "source": "intune"},
        'Apple {{ $labels.type }} token "{{ $labels.token_name }}" expires in under 14 '
        "days (tenant {{ $labels.tenant_id }})",
        "intune_apple_token_days_until_expiry (APNS/VPP/DEP) is below 14 for "
        "token_name={{ $labels.token_name }}, tenant {{ $labels.tenant_id }}, for 15m. "
        "Unlike the bucketed metrics, this is a raw days-remaining gauge over a tiny "
        "admin-configured token set, so the threshold is an exact day count — tune freely. "
        "Paused by default (companion of the primary compliance/credential set) — enable "
        "once the apple_tokens collector is on for tenants that use Apple MDM.",
        True,
        component="apple-token",
    ),
    _alert(
        "g2o-intune-cert-expiry-critical",
        "Intune certificate expiring within 7 days",
        f'sum by (tenant_id, cert_profile_name) '
        f'({_m("intune.certificate.days_until_expiry")}{{expiry_bucket=~"0d_7d|expired"}})',
        "gt", [0], "15m",
        {"severity": "critical", "category": "credential-expiry",
         "source": "intune"},
        'Intune certificate profile "{{ $labels.cert_profile_name }}" has certificates '
        "expiring within 7 days (tenant {{ $labels.tenant_id }})",
        "intune_certificate_days_until_expiry is non-zero in the 0d_7d/expired buckets for "
        "cert_profile_name={{ $labels.cert_profile_name }}, tenant {{ $labels.tenant_id }}, "
        "for 15m. NOTE: cert expiry buckets are named differently from the entra credential "
        "buckets (0d_7d/7d_30d/30d_90d/over_90d/unknown vs lt_7d/lt_30d/lt_90d/gt_90d/"
        "expired) — see README.md. Paused by default — enable once the certificates "
        "collector (beta) is on.",
        True,
        component="certificate",
    ),
    # --- Compliance drop (alerts/README.md doc block 2) ---------------------
    _alert(
        "g2o-intune-compliance-ratio-low",
        "Intune compliant-device fraction below 90%",
        f'(sum by (tenant_id) ({_m("intune.compliance.devices")}{{state="compliant"}}) / '
        f'sum by (tenant_id) ({_m("intune.compliance.devices")})) and '
        f'sum by (tenant_id) ({_m("intune.compliance.devices")}) >= 5',
        "lt", [0.9], "30m",
        {"severity": "warning", "category": "compliance", "source": "intune"},
        "Intune compliant-device fraction below 90% (tenant {{ $labels.tenant_id }})",
        "compliant / total intune_compliance_devices is below 0.9 for tenant "
        "{{ $labels.tenant_id }} for 30m. The `and ... >= 5` guard suppresses the ratio on "
        "tiny fleets where one non-compliant device swings the percentage — see README.md "
        "doc block 2 for the false-positive notes.",
        False,
    ),
    _alert(
        "g2o-intune-compliance-noncompliant-spike",
        "Intune non-compliant device share spiking",
        f'(delta((sum by (tenant_id) '
        f'({_m("intune.compliance.devices")}{{state="non_compliant"}}))[1h:5m]) / '
        f'sum by (tenant_id) ({_m("intune.compliance.devices")})) and '
        f'sum by (tenant_id) ({_m("intune.compliance.devices")}) >= 5',
        "gt", [0.1], "15m",
        {"severity": "warning", "category": "compliance", "source": "intune"},
        "Intune non-compliant device share rose more than 10 percentage points in an hour "
        "(tenant {{ $labels.tenant_id }})",
        "Companion to g2o-intune-compliance-ratio-low: catches a sharp swing even when the "
        "absolute ratio hasn't crossed 90% yet (e.g. a large compliant fleet with a sudden "
        "policy regression). Paused by default — the 1h/10pp thresholds are unvalidated "
        "against real fleet churn.",
        True,
    ),
    # --- Collector staleness (alerts/README.md doc block 3) -----------------
    _alert(
        "g2o-collector-staleness",
        "graph2otel collector scrape stale",
        f'max by (tenant_id, collector) '
        f'({_m("graph2otel.scrape.staleness")})',
        "gt", [3600], "5m",
        {"severity": "critical", "category": "self-observability", "source": "graph2otel"},
        "Collector {{ $labels.collector }} hasn't scraped successfully in over an hour "
        "(tenant {{ $labels.tenant_id }})",
        "graph2otel_scrape_staleness_seconds for collector={{ $labels.collector }}, tenant "
        "{{ $labels.tenant_id }} has exceeded 3600s (the placeholder default: 3x a "
        "20-minute poll interval) for 5m. Replace 3600 with 3x YOUR configured collector "
        "interval in seconds. noDataState is Alerting (not OK) because self-obs metrics are "
        "emitted by every running collector — a fully missing series means the process died "
        "or that collector was removed, same semantics as tailscale2otel's ExporterDown.",
        False,
        no_data_state="Alerting",
    ),
    _alert(
        "g2o-checkpoint-persist-errors",
        "graph2otel checkpoint persist failing",
        f'sum by (tenant_id, collector) '
        f'(increase({_m("graph2otel.checkpoint.persist.errors")}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "self-observability", "source": "graph2otel"},
        "Collector {{ $labels.collector }} failing to persist its checkpoint (tenant "
        "{{ $labels.tenant_id }})",
        "Companion to g2o-collector-staleness: a WindowCollector's high-water mark isn't "
        "reaching disk, so a restart re-polls (or drops, depending on store) an "
        "already-processed window. Even one increment is worth knowing about — for is 0m. "
        "Paused by default — enable once you've picked a notification channel for it.",
        True,
    ),
    # --- End-to-end record integrity (#269; alerts/README.md doc block 6) ---
    _alert(
        "g2o-record-integrity-loss",
        "graph2otel dropped or errored source records",
        f'sum by (tenant_id, collector, ingest_transport) '
        f'(increase({_m("graph2otel.record.outcomes")}'
        f'{{outcome=~"dropped|errored"}}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "record-integrity", "source": "graph2otel"},
        "Collector {{ $labels.collector }} lost source records on "
        "{{ $labels.ingest_transport }} (tenant {{ $labels.tenant_id }})",
        "At least one source record was dropped or errored in the last 15m. `dropped` "
        "covers deliberate rejection such as an unparseable event timestamp; `errored` "
        "covers decode or processing failure. This is default-enabled because either "
        "outcome means fetched source data did not become useful telemetry.",
        False,
    ),
    _alert(
        "g2o-payload-type-mismatch",
        "graph2otel payload JSON type changed",
        f'sum by (tenant_id, collector, ingest_transport, field, expected_type, actual_type) '
        f'(increase({_m("graph2otel.payload.type_mismatches")}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "record-integrity", "source": "graph2otel"},
        "Payload type changed for {{ $labels.collector }} field {{ $labels.field }} "
        "(tenant {{ $labels.tenant_id }})",
        "A source-controlled optional field arrived with a different JSON type. The "
        "otherwise-usable record was still emitted. Paused initially until the tenant's "
        "normal payload-shape baseline is established; labels never contain field values.",
        True,
    ),
    # --- Throttle saturation (alerts/README.md doc block 4) -----------------
    _alert(
        "g2o-throttle-saturation",
        "graph2otel sustained Graph API throttling",
        f'sum by (tenant_id, workload) '
        f'(rate({_m("graph2otel.throttle.count")}[10m]))',
        "gt", [0], "15m",
        {"severity": "warning", "category": "throttle", "source": "graph2otel"},
        "Sustained 429s from Microsoft Graph on the {{ $labels.workload }} workload "
        "(tenant {{ $labels.tenant_id }})",
        "rate(graph2otel_throttle_count_total[10m]) (429 responses observed by the "
        "client-side rate limiter) is above 0 for workload={{ $labels.workload }}, tenant "
        "{{ $labels.tenant_id }}, sustained for 15m — i.e. throttling that isn't a one-off "
        "blip but is still happening 10-15 minutes later. noDataState is OK — zero throttle "
        "events is the healthy steady state, not an absence worth alerting on. See "
        "README.md doc block 4 for per-workload ceiling context (none of the reporting "
        "5/10s, Identity Protection 1/s, Intune reports-export 48/min, or directory RU "
        "workloads send Retry-After, so silent throttling degrades data freshness before "
        "anything else visibly breaks).",
        False,
    ),
    _alert(
        "g2o-throttle-budget-consumption",
        "graph2otel throttle budget consumption high",
        f'max by (tenant_id, workload) '
        f'({_m("graph2otel.throttle.limit_percentage")})',
        "gt", [80], "15m",
        {"severity": "warning", "category": "throttle", "source": "graph2otel"},
        "Graph-reported throttle budget consumption above 80% on the {{ $labels.workload }} "
        "workload (tenant {{ $labels.tenant_id }})",
        "graph2otel_throttle_limit_percentage_percent (from the x-ms-throttle-limit-"
        "percentage response header) is above 80 for workload={{ $labels.workload }}, "
        "tenant {{ $labels.tenant_id }}, sustained for 15m. Best-effort: this header isn't "
        "guaranteed on every 429 or every workload, so absence of data here does NOT mean "
        "the budget is healthy — g2o-throttle-saturation is the primary signal; this is a "
        "companion when the header happens to be present. Paused by default.",
        True,
    ),
    # --- MDCA Cloud Discovery parse health (alerts/README.md doc block 5) ---
    # Two rules because they catch DIFFERENT failures and neither covers the
    # other: a dead uploader emits no failed tasks, so the failure rule stays
    # green forever while data silently stops. See issue #145.
    _alert(
        "g2o-mdca-uploads-stopped",
        "graph2otel MDCA Cloud Discovery uploads stopped",
        f'max by (tenant_id, input_stream_id) '
        f'({_m("mdca.discovery.parse.last_success.age")})',
        "gt", [10800], "15m",
        {"severity": "critical", "category": "mdca-discovery", "source": "graph2otel"},
        "MDCA Cloud Discovery stream {{ $labels.input_stream_id }} hasn't parsed "
        "successfully in over 3h (tenant {{ $labels.tenant_id }})",
        "mdca_discovery_parse_last_success_age_seconds for "
        "input_stream_id={{ $labels.input_stream_id }}, tenant {{ $labels.tenant_id }} has "
        "exceeded 10800s (3h) for 15m. This is the alert-on-SILENCE signal a failure "
        "counter cannot produce: a dead uploader emits no failed parse tasks, so "
        "g2o-mdca-parse-failing stays green while data silently stops. Replace 10800 with "
        "~3x YOUR upload cadence in seconds. noDataState is OK because a tenant with no "
        "Cloud Discovery streams legitimately emits no series; once a stream has parsed "
        "once, the gauge is always present and keeps climbing when uploads stop.",
        False,
    ),
    _alert(
        "g2o-mdca-parse-failing",
        "graph2otel MDCA Cloud Discovery parse failing",
        f'sum by (tenant_id, input_stream_id, template) '
        f'(increase({_m("mdca.discovery.parse.tasks")}{{is_success="false"}}[1h]))',
        "gt", [0], "5m",
        {"severity": "warning", "category": "mdca-discovery", "source": "graph2otel"},
        "MDCA Cloud Discovery parse failing on stream {{ $labels.input_stream_id }} "
        "(tenant {{ $labels.tenant_id }})",
        'increase(mdca_discovery_parse_tasks_total{is_success="false"}[1h]) > 0 for '
        "input_stream_id={{ $labels.input_stream_id }}, template={{ $labels.template }}, "
        "tenant {{ $labels.tenant_id }}: at least one Cloud Discovery parse task FAILED in "
        "the last hour while the upload almost certainly reported HTTP 200. The template "
        "label names which failure (e.g. "
        "REPOOPER_COMPLETION_STATUS_BASELOGPARSER_UNEXPECTED_FORMAT = malformed log "
        "format). This is the 22-silent-failures outage from #145. Default-enabled; pair "
        "with g2o-mdca-uploads-stopped, which catches a dead uploader this rule cannot see.",
        False,
    ),
]


# ---------------------------------------------------------------------------
# the 2 recording rules — ported 1:1 from recording-rules/*.json (#128 §4.3,
# docs/derived-metrics.md). Grafana-managed: a single range query (A) against
# the Loki logs datasource, recorded directly from A (no reduce node — unlike
# alert rules, a Grafana recording rule may record straight from a range
# query), written to the Prometheus datasource named in targetDatasourceUid.
# ---------------------------------------------------------------------------

FOLDER_UID = "efskohpc18lj4b"  # "graph2otel derived metrics" — see recording-rules/README.md
RULE_GROUP = "blob-derived"


def _recording_expr(event: str, by_labels: list) -> str:
    CAT.log(event)  # validates the event name; KeyError at build time on a typo
    sel = f'{{service_name="graph2otel"}} | event_name=`{event}`'
    group_labels = list(dict.fromkeys(["tenant_id", *by_labels]))
    return f"sum by ({', '.join(group_labels)}) (count_over_time({sel} [1h]))"


def _record(metric: str, event: str, by_labels: list) -> dict:
    expr = _recording_expr(event, by_labels)
    return {
        "title": metric,
        "ruleGroup": RULE_GROUP,
        "folderUID": FOLDER_UID,
        "noDataState": "OK",
        "execErrState": "Error",
        "for": "0s",
        "isPaused": False,
        "condition": "A",
        "record": {"metric": metric, "from": "A", "targetDatasourceUid": PROM_UID},
        "annotations": {
            "description": "GENERATED by grafana/build_rules.py — do not edit by hand. "
                            "Edit the RECORDING list there, then run `make rules`."
        },
        "data": [{
            "refId": "A",
            "datasourceUid": LOKI_UID,
            "queryType": "range",
            "relativeTimeRange": {"from": 3600, "to": 0},
            "model": {
                "refId": "A",
                "datasource": {"type": "loki", "uid": LOKI_UID},
                "expr": expr,
                "queryType": "range",
                "editorMode": "code",
                "intervalMs": 1000,
                "maxDataPoints": 43200,
            },
        }],
    }


RECORDING = [
    ("intune-compliance-alert-count.json",
     _record("intune_compliance_alert_count", "intune.compliance_alert",
             ["alert_type", "operating_system", "scenario_name"])),
    ("intune-enrollment-failure-count.json",
     _record("intune_enrollment_failure_count", "intune.enrollment_event",
             ["enrollment_type", "operating_system", "failure_category"])),
]


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

ALERTS_BANNER = """\
# GENERATED by grafana/build_rules.py — do not edit by hand. Edit the RULES
# list there (uid, title, labels, for, isPaused, expr/threshold/description),
# then run `make rules`. See alerts/README.md for the per-rule doc blocks
# (what/why, threshold rationale, false-positive notes, applicability) —
# hand-authored, not generated, so build_rules.py never touches it and it
# cannot drift out of sync with itself the way the shipped expr once did
# (#219: graph2otel_throttle_limit_percentage was missing its _percent
# OTLP->Prometheus suffix because it was hand-typed instead of derived).
#
# Every rule is the canonical Grafana 3-node pipeline — A (Prometheus query) ->
# B (reduce, last) -> C (threshold), condition: C — so it round-trips through
# the Grafana UI/API. datasourceUid uses the portable Grafana Cloud default
# ("grafanacloud-prom"); replace it with your own Prometheus/Mimir datasource
# UID (`gcx datasources list` or Connections -> Data sources in the UI).
#
# Metric names are the OTLP -> Prometheus normalized form (dots -> underscores,
# unit/type suffixes appended) — see docs/signals.md and alerts/README.md.
"""


def render_alerts(rules: list) -> bytes:
    doc = {
        "apiVersion": 1,
        "groups": [{
            "orgId": 1,
            "name": "graph2otel-alerts",
            "folder": "graph2otel",
            "interval": "5m",
            "rules": rules,
        }],
    }
    return (ALERTS_BANNER + yamlify(doc) + "\n").encode()


def render_recording(recording: list) -> dict:
    """filename -> bytes, one per recording rule (#219 keeps these separate

    from the alerts YAML: a different Grafana folder, a 1h group interval, and
    an explicit per-rule targetDatasourceUid the alert pipeline has no use for).
    """
    return {fname: (json.dumps(rule, indent=2) + "\n").encode() for fname, rule in recording}


# ---------------------------------------------------------------------------
# reverse-validation gate: every metric-shaped token that appears in a
# rendered PromQL expr must resolve to a real catalog Prometheus name. This is
# what catches a metric name that bypassed _m()
# entirely (pasted straight into an expr string) rather than merely a
# misspelling of an argument to _m() (which is already a KeyError at
# build time, above).
# ---------------------------------------------------------------------------

_PROMQL_KEYWORDS = {
    "sum", "avg", "min", "max", "count", "count_values", "stddev", "stdvar",
    "rate", "irate", "increase", "delta", "idelta", "resets", "changes",
    "abs", "ceil", "floor", "round", "sort", "sort_desc", "clamp_min",
    "clamp_max", "clamp", "histogram_quantile", "label_replace", "label_join",
    "vector", "scalar", "topk", "bottomk", "quantile", "time", "timestamp",
    "and", "or", "unless", "on", "ignoring", "group_left", "group_right",
    "offset", "bool", "without", "by",
}

_IDENT = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_GROUPING_CLAUSE = re.compile(r"\b(?:by|without)\s*\([^)]*\)")
_LABEL_SELECTOR = re.compile(r"\{[^}]*\}")
_RANGE_VECTOR = re.compile(r"\[[^\]]*\]")  # [15m], [1h:5m] — duration literals, not metrics


def _metric_tokens(expr: str) -> set:
    """Candidate metric-name tokens in a PromQL expr.

    Strips ``by (...)``/``without (...)`` grouping clauses (label names, not
    metric names), every ``{...}`` label selector's contents, and every
    ``[...]`` range-vector/subquery duration literal (``15m``'s ``m`` is not a
    metric name), then returns every remaining bare identifier that is not
    immediately followed by ``(`` (a function call) and is not a PromQL
    keyword.
    """
    stripped = _GROUPING_CLAUSE.sub(" ", expr)
    stripped = _LABEL_SELECTOR.sub("", stripped)
    stripped = _RANGE_VECTOR.sub("", stripped)
    tokens = set()
    for m in _IDENT.finditer(stripped):
        tok = m.group(0)
        if tok in _PROMQL_KEYWORDS:
            continue
        if stripped[m.end():].lstrip().startswith("("):
            continue  # function call
        tokens.add(tok)
    return tokens


def _known_prom_names(cat) -> set:
    names = set()
    for m in cat.metrics.values():
        names.add(m.prom)
        if m.kind == "histogram":
            names.update({m.prom + "_bucket", m.prom + "_sum", m.prom + "_count"})
    return names


def reverse_validate(cat, rules: list) -> list:
    """Every metric token in every rule's PromQL expr resolves, or a violation.

    Returns a list of human-readable violation strings naming the rule uid and
    the offending token. There is no waiver concept here (unlike the dashboard
    coverage gate) — an unresolvable name is just a failure.
    """
    known = _known_prom_names(cat)
    violations = []
    for rule in rules:
        for node in rule.get("data", []):
            model = node.get("model", {})
            if model.get("datasource", {}).get("type") != "prometheus":
                continue
            expr = model.get("expr", "")
            for tok in sorted(_metric_tokens(expr)):
                if tok not in known:
                    violations.append(
                        f"{rule['uid']}: {tok!r} is not a catalogued "
                        f"Prometheus metric name (expr: {expr})")
    return violations


def recording_rule_orphans(expected_names: set[str],
                           present_names: set[str]) -> list[str]:
    """Return deployable recording-rule JSON absent from the generated set."""
    return sorted(present_names - expected_names)


# ---------------------------------------------------------------------------
# routable label gate (#293/#296): every generated rule carries the frozen
# pipeline/severity/source/category contract, non-empty and drawn from its
# closed set; the optional component label is closed-set-validated when
# present. This is the entire public routing interface graph2otel ships —
# see the repository-content gate below for the other half of the contract
# (no route/receiver/policy ships alongside it).
# ---------------------------------------------------------------------------

def validate_labels(rules: list) -> list:
    """Every rule's labels satisfy the frozen routable contract, or a violation.

    Returns human-readable violation strings naming the rule uid and the
    offending label, same style as reverse_validate above.
    """
    violations = []
    for rule in rules:
        uid = rule.get("uid", "<unknown>")
        labels = rule.get("labels", {})

        pipeline = labels.get("pipeline")
        if pipeline != PIPELINE:
            violations.append(
                f"{uid}: labels.pipeline is {pipeline!r}, want {PIPELINE!r}")

        severity = labels.get("severity")
        if not severity or severity not in SEVERITY_VALUES:
            violations.append(
                f"{uid}: labels.severity is {severity!r}, "
                f"not in {sorted(SEVERITY_VALUES)}")

        source = labels.get("source")
        if not source or source not in SOURCE_VALUES:
            violations.append(
                f"{uid}: labels.source is {source!r}, not in {sorted(SOURCE_VALUES)}")

        category = labels.get("category")
        if not category or category not in CATEGORY_VALUES:
            violations.append(
                f"{uid}: labels.category is {category!r}, "
                f"not in {sorted(CATEGORY_VALUES)}")

        if "component" in labels:
            component = labels["component"]
            if not component or component not in COMPONENT_VALUES:
                violations.append(
                    f"{uid}: labels.component is {component!r}, "
                    f"not in {sorted(COMPONENT_VALUES)}")

    return violations


# ---------------------------------------------------------------------------
# repository-content gate (#293/#296): graph2otel ships alert *rules* only —
# no contact point, notification policy, or route, in any form. A real
# content check on committed YAML/JSON top-level keys under alerts/ and
# recording-rules/, not a filename convention (a routing asset could be
# renamed to dodge a filename check; it cannot rename its own top-level
# keys and remain a valid Grafana provisioning document).
# ---------------------------------------------------------------------------

ROUTING_ASSET_KEYS = {
    "contactPoints", "policies", "notification_policies", "receiver",
    "routes", "route",
}

_YAML_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:")


def _top_level_keys(path: str) -> set:
    """Top-level mapping keys of a committed YAML or JSON file.

    No PyYAML dependency (see the module docstring), so YAML is scanned
    line-by-line for an unindented ``key:`` — matching the block style this
    generator's own ``yamlify()`` emits, and Grafana's file-provisioning
    layout generally (``apiVersion:``, ``groups:``, ``contactPoints:``,
    ``policies:`` are all unindented top-level keys). JSON is parsed for
    real via the stdlib, since ``json`` carries no such restriction.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return set()
        return set(doc.keys()) if isinstance(doc, dict) else set()
    keys = set()
    for line in text.splitlines():
        if not line or line[0] in " \t#":
            continue
        m = _YAML_TOP_LEVEL_KEY.match(line)
        if m:
            keys.add(m.group(1))
    return keys


def routing_asset_violations(dirpaths: list) -> list:
    """Committed alert/recording-rule files must never be routing assets.

    Scans every ``.yaml``/``.yml``/``.json`` file directly under each given
    directory for a routing-shaped top-level key (``ROUTING_ASSET_KEYS``).
    Returns human-readable violation strings naming the file and the
    offending key(s); empty means clean.
    """
    violations = []
    for dirpath in dirpaths:
        if not os.path.isdir(dirpath):
            continue
        for fname in sorted(os.listdir(dirpath)):
            if not fname.endswith((".yaml", ".yml", ".json")):
                continue
            path = os.path.join(dirpath, fname)
            if not os.path.isfile(path):
                continue
            hit = _top_level_keys(path) & ROUTING_ASSET_KEYS
            if hit:
                rel = os.path.relpath(path, REPO)
                violations.append(f"{rel}: routing-shaped key(s) {sorted(hit)}")
    return violations


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="run every gate but write nothing (CI mode)")
    args = ap.parse_args()

    violations = reverse_validate(CAT, RULES)
    if violations:
        print(f"RULE EXPR NAMES A METRIC graph2otel DOES NOT EMIT ({len(violations)}):",
              file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    label_violations = validate_labels(RULES)
    if label_violations:
        print(f"RULE LABELS VIOLATE THE FROZEN ROUTABLE CONTRACT ({len(label_violations)}):",
              file=sys.stderr)
        for v in label_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    routing_violations = routing_asset_violations([ALERTS_DIR, RECORDING_DIR])
    if routing_violations:
        print(f"COMMITTED FILE LOOKS LIKE A ROUTING ASSET ({len(routing_violations)}) — "
              f"graph2otel ships alert rules only, no contact point/policy/route:",
              file=sys.stderr)
        for v in routing_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    alerts_bytes = render_alerts(RULES)
    recording_bytes = render_recording(RECORDING)

    if not args.check:
        with open(ALERTS_PATH, "wb") as f:
            f.write(alerts_bytes)
        os.makedirs(RECORDING_DIR, exist_ok=True)
        for fname, data in recording_bytes.items():
            with open(os.path.join(RECORDING_DIR, fname), "wb") as f:
                f.write(data)

    stale = []
    with open(ALERTS_PATH, "rb") as f:
        if f.read() != alerts_bytes:
            stale.append("alerts/graph2otel-alerts.yaml")
    for fname, data in recording_bytes.items():
        path = os.path.join(RECORDING_DIR, fname)
        with open(path, "rb") as f:
            if f.read() != data:
                stale.append(f"recording-rules/{fname}")
    present_recording = {
        fname for fname in os.listdir(RECORDING_DIR)
        if fname.endswith(".json")
    }
    for fname in recording_rule_orphans(
            set(recording_bytes), present_recording):
        stale.append(f"recording-rules/{fname}")

    print(f"rules: {len(RULES)} alert rules ({sum(1 for r in RULES if not r['isPaused'])} "
          f"enabled, {sum(1 for r in RULES if r['isPaused'])} paused), "
          f"{len(RECORDING)} recording rules", file=sys.stderr)

    if stale:
        print(f"\nSTALE GENERATED FILES ({len(stale)}) — run `make rules`:", file=sys.stderr)
        for s in stale:
            print(f"  - {s}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
