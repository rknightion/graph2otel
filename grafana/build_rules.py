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

import catalog as catalog_mod
import logquery
import v2
from logquery import f  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ALERTS_DIR = os.path.join(REPO, "alerts")
RULES_DIR = os.path.join(ALERTS_DIR, "rules")
DASHBOARD_MANIFEST = os.path.join(REPO, "dashboards", "graph2otel.json")
RUNBOOKS_SOURCE = os.path.join(REPO, "docs", "runbooks.md")

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
    # Identity-threat detections (#300). Deliberately distinct from
    # "compliance": these are security signals an operator routes to a security
    # responder, not posture drift routed to the owning team.
    "identity-threat",
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
        "credential_type={{ $labels.credential_type }} for 15m. Bucket-count based, never "
        "per-credential. The runbook covers the false-positive notes and the lt_30d "
        "warning-tier companion rule.",
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
        "expired); the runbook lists both ladders. Paused by default — enable once the "
        "certificates collector (beta) is on.",
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
        "{{ $labels.tenant_id }} for 30m. The `and >= 5` fleet-size guard suppresses the "
        "ratio on tiny fleets where one non-compliant device swings the percentage. The "
        "runbook covers the false-positive notes.",
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
    # #299: interval-aware — the primary rule now compares each collector's
    # staleness against ITS OWN effective poll interval
    # (graph2otel.collector.expected_interval, the scheduler's resolved value,
    # not the raw config override) rather than one fixed 3600s placeholder
    # that was wrong for anything but a ~20-minute collector. Same rule uid,
    # same doc block, same 14-rule count — only the expr/threshold/annotations
    # change.
    _alert(
        "g2o-collector-staleness",
        "graph2otel collector scrape stale",
        f'max by (tenant_id, collector) ({_m("graph2otel.scrape.staleness")}) / '
        f'max by (tenant_id, collector) ({_m("graph2otel.collector.expected_interval")})',
        "gt", [3], "10m",
        {"severity": "critical", "category": "self-observability", "source": "graph2otel"},
        "Collector {{ $labels.collector }} is more than 3x its expected poll interval "
        "overdue (tenant {{ $labels.tenant_id }})",
        "graph2otel_scrape_staleness_seconds / graph2otel_collector_expected_interval_seconds "
        "for collector={{ $labels.collector }}, tenant {{ $labels.tenant_id }} has exceeded 3 "
        "for 10m — i.e. it has been more than 3x that COLLECTOR'S OWN effective poll interval "
        "(not a fixed second count) since its last successful scrape. Both metrics carry "
        "exactly (tenant_id, collector), so the division is a one-to-one vector match with no "
        "on()/ignoring() needed. 3x tolerates one missed poll plus backoff jitter without "
        "paging — several workloads have mandatory client-side rate limiters (reporting "
        "5/10s, Identity Protection 1/s, Intune export 48/min) that make an occasional missed "
        "poll routine rather than a fault; a tighter 2x was rejected for exactly that reason. "
        "The rule sets its no-data state to Alerting because the whole query returning zero "
        "rows means every collector's self-obs signal went dark at once — the exporter process died, or a "
        "tenant's only collector was removed. It does NOT mean one collector's series "
        "disappearing: Grafana evaluates this rule per (tenant_id, collector) combination the "
        "query actually returns, so when ONE collector among several is deliberately "
        "removed (or disabled), its ratio series simply stops existing and its alert "
        "instance resolves silently — the other collectors' instances are unaffected and "
        "noDataState never applies to it. That silent, clean disappearance is the deliberately "
        "removed collector's correct outcome, not an accident. The pending window is 10m rather "
        "than 5m — two evaluations at the 5m interval, not one — because that same noDataState "
        "cannot distinguish a dead exporter from the network between a healthy exporter and "
        "Grafana going away. Where the site firewall is that network, rebooting it takes 10-15 "
        "minutes and every minute of it looks identical to total signal loss from here.",
        False,
        no_data_state="Alerting",
    ),
    # g2o-collector-staleness stopped covering one case in #408: a collector
    # that hits a permanent tenant-entitlement 403 now declines its run and
    # stamps last-success, so staleness no longer climbs and that rule stays
    # silent — deliberately, because no operator action clears an unlicensed
    # endpoint and a critical page that can never be actioned is noise.
    #
    # But a REVOKED consent grant produces the identical outcome, and that one
    # is very much actionable. Nothing else covered it: g2o-detect-graph-403-burst
    # watches tenant-wide caller behaviour over blob-sourced entra.graph_activity,
    # not this exporter's own health, and is paused. This rule closes that gap at
    # warning rather than critical — a collector that is down but not lying is
    # worth knowing about tomorrow morning, not at 3am.
    #
    # scrape.success is level-triggered (re-exported every OTLP interval, not
    # only on a tick), so max_over_time works without any interval arithmetic:
    # a 24h-interval collector whose last tick succeeded holds 1 for the whole
    # window and never fires. That is why this rule needs no division by
    # expected_interval the way the staleness rule does.
    _alert(
        "g2o-collector-degraded-sustained",
        "graph2otel collector degraded for 6h",
        f'max by (tenant_id, collector) '
        f'(max_over_time({_m("graph2otel.scrape.success")}[6h]))',
        "lt", [1], "30m",
        {"severity": "warning", "category": "self-observability", "source": "graph2otel"},
        "Collector {{ $labels.collector }} has not had a single successful scrape in 6h "
        "(tenant {{ $labels.tenant_id }})",
        "graph2otel_scrape_success_ratio for collector={{ $labels.collector }}, tenant "
        "{{ $labels.tenant_id }} has been 0 for every sample in a 6h window. The collector "
        "is running and reporting — this is not staleness — but every run is coming back "
        "degraded or failed. The two causes worth separating are a REVOKED Graph consent "
        "grant (actionable: re-consent the app role) and an endpoint the tenant is simply "
        "not licensed for (not actionable: the collector correctly declines it forever, "
        "which is why g2o-collector-staleness deliberately stays silent for that case since "
        "#408). Read cause= on the WARN 'collector completed with degraded outcome' line, or "
        "graph2otel_scrape_outcomes_total, to tell them apart. Warning rather than critical "
        "because neither cause is a 3am page: the unlicensed one can never be actioned at "
        "all, and a revoked grant has already been broken for six hours by the time this "
        "fires. 6h with a 30m pending window tolerates the slowest collectors (24h "
        "intervals) restarting mid-window without a false positive.",
        False,
    ),
    # #422: the detection gap #417 left behind. #417 livelocked eight collectors
    # for 11 days while g2o-collector-staleness peaked at 1.008, the 6h degraded
    # rule sat at exactly 1 every hour for 7 days, and record-integrity saw only
    # `deduped` — a normal outcome. All three were starved of input because the
    # scrapes genuinely SUCCEEDED: the collector re-polled one frozen 15-minute
    # window and deduped everything it fetched.
    #
    # #422 proposed an expression over record_outcomes (`fetched > 0 unless
    # emitted > 0`, `unless` rather than `== 0` because the emitted series was
    # ABSENT, and `== 0` never matches an absent series). That was rejected in
    # favour of the watermark, which the issue itself raised as the better
    # option: a quiet tenant re-polling its overlap window and deduping every
    # record is INDISTINGUISHABLE from a livelock by outcome counters alone, and
    # the watermark has no such ambiguity — logpipeline.Poll advances it to
    # (to - SafetyLag) even on a window that drained zero records, so it keeps
    # moving on a quiet tenant and freezes only when the window does. It also
    # catches the case no counter can see at all: a window frozen in the FUTURE,
    # fetching nothing, producing no outcomes to count.
    #
    # Normalized by expected_interval for the same reason g2o-collector-staleness
    # is: window collectors run anywhere from minutes to a day apart, so one
    # absolute second count is wrong for all but one of them. Both metrics carry
    # exactly (tenant_id, collector), so this is a one-to-one vector match with
    # no on()/ignoring().
    _alert(
        "g2o-collector-watermark-stalled",
        "graph2otel window watermark not advancing",
        f'(time() - max by (tenant_id, collector) '
        f'({_m("graph2otel.collector.watermark_timestamp")})) / '
        f'max by (tenant_id, collector) ({_m("graph2otel.collector.expected_interval")})',
        "gt", [20], "30m",
        {"severity": "critical", "category": "self-observability", "source": "graph2otel"},
        "Collector {{ $labels.collector }} has a window watermark more than 20x its poll "
        "interval behind now (tenant {{ $labels.tenant_id }})",
        "The durable checkpoint watermark for collector={{ $labels.collector }}, tenant "
        "{{ $labels.tenant_id }} has stopped advancing: it is more than 20x that "
        "COLLECTOR'S OWN effective poll interval behind wall-clock. This is the #417 "
        "fingerprint — a livelocked window poller that re-fetches one frozen range every "
        "tick, dedupes it, and reports a perfectly healthy scrape. Expect "
        "graph2otel_scrape_success_ratio to be 1, availability to read healthy, and "
        "graph2otel_record_outcomes_total to show fetched == mapped == deduped with NO "
        "emitted series at all; none of that is evidence against this alert, it is the "
        "shape of the fault. "
        "PAUSED, and the threshold is a placeholder. The unblock condition is a "
        "MEASUREMENT that cannot be taken until this metric has shipped: observe "
        "(time() - graph2otel_collector_watermark_timestamp_seconds) / "
        "graph2otel_collector_expected_interval_seconds across every window collector for "
        "at least one full week on a live tenant, take the per-collector maximum over that "
        "week, and set the threshold above the largest of them. 20x is a guess chosen to "
        "clear the per-collector SafetyLag (which is subtracted from the watermark and is "
        "NOT exported, so it inflates this ratio by an unknown amount that hurts the "
        "fastest collectors most) — it is not a measured bound. Enabling it before that "
        "measurement risks firing on correct data, which is the specific failure #422 "
        "names: an alert that fires on correct data trains the reader to ignore the "
        "signal, and that is how the next 11-day freeze goes unnoticed.",
        True,
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
        "already-processed window. Even one increment is worth knowing about, so the rule "
        "fires on the first failed persist with no `for` delay. "
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
        "blip but is still happening 10-15 minutes later. The rule treats no data as OK: "
        "zero throttle events is the healthy steady state, not an absence worth alerting on. "
        "The runbook has the per-workload ceiling context (none of the reporting "
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
        "~3x YOUR upload cadence in seconds. The rule treats no data as OK because a tenant with no "
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
    # --- Backend record/content loss (#420) --------------------------------
    # The two counters that exist to make data loss visible. Nothing watched
    # either until #420; a loss metric nobody is alerted on is the same defect
    # #419 was filed for, one level up.
    _alert(
        "g2o-record-attrs-truncated",
        "graph2otel clipped a record's attributes to fit the backend size limit",
        f'sum by (tenant_id, collector, ingest_transport) '
        f'(increase({_m("graph2otel.event.attrs_truncated")}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "record-integrity", "source": "graph2otel"},
        "Collector {{ $labels.collector }} emitted an oversized record on "
        "{{ $labels.ingest_transport }} (tenant {{ $labels.tenant_id }})",
        "At least one log record exceeded the backend's structured-metadata size limit in "
        "the last 15m and had its largest attribute values shortened to fit (#419). This is "
        "CONTENT loss, not record loss: the record landed, but one or more fields are "
        "truncated. Default-enabled at >0 for two reasons — the measured rate is 2-3 records "
        "per day, so it is not noisy, and the clipped record's attrs_truncated_keys is "
        "currently the ONLY way to identify which record shape is oversized, since #419's "
        "live-wire sweep cleared every reachable source. Treat the first firing as the "
        "diagnostic it is.",
        False,
    ),
    _alert(
        "g2o-record-over-horizon",
        "graph2otel dropped records older than the backend accept window",
        f'sum by (tenant_id, collector, ingest_transport) '
        f'(increase({_m("graph2otel.event.over_horizon")}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "record-integrity", "source": "graph2otel"},
        "Collector {{ $labels.collector }} dropped over-age records on "
        "{{ $labels.ingest_transport }} (tenant {{ $labels.tenant_id }})",
        "Records were dropped because their event time was older than the backend's 7-day "
        "accept window, so sending them would have been rejected per-entry and lost anyway "
        "(#401). This is real record loss. PAUSED by default on purpose: a nonzero value is "
        "EXPECTED on a blob-derived stream, which replays historical records and can age one "
        "past 7 days by ordinary aging with nothing misconfigured (#297 measured graph2otel's "
        "blob-ingested Intune stream at 6.95 days at the oldest). Enabling it as-is would "
        "page on normal behaviour. Unblock condition: measure your own steady-state rate on "
        "the 'Backend accept window' panel, raise the threshold above it, then enable.",
        True,
    ),
    _alert(
        "g2o-otlp-delivery-failing",
        "graph2otel OTLP export failing",
        f'sum by (signal) (increase({_m("graph2otel.otlp.delivery.export_failures")}[15m]))',
        "gt", [0], "0m",
        {"severity": "warning", "category": "record-integrity", "source": "graph2otel"},
        "graph2otel OTLP {{ $labels.signal }} export failing",
        "The exporter's own callback reported that a batch did not reach the backend in the "
        "last 15m. This is the most GENERAL data-loss signal graph2otel has: it fires on any "
        "rejection class — a size limit, a label-count limit, an expired credential, a "
        "payload cap, a limit the backend adds in future — with no requirement that anyone "
        "predicted it first. The per-limit rules (g2o-record-attrs-truncated, "
        "g2o-record-over-horizon) each guard ONE known limit; this one is the backstop "
        "behind all of them, and it is what would have caught #419 on the day it started "
        "instead of a container-log grep days later. Enabled at >0 with no baseline needed: "
        "an export failure is never a normal steady state. Grouped by signal because a "
        "metrics-side failure and a logs-side failure are different investigations. "
        "Deliberately watches export_failures ONLY — shutdown_failures moves on an ordinary "
        "restart, and a rule that fires on every deploy is a rule people learn to ignore. "
        "KNOWN BLIND SPOT, and it is why a delivery alert was originally forbidden outright "
        "(#268/#421): this rule's own evidence travels through the METRICS exporter, so it "
        "cannot be the metrics-path watchdog and its SILENCE is not proof that delivery is "
        "healthy. A total metrics outage takes the counter with it. That is what "
        "g2o-collector-staleness, /readyz and the process-local admin status are for. What "
        "this rule does cover is everything that reports itself: every logs-side failure "
        "(the metrics path is healthy throughout, which is exactly how #419 stayed queryable "
        "while being invisible), and every partial metrics-side rejection, whose accepted "
        "batches carry the counter.",
        False,
    ),
]


# ---------------------------------------------------------------------------
# Detection examples (#300) — portable, PAUSED, and deliberately separate
#
# Adapted from detections running on a real tenant. They ship here because they
# are the "how do you actually use this data" worked examples the collector docs
# do not provide, and because three of them encode non-obvious knowledge about
# the SHAPE of the Microsoft data rather than about any one tenant.
#
# Why a separate file and group rather than graph2otel-alerts.yaml: that file is
# the operational graph2otel-health rule set and its drift gate should keep
# meaning exactly that. Mixing tenant-security detections into it would blur what
# an operator agrees to when they provision it.
#
# EVERY RULE HERE IS PAUSED, and that is a hard rule rather than a default. None
# of these thresholds has been measured on more than one tenant, and #375's
# binding decision is that unmeasured detections ship paused or as hunting
# queries. Each carries a mandatory tuning_required annotation naming the
# measurement it needs. Enabling one without that measurement is how a team
# learns to ignore an alert channel.
#
# Deliberately NOT here: any tenant identifier, application GUID, network
# address, or geography. Three further detections on that tenant pin a specific
# service principal to its expected source addresses; those are private
# infrastructure by definition. Their PATTERN is portable and is documented in
# alerts/README.md instead.
# ---------------------------------------------------------------------------


def _loki_alert(uid: str, title: str, expr: str, op: str, params: list,
                labels: dict, summary: str, description: str,
                tuning: str) -> dict:
    """A Loki-backed detection. Always paused; ``tuning`` is mandatory.

    Same A -> B -> C pipeline as the metric alerts, so it round-trips through the
    Grafana UI and API identically. Only the A node's datasource differs.
    """
    if not tuning.strip():
        raise ValueError(
            f"{uid}: a paused detection must name the measurement its threshold "
            "needs, or nobody can tell what would make it safe to enable"
        )
    full_labels = dict(labels)
    full_labels["pipeline"] = PIPELINE
    return {
        "uid": uid,
        "title": title,
        "condition": "C",
        "data": [
            {
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
            },
            _reduce_node(),
            _threshold_node(op, params),
        ],
        # No data is the steady state for every one of these on a healthy tenant,
        # so it must not read as a fault.
        "noDataState": "OK",
        "execErrState": "Error",
        "for": "0s",
        "labels": full_labels,
        "annotations": {
            "summary": summary,
            "description": description,
            "tuning_required": tuning,
        },
        "isPaused": True,
    }


# Accumulated by _sel() as the DETECTIONS list is constructed at import time, so
# validation is derived from the filters actually used rather than from a
# hand-maintained parallel declaration that could drift out of step with them.
DETECTION_VIOLATIONS: list = []


def _sel(event: str, *filters, by: str = "") -> str:
    """Build the ONLY correct LogQL shape, exactly as the dashboards do (#90).

    ``service_name`` is the sole stream label; everything else is structured
    metadata and must be filtered after the pipe. Filters are typed
    (``logquery.f``) and validated against the event's real attribute set by
    ``validate_detection_fields`` — #306 covers alerts, not only dashboards.
    """
    DETECTION_VIOLATIONS.extend(logquery.violations(
        CAT, event, filters=filters,
        by=[key.strip() for key in by.split(",") if key.strip()]))
    parts = ['{service_name="graph2otel"}', f"| event_name=`{event}`"]
    parts.extend(f"| {rendered}" for rendered in logquery.render_filters(filters))
    return " ".join(parts)


def _count(event: str, *filters, by: str = "") -> str:
    grouping = f" by ({by})" if by else ""
    return f"sum{grouping} (count_over_time({_sel(event, *filters, by=by)} [5m]))"


DETECTIONS = [
    _loki_alert(
        "g2o-detect-privileged-directory-change",
        "Privileged directory change (app credential, role, consent, CA or owner)",
        _count(
            "entra.directory_audit",
            f("activity_display_name", "re",
              "(?i)(consent to application|add app role assignment.*|"
              "add delegated permission grant|add service principal.*|"
              "add application.*|.*certificates and secrets management.*|"
              "add member to role.*|add owner to .*|"
              ".*conditional access polic.*)"),
        ),
        "gt", [0],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "A high-risk Entra directory change was recorded",
        "An entra.directory_audit activity matched the high-risk set: application "
        "credential or secret added, admin consent granted, app role or delegated "
        "permission granted, service principal or application created, directory "
        "role member added, owner added, or a Conditional Access policy changed. "
        "Each is a step an attacker takes to establish persistence, and each is "
        "also ordinary administrative work, so this fires on legitimate changes "
        "too by design. Inspect initiated_by and target_resources on the record. "
        "The activity list is the valuable part of this rule: it is tenant "
        "independent and tedious to reconstruct.",
        "Fires on your own admin work. Run the query over 30 days to learn your "
        "tenant's normal change rate, then decide whether to route it to a review "
        "queue rather than a pager, or to exclude specific initiators.",
    ),
    _loki_alert(
        "g2o-detect-security-alert-unresolved",
        "Security alert, medium or high, still unresolved",
        _count("entra.security_alert",
               f("severity", "re", "(?i)(high|medium)"),
               f("status", "re", "(?i)(new|inProgress)")),
        "gt", [0],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "An unresolved medium/high security alert is open",
        "The entra.security_alert stream carries alerts from ALL Microsoft "
        "sources that surface through the security API: Defender for Endpoint, "
        "Defender for Cloud Apps and Entra ID Protection all arrive here, so one "
        "rule covers products that are separate consoles in the portal. Inspect "
        "title, category and service_source to see which product raised it.",
        "Volume depends entirely on your Defender licensing and tenant size. "
        "Measure the alert rate over 30 days before enabling; on a noisy tenant "
        "raise the threshold or narrow to severity=high.",
    ),
    _loki_alert(
        "g2o-detect-security-incident-active",
        "Security incident, medium or high, active",
        _count("entra.security_incident",
               f("severity", "re", "(?i)(high|medium)"),
               f("status", "re", "(?i)(active|inProgress)")),
        "gt", [0],
        {"severity": "warning", "source": "entra", "category": "identity-threat"},
        "An active medium/high security incident is open",
        "Incidents are the CORRELATION layer above individual alerts: one "
        "incident groups related alerts Microsoft believes are the same attack. "
        "This therefore OVERLAPS with the unresolved-alert detection above, and a "
        "single security event will usually match both. That is deliberate, since "
        "the incident carries the correlation and the alert carries the detail, "
        "but decide which one you want to page on rather than enabling both and "
        "being paged twice for one event.",
        "Enable this or the alert rule, not both, until you have watched a real "
        "incident arrive and seen which gives your responders the better entry "
        "point.",
    ),
    _loki_alert(
        "g2o-detect-graph-403-burst",
        "Graph API authorization-denial burst from a single application",
        _count("entra.graph_activity", f("response_status_code", "eq", "403"),
               by="app_id"),
        "gt", [10],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "One application received more than 10 Graph 403s in 5 minutes",
        "A burst of authorization denials from a single caller can indicate "
        "permission probing or a compromised identity exploring what it can "
        "reach. It is equally often an application that lost a consent grant, "
        "which is worth knowing either way. Check app_id and the denied paths.",
        "Needs entra.graph_activity, which arrives over blob ingest. The "
        "threshold of 10 in 5 minutes is a starting point from one small tenant; "
        "a tenant with more automation will need a higher one. Measure your own "
        "per-app 403 baseline before enabling.",
    ),
    _loki_alert(
        "g2o-detect-interactive-signin-anomaly",
        "Interactive sign-in blocked by Conditional Access or flagged at risk",
        # 50097 is excluded from the CA limb by default (#426). A report-only
        # policy still stamps conditional_access_status=failure on a sign-in it
        # never blocked, and 50097 is the code it does it with — see the tuning
        # note. Loki cannot join the interrupt to its own success record, so the
        # exclusion is a default for the common case, not a proof of safety.
        "("
        + _count("entra.signin", f("sign_in_event_types", "eq", "interactiveUser"),
                 f("conditional_access_status", "eq", "failure"),
                 f("status_error_code", "ne", "50097"))
        + ") + ("
        + _count("entra.signin", f("sign_in_event_types", "eq", "interactiveUser"),
                 f("risk_state", "re", "atRisk|confirmedCompromised"))
        + ")",
        "gt", [0],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "An interactive sign-in was CA-blocked or risk-flagged",
        "A real user sign-in that Conditional Access refused, or that Entra ID "
        "Protection scored atRisk or confirmedCompromised. Check "
        "user_principal_name, app_display_name, status_error_code and ip_address "
        "on the record, then read appliedConditionalAccessPolicies on the sign-in "
        "in Entra to see WHICH policy returned failure — graph2otel does not "
        "export that field, and without it a CA failure names no policy. Error "
        "50097 is excluded by default; the tuning note explains why and when to "
        "put it back. The tenant this came from adds a third clause for sign-ins "
        "outside its expected country; that is a per-tenant policy statement "
        "rather than a portable default, so it is not shipped. Add another OR "
        "term filtering location_country_or_region against your own country code "
        "if you want it — and guard it with a presence check "
        "(location_country_or_region != \"\") as well, because Loki reads a "
        "missing label as the empty string and a bare != would fire on records "
        "that carry no location rather than on foreign ones.",
        "Two measurements, and one exclusion already made for you. Error 50097 "
        "'Device authentication is required' is excluded from the CA limb by "
        "default because it is usually not a refusal at all: a REPORT-ONLY "
        "Conditional Access policy is still evaluated, and a report-only grant "
        "that the device cannot satisfy makes Entra stamp "
        "conditional_access_status=failure with 50097 on a sign-in nothing "
        "blocked. Measured on a live tenant 2026-08-10: all 6 interactive 50097 "
        "records in 30 days had every ENFORCED policy returning success, the only "
        "non-success entry a report-only compliant-device grant, and a success "
        "record under the SAME correlation_id about one second later. Since "
        "report-only is the documented way to stage a CA policy, any tenant "
        "rolling one out produces this. PUT 50097 BACK if your tenant ENFORCES a "
        "compliant-device or hybrid-join grant: there a 50097 with no following "
        "success is a real block, and Loki cannot join the two records on "
        "correlation_id to tell the two apart — that join is why this is a "
        "default rather than a proof. Then measure what remains: CA failures "
        "include ordinary events such as a user declining or fumbling an MFA "
        "prompt, so most tenants still need a threshold above zero or a narrowing "
        "to risk_state alone. Run the sign-in error-code hunt for both numbers — "
        "it uses a 14-day window because a 30-day count_over_time exceeds the max "
        "query range on at least one Grafana Cloud Loki stack and returns EMPTY "
        "rather than erroring, so scale what you measure rather than widening the "
        "query blind. Risk states require Entra ID P2.",
    ),
    # --- Second wave (#313) --------------------------------------------------
    #
    # Six further concepts, chosen for being DISTINCT from the five above rather
    # than for looking impressive. Each is expressed in terms of what graph2otel
    # actually emits, with the Microsoft/Sentinel concept cited as provenance —
    # not transliterated from KQL, because a KQL rule reasons over table columns
    # this project does not ship and joins Loki cannot perform.
    #
    # Every value these six match on is a Microsoft spelling this project has not
    # measured on the wire for that exact field, so every regex is
    # case-insensitive and every tuning note names the hunt that confirms the
    # spelling on the operator's own tenant before enabling. That is the value
    # -level twin of the #90 key trap: a regex that never matches is
    # indistinguishable from a quiet tenant.
    _loki_alert(
        "g2o-detect-exchange-inbox-rule-change",
        "Exchange inbox rule created or modified",
        _count("m365.audit", f("operation", "re", "(?i).*inboxrule.*")),
        "gt", [0],
        {"severity": "warning", "source": "m365", "category": "identity-threat"},
        "An Exchange inbox rule was created or changed",
        "A mailbox rule was created, modified or removed. Business email "
        "compromise almost always leaves one behind: a rule that moves replies "
        "from finance, or anything mentioning invoices, into a folder the owner "
        "never opens, so the victim never sees the conversation happening in "
        "their name. Microsoft classifies this as email hiding rules, MITRE "
        "T1564.008, and it is the technique the Defender BEC playbook looks for "
        "first. graph2otel carries it as an m365.audit record whose operation "
        "names the rule cmdlet; inspect user_id, client_ip and "
        "modified_property_names on the record to see who changed what.",
        "Users create their own inbox rules constantly, so on most tenants this "
        "is the noisiest rule in the pack and needs a per-actor exclusion or a "
        "review queue rather than a pager. Run the audit-operation hunt over 30 "
        "days first: it both gives you the rate and confirms your tenant spells "
        "the operation the way this regex expects. Rule parameters are not on "
        "the record, so the rule cannot tell a forwarding rule from a "
        "housekeeping one.",
    ),
    _loki_alert(
        "g2o-detect-mailbox-permission-grant",
        "Mailbox, recipient or folder permission granted",
        _count("m365.audit",
               f("operation", "re",
                 "(?i).*(mailboxpermission|recipientpermission|folderpermission).*")),
        "gt", [0],
        {"severity": "warning", "source": "m365", "category": "identity-threat"},
        "A mailbox delegation or folder permission was granted",
        "Delegate access to a mailbox is durable, survives the owner's password "
        "reset, and is invisible to the owner, which is why granting it is a "
        "standard persistence and collection step once an attacker holds an "
        "administrative session. Microsoft tracks it as additional email "
        "delegate permissions, MITRE T1098.002. It shares the m365.audit "
        "operation field with the inbox-rule detection above and is a separate "
        "rule on purpose: an inbox rule is usually the mailbox owner's own doing "
        "and noisy, while a delegation grant is an administrative act, rarer, "
        "and remediated differently. Combining them would force one threshold "
        "onto two very different base rates.",
        "Shared mailboxes, resource calendars and migration tooling all produce "
        "legitimate grants in bursts. Run the audit-operation hunt for 30 days "
        "to separate your routine grant sources from the rest, and to confirm "
        "the operation spelling, before enabling.",
    ),
    _loki_alert(
        "g2o-detect-identity-risk-detection",
        "Entra ID Protection risk detection, medium or high",
        _count("entra.risk_detection",
               f("risk_event_type", "re",
                 "(?i)(impossibletravel|mcasimpossibletravel|unfamiliarfeatures|"
                 "anonymizedipaddress|maliciousipaddress|leakedcredentials|"
                 "passwordspray|newcountry|suspiciousinboxmanipulation|"
                 "adminconfirmedusercompromised)"),
               f("risk_level", "re", "(?i)(high|medium)")),
        "gt", [0],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "Entra ID Protection raised a medium or high risk detection",
        "This is the detection-level evidence stream, and it answers a question "
        "the sign-in stream cannot: WHY a sign-in was risky. entra.signin "
        "carries risk_state, so a rule on it can say a session was at risk; "
        "risk_event_type exists only here and names the detection — impossible "
        "travel, an unfamiliar sign-in property, an anonymised or known-malicious "
        "address, credentials found in a public dump, a password-spray victim. "
        "Impossible travel in particular is a correlation Microsoft has already "
        "computed: expressing it as a rule over raw sign-ins would need a join "
        "across two records and a distance calculation, which Loki cannot do. "
        "The record also carries mitre_techniques, ip_address and the location "
        "fields for the investigation.",
        "Requires Entra ID P2 — without it the endpoint answers with an empty "
        "collection and the rule can never fire, which reads exactly like a "
        "clean tenant. The event-type list is Microsoft's published set and has "
        "not been measured field-by-field here, so run the risk-detection-type "
        "hunt first: it tells you both which types your tenant actually produces "
        "and whether leakedCredentials alone already exceeds a sane page rate.",
    ),
    _loki_alert(
        "g2o-detect-workload-identity-risk",
        "Workload identity flagged at risk or confirmed compromised",
        _count("entra.service_principal_risk_detection",
               f("risk_level", "re", "(?i)(high|medium)"),
               f("risk_state", "re", "(?i)(atrisk|confirmedcompromised)")),
        "gt", [0],
        {"severity": "critical", "source": "entra", "category": "identity-threat"},
        "A service principal was flagged at risk or confirmed compromised",
        "The workload-identity half of Identity Protection: a service principal "
        "whose credential leaked, or whose activity Microsoft scored anomalous. "
        "This matters more than the user equivalent and gets watched less. A "
        "service principal has no MFA to fall back on, its credential is often "
        "in a pipeline variable rather than a vault, and nothing prompts a human "
        "when it is used from somewhere new. Check service_principal_name, "
        "app_id and risk_detail, then rotate the credential rather than only "
        "dismissing the detection. This is the portable counterpart to pinning "
        "each automation identity to its own expected source, which cannot ship "
        "here because those values are tenant infrastructure.",
        "The endpoint answers with real detections even on a tenant without "
        "Workload Identities Premium, live-measured, so absence of data here is "
        "genuinely absence of detections rather than a licence wall. It is "
        "usually silent, which makes the threshold of zero plausible and "
        "unmeasured at the same time: run the workload-identity risk hunt over "
        "90 days, and if it returns nothing, keep the rule paused until you have "
        "confirmed the stream works by synthesising one detection.",
    ),
    _loki_alert(
        "g2o-detect-legacy-auth-signin",
        "Sign-in over a legacy authentication protocol",
        _count("entra.signin",
               f("client_app_used", "re",
                 "(?i)(imap4?|pop3?|authenticated smtp|exchange activesync|"
                 "other clients|exchange web services|exchange online powershell|"
                 "autodiscover|offline address book)")),
        "gt", [0],
        {"severity": "warning", "source": "entra", "category": "identity-threat"},
        "A sign-in used a legacy authentication protocol",
        "Legacy protocols cannot present an MFA challenge, so a sign-in that "
        "succeeds over one has bypassed multi-factor authentication no matter "
        "what the Conditional Access policy says. Password spraying targets them "
        "for exactly that reason, and Microsoft's own secure-score guidance is "
        "to block them outright. This is a protocol-level question and is "
        "deliberately separate from the risk-and-Conditional-Access sign-in "
        "detection: that rule asks whether a sign-in looked suspicious, this one "
        "asks whether a channel exists that cannot be challenged, which is worth "
        "knowing even when every sign-in on it is legitimate.",
        "The values here are Microsoft's client-app names and have not been "
        "measured on this project's wire, so run the sign-in client-app hunt "
        "first to see which names your tenant emits and at what rate. Add "
        "status_error_code=`0` to narrow to SUCCESSFUL legacy sign-ins, which is "
        "the smaller and more urgent set; failed ones are mostly spray traffic "
        "and better handled as a trend than a page. If your tenant still has "
        "legitimate legacy clients this fires continuously and belongs on a "
        "dashboard, not a pager, until they are migrated.",
    ),
    _loki_alert(
        "g2o-detect-mail-remediation-failed",
        "Post-delivery mail remediation did not succeed",
        _count("defender.email_post_delivery",
               f("action_result", "re", ".+"),
               f("action_result", "nre", "(?i)success")),
        "gt", [0],
        {"severity": "warning", "source": "defender", "category": "identity-threat"},
        "Defender tried to remove a delivered message and did not succeed",
        "Zero-hour auto purge and manual remediation exist because a message can "
        "be reclassified as malicious after it has already landed in a mailbox. "
        "When that removal FAILS the message is still sitting in an inbox that "
        "Microsoft has already decided is dangerous, and nothing else tells you "
        "so — the alert says the threat was found, the remediation record says "
        "whether it was actually removed. Read action_type, action_trigger and "
        "recipient_email_address, then remove the message by hand.",
        "The filter is two terms because a negative label filter also matches a "
        "record that carries no action_result at all: LogQL treats a missing "
        "structured-metadata key as the empty string, so the presence term "
        "`action_result=~`.+`` is what keeps this from firing on every "
        "remediation record. Run the post-delivery hunt to see which result "
        "values your tenant emits and how often a non-success one is a transient "
        "retry rather than a real miss. Needs the Defender advanced-hunting blob "
        "ingest configured; without it the stream is absent, not clean.",
    ),
]


# ---------------------------------------------------------------------------
# The hunting-query library (#313)
#
# A hunt is a query you RUN, not a rule that runs itself. Three kinds of concept
# end up here rather than in DETECTIONS, and the boundary is deliberate:
#
#   1. The concept needs a correlation Loki cannot perform. Loki has no join, so
#      "two sign-ins too far apart to be the same person" is not expressible as a
#      rule over raw records — but it is a perfectly good question for a human
#      with a grouped query, and where Microsoft has already computed the
#      correlation (Identity Protection) the detection reads it back instead.
#   2. The signal is an INVENTORY, not an event stream. A snapshot collector
#      re-emits every existing row every poll, so `count_over_time(...) > 0` on
#      one is true forever and says nothing. Grouped and read by a person, the
#      same query is the most useful thing in the pack.
#   3. It is the MEASUREMENT a paused detection is waiting for. Every rule in
#      DETECTIONS names a measurement in `tuning_required`; a named measurement
#      with no way to take it is a rule nobody can ever enable, so each one has a
#      hunt here that produces it.
#
# The queries are built through the same `_sel()` path as the detections, so a
# misspelled filter or group key in a DOCUMENTED query fails CI exactly as it
# would in a shipped rule. A hunting page nobody validates is a page of queries
# that silently return nothing, which is worse than no page: the reader concludes
# their tenant is clean.
# ---------------------------------------------------------------------------

HUNTS_DOC = os.path.join(REPO, "docs", "hunting.md")


def _hunt(title: str, event: str, *filters, by: str = "", window: str = "24h",
          question: str, look_for: str, unblocks=()) -> dict:
    return {
        "title": title,
        "event": event,
        "filters": filters,
        "by": by,
        "window": window,
        "question": question,
        "look_for": look_for,
        "unblocks": list(unblocks),
    }


def hunt_query(hunt: dict) -> str:
    """The LogQL a reader pastes into Explore.

    Grouped hunts aggregate; ungrouped ones return the raw log lines, because an
    inventory question is answered by reading the records and a rate question is
    answered by counting them.
    """
    selector = _sel(hunt["event"], *hunt["filters"], by=hunt["by"])
    if not hunt["by"]:
        return selector
    return (f"sum by ({hunt['by']}) "
            f"(count_over_time({selector} [{hunt['window']}]))")


HUNTS = [
    _hunt(
        "Which audit operations does your tenant actually record",
        "m365.audit", by="workload, operation", window="24h",
        question="Which unified-audit operations occur on this tenant, on which "
                 "workload, and how often?",
        look_for="The operation spelling. Both mail detections match a regex "
                 "against `operation`, and if your tenant names the cmdlet "
                 "differently the rule matches nothing and looks healthy. Sort "
                 "descending and read the top of the list: whatever dominates is "
                 "your routine administrative traffic, and anything you do not "
                 "recognise is worth one look.",
        unblocks=("g2o-detect-exchange-inbox-rule-change",
                  "g2o-detect-mailbox-permission-grant"),
    ),
    _hunt(
        "Which client apps sign in, and how much legacy protocol is left",
        "entra.signin", by="client_app_used, status_error_code", window="7d",
        question="Which authentication client does each sign-in use, and does it "
                 "succeed?",
        look_for="Any client that is not a browser or a modern-auth client. Each "
                 "one is a channel that cannot be challenged for MFA. Successful "
                 "legacy sign-ins (`status_error_code` 0) are the urgent set; a "
                 "wall of failures on a legacy protocol is usually spray traffic "
                 "and is a trend, not an incident.",
        unblocks=("g2o-detect-legacy-auth-signin",
                  "g2o-detect-interactive-signin-anomaly"),
    ),
    _hunt(
        "Which Conditional Access failures does your tenant produce, by error code",
        "entra.signin", f("sign_in_event_types", "eq", "interactiveUser"),
        f("conditional_access_status", "eq", "failure"),
        by="status_error_code, app_display_name", window="14d",
        question="Which error codes does Conditional Access actually refuse with "
                 "here, and how often?",
        look_for="The window is 14d, not the 30d the rule's tuning note asks "
                 "for, because a `[30d]` count_over_time exceeds the max query "
                 "range on at least one Grafana Cloud Loki stack and comes back "
                 "EMPTY rather than erroring — measured 2026-08-10, where 21d "
                 "returned data and 30d returned nothing on the same stream. An "
                 "empty result there is indistinguishable from a clean tenant, "
                 "which is the exact trap this page exists to avoid; widen it "
                 "only after checking your own backend answers at that range. "
                 "The share of 50097 'Device authentication is required'. "
                 "`g2o-detect-interactive-signin-anomaly` excludes it by default "
                 "because a REPORT-ONLY policy still stamps "
                 "`conditional_access_status=failure` on a sign-in it never "
                 "blocked, and 50097 is the code it uses; on the tenant this was "
                 "measured on it was 6 of 10 CA failures in 30 days and every one "
                 "was followed by a success. Confirm that on your own tenant "
                 "before trusting the exclusion: take a handful of 50097 records "
                 "and read `appliedConditionalAccessPolicies` on each in Entra "
                 "(graph2otel does not export it). If the only non-success entry "
                 "is a `reportOnlyFailure`, the exclusion is right for you. If "
                 "you ENFORCE a compliant-device or hybrid-join grant, it is not "
                 "— put 50097 back, because there it is a real block. Whatever "
                 "remains after that decision is the number your threshold has to "
                 "clear.",
        unblocks=("g2o-detect-interactive-signin-anomaly",),
    ),
    _hunt(
        "Where do your workload identities sign in from",
        "entra.signin", f("service_principal_name", "re", ".+"),
        by="service_principal_name, ip_address", window="7d",
        question="Which source addresses does each service-principal sign-in "
                 "come from?",
        look_for="An automation identity with exactly one source address. That is "
                 "the almost-zero-false-positive detection described in "
                 "`alerts/README.md`, and this hunt is how you find which of your "
                 "identities qualify and what their expected address is. Those "
                 "values are yours and cannot ship here, which is why the rule "
                 "does not.",
        unblocks=("g2o-detect-workload-identity-risk",),
    ),
    _hunt(
        "Which risk detection types does Identity Protection raise here",
        "entra.risk_detection", by="risk_event_type, risk_level", window="30d",
        question="Which risk detections does this tenant produce, at which level?",
        look_for="Whether the tenant produces anything at all — an empty result "
                 "on a tenant without Entra ID P2 is a licence wall, not a clean "
                 "bill of health. Then the rate per type: `leakedCredentials` "
                 "alone can exceed a sane page rate on a large tenant, and "
                 "`impossibleTravel` is the correlation Loki could not compute "
                 "for you.",
        unblocks=("g2o-detect-identity-risk-detection",),
    ),
    _hunt(
        "Which workload identities have risk detections",
        "entra.service_principal_risk_detection",
        by="risk_event_type, risk_state", window="30d",
        question="Which service principals has Identity Protection flagged, and "
                 "for what?",
        look_for="Usually nothing, which is the problem: a rule that has never "
                 "matched is indistinguishable from a rule that cannot match. If "
                 "this returns nothing over 90 days, prove the stream works "
                 "before trusting the silence.",
        unblocks=("g2o-detect-workload-identity-risk",),
    ),
    _hunt(
        "Which post-delivery mail remediations succeed",
        "defender.email_post_delivery", by="action_type, action_result",
        window="30d",
        question="When Defender removes a message after delivery, does the "
                 "removal succeed?",
        look_for="The exact `action_result` values your tenant emits, and whether "
                 "any record omits the field entirely — a missing structured-"
                 "metadata key compares equal to the empty string, so it would "
                 "match a bare negative filter. Anything that is not a success is "
                 "a message still sitting in a mailbox Microsoft has already "
                 "judged dangerous.",
        unblocks=("g2o-detect-mail-remediation-failed",),
    ),
    _hunt(
        "Which applications hold federated identity credentials",
        "entra.federated_identity_credential", window="24h",
        question="Which applications trust an external issuer to mint tokens for "
                 "them, and which subject in that issuer?",
        look_for="An issuer or subject you do not recognise. A federated identity "
                 "credential is a keyless trust: whoever controls that subject at "
                 "that issuer can obtain tokens for the application with no "
                 "secret to leak or rotate, which makes adding one an attractive "
                 "and quiet persistence step. This is an inventory rather than an "
                 "event stream, so it is a hunt: the collector re-emits every "
                 "existing credential every poll, and a rule counting them would "
                 "fire forever. Read `issuer`, `subject` and `audiences` on each "
                 "record.",
        unblocks=("g2o-detect-privileged-directory-change",),
    ),
    _hunt(
        "Which consent grants exist, and how privileged are they",
        "entra.consent_grant", by="privilege, consent_type", window="24h",
        question="What has been consented to in this tenant, at what privilege, "
                 "and for the whole tenant or one user?",
        look_for="High-privilege application-wide grants. `consent_type` "
                 "separates a tenant-wide admin grant from one user's own, and "
                 "the tenant-wide ones are the ones worth auditing line by line. "
                 "Also an inventory rather than an event stream — the ACT of "
                 "granting consent is already covered by the privileged-directory"
                 "-change detection, so this hunt answers the different question "
                 "of what is standing granted right now.",
        unblocks=("g2o-detect-privileged-directory-change",),
    ),
    _hunt(
        "Who holds privileged roles, permanently or eligibly",
        "entra.role_member", by="role_name, assignment_type, permanent",
        window="24h",
        question="Which principals hold which directory roles, and is the "
                 "assignment permanent or time-bound?",
        look_for="Permanent assignments to the high-privilege roles, and any "
                 "assignment held by a service principal rather than a person. "
                 "Role ACTIVATION is an event and is already covered by the "
                 "privileged-directory-change detection; standing membership is a "
                 "posture question, which is why it is a hunt — a rule over an "
                 "inventory would fire on your correct configuration forever.",
        unblocks=("g2o-detect-privileged-directory-change",),
    ),
    _hunt(
        "What operations do Intune administrators perform",
        "intune.audit_event",
        by="activity_operation_type, activity_result, category", window="30d",
        question="Which Intune administrative operations happen, on which object "
                 "category, and do they succeed?",
        look_for="Deletions of compliance or configuration policies, and any "
                 "operation type you did not expect. This project has only ever "
                 "observed `Create` on the wire for `activity_operation_type`, "
                 "which is exactly why a destructive-action rule is NOT shipped: "
                 "a rule matching a value spelling nobody has seen is a rule that "
                 "may never fire. Take this measurement, and if your tenant emits "
                 "the deletion spelling, write the rule against what you "
                 "measured.",
        unblocks=("g2o-detect-security-incident-active",),
    ),
    _hunt(
        "Which security alerts arrive, from which Microsoft product",
        "entra.security_alert", by="severity, status, service_source",
        window="30d",
        question="What is the arrival rate of security alerts by severity, "
                 "resolution status and originating product?",
        look_for="The rate. Two shipped detections page on this stream and its "
                 "incident sibling, and their volume is set by your Defender "
                 "licensing rather than by the query. If medium severity "
                 "dominates, narrow to high before enabling either.",
        unblocks=("g2o-detect-security-alert-unresolved",
                  "g2o-detect-security-incident-active"),
    ),
    _hunt(
        "Which applications take Graph authorization denials",
        "entra.graph_activity", f("response_status_code", "eq", "403"),
        by="app_id", window="7d",
        question="Which callers receive HTTP 403 from Microsoft Graph, and how "
                 "many?",
        look_for="Your own baseline. The shipped burst detection uses ten in five "
                 "minutes, which came from one small tenant; a tenant with more "
                 "automation will have a caller that routinely exceeds it because "
                 "it probes for an optional permission. Find that caller first, "
                 "then set the threshold above it.",
        unblocks=("g2o-detect-graph-403-burst",),
    ),
]


HUNTS_PAGE_HEADER = """\
<!-- GENERATED by grafana/build_rules.py from its HUNTS list — do not edit by
     hand. Edit the hunt there, then run `make rules`. Every query below is built
     by the same typed-filter path as the shipped alert rules, so a misspelled
     attribute fails CI instead of silently matching nothing. -->

# Hunting queries

A hunt is a query you **run**, not a rule that runs itself. This page is the
measurement instrument for the [paused detections](runbooks.md): each one names
the measurement it needs before it is safe to enable, and the query that produces
that measurement is here.

Three kinds of question live here rather than in a rule, and the boundary is
deliberate:

- **The correlation is one Loki cannot perform.** Loki has no join, so "two
  sign-ins too far apart to be the same person" is not expressible as a rule over
  raw records. It is a fine question for a person with a grouped query, and where
  Microsoft has already computed the correlation the detection reads its verdict
  back instead of pretending to recompute it.
- **The signal is an inventory, not an event stream.** A snapshot collector
  re-emits every existing row on every poll, so `count_over_time(...) > 0` over
  one is true forever and tells you nothing. Grouped and read by a person, the
  same query is the most useful thing here.
- **It is a threshold you do not have yet.** Every number in the detection pack
  came from one tenant or from nowhere at all. These queries are how you replace
  it with your own.

## How to run them

Paste a query into **Explore**, pick your Loki datasource, and set the time range
to at least the window in the query. Then read the result, do not alert on it.

Two things about the query shape, both of which have bitten this project:

- The stream selector is **always** `{service_name="graph2otel"}` and nothing
  else. Every attribute is Loki structured metadata, so
  `{event_name="entra.signin"}` matches **zero rows silently** — it is not an
  error, it is an empty graph that looks like a clean tenant. See
  [Signals](signals.md).
- A **negative** filter also matches a record that lacks the attribute entirely,
  because a missing structured-metadata key compares equal to the empty string.
  Pair it with a presence term (`` attr=~`.+` ``) when that matters.

Windows longer than a few days over a busy stream are slow. Narrow the window
first, then widen it once you know the query returns what you expect.
"""


def render_hunting_page() -> bytes:
    """The hunting library as a docs page, generated from HUNTS.

    Generated rather than hand-written for one reason: a hand-copied query is an
    unvalidated query, and it looks identical to a validated one. The prose lives
    next to the query it describes in ``HUNTS`` so the two cannot drift apart.
    """
    parts = [HUNTS_PAGE_HEADER]
    for hunt in HUNTS:
        parts.append(f"## {hunt['title']}\n")
        parts.append(f"**Question:** {hunt['question']}\n")
        parts.append(f"```logql\n{hunt_query(hunt)}\n```\n")
        parts.append(f"**What to look for:** {hunt['look_for']}\n")
        if hunt["unblocks"]:
            targets = ", ".join(f"[`{uid}`](runbooks.md#{uid})"
                                for uid in hunt["unblocks"])
            parts.append(f"**Measurement for:** {targets}\n")
        parts.append("")
    return ("\n".join(parts).rstrip() + "\n").encode()


def validate_detection_fields(cat) -> list:
    """Every event and attribute a detection names must exist in the catalog.

    A LogQL filter on an attribute graph2otel does not emit is not an error at
    query time — it simply matches nothing, silently, forever (#90). For a
    detection that is the worst possible failure: it looks installed and healthy
    while being unable to ever fire.

    Derived from the typed filters themselves (#306), accumulated as the
    DETECTIONS list is built, so there is no parallel declaration to drift.
    """
    del cat  # validated against the module-level CAT at construction time
    return list(DETECTION_VIOLATIONS)





# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# App Platform projection (#294) — the ONE deployable representation
#
# graph2otel provisions Grafana-managed rules as
# `rules.alerting.grafana.app/v0alpha1` AlertRule manifests, one YAML per rule,
# pushed by stable `metadata.name` so a repeat push updates in place.
#
# Every field shape below was MEASURED off the live wire on 2026-07-27, not read
# out of documentation: an existing rule was read back with `gcx resources get
# alertrules.v0alpha1.rules.alerting.grafana.app/<uid>`, a projected manifest was
# pushed, and the result read back again and compared field by field. That
# matters because the representation this replaces — the classic `apiVersion: 1`
# + `groups:` file-provisioning bundle — is REJECTED with HTTP 400 when posted as
# an individual object, and a repeated classic recording-rule POST created
# duplicates with fresh UIDs. The classic provisioning endpoints are also
# deprecated upstream.
#
# The five shape differences from the classic form, all measured:
#   * `data` list            -> `spec.expressions` MAP keyed by refId
#   * `condition: "C"`       -> `source: true` on that one expression
#   * second counts          -> Go duration strings ("1h0m0s", "0s", "5m0s")
#   * group `interval`       -> per-rule `spec.trigger.interval`
#   * group/folder in a bundle header -> `metadata.labels`/`metadata.annotations`
#
# Expression nodes (`__expr__`) carry NEITHER `datasourceUID` NOR
# `relativeTimeRange` on the wire; only datasource-backed nodes do.
# ---------------------------------------------------------------------------

# A folder UID is stack-specific, so a public repository cannot know it. This
# token is deliberately loud rather than absent: measured 2026-07-27, pushing an
# unresolvable folder UID fails with `403 Forbidden` and creates nothing, while
# OMITTING the annotation silently files every rule in the General folder. A
# visible failure beats a silent wrong placement. `grafana/rules_deploy.py`
# resolves the real UID from a folder title at push time.
FOLDER_TOKEN = "REPLACE_WITH_FOLDER_UID"

# Measured 2026-07-27, and NOT optional. Grafana refuses the update outright
# without it — `409 Conflict: cannot update with provided provenance '', needs
# 'api'` — because the live rules were created through API provisioning and the
# provenance must match. Declaring it also makes the rule read-only in the
# Grafana UI, which is what we want for a generated asset: hand-editing it there
# would silently diverge from this repository until the next push overwrote the
# edit. The push additionally requires `--omit-manager-fields`; without it the
# manager fields gcx appends produce their own 409 (`provided provenance 'api',
# needs 'api'`, whose message is self-contradictory and cost real time to read
# past). Both requirements are exercised by `grafana/rules_deploy.py`.
PROVENANCE = "api"

# The App Platform enum is `Ok`, NOT `OK`. Measured 2026-07-27 — 18 of 19 rules
# were rejected with `403 Forbidden: spec.noDataState: Invalid value: "OK":
# value is not one of the allowed values ["NoData","Ok","Alerting","KeepLast"]`.
# The classic file-provisioning API accepted `OK`, so this is a real
# representation difference and not a typo in the canonical rules; RULES keeps
# the classic spelling and the projection maps it. Nothing in the documentation
# said so — it took a push to find.
STATE_SPELLING = {"OK": "Ok"}


def app_platform_state(state: str) -> str:
    return STATE_SPELLING.get(state, state)

APP_PLATFORM_API = "rules.alerting.grafana.app/v0alpha1"

ALERT_GROUP = "graph2otel-alerts"
ALERT_FOLDER_TITLE = "graph2otel"
DETECTION_GROUP = "graph2otel-detections"
DETECTION_FOLDER_TITLE = "graph2otel detections"
GROUP_INTERVAL = "5m"


# The server fills these in on every expression node it stores, including the
# reduce/threshold nodes where the canonical rule dicts omit them. Emitting them
# means the committed manifest is byte-comparable with stored state instead of
# needing a normalization step in the read-back — and a normalization is a place a
# real difference can hide (#294; the same reasoning as go_duration below).
EXPRESSION_DEFAULTS = {"intervalMs": 1000, "maxDataPoints": 43200}


def parse_duration(text: str) -> int:
    """Grafana's short duration spellings -> seconds. Raises on anything else.

    Refuses to guess: an unparseable `for` silently becoming 0 would turn a
    5-minute alert into an instant one.
    """
    match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", text.strip())
    if not match or not any(match.groups()):
        raise ValueError(f"cannot parse duration {text!r}")
    hours, minutes, seconds = (int(g or 0) for g in match.groups())
    return hours * 3600 + minutes * 60 + seconds


def go_duration(seconds: int) -> str:
    """Seconds -> the exact duration string the App Platform API returns.

    This is Go's own `time.Duration.String()` format, which **omits leading zero
    units and keeps trailing ones**: 3600 -> `1h0m0s`, 300 -> `5m0s`, 30 -> `30s`,
    0 -> `0s`. Measured against the live wire, and worth spelling out because the
    obvious implementation (always `HhMmSs`) emits `0h5m0s`, which read back as
    `5m0s` and reported all 11 rules as divergent on nothing.

    The generated manifest uses the server's exact spelling so a read-back
    comparison needs no duration normalization — a normalization is somewhere a
    real difference can hide.
    """
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes}m{secs}s"
    if minutes:
        return f"{minutes}m{secs}s"
    return f"{secs}s"


def to_app_platform(rule: dict, group: str, interval: str, index: int) -> dict:
    """Project one canonical rule dict into an App Platform AlertRule."""
    expressions = {}
    for node in rule["data"]:
        model = dict(node["model"])
        for key, value in EXPRESSION_DEFAULTS.items():
            model.setdefault(key, value)
        entry = {"model": model}
        if node.get("datasourceUid") and node["datasourceUid"] != EXPR_UID:
            entry["datasourceUID"] = node["datasourceUid"]
            window = node.get("relativeTimeRange") or {}
            entry["relativeTimeRange"] = {
                "from": go_duration(window.get("from", 0)),
                "to": go_duration(window.get("to", 0)),
            }
        if node["refId"] == rule["condition"]:
            entry["source"] = True
        expressions[node["refId"]] = entry

    spec = {}
    # A zero `for` is OMITTED, not spelled: the server drops it (measured — a
    # projected `0m0s` read back as absent), so emitting it would make every
    # instant-firing rule permanently "divergent" and bury real drift in noise.
    hold_seconds = parse_duration(rule["for"])
    if hold_seconds:
        spec["for"] = go_duration(hold_seconds)

    return {
        "apiVersion": APP_PLATFORM_API,
        "kind": "AlertRule",
        "metadata": {
            "name": rule["uid"],
            "annotations": {
                "grafana.app/folder": FOLDER_TOKEN,
                "grafana.com/provenance": PROVENANCE,
            },
            "labels": {
                "grafana.com/group": group,
                "grafana.com/group-index": str(index),
            },
        },
        "spec": {
            "title": rule["title"],
            "paused": rule["isPaused"],
            **spec,
            "noDataState": app_platform_state(rule["noDataState"]),
            "execErrState": app_platform_state(rule["execErrState"]),
            "trigger": {"interval": interval},
            "labels": rule["labels"],
            "annotations": rule["annotations"],
            "expressions": expressions,
        },
    }


MANIFEST_BANNER = """\
# GENERATED by grafana/build_rules.py — do not edit by hand. Edit the RULES or
# DETECTIONS list there, then run `make rules`.
#
# Grafana App Platform AlertRule (rules.alerting.grafana.app/v0alpha1). Deploy
# with `make rules-push` (see docs/deploying-observability.md), NOT with a bare
# `gcx resources push`: `grafana.app/folder` below is a substitution token, and
# an unresolved one fails with 403 rather than filing the rule somewhere wrong.
"""


def render_app_platform() -> dict:
    """filename -> bytes, one manifest per alert rule and per detection."""
    out = {}
    for index, rule in enumerate(RULES):
        doc = to_app_platform(rule, ALERT_GROUP, GROUP_INTERVAL, index)
        out[f"{rule['uid']}.yaml"] = (
            MANIFEST_BANNER + yamlify(doc) + "\n").encode()
    for index, rule in enumerate(DETECTIONS):
        doc = to_app_platform(rule, DETECTION_GROUP, GROUP_INTERVAL, index)
        out[f"{rule['uid']}.yaml"] = (
            MANIFEST_BANNER + yamlify(doc) + "\n").encode()
    return out


def manifest_orphans(expected: set, present: set) -> list:
    """Committed manifests with no generating rule."""
    return sorted(present - expected)


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


SCAN_SKIP_DIRS = {".git", "__pycache__", "node_modules", "third_party",
                  ".superpowers", "testdata", ".venv", "site"}


def retired_recording_rule_violations() -> list:
    """#297: no recording rule ships in this repository, in any form.

    Both Loki recording rules were retired on measured evidence — they wrote no
    series for 30+ days while reporting ``health: ok``, because a 1h *event-time*
    window can never overlap a blob-derived source whose records are 3.3-7.0 days
    old (median 5.97, n=223). Nothing consumed their output.

    This is a gate on the OUTCOME, not on a filename: any committed YAML/JSON
    carrying a top-level Grafana ``record`` block is a recording rule whatever it
    is called, and the retired ``recording-rules/`` directory coming back is
    itself a violation. Reintroducing one has to delete this gate, deliberately.
    """
    violations = []
    if os.path.isdir(os.path.join(REPO, "recording-rules")):
        violations.append(
            "recording-rules/ exists — the directory was removed by #297")
    for dirpath, dirnames, fnames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS]
        for fname in sorted(fnames):
            if not fname.endswith((".yaml", ".yml", ".json")):
                continue
            path = os.path.join(dirpath, fname)
            if not os.path.isfile(path):
                continue
            if "record" in _top_level_keys(path):
                violations.append(
                    f"{os.path.relpath(path, REPO)}: declares a top-level "
                    f"`record` block")
    return sorted(violations)


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
# runbook + dashboard navigation metadata (#307)
#
# Three annotations are attached to EVERY rule, paused ones included:
#
#   runbook_url        the docs-site runbook section for this rule
#   __dashboardUid__   Grafana's own panel-link feature; must be set TOGETHER
#   __panelId__        with __dashboardUid__ or Grafana ignores both
#   dashboard_path     the same target as a deep link, relative to the
#                      operator's own Grafana host
#
# Paused rules get the same treatment on purpose. A paused rule is precisely the
# one an operator is about to enable, and the runbook is what tells them whether
# enabling it is safe — withholding it from exactly those rules would invert the
# need.
#
# Nothing here is hand-typed. The runbook URL is derived from the rule uid; the
# panel id and tab slug are resolved out of the GENERATED dashboard manifest by
# (tab title, panel title). A wrong ``dtab`` slug is silently ignored by Grafana
# (measured, #399) and a wrong panel id renders "Panel not found", so neither may
# be written by hand at a link site. Renaming a panel therefore breaks the build
# here rather than shipping a dead link.
#
# CONSEQUENCE, deliberately accepted: the generated alerts YAML now depends on
# dashboards/graph2otel.json. Change the dashboard, re-run `make rules`. The
# staleness gate says so.
# ---------------------------------------------------------------------------

DASHBOARD_UID = "graph2otel"
RUNBOOK_URL_BASE = "https://m7kni.io/graph2otel/runbooks/"

# Every section of docs/runbooks.md must answer all four, because these are the
# four states a responder actually meets: the rule fired, the rule went to no
# data, the rule errored, or the rule was wrong.
RUNBOOK_REQUIRED_SECTIONS = (
    "**No data:**",
    "**Evaluator error:**",
    "**False positives:**",
    "**Remediation:**",
)

# rule uid -> (top-level dashboard tab title, panel title). Resolved to a numeric
# panel id at build time. Every rule is mapped: an unmapped rule fails the gate
# rather than shipping with no dashboard context.
DASHBOARD_TARGETS = {
    "g2o-entra-cred-expiry-critical": ("Entra", "Credentials expiring total"),
    "g2o-entra-cred-expiry-warning": ("Entra", "Credentials expiring total"),
    "g2o-intune-apple-token-expiry-critical":
        ("Intune", "Apple token days until expiry"),
    "g2o-intune-cert-expiry-critical":
        ("Intune", "Certificate days until expiry"),
    "g2o-intune-compliance-ratio-low": ("Intune", "Compliance devices"),
    "g2o-intune-compliance-noncompliant-spike": ("Intune", "Compliance devices"),
    "g2o-collector-staleness":
        ("Self-obs", "Scrape staleness (seconds since last healthy result)"),
    "g2o-collector-degraded-sustained":
        ("Self-obs", "Scrape success by collector"),
    "g2o-collector-watermark-stalled":
        ("Self-obs", "Window watermark age (seconds behind now)"),
    "g2o-checkpoint-persist-errors":
        ("Self-obs", "Checkpoint persist error rate"),
    "g2o-record-integrity-loss":
        ("Self-obs", "Dropped / errored source-record rate"),
    "g2o-payload-type-mismatch": ("Self-obs", "Payload type-mismatch rate"),
    "g2o-throttle-saturation":
        ("Self-obs", "Throttle (429) rate by workload"),
    "g2o-throttle-budget-consumption":
        ("Self-obs", "Graph-reported throttle budget consumed"),
    "g2o-mdca-uploads-stopped":
        ("Defender", "Discovery parse last success age"),
    "g2o-mdca-parse-failing": ("Defender", "Discovery parse tasks rate"),
    "g2o-record-attrs-truncated": (
        "Self-obs", "Records whose attributes were clipped to fit the backend size limit"),
    "g2o-record-over-horizon": (
        "Self-obs", "Records dropped as older than the backend accept window"),
    "g2o-otlp-delivery-failing": (
        "Self-obs", "Exporter callback rates by signal"),
    "g2o-detect-privileged-directory-change":
        ("Entra", "Top directory audit activities"),
    "g2o-detect-security-alert-unresolved":
        ("Defender", "Defender alerts — which alert, which source"),
    "g2o-detect-security-incident-active":
        ("Defender", "Alerts by severity and detection source"),
    "g2o-detect-graph-403-burst": ("Entra", "Graph activity requests rate"),
    "g2o-detect-interactive-signin-anomaly":
        ("Entra", "Failed sign-ins — which user, which IP, which error"),
    # Second wave (#313).
    "g2o-detect-exchange-inbox-rule-change":
        ("M365", "Top audited operations by workload"),
    "g2o-detect-mailbox-permission-grant":
        ("M365", "Unified audit — which user, which operation"),
    "g2o-detect-identity-risk-detection":
        ("Entra", "Risk detections by event type and level"),
    "g2o-detect-workload-identity-risk":
        ("Entra", "Risky service principals total"),
    "g2o-detect-legacy-auth-signin":
        ("Entra", "Top failing sign-in sources (country, client app)"),
    "g2o-detect-mail-remediation-failed":
        ("Defender", "Quarantine held messages total"),
}


def load_manifest(path: str = DASHBOARD_MANIFEST) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _rows_of(spec: dict) -> list:
    layout = spec.get("layout", {})
    if layout.get("kind") == "RowsLayout":
        return layout["spec"]["rows"]
    return []


def panel_index(man: dict) -> dict:
    """``(top-level tab title, panel title) -> numeric panel id``.

    Keyed on the TOP-LEVEL tab because that is the only slug in a deep link that
    is measured (``?dtab=<Tab-Slug>``); leaf-tab nesting is irrelevant to a
    ``viewPanel`` link, which opens full-screen. A duplicate key is a build
    error: it would make the resolution ambiguous, and an ambiguous slug is the
    one failure Grafana does not report.
    """
    elements = {name: el["spec"] for name, el in man["spec"]["elements"].items()}
    index: dict = {}
    for tab in man["spec"]["layout"]["spec"]["tabs"]:
        top = tab["spec"]["title"]

        def walk(spec: dict) -> None:
            layout = spec.get("layout", {})
            if layout.get("kind") == "TabsLayout":
                for nested in layout["spec"]["tabs"]:
                    walk(nested["spec"])
                return
            for row in _rows_of(spec):
                grid = row["spec"].get("layout", {})
                if grid.get("kind") != "GridLayout":
                    continue
                for item in grid["spec"]["items"]:
                    panel = elements[item["spec"]["element"]["name"]]
                    key = (top, panel.get("title", ""))
                    if key in index and index[key] != panel["id"]:
                        raise ValueError(
                            f"panel title {key[1]!r} appears twice under tab "
                            f"{top!r}: a link to it would be ambiguous")
                    index[key] = panel["id"]

        walk(tab["spec"])
    return index


def resolve_target(man: dict, tab: str, panel_title: str) -> tuple:
    """``(panel id, tab slug)`` for a dashboard target, or ``KeyError``.

    The error names the tab and lists its real panel titles, because the common
    cause is a deliberate panel rename in a file this module does not own — that
    is a one-line fix here, provided the message says what to change it to.
    """
    index = panel_index(man)
    titles = sorted(title for existing, title in index if existing == tab)
    if not titles:
        raise KeyError(
            f"no top-level dashboard tab titled {tab!r}; known tabs: "
            f"{sorted({t for t, _ in index})}")
    try:
        panel_id = index[(tab, panel_title)]
    except KeyError:
        raise KeyError(
            f"no panel titled {panel_title!r} under dashboard tab {tab!r} — a "
            f"panel was renamed. Titles under {tab!r}: {titles}"
        ) from None
    return panel_id, v2.slug(tab)


# uid -> reason. A rule whose linked panel legitimately plots a DIFFERENT signal
# from the rule's own. Same principle as the dashboard coverage waivers: a gate
# with no escape hatch gets turned off, and one with an undocumented escape hatch
# is not a gate. An unused entry here fails too, so a waiver cannot outlive the
# panel that justified it.
SIGNAL_MATCH_WAIVERS = {
    "g2o-detect-security-alert-unresolved":
        "no panel plots the entra.security_alert stream; the Defender alert log "
        "panel (defender.alert) is the nearest investigation surface, and the "
        "two streams overlap in content without sharing a signal name",
    "g2o-detect-security-incident-active":
        "no panel plots entra.security_incident at all — incidents are the "
        "correlation layer above alerts, so the alert-severity panel is the "
        "closest context a responder can pivot to",
    "g2o-detect-workload-identity-risk":
        "no panel plots entra.service_principal_risk_detection; the "
        "risky-service-principal gauge is the same subject one layer up — it "
        "counts how many workload identities are risky right now, where this "
        "rule fires on the detection that made one of them risky",
    "g2o-detect-mail-remediation-failed":
        "no panel plots defender.email_post_delivery; the quarantine gauge is "
        "the nearest surface, because both are about messages Defender has "
        "already judged malicious and acted on, and a failed post-delivery "
        "removal is the case where that action did not land",
}


def rule_signal_tokens(rule: dict) -> set:
    """Every signal name a rule's own queries reference.

    Prometheus metric names for a metric rule, log event names for a Loki
    detection. Derived from the rendered query text, so it cannot disagree with
    what the rule actually evaluates.
    """
    tokens = set()
    for node in rule.get("data", []):
        model = node.get("model", {})
        expr = model.get("expr", "")
        ds_type = model.get("datasource", {}).get("type")
        if ds_type == "prometheus":
            tokens |= _metric_tokens(expr)
        elif ds_type == "loki":
            tokens |= set(re.findall(r"event_name=`([^`]+)`", expr))
    return tokens


def panel_query_text(man: dict) -> dict:
    """``panel id -> the concatenated text of its queries``."""
    text = {}
    for element in man["spec"]["elements"].values():
        spec = element["spec"]
        queries = spec.get("data", {}).get("spec", {}).get("queries", [])
        text[spec["id"]] = " ".join(
            json.dumps(q["spec"]["query"]["spec"]) for q in queries)
    return text


def dashboard_path(slug: str, panel_id: int) -> str:
    """A deep link relative to the operator's own Grafana host.

    Carries the owning tab's ``dtab`` as well as ``viewPanel``: a ``viewPanel``
    link whose ancestor tab is conditioned away renders a completely blank body
    with no message, and a ``dtab`` overrides that hiding (both measured, #399).
    """
    return f"/d/{DASHBOARD_UID}?dtab={slug}&viewPanel={panel_id}"


def attach_navigation(rules: list, man: dict) -> None:
    """Add the runbook + dashboard annotations to every rule, in place."""
    for rule in rules:
        uid = rule["uid"]
        tab, panel_title = DASHBOARD_TARGETS[uid]
        panel_id, slug = resolve_target(man, tab, panel_title)
        rule["annotations"].update({
            "runbook_url": f"{RUNBOOK_URL_BASE}#{uid}",
            "__dashboardUid__": DASHBOARD_UID,
            "__panelId__": str(panel_id),
            "dashboard_path": dashboard_path(slug, panel_id),
        })


_RUNBOOK_HEADING = re.compile(r"^###\s+(?:`)?([a-z0-9][a-z0-9-]*)(?:`)?\s*$")


def runbook_sections(path: str = RUNBOOKS_SOURCE) -> dict:
    """``anchor -> section body`` for every per-rule section of the runbook page.

    The anchor is the ``###`` heading text verbatim, which is also the rule uid:
    the docs-site slugifier leaves an already-lowercase hyphenated string alone,
    so ``#<uid>`` resolves without a second naming scheme to keep in step.
    """
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    sections: dict = {}
    current = None
    for line in lines:
        m = _RUNBOOK_HEADING.match(line)
        if m:
            current = m.group(1)
            sections[current] = []
            continue
        if line.startswith("## "):
            current = None
            continue
        if current is not None:
            sections[current].append(line)
    return {anchor: "\n".join(body) for anchor, body in sections.items()}


def navigation_violations(rules: list, man: dict) -> list:
    """Every unreachable runbook or dashboard link, as human-readable strings."""
    violations = []
    anchors = set(runbook_sections())
    ids = {el["spec"]["id"] for el in man["spec"]["elements"].values()}
    index = panel_index(man)
    tab_of_id: dict = {}
    for (tab, _title), panel_id in index.items():
        tab_of_id.setdefault(panel_id, set()).add(v2.slug(tab))
    tab_slugs = {v2.slug(tab["spec"]["title"])
                 for tab in man["spec"]["layout"]["spec"]["tabs"]}
    queries = panel_query_text(man)
    waivers_used = set()

    for rule in rules:
        uid = rule.get("uid", "<unknown>")
        ann = rule.get("annotations", {})

        url = ann.get("runbook_url", "")
        if not url:
            violations.append(
                f"{uid}: no runbook_url — a rule with no runbook leaves a "
                "responder reading the expr at 3am")
        elif not url.startswith(RUNBOOK_URL_BASE + "#"):
            violations.append(
                f"{uid}: runbook_url {url!r} is not a {RUNBOOK_URL_BASE} anchor")
        elif url.split("#", 1)[1] not in anchors:
            violations.append(
                f"{uid}: runbook_url anchor {url.split('#', 1)[1]!r} has no "
                "section in docs/runbooks.md — the link would silently land on "
                "the page top")

        dash_uid = ann.get("__dashboardUid__", "")
        panel = ann.get("__panelId__", "")
        if dash_uid and not panel:
            violations.append(
                f"{uid}: __dashboardUid__ without __panelId__ — Grafana needs "
                "both set together or it renders no panel link")
        if panel and not dash_uid:
            violations.append(
                f"{uid}: __panelId__ without __dashboardUid__ — Grafana needs "
                "both set together or it renders no panel link")
        if not panel:
            violations.append(
                f"{uid}: no __panelId__ — the alert offers no dashboard context")
            continue
        if dash_uid != DASHBOARD_UID:
            violations.append(
                f"{uid}: __dashboardUid__ is {dash_uid!r}, want {DASHBOARD_UID!r}")
        if not panel.isdigit():
            violations.append(
                f"{uid}: __panelId__ {panel!r} is not a numeric panel id "
                "(viewPanel keys on spec.id, never on an element name)")
            continue
        panel_id = int(panel)
        if panel_id not in ids:
            violations.append(
                f"{uid}: __panelId__ {panel_id} is not a panel in the generated "
                "dashboard — the drilldown renders 'Panel not found'")
        else:
            # A title check alone proves the label survived, not that the panel is
            # still ABOUT this rule's signal. Match the panel's own query text
            # against the signals the rule evaluates, accepting a log event's
            # metric-twin spelling (entra.graph_activity -> entra_graph_activity).
            wanted = rule_signal_tokens(rule)
            text = queries.get(panel_id, "")
            hit = any(token in text or token.replace(".", "_") in text
                      for token in wanted)
            if wanted and not hit:
                if uid in SIGNAL_MATCH_WAIVERS:
                    waivers_used.add(uid)
                    if not SIGNAL_MATCH_WAIVERS[uid].strip():
                        violations.append(
                            f"{uid}: signal-match waiver has no reason")
                else:
                    violations.append(
                        f"{uid}: linked panel {panel_id} queries none of the "
                        f"rule's own signals {sorted(wanted)} — the link points "
                        "at a panel about something else. Re-point it, or add a "
                        "SIGNAL_MATCH_WAIVERS reason")

        path = ann.get("dashboard_path", "")
        if not path:
            violations.append(f"{uid}: no dashboard_path deep link")
            continue
        dtab = re.search(r"[?&]dtab=([^&]+)", path)
        view = re.search(r"[?&]viewPanel=(\d+)", path)
        if not dtab or not view:
            violations.append(
                f"{uid}: dashboard_path {path!r} must carry both dtab and "
                "viewPanel")
            continue
        if dtab.group(1) not in tab_slugs:
            violations.append(
                f"{uid}: dashboard_path names dtab {dtab.group(1)!r}, which is "
                "not a tab slug in the generated dashboard — Grafana ignores a "
                f"wrong dtab SILENTLY. Known: {sorted(tab_slugs)}")
        elif dtab.group(1) not in tab_of_id.get(panel_id, set()):
            violations.append(
                f"{uid}: panel {panel_id} does not sit under dtab "
                f"{dtab.group(1)!r}")
        if view.group(1) != panel:
            violations.append(
                f"{uid}: dashboard_path viewPanel={view.group(1)} disagrees with "
                f"__panelId__={panel}")

    # Only meaningful when every waived rule is in scope, so it is skipped for
    # the single-rule mutation tests.
    uids_in_scope = {rule.get("uid") for rule in rules}
    if set(SIGNAL_MATCH_WAIVERS) <= uids_in_scope:
        for uid in sorted(set(SIGNAL_MATCH_WAIVERS) - waivers_used):
            violations.append(
                f"{uid}: SIGNAL_MATCH_WAIVERS entry is unused — the panel it "
                "excused now matches, so delete the waiver")

    return violations


# ---------------------------------------------------------------------------
# annotation lint (#307): the prose a responder actually reads
#
# Generalized from one shipped defect rather than special-cased to it: the
# checkpoint rule's description ended `Even one increment is worth knowing
# about — for is 0m.`, a rule FIELD used as a bare English subject, and several
# descriptions pointed at "README doc block N", which is not clickable from a
# Grafana notification. Both classes are linted, not just those two strings.
# ---------------------------------------------------------------------------

# The prose keys. runbook_url/dashboard_path/__*__ are machine targets, gated by
# navigation_violations above, and would trip the file-reference check.
PROSE_ANNOTATIONS = ("summary", "description", "tuning_required",
                     "exec_error_waiver")

# A repository path is meaningless in a notification: the reader is in Grafana or
# a chat client, not a checkout.
_REPO_FILE = re.compile(r"\b[\w][\w./-]*\.(?:md|ya?ml|json|py|go|toml)\b")
_DOC_BLOCK = re.compile(r"\bdoc block\b", re.IGNORECASE)
# A rule field used as a bare subject. Backticked (`for` is 0m) is fine, which
# the pattern gets for free: a backtick sits between the field and the verb.
_FIELD_SUBJECT = re.compile(
    r"\b(for|noDataState|execErrState|isPaused)\s+(?:is|are)\b")
_PLACEHOLDER = re.compile(r"\b(TODO|TBD|FIXME|XXX)\b")
# Doubled spacing, or whitespace before punctuation. An ellipsis inside a quoted
# PromQL fragment (``sum ... >= 5``) is not that, hence the negative lookahead.
_DOUBLE_SPACE = re.compile(r"[ \t]{2,}|\s+,|\s+\.(?!\.)")
_TERMINATORS = ".!)}"
# A summary is a notification HEADLINE, not prose, so it is exempt from the
# sentence-terminator check that the multi-sentence keys take.
_UNTERMINATED_EXEMPT = ("summary",)


def linted_annotation_count(rules: list) -> int:
    """How many annotation values the lint actually inspected.

    Exposed so a caller can assert it did not pass vacuously over an empty set.
    """
    return sum(1 for rule in rules
               for key in PROSE_ANNOTATIONS
               if key in rule.get("annotations", {}))


def annotation_violations(rules: list) -> list:
    """Every rotted or malformed annotation string, as violations."""
    violations = []
    for rule in rules:
        uid = rule.get("uid", "<unknown>")
        ann = rule.get("annotations", {})
        for key in ("summary", "description"):
            if not ann.get(key, "").strip():
                violations.append(f"{uid}: {key} is empty")
        for key in PROSE_ANNOTATIONS:
            text = ann.get(key)
            if text is None:
                continue
            if not text.strip():
                continue
            for m in _REPO_FILE.finditer(text):
                violations.append(
                    f"{uid}: {key} names repository file {m.group(0)!r}, which "
                    "a reader cannot open from Grafana — point at the runbook")
            if _DOC_BLOCK.search(text):
                violations.append(
                    f"{uid}: {key} refers to a 'doc block', a stale internal "
                    "reference with no clickable target")
            m = _FIELD_SUBJECT.search(text)
            if m:
                violations.append(
                    f"{uid}: {key} uses the rule field {m.group(1)!r} as a bare "
                    f"English subject ({m.group(0)!r}) — write it as a code "
                    f"span (`{m.group(1)}`) or as a full clause")
            m = _PLACEHOLDER.search(text)
            if m:
                violations.append(
                    f"{uid}: {key} still carries the placeholder marker "
                    f"{m.group(1)!r}")
            if _DOUBLE_SPACE.search(text):
                violations.append(
                    f"{uid}: {key} has doubled or misplaced whitespace")
            if key not in _UNTERMINATED_EXEMPT and text.rstrip()[-1] not in _TERMINATORS:
                violations.append(
                    f"{uid}: {key} ends without a sentence terminator "
                    f"({text.rstrip()[-40:]!r})")
    return violations


attach_navigation(RULES, load_manifest())
attach_navigation(DETECTIONS, load_manifest())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="run every gate but write nothing (CI mode)")
    args = ap.parse_args()

    # Rendered FIRST, before the field gate below. A hunt's query is built
    # lazily by hunt_query(), so its filter and group keys reach
    # DETECTION_VIOLATIONS only once it has been rendered — validating before
    # that point would check the detections and silently skip every documented
    # query, then write the broken one to disk as a "regeneration".
    hunting = render_hunting_page()

    violations = reverse_validate(CAT, RULES)
    if violations:
        print(f"RULE EXPR NAMES A METRIC graph2otel DOES NOT EMIT ({len(violations)}):",
              file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    field_violations = validate_detection_fields(CAT)
    if field_violations:
        print(f"DETECTION QUERIES A SIGNAL graph2otel DOES NOT EMIT "
              f"({len(field_violations)}) — the query would match zero rows "
              f"silently (#90):", file=sys.stderr)
        for v in field_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    # #375's binding rule: unmeasured detections ship paused or as hunting
    # queries. Enforce it here rather than trusting the DETECTIONS list, so
    # un-pausing one is a deliberate change to this gate and not a one-character
    # edit nobody reviews.
    enabled = [rule["uid"] for rule in DETECTIONS if not rule["isPaused"]]
    if enabled:
        print(f"DETECTION IS NOT PAUSED ({len(enabled)}) — every shipped "
              f"detection must be paused until measured on the operator's own "
              f"tenant:", file=sys.stderr)
        for uid in enabled:
            print(f"  - {uid}", file=sys.stderr)
        return 1

    label_violations = validate_labels(RULES) + validate_labels(DETECTIONS)
    if label_violations:
        print(f"RULE LABELS VIOLATE THE FROZEN ROUTABLE CONTRACT ({len(label_violations)}):",
              file=sys.stderr)
        for v in label_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    manifest = load_manifest()
    nav_violations = navigation_violations(RULES + DETECTIONS, manifest)
    if nav_violations:
        print(f"RULE LINKS TO SOMETHING THAT DOES NOT EXIST ({len(nav_violations)}) "
              f"— a wrong dtab slug is ignored SILENTLY and an unreachable "
              f"runbook is worse than none:", file=sys.stderr)
        for v in nav_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    prose_violations = (annotation_violations(RULES)
                        + annotation_violations(DETECTIONS))
    if prose_violations:
        print(f"ANNOTATION TEXT IS BROKEN OR STALE ({len(prose_violations)}):",
              file=sys.stderr)
        for v in prose_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    retired_violations = retired_recording_rule_violations()
    if retired_violations:
        print(f"A RECORDING RULE CAME BACK ({len(retired_violations)}) — both were "
              f"retired by #297 because a 1h event-time window can never overlap a "
              f"blob-derived source whose records are days old:", file=sys.stderr)
        for v in retired_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    routing_violations = routing_asset_violations([ALERTS_DIR])
    if routing_violations:
        print(f"COMMITTED FILE LOOKS LIKE A ROUTING ASSET ({len(routing_violations)}) — "
              f"graph2otel ships alert rules only, no contact point/policy/route:",
              file=sys.stderr)
        for v in routing_violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    manifests = render_app_platform()

    if not args.check:
        os.makedirs(RULES_DIR, exist_ok=True)
        for fname, data in manifests.items():
            with open(os.path.join(RULES_DIR, fname), "wb") as f:
                f.write(data)
        with open(HUNTS_DOC, "wb") as f:
            f.write(hunting)

    stale = []
    if not os.path.exists(HUNTS_DOC):
        stale.append("docs/hunting.md (missing)")
    else:
        with open(HUNTS_DOC, "rb") as f:
            if f.read() != hunting:
                stale.append("docs/hunting.md")
    for fname, data in manifests.items():
        path = os.path.join(RULES_DIR, fname)
        if not os.path.exists(path):
            stale.append(f"alerts/rules/{fname} (missing)")
            continue
        with open(path, "rb") as f:
            if f.read() != data:
                stale.append(f"alerts/rules/{fname}")
    present = {f for f in os.listdir(RULES_DIR) if f.endswith(".yaml")} \
        if os.path.isdir(RULES_DIR) else set()
    for fname in manifest_orphans(set(manifests), present):
        stale.append(f"alerts/rules/{fname} (orphan — no rule generates it)")

    print(f"rules: {len(RULES)} alert rules ({sum(1 for r in RULES if not r['isPaused'])} "
          f"enabled, {sum(1 for r in RULES if r['isPaused'])} paused), "
          f"0 recording rules (retired, #297), "
          f"{len(DETECTIONS)} detection examples (all paused), "
          f"{len(manifests)} App Platform manifests, "
          f"{len(HUNTS)} hunting queries", file=sys.stderr)

    if stale:
        print(f"\nSTALE GENERATED FILES ({len(stale)}) — run `make rules`:", file=sys.stderr)
        for s in stale:
            print(f"  - {s}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
