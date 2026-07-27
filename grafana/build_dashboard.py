#!/usr/bin/env python3
"""Build graph2otel's Grafana dashboards, and gate their metric coverage (#218).

    python3 build_dashboard.py            # write dashboards/*.json, then gate
    python3 build_dashboard.py --check    # gate only, write nothing (CI)

Run from grafana/ (``make dashboard`` / ``make grafana-check`` do).

# What the coverage gate is for

graph2otel emits hundreds of metrics. Nothing forced a newly-emitted one onto a panel,
which is the exact drift the fleet coverage gate exists to prevent: a collector
lands, its signal ships, and no operator ever sees it because nobody remembered
to add a panel. The gate closes that by failing when a cataloged metric is on no
panel — in BOTH write and --check mode, so it blocks the commit and CI alike.

# Why the gate has an explicit waiver list, and why the list must carry reasons

A hard gate with no escape hatch gets disabled the first time it blocks something
urgent. A gate with an UNDOCUMENTED escape hatch is not a gate. So a deliberately
unpanelled metric goes in waivers.json with a reason someone chose to write, and
a waiver for a metric that is no longer emitted fails too — otherwise the list
would silently become the place coverage goes to die.

# Why log coverage is per DOMAIN and not per event

There are 133 distinct log event names. One panel each would be an unusable
dashboard and a gate nobody could satisfy, so it would be waived wholesale within
a week. #162's actual ask is "at least one shipped log panel per domain that has
a log-shaped signal", and that is the unit gated here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import catalog as catalog_mod  # noqa: E402
import v2  # noqa: E402
from boards import common  # noqa: E402
from builder import (  # noqa: E402
    CENSUS_SENTINEL,
    DASHBOARD_NAME,
    Builder,
    dumps,
)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT_DIR = os.path.join(REPO, "dashboards")
OUT_FILE = f"{DASHBOARD_NAME}.json"
WAIVERS = os.path.join(HERE, "waivers.json")

# One dashboard, one tab per board module, in tab order (#399). Self-obs last:
# it is the exporter's own health, not a Microsoft domain.
BOARDS = [
    "boards.entra_compliance",
    "boards.intune_fleet",
    "boards.defender_security",
    "boards.m365_services",
    "boards.purview_compliance",
    "boards.selfobs",
]

TITLE = "graph2otel"
DESCRIPTION = (
    "Microsoft Graph telemetry — Entra ID, Intune, Defender, Microsoft 365 and "
    "Purview — plus graph2otel's own health. Generated from "
    "grafana/boards/*.py against spec/signal-catalog.json; edit those, not this "
    "JSON."
)
TAGS = ["graph2otel", "generated"]


def load_waivers() -> dict:
    with open(WAIVERS) as f:
        raw = json.load(f)
    return raw.get("metrics", {})


def build_all(cat):
    """Build the estate. Returns (builder, domain_tabs, log_domains).

    Every board appends into ONE builder, so panel ids are unique across the
    whole dashboard and the self-obs drilldown links — derived from
    ``panel["id"]`` at build time — stay correct with no coordination.
    """
    import importlib

    b = Builder(
        name=DASHBOARD_NAME,
        title=TITLE,
        description=DESCRIPTION,
        tags=list(TAGS),
        catalog=cat,
    )
    tabs = []
    log_domains = set()
    for mod_name in BOARDS:
        mod = importlib.import_module(mod_name)
        tabs.append(common.add(b, mod))
        for spec in getattr(mod, "LOGS", ()):
            log_domains.add(cat.log(spec["event"]).domain)
    return b, tabs, log_domains


def overview(b: Builder) -> dict:
    """The landing tab: exporter failure vs domain posture, then the links (#311).

    Never conditional. It is the one surface that must render when the census is
    missing entirely, because that is exactly the state an operator needs
    explained rather than hidden.
    """
    b.row("Overview")
    census = b.availability(".+")
    guide = b.text(common.PREAMBLE, title="Read this before writing your own query",
                   h=10)
    leaf = v2.leaf("Overview", [v2.rowspec("", [
        {"w": 24, "h": 8, "spec": census},
        {"w": 24, "h": 10, "spec": guide},
    ])])
    b.sentinel(CENSUS_SENTINEL)
    return leaf


def coverage(cat, covered: set, waivers: dict) -> tuple:
    """Return (missing, stale_waivers, reasonless_waivers).

    ``missing`` is every cataloged metric that no panel query names and that no
    waiver excuses. ``stale_waivers`` are waived names the catalog no longer
    has — a waiver that outlives its metric is a comment pretending to be a
    decision. ``reasonless_waivers`` are entries with an empty reason.
    """
    cataloged = set(cat.metrics)
    missing = sorted(cataloged - covered - set(waivers))
    stale = sorted(set(waivers) - cataloged)
    reasonless = sorted(k for k, v in waivers.items() if not str(v).strip())
    return missing, stale, reasonless


def log_coverage(cat, log_domains: set) -> list:
    """Domains that have a log-shaped signal but no shipped log panel (#162)."""
    have_logs = {log.domain for log in cat.logs.values()}
    return sorted(have_logs - log_domains)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="run every gate but write nothing (CI mode)")
    args = ap.parse_args()

    cat = catalog_mod.load()
    waivers = load_waivers()
    b, domain_tabs, log_domains = build_all(cat)
    covered = b._covered
    manifest = b.render([overview(b), *domain_tabs])

    # Structural gates first: they mean the build itself is wrong, so nothing
    # should be written on the back of them.
    violations = list(b.violations) + v2.manifest_violations(manifest)
    if violations:
        print("dashboard build violations:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    if not args.check:
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(os.path.join(OUT_DIR, OUT_FILE), "w") as f:
            f.write(dumps(manifest))

    missing, stale, reasonless = coverage(cat, covered, waivers)
    domains_without_logs = log_coverage(cat, log_domains)

    total = len(cat.metrics)
    placed = v2.placed_element_names(manifest)
    leaves = sum(len(t["spec"]["layout"]["spec"]["tabs"])
                 if t["spec"]["layout"]["kind"] == "TabsLayout" else 1
                 for t in manifest["spec"]["layout"]["spec"]["tabs"])
    print(f"coverage: {len(covered)}/{total} catalog metrics on a panel "
          f"({len(waivers)} waived, {len(placed)} panels placed across "
          f"{len(manifest['spec']['layout']['spec']['tabs'])} tabs and {leaves} leaves, "
          f"{len(cat.logs)} log events over {len(log_domains)} log-panelled domains)",
          file=sys.stderr)

    failed = False
    if missing:
        print(f"\nUNPANELLED CATALOGUE METRICS ({len(missing)}) — every metric graph2otel "
              f"emits must reach a panel or carry a waiver:", file=sys.stderr)
        for n in missing:
            m = cat.metric(n)
            print(f"  - {n}  ({m.prom}, {m.kind}, emitted by {m.packages[0]})",
                  file=sys.stderr)
        print("\nAdd it to the matching grafana/boards/*.py SECTIONS, or — if it is "
              "deliberately unpanelled — to grafana/waivers.json WITH A REASON.",
              file=sys.stderr)
        failed = True
    if stale:
        print(f"\nSTALE WAIVERS ({len(stale)}) — waived metrics the catalog no longer "
              f"has, so the waiver excuses nothing:", file=sys.stderr)
        for n in stale:
            print(f"  - {n}", file=sys.stderr)
        print("\nDelete them from grafana/waivers.json.", file=sys.stderr)
        failed = True
    if reasonless:
        print(f"\nWAIVERS WITH NO REASON ({len(reasonless)}) — a waiver without a reason "
              f"is an undocumented escape hatch, which is not a gate:", file=sys.stderr)
        for n in reasonless:
            print(f"  - {n}", file=sys.stderr)
        failed = True
    if domains_without_logs:
        print(f"\nDOMAINS WITH A LOG-SHAPED SIGNAL BUT NO LOG PANEL "
              f"({len(domains_without_logs)}) — #162:", file=sys.stderr)
        for d in domains_without_logs:
            events = sorted(log.event for log in cat.logs.values() if log.domain == d)
            print(f"  - {d}  (e.g. {events[0]})", file=sys.stderr)
        print("\nAdd a LOGS entry to that domain's board module. Use the "
              '{service_name="graph2otel"} | attr=… form — a stream selector on an '
              "attribute matches zero rows silently (#90).", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
