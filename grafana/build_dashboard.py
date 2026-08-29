#!/usr/bin/env python3
"""Build graph2otel's Grafana dashboards, and gate their metric coverage (#218).

    python3 build_dashboard.py            # write dashboards/*.json, then gate
    python3 build_dashboard.py --check    # gate only, write nothing (CI)

Run from grafana/ (``just dashboard`` / ``just grafana-check`` do).

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
import pivots  # noqa: E402
import presentation  # noqa: E402
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

# Per-leaf render budget (#309). Under v1 every row was expanded, so opening a
# dashboard queried all of its panels and panel count WAS the cost. Under v2 only
# the active leaf tab renders, so an operator opening Entra pays for one of twelve
# leaves rather than for all 348 panels. The largest LEAF is therefore the unit of
# cost, and an estate-wide total would gate the wrong thing.
#
# Measured 2026-07-27 on the post-#399 estate: 60 leaves, median 5 panels,
# largest 18 ("Endpoint analytics (UXA)"). The ceiling is that maximum plus
# deliberate headroom, so it catches the realistic regression — a board module
# quietly adding thirty panels to one leaf — without firing on ordinary growth.
LEAF_PANEL_CEILING = 24

# leaf tab title -> reason. A leaf legitimately over the ceiling goes here WITH a
# reason, on the same principle as the metric coverage waivers: a gate with no
# escape hatch gets disabled the first time it blocks something urgent, and a
# gate with an UNDOCUMENTED escape hatch is not a gate. Empty today.
LEAF_WAIVERS: dict = {}

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

    It also carries the entity investigation pivots (#305), one collapsed row per
    entity kind. They live here rather than on a tab of their own for two reasons:
    a pivot must never land somewhere the census can hide — a dtab into
    conditioned-away content renders a completely blank body with no message
    (measured, #399) — and this is the one tab that is unconditional by contract.
    The seven-tab topology frozen by #399 is unchanged.
    """
    b.row("Overview")
    census = b.availability(".+")
    guide = b.text(common.PREAMBLE, title="Read this before writing your own query",
                   h=10)
    how_to_pivot = b.text(pivots.PREAMBLE, title="Investigate one entity", h=10)
    leaf = v2.leaf("Overview", [
        v2.rowspec("", [
            {"w": 24, "h": 8, "spec": census},
            {"w": 12, "h": 10, "spec": guide},
            {"w": 12, "h": 10, "spec": how_to_pivot},
        ]),
        *pivots.rows(b),
    ])
    b.sentinel(CENSUS_SENTINEL)
    # Deploy / configuration markers on every time axis in the estate (#310).
    # graph2otel.startup fires once per configured tenant on every process start
    # and carries the version and a one-way configuration fingerprint, so a
    # metric that moves at 14:00 can be lined up against a restart that also
    # happened at 14:00.
    #
    # "Configuration changed" is a COMPARISON, not a field: the marker fires on
    # every start, so a config change is two consecutive markers with different
    # config.fingerprint values, and an upgrade is two with different version
    # values. The annotation deliberately does not claim otherwise.
    b.annotation("graph2otel starts, versions and config changes",
                 "graph2otel.startup", color="rgba(255, 152, 0, 1)")
    return leaf


def build(cat) -> tuple:
    """Assemble the estate once. Returns ``(builder, manifest, log_domains)``.

    A single entry point so a gate cannot accidentally assert against a
    differently-assembled dashboard than the one that gets written.
    """
    b, domain_tabs, log_domains = build_all(cat)
    return b, b.render([overview(b), *domain_tabs]), log_domains


def render(cat) -> dict:
    """The assembled manifest."""
    return build(cat)[1]


def gate_violations(cat, b: Builder, man: dict) -> list:
    """Every structural rule breach in one assembled estate.

    Structural gates run before anything is written: they mean the build itself
    is wrong, so a manifest should not be shipped on the back of them.
    """
    return (list(b.violations)
            + v2.manifest_violations(man)
            + presentation.manifest_violations(man)
            + presentation.violations(cat, b.covered)
            + pivots.violations(cat)
            + pivots.link_violations(cat, man)
            + leaf_budget_violations(man, LEAF_WAIVERS))


def leaf_panel_counts(man: dict) -> dict:
    """Leaf tab title -> how many panels it places.

    A leaf is a tab whose own layout is a ``RowsLayout`` — the deepest tab level,
    and the unit an operator actually renders.
    """
    counts = {}

    def walk(tabs: list):
        for tab in tabs:
            layout = tab["spec"].get("layout", {})
            if layout.get("kind") == "TabsLayout":
                walk(layout["spec"]["tabs"])
                continue
            if layout.get("kind") != "RowsLayout":
                continue
            total = 0
            for row in layout["spec"]["rows"]:
                grid = row["spec"].get("layout", {})
                if grid.get("kind") == "GridLayout":
                    total += len(grid["spec"]["items"])
            counts[tab["spec"]["title"]] = total

    walk(man["spec"]["layout"]["spec"]["tabs"])
    return counts


def leaf_budget_violations(man: dict, waivers: dict) -> list:
    """Leaves over ``LEAF_PANEL_CEILING``, plus waivers that no longer apply."""
    violations = []
    counts = leaf_panel_counts(man)
    for title, count in sorted(counts.items()):
        reason = waivers.get(title)
        if count <= LEAF_PANEL_CEILING:
            if reason is not None:
                violations.append(
                    f"leaf {title!r} is waived from the panel budget but holds "
                    f"{count} panels, within the ceiling of {LEAF_PANEL_CEILING}: "
                    "a waiver that outlives its problem silently re-permits the "
                    "regression it was written for"
                )
            continue
        if reason is None:
            violations.append(
                f"leaf {title!r} places {count} panels, over the per-leaf ceiling "
                f"of {LEAF_PANEL_CEILING}: an operator opening that tab pays for "
                "all of them at once. Split the section, or waive it in "
                "LEAF_WAIVERS with a reason"
            )
        elif not str(reason).strip():
            violations.append(
                f"leaf {title!r} has a budget waiver with no reason, which is an "
                "undocumented escape hatch rather than a decision"
            )
    for title in sorted(set(waivers) - set(counts)):
        violations.append(
            f"LEAF_WAIVERS names leaf {title!r}, which no longer exists"
        )
    return violations


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
    ap.add_argument("--catalog", default=catalog_mod.CATALOGUE,
                    help="signal catalog to build against; a non-default path "
                         "never writes, so a sabotage run cannot ship its own "
                         "mutation")
    args = ap.parse_args()

    cat = catalog_mod.load(args.catalog)
    waivers = load_waivers()
    b, manifest, log_domains = build(cat)
    covered = b._covered

    violations = gate_violations(cat, b, manifest)
    if violations:
        print("dashboard build violations:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    if not args.check and args.catalog == catalog_mod.CATALOGUE:
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
          f"{len(cat.logs)} log events over {len(log_domains)} log-panelled domains, "
          f"largest leaf {max(leaf_panel_counts(manifest).values())}/"
          f"{LEAF_PANEL_CEILING} panels)",
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
