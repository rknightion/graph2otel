"""The audited Grafana presentation registry (#304).

Pure standard library, like the rest of ``grafana/``.

# What this owns, and why it is a separate file

Units, panel titles, value mappings and thresholds — keyed by **catalog metric
name**. Three places were considered and two were rejected by maintainer
decision (recorded on #304, 2026-07-27):

- ``spec/signal-catalog.json`` stays **wire-derived** and acquires no
  presentation opinion. It is generated from Go ``testdata/signals.json``
  goldens, so a colour written there would either be overwritten by the next
  regeneration or force the Go generator to own colour choices it has no
  evidence for.
- **Per-board overrides** in ``grafana/boards/*.py`` were rejected: the same
  metric would drift between boards, and the honesty gate below would be
  unenforceable because there would be no single place to audit.

So a board module still names only *which metric a panel is about*, and this
file decides how that quantity is displayed.

# The honesty rules, in the order they matter

**1. An uncited threshold cannot be constructed.** :class:`Thresholds` and
:class:`Mappings` refuse an empty ``evidence``. A colour that implies alarm with
no stated operational meaning is an opinion wearing the authority of a
measurement, and it is the specific defect #304 was opened for. The evidence
string is not decoration: it is appended to the panel description behind
:data:`CITATION_PREFIX`, so the operator reading the red panel can see *why* it
is red, and so :func:`manifest_violations` can prove on the shipped artifact
that no coloured panel is uncited.

**2. Absence of a threshold is not neutrality.** Every one of the 331 generated
panels previously omitted ``fieldConfig.defaults.thresholds`` entirely, and
Grafana then supplies its own default — a green base with a red step at 80. So a
neutral inventory count of 95 managed devices rendered **red**, which is exactly
the "neutral inventory can imply an alarm" evidence on the issue. Neutral has to
be written down: :func:`neutral_thresholds` is applied to every panel that has no
cited one, and :func:`manifest_violations` fails on a panel with no explicit
thresholds at all.

**3. A counter panel must say and format a rate.** Every ``sum`` instrument is
plotted through ``rate()`` by ``Builder._expr``, so a count unit and a
count-derived title both describe a quantity the panel is not showing.
``m365.message_trace.bytes`` was the worst case: a bytes/sec series formatted as
``bytes``, which reads three orders of magnitude wrong.

The one trap in rule 3, and the reason :func:`plots_a_rate` exists rather than a
substring test: ``histogram_quantile(0.95, sum by (le) (rate(x_bucket[…])))``
contains ``rate(`` but its result is in the **bucket's** unit. Seconds, not
seconds per second. A naive check would relabel every latency panel as a rate.

# What this file deliberately does not do

It thresholds **five** metrics out of 331 panels. That restraint is the point.
"How many ownerless Teams is too many" and "what EPSS probability is
unacceptable" are policy judgements an operator makes, not facts this repository
has evidence for, so they get neutral colouring and a log twin to query. A
threshold is written here only where the *source* defines the operational state:
a scrape consuming its whole poll interval, an exporter failure that has not
recovered, a Microsoft service-health level Microsoft itself calls degradation.

Value mappings applied through a panel **override** rather than
``fieldConfig.defaults`` — currently only the Signal availability table's
``state``/``reason`` columns, built in ``builder.availability()`` — are outside
this registry and outside :func:`manifest_violations`. That table's description
already enumerates every state and what it means, which is the same obligation
discharged in prose.
"""

from __future__ import annotations

import re

# UCUM unit -> Grafana field unit id, for a metric displayed as an instantaneous
# value. An annotation unit ("{device}") is a count of a thing, which Grafana
# renders as "short".
GAUGE_UNITS = {
    "s": "s",
    "ms": "ms",
    "min": "m",
    "h": "h",
    "d": "d",
    "By": "bytes",
    "MB": "decmbytes",
    "%": "percent",
    "1": "short",
}

# UCUM unit -> Grafana field unit id for the *rate* of that unit. A counter of
# anything other than bytes is a count of events, so its rate is counts/sec.
RATE_UNITS = {"By": "Bps"}
RATE_UNIT_DEFAULT = "cps"

# Every per-second unit this file can produce. The manifest gate checks
# membership rather than equality so a future unit (reqps, pps) is a one-line
# addition and not a silent pass.
PER_SECOND_UNITS = frozenset({"cps", "Bps"})

# Grafana's fixed-colour names, restricted to the ones an operational threshold
# has any business using. A closed set so a typo cannot produce a step Grafana
# silently renders as no colour, which would read as a deliberate neutral.
COLORS = frozenset({"text", "green", "yellow", "orange", "red", "blue"})

# The base step colour that means "this number carries no operational verdict".
NEUTRAL_COLOR = "text"

# Prepended to the evidence when it is appended to a panel description. Both the
# operator and :func:`manifest_violations` read it: a coloured panel whose
# description lacks this marker is an uncited threshold.
CITATION_PREFIX = "Colour meaning:"

_RATE_RE = re.compile(r"\brate\(")
_SAYS_RATE_RE = re.compile(r"\brates?\b|/s\b|per second", re.IGNORECASE)
_COUNT_TAIL_RE = re.compile(r"\s+(counts?|totals?)$", re.IGNORECASE)


class Thresholds:
    """Absolute threshold steps plus the evidence for the operational state.

    ``steps`` is a list of ``(colour, value)`` pairs, each the value at which
    that colour starts. The neutral base step is supplied automatically, so a
    caller declares only the meaningful boundaries.
    """

    __slots__ = ("steps", "evidence")

    def __init__(self, steps, *, evidence: str):
        pairs = list(steps or [])
        if not pairs:
            raise ValueError(
                "a threshold with no coloured step colours nothing; it is a "
                "citation with no effect"
            )
        for color, value in pairs:
            if color not in COLORS:
                raise ValueError(
                    f"unknown threshold colour {color!r}; use one of "
                    f"{sorted(COLORS)}"
                )
            if not isinstance(value, (int, float)):
                raise ValueError(
                    f"threshold step {color!r} needs a numeric boundary, got "
                    f"{value!r}"
                )
        if not (evidence or "").strip():
            raise ValueError(
                "a threshold must cite the evidence for the operational state "
                "it colours; an uncited threshold is an opinion wearing the "
                "authority of a measurement (#304)"
            )
        self.steps = pairs
        self.evidence = evidence.strip()

    def field_config(self) -> dict:
        return {
            "mode": "absolute",
            "steps": [{"color": NEUTRAL_COLOR, "value": None},
                      *({"color": c, "value": v} for c, v in self.steps)],
        }


class Mappings:
    """Numeric value -> display text, plus the evidence for the encoding."""

    __slots__ = ("values", "evidence")

    def __init__(self, values: dict, *, evidence: str):
        if not values:
            raise ValueError("a value mapping needs at least one value")
        if not (evidence or "").strip():
            raise ValueError(
                "a value mapping must cite where the encoding comes from; "
                "otherwise the label is a guess about what the emitter meant "
                "(#304)"
            )
        self.values = dict(values)
        self.evidence = evidence.strip()

    def field_config(self) -> list:
        return [{
            "type": "value",
            "options": {str(k): {"text": t, "index": i}
                        for i, (k, t) in enumerate(self.values.items())},
        }]


class Presentation:
    """How one cataloged metric is displayed."""

    __slots__ = ("unit", "mappings", "thresholds")

    def __init__(self, unit: str = None, mappings: Mappings = None,
                 thresholds: Thresholds = None):
        self.unit = unit
        self.mappings = mappings
        self.thresholds = thresholds

    def citations(self) -> list:
        return [c.evidence for c in (self.mappings, self.thresholds)
                if c is not None]


# --- shared cited encodings -------------------------------------------------
#
# The 0/1 flags below all state their encoding in the emitter's own metric
# description, which the catalog carries verbatim. That description IS the
# citation: it is generated from the Go source that writes the value, so it
# cannot drift from the encoding without the catalog changing too.

def _flag(off: str, on: str, metric: str) -> Mappings:
    return Mappings(
        {0: off, 1: on},
        evidence=(f"0/1 encoding declared by the emitter's own description of "
                  f"{metric}, which the wire-derived catalog carries verbatim."),
    )


ENTRIES: dict = {
    # --- units: a dimensionless "1" that is really a ratio ------------------
    #
    # UCUM "1" is dimensionless and the catalog is right to say so, but Grafana
    # renders it "short", i.e. 0.87 instead of 87%. Both of these are genuine
    # fractions, and their own descriptions say so.
    "graph2otel.scrape.budget": Presentation(
        unit="percentunit",
        thresholds=Thresholds(
            [("red", 1.0)],
            evidence=("1.0 is a scrape consuming its entire poll interval, so it "
                      "cannot finish before the next one is due. The boundary is "
                      "the configured poll interval itself, not a chosen number."),
        ),
    ),
    "defender.vulnerability.max_epss": Presentation(unit="percentunit"),

    # --- enum ladders -------------------------------------------------------
    "m365.service_health.status": Presentation(
        mappings=Mappings(
            {-1: "Unmapped status",
             0: "Operational",
             1: "Restored or resolved",
             2: "Recovering",
             3: "Investigating",
             4: "Degradation",
             5: "Interruption"},
            evidence=("severity ladder defined by statusEnum in "
                      "internal/collectors/m365/servicehealth/servicehealth.go, "
                      "which maps Microsoft's microsoftServiceHealthStatus values "
                      "onto 0-5 with -1 for an unmapped value. A level Microsoft "
                      "adds beyond 5 renders as its bare number, which is visible "
                      "rather than mislabelled."),
        ),
        thresholds=Thresholds(
            [("red", 4)],
            evidence=("levels 4 and 5 are Microsoft's own serviceDegradation and "
                      "serviceInterruption: the service is impaired, which is a "
                      "state Microsoft defines rather than one this repository "
                      "picked. Levels 1-3 are recovery and investigation, which "
                      "are not impairment, so they are not coloured."),
        ),
    ),
    "entra.gsa.onboarding_status": Presentation(
        mappings=Mappings(
            {-1: "Unmapped status",
             0: "Onboarded",
             1: "In progress",
             2: "Error or offboarded"},
            evidence=("ladder declared in internal/collectors/entra/gsa/gsa.go and "
                      "restated in the collector's own registry annotation: "
                      "0=onboarded, 1=in-progress, 2=error-or-offboarded, "
                      "-1=unmapped."),
        ),
    ),

    # --- 0/1 flags ----------------------------------------------------------
    "entra.auth_methods_policy.method.enabled": Presentation(
        mappings=_flag("Disabled", "Enabled",
                       "entra.auth_methods_policy.method.enabled")),
    "entra.organization.on_premises_sync_enabled": Presentation(
        mappings=Mappings(
            {0: "Cloud-only", 1: "Synced from on-premises"},
            evidence=("the emitter's description states 1 means the tenant is "
                      "currently synced from an on-premises directory."))),
    "intune.autopilot.profile.setting": Presentation(
        mappings=_flag("Disabled", "Enabled", "intune.autopilot.profile.setting")),
    "intune.update_ring.pause_state": Presentation(
        mappings=Mappings(
            {0: "Not paused", 1: "Paused"},
            evidence=("the emitter's description states 1=paused, 0=not paused."))),
    "intune.update_ring.rollback_active": Presentation(
        mappings=Mappings(
            {0: "Inactive", 1: "Rollback active"},
            evidence=("the emitter's description states 1=active, "
                      "0=inactive."))),
    "m365.sharepoint.external_resharing_enabled": Presentation(
        mappings=_flag("Disabled", "Enabled",
                       "m365.sharepoint.external_resharing_enabled")),
    "m365.sharepoint.idle_session_signout_enabled": Presentation(
        mappings=_flag("Disabled", "Enabled",
                       "m365.sharepoint.idle_session_signout_enabled")),
    "m365.sharepoint.legacy_auth_enabled": Presentation(
        mappings=_flag("Disabled", "Enabled",
                       "m365.sharepoint.legacy_auth_enabled")),
    "m365.sharepoint.unmanaged_sync_restricted": Presentation(
        mappings=Mappings(
            {0: "Unrestricted", 1: "Restricted to managed devices"},
            evidence=("the emitter's description states 1 means the OneDrive sync "
                      "app is restricted to managed or domain-joined devices."))),

    # --- self-observability states ------------------------------------------
    "graph2otel.scrape.success": Presentation(
        mappings=Mappings(
            {0: "Partial or failed", 1: "Success or empty"},
            evidence=("the emitter's description states 1 if the last scrape "
                      "result was empty or success, 0 for partial or failure.")),
        thresholds=Thresholds(
            [("green", 1)],
            evidence=("0 is a partial or failed scrape, which is a completed "
                      "runtime failure the emitter defines. Green starts at 1 so "
                      "the failing state is the uncoloured one and cannot be "
                      "mistaken for a threshold this repository invented."),
        ),
    ),
    "graph2otel.otlp.delivery.degraded": Presentation(
        mappings=Mappings(
            {0: "Recovered", 1: "Degraded"},
            evidence=("the emitter's description states this is whether the most "
                      "recent exporter callback failure remains unrecovered by a "
                      "subsequent successful export (#268).")),
        thresholds=Thresholds(
            [("red", 1)],
            evidence=("1 means the most recent exporter failure has not been "
                      "followed by a success, so telemetry is being lost now. "
                      "This is the delivery-degradation state #268 defines, not a "
                      "rate this repository chose a limit for."),
        ),
    ),
}

# Every metric this registry colours. Used by the tests to separate the cited
# panels from the ones that must be neutral.
THRESHOLDED_METRICS = frozenset(
    name for name, entry in ENTRIES.items() if entry.thresholds is not None)


# --- derivation -------------------------------------------------------------

def gauge_unit(ucum: str) -> str:
    """Grafana unit for an instantaneous value in ``ucum``."""
    return GAUGE_UNITS.get(ucum, "short")


def rate_unit(ucum: str) -> str:
    """Grafana unit for the per-second rate of a counter in ``ucum``."""
    return RATE_UNITS.get(ucum, RATE_UNIT_DEFAULT)


def plots_a_rate(expr: str) -> bool:
    """Whether ``expr``'s result is a per-second rate.

    ``histogram_quantile(0.95, sum by (le) (rate(x_bucket[…])))`` contains
    ``rate(`` and is NOT a rate: the quantile is in the bucket's unit. Treating
    it as one would relabel every latency panel in the estate as counts/sec.
    """
    if "histogram_quantile(" in expr:
        return False
    return bool(_RATE_RE.search(expr))


def title_says_rate(title: str) -> bool:
    return bool(_SAYS_RATE_RE.search(title or ""))


def rate_title(title: str) -> str:
    """Make a derived counter title describe the rate it actually plots.

    Idempotent: a title that already says rate is returned unchanged, so this
    can be applied unconditionally to derived titles.
    """
    if title_says_rate(title):
        return title
    return f"{_COUNT_TAIL_RE.sub('', title)} rate"


def neutral_thresholds() -> dict:
    """The explicit "this number carries no verdict" threshold.

    Written on every panel with no cited threshold, because omitting the field
    is not neutral — Grafana substitutes a green base and a red step at 80.
    """
    return {"mode": "absolute",
            "steps": [{"color": NEUTRAL_COLOR, "value": None}]}


def agreed(names: list) -> Presentation | None:
    """The presentation for a panel, when every metric on it agrees.

    A panel carrying four boolean tenant switches shares one 0/1 mapping and is
    correctly mapped; a panel mixing a flag and a count agrees on nothing and
    gets the neutral default. Attributes are considered independently so a
    shared mapping survives a disagreement about thresholds.
    """
    entries = [ENTRIES.get(n) for n in names]
    if not entries or any(e is None for e in entries):
        return None
    out = Presentation()
    for field in ("unit", "mappings", "thresholds"):
        values = [getattr(e, field) for e in entries]
        first = values[0]
        if first is None:
            continue
        if all(_same(v, first) for v in values):
            setattr(out, field, first)
    return out if any(getattr(out, f) for f in
                      ("unit", "mappings", "thresholds")) else None


def _same(a, b) -> bool:
    if a is b:
        return True
    if a is None or b is None:
        return False
    if isinstance(a, Mappings) and isinstance(b, Mappings):
        return a.values == b.values
    if isinstance(a, Thresholds) and isinstance(b, Thresholds):
        return a.steps == b.steps
    return a == b


def cite(desc: str, entry: Presentation | None) -> str:
    """Append the entry's evidence to a panel description.

    The citation reaches the operator, not just the reviewer: someone looking at
    a red panel can read why it is red. It is also what
    :func:`manifest_violations` matches on, so a coloured panel with no citation
    fails the build.
    """
    if entry is None:
        return desc
    cites = entry.citations()
    if not cites:
        return desc
    joined = " ".join(cites)
    return f"{desc}\n\n{CITATION_PREFIX} {joined}" if desc else \
        f"{CITATION_PREFIX} {joined}"


# --- gates ------------------------------------------------------------------

def violations(cat, covered: set, entries: dict = None) -> list:
    """Registry entries that describe nothing.

    An entry for a metric the catalog no longer has, or for a metric on no
    panel, is dead weight that reads as coverage — the same failure mode as a
    coverage waiver that outlives its metric.
    """
    reg = ENTRIES if entries is None else entries
    found = []
    for name in sorted(reg):
        try:
            cat.metric(name)
        except KeyError:
            found.append(
                f"presentation registry describes {name!r}, which the catalog no "
                "longer has, so the entry decides nothing"
            )
            continue
        if name not in covered:
            found.append(
                f"presentation registry describes {name!r}, which no panel query "
                "names; delete the entry or panel the metric"
            )
    return found


def panel_presentation(man: dict) -> list:
    """Every panel's displayed presentation, read off the built manifest.

    Read from the artifact rather than from the builder on purpose: the
    translation into v2 moves the unit and the field config, and a gate that
    inspects the pre-translation shape would pass while the shipped file was
    wrong.
    """
    out = []
    for name, element in man["spec"]["elements"].items():
        spec = element.get("spec", {})
        viz = spec.get("vizConfig", {}).get("spec", {})
        defaults = viz.get("fieldConfig", {}).get("defaults")
        if defaults is None:
            continue
        queries = spec.get("data", {}).get("spec", {}).get("queries", [])
        exprs = [q.get("spec", {}).get("query", {}).get("spec", {}).get("expr", "")
                 for q in queries]
        out.append({
            "element": name,
            "title": spec.get("title", ""),
            "description": spec.get("description", "") or "",
            "unit": defaults.get("unit"),
            "thresholds": defaults.get("thresholds"),
            "mappings": defaults.get("mappings"),
            "exprs": exprs,
            "rate": any(plots_a_rate(e) for e in exprs),
        })
    return out


def manifest_violations(man: dict) -> list:
    """Every presentation dishonesty visible in the shipped manifest."""
    found = []
    panels = panel_presentation(man)
    for p in panels:
        title = p["title"] or p["element"]
        steps = (p["thresholds"] or {}).get("steps")
        if not steps:
            found.append(
                f"panel {title!r} has no explicit threshold steps. Omitting them "
                "is not neutral: Grafana substitutes a green base and a red step "
                "at 80, so a neutral inventory count renders as an alarm"
            )
        elif len(steps) > 1 and CITATION_PREFIX not in p["description"]:
            found.append(
                f"panel {title!r} carries an uncited threshold. A colour that "
                "implies an operational verdict must state its evidence via the "
                "presentation registry, which puts it in the description behind "
                f"{CITATION_PREFIX!r}"
            )
        if p["mappings"] and CITATION_PREFIX not in p["description"]:
            found.append(
                f"panel {title!r} carries an uncited value mapping; the encoding "
                "it claims must cite where it comes from"
            )
        if not p["rate"]:
            continue
        if p["unit"] not in PER_SECOND_UNITS:
            found.append(
                f"panel {title!r} plots rate() but formats its values as "
                f"{p['unit']!r}, which is not per second. Every sum instrument is "
                "displayed as a rate, so a count unit describes a quantity the "
                f"panel is not showing; use one of {sorted(PER_SECOND_UNITS)}"
            )
        if not title_says_rate(title):
            found.append(
                f"panel {title!r} plots rate() but its title describes a count. "
                "Pass a title that says rate or per second, or let the title be "
                "derived so rate_title() fixes it"
            )
    if not panels:
        found.append("presentation gate inspected no panels at all")
    return found
