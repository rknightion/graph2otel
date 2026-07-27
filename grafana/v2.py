"""Grafana v2 dynamic-dashboard translation layer for graph2otel (#399).

Pure standard library, like the rest of ``grafana/``. Nothing here reads the
catalog or builds a query; this module only translates already-built panels into
the ``dashboard.grafana.app/v2`` resource shape and assembles the layout.

# The seam this module exists to hold (#399 C3)

**Panel constructors keep returning v1-shaped dicts.** ``Builder.metric()`` and
friends are unchanged, and the ~45 board-module sites that mutate
``panel["fieldConfig"]["defaults"]…`` keep working. The v1 shape becomes an
internal intermediate representation and the v1 -> v2 translation happens here,
in one place, as a pure function. The alternative — constructors returning
v2-shaped dicts — would have required a mutation accessor and spread v2 layout
awareness across six board modules.

# Why the condition builder is hand-written rather than adapted (#399 C1)

The reference implementation's ``_cond`` raises only when more than one presence
variable is combined with an absence variable. graph2otel's fail-visible shape is
*one* presence plus *one* absence, which falls through that guard and emits
``condition: "and"``. That group is false in the normal healthy state, so every
tab hides and the operator gets a blank dashboard with no error at all.

So :func:`condition` refuses to emit anything but ``"or"``, and refuses to build a
presence condition with no census escape. :func:`manifest_violations` then checks
both properties again on the assembled manifest, because the original design's
gate checked only that the escape *item* was present and never that the group
``condition`` was ``or``.

The four-state folding table behind this was measured against real renders on
Grafana 13.2.0 and 13.1.1 (identical results), not inferred from the schema.

# Three things rendering can never catch for us

Measured during the same spike, and therefore generator-side gates:

* A condition naming a **variable that does not exist** evaluates TRUE for both
  operators. That fails visible, which is the right default — but it means a
  misspelled sentinel renders perfectly and is invisible in review.
* A wrong ``dtab`` slug is **silently ignored** and falls back to the first tab.
  It is the one non-fail-visible behaviour on the tab path.
* A panel can live in ``spec.elements`` yet never be referenced by the layout:
  counted by the metric coverage gate, invisible to an operator.
"""

from __future__ import annotations

import re

# The v2 schema with TabsLayout and conditionalRendering needs Grafana 13+.
# Asserted by a test rather than documented in prose, which is the one place this
# implementation deliberately does more than the reference.
MIN_GRAFANA_VERSION = "13.0.0"

API_VERSION = "dashboard.grafana.app/v2"
KIND = "Dashboard"

# Pinned viz schema version, matching the reference implementation's deployed
# manifests.
VIZ_VERSION = "v11.5.0"

GRID_COLUMNS = 24

# `sort` is a closed enum on the server side and the bare value "alphabetical" is
# NOT a member — a manifest carrying it is rejected 422 by the dashboards API even
# though it looks obviously right. Caught only by server-side validation, so both
# members used here are named rather than spelled at call sites.
SORT_ALPHABETICAL = "alphabeticalAsc"
SORT_NONE = "disabled"

# v2 routes a query by its plugin group rather than by a datasource ref on the
# panel, so the group is derived from the v1 target's datasource type. A log
# panel cannot end up in the prometheus group by accident.
QUERY_GROUPS = {"prometheus": "prometheus", "loki": "loki"}


def element_name(panel_id: int) -> str:
    """The element key for a panel id.

    ``?viewPanel=`` keys on the numeric ``spec.id``, not on this name (measured:
    ``?viewPanel=41`` and ``?viewPanel=panel-41`` both resolve, an element name
    does not). The name only has to be stable and unique; the id is what the
    eight shipped drilldown links depend on.
    """
    return f"panel-{panel_id}"


def slug(title: str) -> str:
    """Derive a tab's URL slug the way Grafana's ``dtab`` parameter expects.

    Measured: the slug is the title with whitespace collapsed to single hyphens,
    case preserved (a fully-lowercased slug is also accepted). Derived rather
    than declared so a link site cannot hand-write one that does not exist.
    """
    return "-".join(title.split())


# ---------------------------------------------------------------------------
# panel translation
# ---------------------------------------------------------------------------

def _query(target: dict) -> dict:
    ds = target.get("datasource") or {}
    ds_type = ds.get("type", "prometheus")
    group = QUERY_GROUPS.get(ds_type)
    if group is None:
        raise ValueError(f"no v2 query group for datasource type {ds_type!r}")

    spec = {key: value for key, value in target.items() if key != "datasource"}
    return {
        "kind": "PanelQuery",
        "spec": {
            "refId": target.get("refId", "A"),
            "hidden": False,
            "datasource": ds,
            "query": {
                "kind": "DataQuery",
                "version": "v0",
                "group": group,
                "datasource": {"name": ds.get("uid", "")},
                "spec": spec,
            },
        },
    }


def _transformation(transformation: dict) -> dict:
    """Rewrite a v1 ``{id, options}`` transformation into the v2 shape.

    A v1-shaped transformation **validates clean server-side and renders wrong**
    (#399 C5) — ``gcx resources validate`` does not catch it, only a render check
    does. So the conversion is mandatory and double-wrapping is refused rather
    than silently nested into something unrenderable.
    """
    if "kind" in transformation:
        raise ValueError(
            "transformation is already v2-shaped; pass the v1 {id, options} form "
            f"so it is converted exactly once: {transformation!r}"
        )
    return {
        "kind": "Transformation",
        "group": transformation["id"],
        "spec": {"options": transformation.get("options", {})},
    }


def panel_element(spec: dict, width: int, height: int) -> tuple[str, dict]:
    """Translate one v1-shaped panel spec into a named v2 ``Panel`` element.

    ``width``/``height`` are not part of the element in v2 — they belong to the
    ``GridLayoutItem`` that references it — so they are accepted and ignored
    here, keeping the call signature aligned with the accumulated
    ``{"w", "h", "spec"}`` items.
    """
    del width, height  # placement is the grid's job, not the element's

    panel_id = spec["id"]
    queries = [_query(target) for target in spec.get("targets", [])]
    transformations = [_transformation(t) for t in spec.get("transformations", [])]

    viz_spec = {"options": spec.get("options", {})}
    if "fieldConfig" in spec:
        viz_spec["fieldConfig"] = spec["fieldConfig"]

    element = {
        "kind": "Panel",
        "spec": {
            "id": panel_id,
            "title": spec.get("title", ""),
            "description": spec.get("description", ""),
            "links": spec.get("links", []),
            "data": {
                "kind": "QueryGroup",
                "spec": {
                    "queries": queries,
                    "queryOptions": {},
                    "transformations": transformations,
                },
            },
            "vizConfig": {
                "kind": "VizConfig",
                "group": spec["type"],
                "version": VIZ_VERSION,
                "spec": viz_spec,
            },
        },
    }
    return element_name(panel_id), element


# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------

def grid(items: list) -> dict:
    """24-column shelf pack over ``{"w", "h", "spec"}`` items, per row.

    The v1 layout already reset ``x`` at every row boundary, so packing each row
    independently reproduces the same coordinates within a row: no panel changes
    width or position relative to its neighbours.
    """
    out, x, y, shelf_height = [], 0, 0, 0
    for item in items:
        width, height = item["w"], item["h"]
        if width > GRID_COLUMNS:
            raise ValueError(
                f"panel width {width} exceeds the {GRID_COLUMNS}-column grid"
            )
        if x + width > GRID_COLUMNS:
            x, y, shelf_height = 0, y + shelf_height, 0
        out.append({
            "kind": "GridLayoutItem",
            "spec": {
                "x": x, "y": y, "width": width, "height": height,
                "element": {
                    "kind": "ElementReference",
                    "name": element_name(item["spec"]["id"]),
                },
            },
        })
        x += width
        shelf_height = max(shelf_height, height)
    return {"kind": "GridLayout", "spec": {"items": out}}


def condition(present=None, census: str | None = None) -> dict | None:
    """Build the fail-visible presence condition, or ``None`` for unconditional.

    ``present`` is one sentinel name or a list of them; the element shows if
    **any** is non-empty. ``census`` is the availability-census sentinel, and its
    emptiness is an independent reason to show: an entirely absent census means
    *unknown*, never *disabled* (#303), so a wrong datasource or a stopped
    exporter must not silently blank the dashboard.

    Refuses ``present`` without ``census`` — an unescaped presence condition is
    exactly the blank-dashboard failure, so it has to be unbuildable rather than
    merely discouraged.
    """
    names = [present] if isinstance(present, str) else list(present or [])
    if not names:
        # A census sentinel alone would hide content whenever the census is
        # healthy, which is backwards. No presence claim means no condition.
        return None
    if not census:
        raise ValueError(
            "a presence condition needs a census escape sentinel; without one "
            "an absent census hides every conditional element and the dashboard "
            "renders blank with no error (#399 C1)"
        )

    items = [
        {"kind": "ConditionalRenderingVariable",
         "spec": {"variable": name, "operator": "matches", "value": ".+"}}
        for name in names
    ]
    items.append({
        "kind": "ConditionalRenderingVariable",
        "spec": {"variable": census, "operator": "notMatches", "value": ".+"},
    })
    return {
        "kind": "ConditionalRenderingGroup",
        # Always "or", never "and". See this module's docstring.
        "spec": {"visibility": "show", "condition": "or", "items": items},
    }


def _with_condition(spec: dict, present, census) -> dict:
    cond = condition(present, census)
    if cond:
        spec["conditionalRendering"] = cond
    return spec


def rowspec(title: str, items: list, *, present=None, census: str | None = None,
            collapse: bool = False) -> dict:
    """One ``RowsLayoutRow`` holding a grid of panels.

    An empty title hides the header, so a section with a single implicit row does
    not show a blank header bar.
    """
    spec = {"title": title, "collapse": collapse, "layout": grid(items)}
    if not title:
        spec["hideHeader"] = True
    return {"kind": "RowsLayoutRow", "spec": _with_condition(spec, present, census)}


def leaf(title: str, rows: list, *, present=None,
         census: str | None = None) -> dict:
    """A tab whose content is rows of panels.

    Used both for a domain's leaf feature tabs and, unconditionally, for the
    top-level ``Overview`` tab — which must stay reachable in every state,
    including census-absent, so it never takes a condition.
    """
    spec = {"title": title, "layout": {"kind": "RowsLayout", "spec": {"rows": rows}}}
    return {"kind": "TabsLayoutTab", "spec": _with_condition(spec, present, census)}


def domain(title: str, leaves: list, *, present=None,
           census: str | None = None) -> dict:
    """A top-level tab whose content is a nested tab layout of leaves.

    Leaves keep their own conditional rendering: an opt-in section inside an
    active domain hides independently of the domain itself.
    """
    spec = {"title": title, "layout": {"kind": "TabsLayout", "spec": {"tabs": leaves}}}
    return {"kind": "TabsLayoutTab", "spec": _with_condition(spec, present, census)}


# ---------------------------------------------------------------------------
# variables
# ---------------------------------------------------------------------------

def datasource_variable(name: str, label: str, plugin_id: str, *,
                        default: str = "", regex: str = "",
                        description: str = "") -> dict:
    """A ``DatasourceVariable``.

    v2 renames the two fields #295's tests asserted on — ``type`` becomes
    ``pluginId`` and ``hide: 0`` becomes ``hide: "dontHide"`` — but keeps
    ``current`` and ``regex``, which are #295's actual substance: a saved
    Grafana Cloud default plus an exclusion regex so a same-typed near-miss
    datasource is never resolved as the default.
    """
    spec = {
        "name": name,
        "label": label,
        "pluginId": plugin_id,
        "current": {"text": default, "value": default},
        "options": [],
        "multi": False,
        "includeAll": False,
        "allowCustomValue": True,
        "hide": "dontHide",
        "refresh": "onDashboardLoad",
        "regex": regex,
        "skipUrlSync": False,
    }
    if description:
        spec["description"] = description
    return {"kind": "DatasourceVariable", "spec": spec}


def query_variable(name: str, query: str, *, label: str = "",
                   multi: bool = False, include_all: bool = False,
                   description: str = "", hide: str = "dontHide",
                   skip_url_sync: bool = False, sort: str = SORT_ALPHABETICAL) -> dict:
    """A Prometheus-backed ``QueryVariable``.

    Note for anyone adding a Loki-backed variable later: the Loki **variable**
    query spec is a bare ``__legacyStringValue`` string, not this
    ``{query, refId}`` shape. They differ, and the difference is not obvious.
    """
    spec = {
        "name": name,
        "label": label or name,
        "hide": hide,
        "query": {
            "kind": "DataQuery",
            "version": "v0",
            "group": "prometheus",
            "datasource": {"name": "${datasource}"},
            "spec": {"query": query, "refId": name},
        },
        "current": {"text": "", "value": ""},
        "options": [],
        "multi": multi,
        "includeAll": include_all,
        "allowCustomValue": False,
        "refresh": "onDashboardLoad",
        "regex": "",
        "skipUrlSync": skip_url_sync,
        "sort": sort,
    }
    if description:
        spec["description"] = description
    return {"kind": "QueryVariable", "spec": spec}


def sentinel(name: str, query: str) -> dict:
    """A hidden presence variable driving conditional rendering.

    Hidden so it never appears in the variable picker, and URL-unsynced so it
    never lands in a shared link. ``hide: "hideVariable"`` was measured **not** to
    affect conditional folding.

    Refuses a value-threshold query. A ``> 0`` sentinel hides a live-but-idle
    collector by conflating *absent* with *present but zero* — the #114 mistake in
    a new costume, and a direct contradiction of the availability census, which
    already distinguishes disabled from healthy-empty. Presence is series
    existence, decided by the census, never by a current value.
    """
    if "query_result(" in query or "> 0" in query:
        raise ValueError(
            f"sentinel {name!r} tests a value, not presence: {query!r}. A "
            "value-threshold sentinel hides a healthy-but-empty collector; drive "
            "presence from graph2otel_collector_availability instead"
        )
    return query_variable(name, query, hide="hideVariable", skip_url_sync=True,
                          sort=SORT_NONE)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------

def manifest(*, name: str, title: str, description: str, tags: list,
             variables: list, elements: dict, tabs: list) -> dict:
    """Assemble the v2 dashboard resource.

    ``metadata.name`` is the v2 identity — there is no top-level ``uid`` — and
    ``spec.timeSettings`` replaces v1's top-level ``time``/``refresh``/
    ``timezone``.
    """
    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"name": name, "annotations": {}},
        "spec": {
            "title": title,
            "description": description,
            "tags": tags,
            "cursorSync": "Crosshair",
            "editable": True,
            "liveNow": False,
            "preload": False,
            "timeSettings": {
                "from": "now-24h",
                "to": "now",
                "autoRefresh": "5m",
                "autoRefreshIntervals": ["1m", "5m", "15m", "30m", "1h"],
                "timezone": "browser",
                "fiscalYearStartMonth": 0,
                "hideTimepicker": False,
            },
            "links": [],
            "annotations": [],
            "variables": variables,
            "elements": elements,
            "layout": {"kind": "TabsLayout", "spec": {"tabs": tabs}},
        },
    }


def _walk_tabs(tabs: list):
    """Yield every ``TabsLayoutTab`` spec, depth-first, with its nesting group.

    The group is the list of sibling titles it belongs to, which is what the
    duplicate-title check needs: slugs only have to be unique among siblings.
    """
    for tab in tabs:
        spec = tab["spec"]
        yield spec, tabs
        layout = spec.get("layout", {})
        if layout.get("kind") == "TabsLayout":
            yield from _walk_tabs(layout["spec"]["tabs"])


def _rows_of(spec: dict) -> list:
    layout = spec.get("layout", {})
    if layout.get("kind") == "RowsLayout":
        return layout["spec"]["rows"]
    return []


def _conditional_groups(tabs: list):
    for spec, _ in _walk_tabs(tabs):
        if "conditionalRendering" in spec:
            yield spec["title"], spec["conditionalRendering"]
        for row in _rows_of(spec):
            if "conditionalRendering" in row["spec"]:
                yield row["spec"]["title"] or "(untitled row)", \
                    row["spec"]["conditionalRendering"]


VIEW_PANEL_RE = re.compile(r"[?&]viewPanel=(\d+)")
DTAB_RE = re.compile(r"[?&](?:[\w-]+-)?dtab=")


def _panel_links(elements: dict):
    """Yield ``(element_name, url)`` for every panel data link in the manifest."""
    for name, element in elements.items():
        viz = element["spec"]["vizConfig"]["spec"]
        defaults = viz.get("fieldConfig", {}).get("defaults", {})
        for link in defaults.get("links") or []:
            yield name, link.get("url", "")
        for link in element["spec"].get("links") or []:
            yield name, link.get("url", "")


def _conditional_element_names(man: dict) -> set:
    """Elements whose containing tab or row can be conditioned away.

    A ``viewPanel`` link into one of these is the spike's only silent-blank path:
    when the ancestor tab is hidden, the deep link renders a **completely empty
    body** — no message, no tab bar, nothing.
    """
    names = set()

    def walk(tabs: list, hidden: bool):
        for tab in tabs:
            spec = tab["spec"]
            tab_hidden = hidden or "conditionalRendering" in spec
            layout = spec.get("layout", {})
            if layout.get("kind") == "TabsLayout":
                walk(layout["spec"]["tabs"], tab_hidden)
                continue
            for row in _rows_of(spec):
                row_hidden = tab_hidden or "conditionalRendering" in row["spec"]
                if not row_hidden:
                    continue
                grid = row["spec"].get("layout", {})
                if grid.get("kind") != "GridLayout":
                    continue
                for item in grid["spec"]["items"]:
                    names.add(item["spec"]["element"]["name"])

    walk(man["spec"]["layout"]["spec"]["tabs"], False)
    return names


def placed_element_names(man: dict) -> set:
    """Every element name the layout actually references.

    Exposed so a caller can assert it inspected a non-zero number of panels
    rather than passing vacuously over an empty set (#399 C7).
    """
    names = set()
    for spec, _ in _walk_tabs(man["spec"]["layout"]["spec"]["tabs"]):
        for row in _rows_of(spec):
            layout = row["spec"].get("layout", {})
            if layout.get("kind") != "GridLayout":
                continue
            for item in layout["spec"]["items"]:
                names.add(item["spec"]["element"]["name"])
    return names


def manifest_violations(man: dict) -> list:
    """Every structural rule breach in an assembled manifest, as strings.

    Returns all of them rather than raising on the first, so one build reports
    the whole list.
    """
    violations = []
    tabs = man["spec"]["layout"]["spec"]["tabs"]
    elements = man["spec"]["elements"]

    placed = placed_element_names(man)

    for name in sorted(set(elements) - placed):
        violations.append(
            f"element {name} is built but not placed in any row: it would be "
            "counted by the coverage gate and invisible to an operator"
        )
    for name in sorted(placed - set(elements)):
        violations.append(f"layout references element {name}, which does not exist")

    declared = {var["spec"]["name"] for var in man["spec"]["variables"]}
    for owner, group in _conditional_groups(tabs):
        items = group["spec"]["items"]
        operators = [item["spec"]["operator"] for item in items]
        if "matches" in operators:
            if group["spec"]["condition"] != "or":
                violations.append(
                    f"{owner!r} has a presence condition whose group condition is "
                    f"{group['spec']['condition']!r}, not 'or': it is false in the "
                    "normal healthy state and hides the element (#399 C1)"
                )
            if "notMatches" not in operators:
                violations.append(
                    f"{owner!r} has a presence condition with no census escape "
                    "item: an absent census would hide it (#399 C1)"
                )
        for item in items:
            referenced = item["spec"]["variable"]
            if referenced not in declared:
                violations.append(
                    f"{owner!r} references sentinel {referenced!r}, which is not a "
                    "declared variable; an undeclared variable evaluates TRUE, so "
                    "rendering cannot catch this"
                )

    ids = {element["spec"]["id"] for element in elements.values()}
    by_id = {element["spec"]["id"]: name for name, element in elements.items()}
    conditional = _conditional_element_names(man)
    for owner, url in _panel_links(elements):
        match = VIEW_PANEL_RE.search(url)
        if not match:
            continue
        target = int(match.group(1))
        if target not in ids:
            violations.append(
                f"{owner} links to viewPanel={target}, which is not a panel id; "
                "the drilldown would render 'Panel not found'"
            )
            continue
        # Measured: a viewPanel link whose ancestor tab is conditioned away renders
        # a completely blank body with no message. A ?dtab= overrides the hiding,
        # so a link carrying one is safe; otherwise the target must be
        # unconditional.
        if by_id[target] in conditional and not DTAB_RE.search(url):
            violations.append(
                f"{owner} links to viewPanel={target} ({by_id[target]}), which sits "
                "under a conditional tab or row: if it is hidden the drilldown "
                "renders a blank page with no message. Add the owning tab's dtab "
                "to the link, or point it at unconditional content"
            )

    for _, siblings in _walk_tabs(tabs):
        titles = [tab["spec"]["title"] for tab in siblings]
        for title in sorted({t for t in titles if titles.count(t) > 1}):
            violations.append(
                f"tab title {title!r} appears more than once among siblings, so "
                f"slug {slug(title)!r} is ambiguous and a wrong slug is silently "
                "ignored"
            )

    return sorted(set(violations))
