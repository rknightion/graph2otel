"""Tests for the Grafana v2 dynamic-dashboard translation layer (#399).

Every assertion here traces to a recorded correction on #399. The C-numbers are
load-bearing: each one is a defect an adversarial design review or a live render
spike found *before* implementation, and this file is what stops it coming back.

The three that matter most, because each fails SILENTLY in production:

* **C1** — a conditional group built the way the reference implementation builds
  it emits ``condition: "and"``, which is false in the normal healthy state, so
  every tab hides and the operator sees a blank dashboard with no error. The
  condition builder here refuses to emit anything but ``"or"`` once a presence
  sentinel is involved.
* **C5** — a v1-shaped transformation validates clean server-side and renders
  wrong. Only a render check catches it, so the shape is pinned here instead.
* **C10** — a panel can be constructed (crediting the coverage gate) yet never
  placed in the layout: counted as panelled, invisible in reality.

Plus two traps the live render spike found, neither of which rendering can ever
catch for us: a condition naming a **non-existent** variable evaluates TRUE, and
a wrong tab slug is **silently ignored** and falls back to the first tab. Both
are therefore generator-side gates.
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import v2  # noqa: E402


def _panel(pid: int, title: str = "P", viz: str = "timeseries", **extra) -> dict:
    """A minimal v1-shaped panel spec, as the existing constructors return one."""
    spec = {
        "id": pid, "type": viz, "title": title, "description": "",
        "gridPos": {}, "datasource": {"type": "prometheus", "uid": "${datasource}"},
        "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
        "options": {}, "targets": [],
    }
    spec.update(extra)
    return spec


def _item(pid: int, w: int = 12, h: int = 8, **kw) -> dict:
    return {"w": w, "h": h, "spec": _panel(pid, **kw)}


class TestMinimumGrafanaVersion(unittest.TestCase):
    """The v2 schema needs Grafana 13+; assert it rather than document it.

    The reference implementation states this in prose in its README with no
    build-time or runtime assertion. #399 deliberately does more.
    """

    def test_minimum_version_is_pinned_at_thirteen(self):
        self.assertEqual(v2.MIN_GRAFANA_VERSION, "13.0.0")

    def test_api_version_and_kind_are_the_v2_dashboard_resource(self):
        self.assertEqual(v2.API_VERSION, "dashboard.grafana.app/v2")
        self.assertEqual(v2.KIND, "Dashboard")


class TestPanelTranslation(unittest.TestCase):
    """v1-shaped dict in, v2 ``Panel`` element out (the C3 seam decision).

    Panel constructors keep returning v1 dicts and the translation happens here,
    so no board module ever learns the v2 layout shape and the ~45 sites that
    mutate ``panel["fieldConfig"]`` keep working untouched.
    """

    def test_numeric_id_is_preserved_so_existing_drilldowns_survive(self):
        """C4: ``?viewPanel=`` keys on ``spec.id``, NOT the element name.

        Measured against real renders: ``?viewPanel=41`` and
        ``?viewPanel=panel-41`` both resolve, while ``?viewPanel=<element-name>``
        gives "Panel not found". So the eight shipped ``selfobs.py`` drilldowns
        survive this migration as long as the numeric id is carried across.
        """
        name, el = v2.panel_element(_panel(41), 12, 8)
        self.assertEqual(el["spec"]["id"], 41)
        self.assertEqual(name, "panel-41")

    def test_element_carries_the_v2_panel_kind_and_shape(self):
        _, el = v2.panel_element(_panel(1, title="Widgets"), 12, 8)
        self.assertEqual(el["kind"], "Panel")
        spec = el["spec"]
        self.assertEqual(spec["title"], "Widgets")
        self.assertEqual(spec["links"], [])
        self.assertEqual(spec["data"]["kind"], "QueryGroup")
        self.assertEqual(spec["vizConfig"]["kind"], "VizConfig")

    def test_viz_type_moves_to_vizconfig_group_and_options_into_its_spec(self):
        """In v2 the viz type is ``vizConfig.group``, not a top-level ``type``."""
        _, el = v2.panel_element(
            _panel(1, viz="table", options={"showHeader": True}), 24, 10)
        viz = el["spec"]["vizConfig"]
        self.assertEqual(viz["group"], "table")
        self.assertEqual(viz["spec"]["options"], {"showHeader": True})
        self.assertNotIn("type", el["spec"])

    def test_field_config_moves_under_vizconfig_spec(self):
        _, el = v2.panel_element(_panel(1), 12, 8)
        self.assertIn("fieldConfig", el["spec"]["vizConfig"]["spec"])
        self.assertNotIn("fieldConfig", el["spec"])

    def test_a_text_panel_with_no_targets_still_translates(self):
        """Text panels carry no ``targets`` key at all in the v1 shape."""
        spec = {"id": 3, "type": "text", "title": "", "gridPos": {},
                "options": {"mode": "markdown", "content": "hi"}}
        _, el = v2.panel_element(spec, 24, 4)
        self.assertEqual(el["spec"]["data"]["spec"]["queries"], [])
        self.assertEqual(el["spec"]["vizConfig"]["group"], "text")


class TestQueryTranslation(unittest.TestCase):
    def test_prometheus_target_becomes_a_panelquery_in_the_prometheus_group(self):
        target = {"refId": "A", "expr": "up", "editorMode": "code",
                  "range": True, "instant": False,
                  "datasource": {"type": "prometheus", "uid": "${datasource}"}}
        _, el = v2.panel_element(_panel(1, targets=[target]), 12, 8)
        q = el["spec"]["data"]["spec"]["queries"][0]
        self.assertEqual(q["kind"], "PanelQuery")
        self.assertEqual(q["spec"]["refId"], "A")
        self.assertIs(q["spec"]["hidden"], False)
        self.assertEqual(q["spec"]["query"]["group"], "prometheus")
        self.assertEqual(q["spec"]["query"]["kind"], "DataQuery")
        self.assertEqual(q["spec"]["query"]["spec"]["expr"], "up")

    def test_loki_target_is_routed_to_the_loki_group(self):
        """The datasource type decides the query group, so a log panel cannot be
        emitted into the prometheus group by accident."""
        target = {"refId": "A", "expr": '{service_name="graph2otel"}',
                  "queryType": "range",
                  "datasource": {"type": "loki", "uid": "${loki_datasource}"}}
        _, el = v2.panel_element(
            _panel(1, viz="logs", targets=[target],
                   datasource={"type": "loki", "uid": "${loki_datasource}"}), 24, 10)
        q = el["spec"]["data"]["spec"]["queries"][0]
        self.assertEqual(q["spec"]["query"]["group"], "loki")

    def test_legend_format_survives_translation(self):
        """#301's tenant-preserving legends are per-query, so they must carry."""
        target = {"refId": "A", "expr": "up", "legendFormat": "{{tenant_id}}",
                  "datasource": {"type": "prometheus", "uid": "${datasource}"}}
        _, el = v2.panel_element(_panel(1, targets=[target]), 12, 8)
        spec = el["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]
        self.assertEqual(spec["legendFormat"], "{{tenant_id}}")


class TestTransformationTranslation(unittest.TestCase):
    """C5: a v1 transformation validates clean server-side and renders wrong.

    ``gcx resources validate`` does not catch this class — only a render check
    does — so the shape is pinned here. graph2otel emits two: ``labelsToFields``
    on the availability table and ``reduce`` on every ``log_table``.
    """

    def test_v1_transformation_is_rewritten_into_the_v2_kind_group_spec_shape(self):
        _, el = v2.panel_element(
            _panel(1, viz="table", transformations=[
                {"id": "labelsToFields", "options": {"mode": "columns"}}]),
            24, 8)
        got = el["spec"]["data"]["spec"]["transformations"]
        self.assertEqual(got, [{
            "kind": "Transformation",
            "group": "labelsToFields",
            "spec": {"options": {"mode": "columns"}},
        }])

    def test_a_panel_with_no_transformations_gets_an_empty_list(self):
        _, el = v2.panel_element(_panel(1), 12, 8)
        self.assertEqual(el["spec"]["data"]["spec"]["transformations"], [])

    def test_an_already_v2_shaped_transformation_is_rejected_not_double_wrapped(self):
        """Defence in depth: if a call site ever emits the v2 shape directly,
        fail loudly rather than nest it into an unrenderable double wrapper."""
        with self.assertRaises(ValueError):
            v2.panel_element(
                _panel(1, transformations=[
                    {"kind": "Transformation", "group": "reduce", "spec": {}}]),
                12, 8)


class TestGridPacking(unittest.TestCase):
    """The 24-column shelf pack, now applied per row instead of per dashboard.

    Panel widths are unchanged by the migration: the v1 ``_layout`` already reset
    ``x`` at every row boundary, so packing each row independently produces the
    same coordinates within a row.
    """

    def test_panels_pack_left_to_right_then_wrap_at_24_columns(self):
        grid = v2.grid([_item(1), _item(2), _item(3)])
        coords = [(i["spec"]["x"], i["spec"]["y"]) for i in grid["spec"]["items"]]
        self.assertEqual(coords, [(0, 0), (12, 0), (0, 8)])

    def test_wrapping_advances_by_the_tallest_panel_on_the_shelf(self):
        grid = v2.grid([_item(1, h=8), _item(2, h=12), _item(3)])
        self.assertEqual(grid["spec"]["items"][2]["spec"]["y"], 12)

    def test_items_are_element_references_by_name(self):
        grid = v2.grid([_item(7)])
        item = grid["spec"]["items"][0]
        self.assertEqual(item["kind"], "GridLayoutItem")
        self.assertEqual(item["spec"]["element"],
                         {"kind": "ElementReference", "name": "panel-7"})

    def test_a_panel_wider_than_the_grid_is_a_build_error(self):
        with self.assertRaises(ValueError):
            v2.grid([_item(1, w=25)])


class TestConditionBuilder(unittest.TestCase):
    """C1 — the correction that would otherwise have blanked every tab.

    The reference's ``_cond`` raises only when ``len(present) > 1 and absent``.
    One present plus one absent — exactly graph2otel's fail-visible shape — falls
    through and emits ``condition: "and"``. That group is true only when the
    domain is active AND the census is absent, so it is false in state 1, the
    normal healthy operating state: every tab hides, silently.

    The four-state folding table was measured against real renders on Grafana
    13.2.0 and 13.1.1 (identical), so the ``"or"`` encoding below is proven, not
    assumed.
    """

    def test_a_presence_condition_emits_or_never_and(self):
        cond = v2.condition(present="has_entra", census="census_present")
        self.assertEqual(cond["kind"], "ConditionalRenderingGroup")
        self.assertEqual(cond["spec"]["condition"], "or")
        self.assertEqual(cond["spec"]["visibility"], "show")

    def test_the_census_escape_is_a_notmatches_item_alongside_the_presence_item(self):
        """State 3: census entirely absent (wrong datasource, exporter stopped)
        must render VISIBLE, because empty availability is *unknown* and never
        evidence of disabled (#303)."""
        cond = v2.condition(present="has_entra", census="census_present")
        items = cond["spec"]["items"]
        self.assertEqual([i["spec"]["operator"] for i in items],
                         ["matches", "notMatches"])
        self.assertEqual([i["spec"]["variable"] for i in items],
                         ["has_entra", "census_present"])
        for i in items:
            self.assertEqual(i["kind"], "ConditionalRenderingVariable")
            self.assertEqual(i["spec"]["value"], ".+")

    def test_several_presence_sentinels_are_supported_in_one_or_group(self):
        """A 3-item mixed OR was measured working, so we are not limited to the
        2-item shape the reference's guard would have refused."""
        cond = v2.condition(present=["has_a", "has_b"], census="census_present")
        self.assertEqual(cond["spec"]["condition"], "or")
        self.assertEqual(len(cond["spec"]["items"]), 3)

    def test_presence_without_the_census_escape_is_refused(self):
        """The whole point of C1: an unescaped presence condition is the blank
        dashboard. It must be impossible to build, not merely discouraged."""
        with self.assertRaises(ValueError):
            v2.condition(present="has_entra")

    def test_no_presence_means_no_condition_at_all(self):
        """An unconditional element carries no ``conditionalRendering`` key.
        Overview must be reachable in every state, including census-absent."""
        self.assertIsNone(v2.condition())
        self.assertIsNone(v2.condition(census="census_present"))


class TestSlugs(unittest.TestCase):
    """A wrong ``dtab`` slug is silently ignored and falls back to the first tab.

    Measured: it is the one non-fail-visible behaviour on the tab path, so slug
    derivation is pinned and cross-checked by a gate rather than hand-written at
    link sites.
    """

    def test_slug_replaces_spaces_with_hyphens_and_preserves_case(self):
        self.assertEqual(v2.slug("Entra ID"), "Entra-ID")

    def test_slug_collapses_runs_of_whitespace(self):
        self.assertEqual(v2.slug("Risk  and   sign-ins"), "Risk-and-sign-ins")


class TestLayoutPrimitives(unittest.TestCase):
    def test_rowspec_wraps_panels_in_a_rows_layout_row_holding_a_grid(self):
        row = v2.rowspec("Directory objects", [_item(1)])
        self.assertEqual(row["kind"], "RowsLayoutRow")
        self.assertEqual(row["spec"]["title"], "Directory objects")
        self.assertIs(row["spec"]["collapse"], False)
        self.assertEqual(row["spec"]["layout"]["kind"], "GridLayout")

    def test_an_untitled_row_hides_its_header(self):
        """A section with one implicit row should not show an empty header bar."""
        row = v2.rowspec("", [_item(1)])
        self.assertIs(row["spec"]["hideHeader"], True)

    def test_leaf_wraps_rows_in_a_tab_holding_a_rows_layout(self):
        leaf = v2.leaf("Risk and sign-ins", [v2.rowspec("", [_item(1)])])
        self.assertEqual(leaf["kind"], "TabsLayoutTab")
        self.assertEqual(leaf["spec"]["layout"]["kind"], "RowsLayout")

    def test_domain_wraps_leaves_in_a_tab_holding_a_nested_tabs_layout(self):
        leaf = v2.leaf("Risk", [v2.rowspec("", [_item(1)])])
        dom = v2.domain("Entra", [leaf], present="has_entra",
                        census="census_present")
        self.assertEqual(dom["kind"], "TabsLayoutTab")
        self.assertEqual(dom["spec"]["layout"]["kind"], "TabsLayout")
        self.assertEqual(dom["spec"]["conditionalRendering"]["spec"]["condition"], "or")

    def test_a_conditional_leaf_carries_its_own_or_group(self):
        """Opt-in sections (beta, Experimental, HIGH VOLUME) are exactly the
        leaves whose conditional rendering matters most."""
        leaf = v2.leaf("Global Secure Access", [v2.rowspec("", [_item(1)])],
                       present="has_gsa", census="census_present")
        self.assertEqual(leaf["spec"]["conditionalRendering"]["spec"]["condition"], "or")

    def test_an_unconditional_domain_has_no_conditional_rendering_key(self):
        dom = v2.domain("Overview", [v2.leaf("x", [v2.rowspec("", [_item(1)])])])
        self.assertNotIn("conditionalRendering", dom["spec"])


class TestVariables(unittest.TestCase):
    """v2 renames the fields #295 asserted on, but keeps its substance.

    C9: ``DatasourceVariable.spec`` uses ``pluginId`` not ``type``, and ``hide``
    is the string ``"dontHide"`` not ``0``. ``current`` and ``regex`` — the two
    things #295 actually landed — survive unchanged.
    """

    def test_datasource_variable_uses_pluginid_and_string_hide(self):
        var = v2.datasource_variable(
            "datasource", "Prometheus datasource", "prometheus",
            default="grafanacloud-prom", regex="(?!x).+", description="d")
        self.assertEqual(var["kind"], "DatasourceVariable")
        spec = var["spec"]
        self.assertEqual(spec["pluginId"], "prometheus")
        self.assertEqual(spec["hide"], "dontHide")
        self.assertNotIn("type", spec)

    def test_datasource_variable_preserves_the_295_saved_default_and_exclusion(self):
        var = v2.datasource_variable(
            "datasource", "L", "prometheus",
            default="grafanacloud-prom", regex="(?!grafanacloud-usage).+")
        self.assertEqual(var["spec"]["current"],
                         {"text": "grafanacloud-prom", "value": "grafanacloud-prom"})
        self.assertEqual(var["spec"]["regex"], "(?!grafanacloud-usage).+")

    def test_query_variable_carries_the_prometheus_query_spec_shape(self):
        var = v2.query_variable("tenant", "label_values(m, tenant_id)",
                                label="Tenant", multi=True, include_all=True)
        self.assertEqual(var["kind"], "QueryVariable")
        spec = var["spec"]
        self.assertEqual(spec["query"]["group"], "prometheus")
        self.assertEqual(spec["query"]["spec"]["query"], "label_values(m, tenant_id)")
        self.assertIs(spec["multi"], True)
        self.assertIs(spec["includeAll"], True)
        self.assertEqual(spec["hide"], "dontHide")

    def test_a_sentinel_is_a_hidden_unsynced_query_variable(self):
        """Hidden so it never appears in the picker; unsynced so it never lands
        in a shared URL. ``hide: "hideVariable"`` was measured NOT to affect
        conditional folding."""
        var = v2.sentinel("has_entra", 'label_values(m{state!~"disabled"}, collector)')
        spec = var["spec"]
        self.assertEqual(spec["name"], "has_entra")
        self.assertEqual(spec["hide"], "hideVariable")
        self.assertIs(spec["skipUrlSync"], True)
        self.assertEqual(spec["current"], {"text": "", "value": ""})

    def test_a_value_threshold_sentinel_is_refused(self):
        """The #114 mistake in a new costume: a ``> 0`` sentinel hides a
        live-but-idle collector, conflating absent with present-but-zero. The
        presence contract is driven by the availability census, never by a value.
        """
        with self.assertRaises(ValueError):
            v2.sentinel("has_entra", "query_result(entra_users_count > 0)")


class TestManifest(unittest.TestCase):
    def test_manifest_carries_the_v2_envelope_and_names_the_dashboard(self):
        man = v2.manifest(
            name="graph2otel", title="graph2otel", description="d", tags=["t"],
            variables=[], elements={}, tabs=[])
        self.assertEqual(man["apiVersion"], v2.API_VERSION)
        self.assertEqual(man["kind"], v2.KIND)
        self.assertEqual(man["metadata"]["name"], "graph2otel")
        self.assertEqual(man["spec"]["layout"]["kind"], "TabsLayout")

    def test_time_settings_replace_the_v1_top_level_time_and_refresh(self):
        man = v2.manifest(name="g", title="t", description="d", tags=[],
                          variables=[], elements={}, tabs=[])
        ts = man["spec"]["timeSettings"]
        self.assertEqual(ts["from"], "now-24h")
        self.assertEqual(ts["to"], "now")
        self.assertNotIn("time", man["spec"])
        self.assertNotIn("refresh", man["spec"])


class TestManifestGates(unittest.TestCase):
    """The gates that keep this migration from reporting coverage it lacks.

    #139/#100 is the standing precedent: a gate that cannot see its subject
    reports coverage it does not have. Each gate below returns a list of
    violation strings so the build can fail with all of them at once.
    """

    def _manifest(self, elements, tabs, variables=None):
        return v2.manifest(name="g", title="t", description="d", tags=[],
                           variables=variables or [], elements=elements, tabs=tabs)

    def test_an_element_that_is_never_placed_is_a_violation(self):
        """C10: a panel can be built — crediting the metric coverage gate — yet
        never passed to a row. Panelled according to the gate, invisible in
        reality."""
        name, el = v2.panel_element(_panel(1), 12, 8)
        orphan_name, orphan = v2.panel_element(_panel(2), 12, 8)
        tabs = [v2.leaf("L", [v2.rowspec("", [_item(1)])])]
        man = self._manifest({name: el, orphan_name: orphan}, tabs)
        violations = v2.manifest_violations(man)
        self.assertTrue(any("panel-2" in v and "not placed" in v for v in violations),
                        violations)

    def test_a_reference_to_an_element_that_does_not_exist_is_a_violation(self):
        tabs = [v2.leaf("L", [v2.rowspec("", [_item(9)])])]
        man = self._manifest({}, tabs)
        violations = v2.manifest_violations(man)
        self.assertTrue(any("panel-9" in v for v in violations), violations)

    def test_a_fully_placed_manifest_has_no_violations(self):
        name, el = v2.panel_element(_panel(1), 12, 8)
        tabs = [v2.leaf("L", [v2.rowspec("", [_item(1)])])]
        self.assertEqual(v2.manifest_violations(self._manifest({name: el}, tabs)), [])

    def test_a_sentinel_referenced_but_never_declared_is_a_violation(self):
        """Measured trap: a condition naming a variable that does not exist
        evaluates TRUE for both operators, so the element shows. That fails
        visible — the right default — but it means **rendering can never catch a
        misspelled sentinel**. Only this gate can."""
        name, el = v2.panel_element(_panel(1), 12, 8)
        tabs = [v2.domain("D", [v2.leaf("L", [v2.rowspec("", [_item(1)])])],
                          present="has_typo", census="census_present")]
        man = self._manifest({name: el}, tabs)
        violations = v2.manifest_violations(man)
        self.assertTrue(any("has_typo" in v for v in violations), violations)

    def test_declared_sentinels_satisfy_the_reference_gate(self):
        name, el = v2.panel_element(_panel(1), 12, 8)
        tabs = [v2.domain("D", [v2.leaf("L", [v2.rowspec("", [_item(1)])])],
                          present="has_d", census="census_present")]
        variables = [
            v2.sentinel("has_d", "label_values(m, collector)"),
            v2.sentinel("census_present", "label_values(m, collector)"),
        ]
        man = self._manifest({name: el}, tabs, variables)
        self.assertEqual(v2.manifest_violations(man), [])

    def test_a_conditional_group_that_is_not_an_or_is_a_violation(self):
        """The gate C1 demands, and the one the original design lacked: it
        checked only that the census escape *item* was present, never that the
        group ``condition`` was ``or``. A hand-built ``and`` group must fail."""
        name, el = v2.panel_element(_panel(1), 12, 8)
        leaf = v2.leaf("L", [v2.rowspec("", [_item(1)])])
        bad = v2.domain("D", [leaf], present="has_d", census="census_present")
        bad["spec"]["conditionalRendering"]["spec"]["condition"] = "and"
        man = self._manifest({name: el}, [bad], [
            v2.sentinel("has_d", "label_values(m, collector)"),
            v2.sentinel("census_present", "label_values(m, collector)"),
        ])
        violations = v2.manifest_violations(man)
        self.assertTrue(any("condition" in v for v in violations), violations)

    def test_a_presence_group_missing_its_census_escape_is_a_violation(self):
        """Both halves of C1's binding gate are checked independently, so
        stripping either one fails."""
        name, el = v2.panel_element(_panel(1), 12, 8)
        leaf = v2.leaf("L", [v2.rowspec("", [_item(1)])])
        bad = v2.domain("D", [leaf], present="has_d", census="census_present")
        items = bad["spec"]["conditionalRendering"]["spec"]["items"]
        del items[1]
        man = self._manifest({name: el}, [bad], [
            v2.sentinel("has_d", "label_values(m, collector)")])
        violations = v2.manifest_violations(man)
        self.assertTrue(any("escape" in v for v in violations), violations)

    def test_duplicate_tab_titles_at_one_level_are_a_violation(self):
        """Slugs are derived from titles, and a wrong slug is silently ignored,
        so two tabs sharing a title make one of them unaddressable."""
        n1, e1 = v2.panel_element(_panel(1), 12, 8)
        n2, e2 = v2.panel_element(_panel(2), 12, 8)
        tabs = [v2.leaf("Same", [v2.rowspec("", [_item(1)])]),
                v2.leaf("Same", [v2.rowspec("", [_item(2)])])]
        man = self._manifest({n1: e1, n2: e2}, tabs)
        violations = v2.manifest_violations(man)
        self.assertTrue(any("Same" in v for v in violations), violations)

    def _linked(self, pid: int, url: str) -> dict:
        panel = _panel(pid)
        panel["fieldConfig"]["defaults"]["links"] = [{"title": "t", "url": url}]
        return panel

    def test_a_drilldown_to_a_nonexistent_panel_id_is_a_violation(self):
        """The eight shipped drilldowns are built from ``panel["id"]``, and panel
        ids are non-contiguous because row markers consume them. A hand-written or
        stale id renders "Panel not found"."""
        src = self._linked(1, "/d/graph2otel?viewPanel=999")
        n1, e1 = v2.panel_element(src, 12, 8)
        tabs = [v2.leaf("L", [v2.rowspec("", [{"w": 12, "h": 8, "spec": src}])])]
        man = self._manifest({n1: e1}, tabs)
        violations = v2.manifest_violations(man)
        self.assertTrue(any("999" in v for v in violations), violations)

    def test_a_drilldown_into_conditional_content_without_a_dtab_is_a_violation(self):
        """The spike's only silent-blank path: a ``viewPanel`` whose ancestor tab
        is conditioned away renders an empty body with no message at all. A
        ``?dtab=`` overrides hiding, so carrying one is the escape."""
        src = self._linked(1, "/d/graph2otel?viewPanel=2")
        target = _panel(2)
        n1, e1 = v2.panel_element(src, 12, 8)
        n2, e2 = v2.panel_element(target, 12, 8)
        leaf = v2.leaf("L", [v2.rowspec("", [
            {"w": 12, "h": 8, "spec": src}, {"w": 12, "h": 8, "spec": target}])])
        tabs = [v2.domain("D", [leaf], present="has_d", census="census_present")]
        man = self._manifest({n1: e1, n2: e2}, tabs, [
            v2.sentinel("has_d", "label_values(m, collector)"),
            v2.sentinel("census_present", "label_values(m, collector)"),
        ])
        violations = v2.manifest_violations(man)
        self.assertTrue(any("blank page" in v for v in violations), violations)

    def test_the_same_drilldown_is_accepted_when_it_carries_a_dtab(self):
        src = self._linked(1, "/d/graph2otel?dtab=D&viewPanel=2")
        target = _panel(2)
        n1, e1 = v2.panel_element(src, 12, 8)
        n2, e2 = v2.panel_element(target, 12, 8)
        leaf = v2.leaf("L", [v2.rowspec("", [
            {"w": 12, "h": 8, "spec": src}, {"w": 12, "h": 8, "spec": target}])])
        tabs = [v2.domain("D", [leaf], present="has_d", census="census_present")]
        man = self._manifest({n1: e1, n2: e2}, tabs, [
            v2.sentinel("has_d", "label_values(m, collector)"),
            v2.sentinel("census_present", "label_values(m, collector)"),
        ])
        self.assertEqual(v2.manifest_violations(man), [])

    def test_a_drilldown_into_unconditional_content_is_accepted(self):
        src = self._linked(1, "/d/graph2otel?viewPanel=2")
        target = _panel(2)
        n1, e1 = v2.panel_element(src, 12, 8)
        n2, e2 = v2.panel_element(target, 12, 8)
        tabs = [v2.leaf("L", [v2.rowspec("", [
            {"w": 12, "h": 8, "spec": src}, {"w": 12, "h": 8, "spec": target}])])]
        man = self._manifest({n1: e1, n2: e2}, tabs)
        self.assertEqual(v2.manifest_violations(man), [])

    def test_the_gate_reports_how_many_panels_it_inspected(self):
        """C7: two existing gates degrade to vacuous rather than failing when the
        datasource moves into each query. Anything that walks panels must be able
        to prove it saw some."""
        name, el = v2.panel_element(_panel(1), 12, 8)
        tabs = [v2.leaf("L", [v2.rowspec("", [_item(1)])])]
        self.assertEqual(v2.placed_element_names(self._manifest({name: el}, tabs)),
                         {"panel-1"})


class TestTranslatesTheRealEstate(unittest.TestCase):
    """Translate every panel the six live boards actually build.

    Fixture-green is not evidence here. The estate carries text, stat,
    timeseries, table, bargauge, heatmap and logs panels, two transformations,
    both datasources, and ~45 panels whose ``fieldConfig`` a board module mutated
    after construction. This test is what proves the translator meets all of it,
    and it is the reason commit 2 can be wiring rather than discovery.
    """

    @classmethod
    def setUpClass(cls):
        import build_dashboard  # noqa: PLC0415
        import catalog as catalog_mod  # noqa: PLC0415

        builder, domain_tabs, _ = build_dashboard.build_all(catalog_mod.load())
        cls.builder = builder
        cls.tabs = domain_tabs
        cls.manifest = builder.render(
            [build_dashboard.overview(builder), *domain_tabs])

    def _items(self):
        for item in self.builder._panels:
            if not item.get("row"):
                yield item["spec"].get("title", ""), item

    def test_every_real_panel_translates_without_error(self):
        seen = 0
        for board_name, item in self._items():
            with self.subTest(board=board_name, panel=item["spec"]["id"]):
                name, el = v2.panel_element(item["spec"], item["w"], item["h"])
                self.assertTrue(name.startswith("panel-"))
                self.assertEqual(el["kind"], "Panel")
                seen += 1
        # A gate that cannot see its subject reports coverage it does not have
        # (#139/#100). Assert the walk was not vacuous.
        self.assertGreater(seen, 300, "expected the full estate, got almost none")

    def test_every_viz_type_in_the_estate_maps_to_a_vizconfig_group(self):
        groups = set()
        for _, item in self._items():
            _, el = v2.panel_element(item["spec"], item["w"], item["h"])
            groups.add(el["spec"]["vizConfig"]["group"])
        self.assertIn("timeseries", groups)
        self.assertIn("table", groups)
        self.assertIn("logs", groups)
        self.assertIn("text", groups)

    def test_both_real_transformations_convert(self):
        """The two C5 sites: ``labelsToFields`` and ``reduce``."""
        converted = set()
        for _, item in self._items():
            _, el = v2.panel_element(item["spec"], item["w"], item["h"])
            for t in el["spec"]["data"]["spec"]["transformations"]:
                self.assertEqual(t["kind"], "Transformation")
                converted.add(t["group"])
        self.assertEqual(converted, {"labelsToFields", "reduce"})

    def test_every_real_panel_id_is_preserved_exactly(self):
        for board_name, item in self._items():
            _, el = v2.panel_element(item["spec"], item["w"], item["h"])
            self.assertEqual(el["spec"]["id"], item["spec"]["id"], board_name)

    def test_the_real_estate_manifest_has_no_violations(self):
        """Every gate in this module, run against the manifest actually shipped.

        This is the one that would fail if a board module drifted into an
        unplaced panel, an undeclared sentinel, a duplicate tab title, an `and`
        condition, or a drilldown into hideable content.
        """
        self.assertEqual(v2.manifest_violations(self.manifest), [])

    def test_every_element_in_the_real_estate_is_placed(self):
        placed = v2.placed_element_names(self.manifest)
        self.assertEqual(placed, set(self.manifest["spec"]["elements"]))
        self.assertGreater(len(placed), 300)

    def test_the_real_estate_has_the_seven_expected_top_level_tabs(self):
        titles = [t["spec"]["title"]
                  for t in self.manifest["spec"]["layout"]["spec"]["tabs"]]
        self.assertEqual(titles, ["Overview", "Entra", "Intune", "Defender",
                                  "M365", "Purview", "Self-obs"])

    def test_overview_is_never_conditional(self):
        """It is the one surface that must render when the census is missing —
        that is exactly the state an operator needs explained, not hidden."""
        overview = self.manifest["spec"]["layout"]["spec"]["tabs"][0]
        self.assertNotIn("conditionalRendering", overview["spec"])

    def test_every_conditional_domain_tab_uses_the_fail_visible_or_encoding(self):
        seen = 0
        for tab in self.manifest["spec"]["layout"]["spec"]["tabs"]:
            cond = tab["spec"].get("conditionalRendering")
            if cond is None:
                continue
            seen += 1
            self.assertEqual(cond["spec"]["condition"], "or",
                             tab["spec"]["title"])
            operators = [i["spec"]["operator"] for i in cond["spec"]["items"]]
            self.assertIn("notMatches", operators, tab["spec"]["title"])
        # Five Microsoft domains are conditional; Overview and Self-obs are not.
        self.assertEqual(seen, 5)


class TestLeafPanelBudget(unittest.TestCase):
    """The per-leaf render budget (#309).

    Under v1 all rows were expanded, so opening a dashboard queried every panel
    on it and panel count *was* the cost. Under v2 only the active leaf tab
    renders, so an operator opening Entra pays for one of twelve leaves, not for
    348 panels. **The largest leaf is the unit of cost, not the estate**, which
    is why an estate-wide total would be the wrong thing to gate.
    """

    def test_the_ceiling_leaves_deliberate_headroom_over_the_measured_maximum(self):
        import build_dashboard  # noqa: PLC0415

        self.assertGreater(build_dashboard.LEAF_PANEL_CEILING, 18,
                           "ceiling must exceed the largest leaf measured at "
                           "the time it was chosen, or it fails on arrival")

    def test_a_leaf_over_the_ceiling_is_reported(self):
        """A gate nobody has seen fail is a hope, not a gate."""
        import build_dashboard  # noqa: PLC0415

        over = build_dashboard.LEAF_PANEL_CEILING + 1
        items = [{"w": 1, "h": 1, "spec": _panel(i + 1)} for i in range(over)]
        tabs = [v2.domain("D", [v2.leaf("Fat", [v2.rowspec("", items)])])]
        man = v2.manifest(name="g", title="t", description="d", tags=[],
                          variables=[], elements={}, tabs=tabs)
        violations = build_dashboard.leaf_budget_violations(man, {})
        self.assertTrue(any("Fat" in v and str(over) in v for v in violations),
                        violations)

    def test_a_waiver_excuses_a_leaf_but_only_with_a_reason(self):
        import build_dashboard  # noqa: PLC0415

        over = build_dashboard.LEAF_PANEL_CEILING + 1
        items = [{"w": 1, "h": 1, "spec": _panel(i + 1)} for i in range(over)]
        tabs = [v2.domain("D", [v2.leaf("Fat", [v2.rowspec("", items)])])]
        man = v2.manifest(name="g", title="t", description="d", tags=[],
                          variables=[], elements={}, tabs=tabs)
        self.assertEqual(
            build_dashboard.leaf_budget_violations(man, {"Fat": "measured, fine"}),
            [])
        # A waiver with no reason is an undocumented escape hatch, which is not
        # a gate — same rule as the metric coverage waivers.
        self.assertTrue(build_dashboard.leaf_budget_violations(man, {"Fat": "  "}))

    def test_a_waiver_for_a_leaf_that_is_now_within_budget_is_reported(self):
        """A waiver that outlives its problem is a comment pretending to be a
        decision, and it silently re-permits the regression it was written for."""
        import build_dashboard  # noqa: PLC0415

        tabs = [v2.domain("D", [v2.leaf("Thin", [v2.rowspec("", [_item(1)])])])]
        man = v2.manifest(name="g", title="t", description="d", tags=[],
                          variables=[], elements={}, tabs=tabs)
        violations = build_dashboard.leaf_budget_violations(
            man, {"Thin": "was fat once"})
        self.assertTrue(any("Thin" in v for v in violations), violations)

    def test_the_real_estate_is_within_budget(self):
        import build_dashboard  # noqa: PLC0415
        import catalog as catalog_mod  # noqa: PLC0415

        builder, tabs, _ = build_dashboard.build_all(catalog_mod.load())
        man = builder.render([build_dashboard.overview(builder), *tabs])
        self.assertEqual(
            build_dashboard.leaf_budget_violations(man, build_dashboard.LEAF_WAIVERS),
            [])



if __name__ == "__main__":
    unittest.main()
