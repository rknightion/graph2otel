"""Gates for the generated entity-centric investigation pivots (#305).

The sabotage tests are the point of this file. #305's second acceptance criterion
is that **generation fails if a referenced event or attribute disappears**, and a
gate that merely checks a precondition is not a gate on that outcome — the #304
no-op shipped on exactly that mistake. So every one of the three ways a pivot can
rot is mutated here and the real gate is asserted to name it:

* an anchor event's identifier attribute is renamed;
* the identifier attribute disappears from every event that carried it;
* the anchor event itself disappears from the catalog.

The other half is the claim a link makes. A pivot link that says "this device's
compliance records" while sitting on a panel whose event carries no device
identifier is worse than no link: it is a navigation aid that lies. That is gated
against the shipped manifest, not against the declaration.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import catalog as catalog_mod  # noqa: E402
import pivots  # noqa: E402
import v2  # noqa: E402

CAT = catalog_mod.load()
BUILDER, MANIFEST, _ = build_dashboard.build(CAT)

REQUIRED_KINDS = ["device", "application", "account", "message", "alert",
                  "incident"]


def _mutated(mutate) -> catalog_mod.Catalog:
    """A real Catalog object built from a mutated copy of the shipped catalog."""
    with open(catalog_mod.CATALOGUE) as handle:
        raw = json.load(handle)
    mutate(raw)
    return catalog_mod.Catalog(raw)


def _rename_key(raw: dict, event: str, old: str, new: str):
    for log in raw["logs"]:
        if log["event_name"] == event:
            log["attr_keys"] = [new if k == old else k for k in log["attr_keys"]]


def _rename_key_everywhere(raw: dict, old: str, new: str):
    for log in raw["logs"]:
        log["attr_keys"] = [new if k == old else k for k in log["attr_keys"]]


def _drop_event(raw: dict, event: str):
    raw["logs"] = [log for log in raw["logs"] if log["event_name"] != event]


class TestEntityDeclarations(unittest.TestCase):
    def test_the_six_required_entity_kinds_are_covered(self):
        """#305 names these six as the initial set."""
        self.assertEqual([e.kind for e in pivots.ENTITIES], REQUIRED_KINDS)

    def test_every_entity_states_the_identifier_meaning_and_the_direction(self):
        """A pivot an analyst cannot read before clicking is a guess."""
        for e in pivots.ENTITIES:
            with self.subTest(e.kind):
                self.assertTrue(e.title.strip())
                self.assertTrue(e.variable.startswith("pivot_"))
                self.assertGreater(len(e.meaning), 40, e.meaning)
                self.assertGreater(len(e.direction), 30, e.direction)
                self.assertIn("this", e.direction.lower())

    def test_every_identifier_key_is_carried_by_a_cataloged_event(self):
        for e in pivots.ENTITIES:
            for key in e.keys:
                with self.subTest(f"{e.kind}.{key}"):
                    self.assertTrue(pivots.events_for(CAT, key),
                                    f"{key} is on no cataloged log event")

    def test_every_anchor_names_a_real_event_that_really_carries_the_key(self):
        for e in pivots.ENTITIES:
            for event, key in e.anchors:
                with self.subTest(f"{e.kind}:{event}:{key}"):
                    self.assertIn(event, CAT.logs)
                    self.assertIn(key, CAT.log(event).keys)
                    self.assertIn(key, e.keys)

    def test_every_documented_synonym_exists_and_is_deliberately_not_queried(self):
        """``also_named_by`` is what the panel description tells the analyst is
        NOT covered. A synonym that no longer exists makes that note a lie."""
        for e in pivots.ENTITIES:
            for key in e.also_named_by:
                with self.subTest(f"{e.kind}.{key}"):
                    self.assertTrue(pivots.events_for(CAT, key))
                    self.assertNotIn(key, e.keys)

    def test_the_gate_is_clean_on_the_shipped_catalog(self):
        self.assertEqual(pivots.violations(CAT), [])


class TestTheDisappearanceGate(unittest.TestCase):
    """#305 C2: generation fails if a referenced event or attribute disappears."""

    def test_a_renamed_attribute_on_an_anchor_event_fails_the_gate(self):
        cat = _mutated(lambda raw: _rename_key(
            raw, "intune.device_hardware", "device_id", "device_idx"))
        found = pivots.violations(cat)
        self.assertTrue(any("intune.device_hardware" in v and "device_id" in v
                            for v in found), found)

    def test_an_attribute_that_disappears_everywhere_fails_the_gate(self):
        cat = _mutated(lambda raw: _rename_key_everywhere(
            raw, "network_message_id", "networkMessageId"))
        found = pivots.violations(cat)
        self.assertTrue(any("network_message_id" in v for v in found), found)

    def test_a_disappeared_anchor_event_fails_the_gate(self):
        cat = _mutated(lambda raw: _drop_event(raw, "defender.alert_evidence"))
        found = pivots.violations(cat)
        self.assertTrue(any("defender.alert_evidence" in v for v in found), found)

    def test_a_disappeared_synonym_fails_the_gate(self):
        cat = _mutated(lambda raw: _rename_key_everywhere(
            raw, "serial_number", "serialNumber"))
        found = pivots.violations(cat)
        self.assertTrue(any("serial_number" in v for v in found), found)

    def test_the_whole_build_fails_and_not_just_the_declaration_check(self):
        """The gate has to be wired into the build, not merely exist.

        A validator connected to nothing is the #304 failure: it passes review
        because the code is right and it never runs.
        """
        cat = _mutated(lambda raw: _rename_key(
            raw, "defender.device_logon", "device_id", "device_idx"))
        builder, manifest, _ = build_dashboard.build(cat)
        found = build_dashboard.gate_violations(cat, builder, manifest)
        self.assertTrue(any("device_id" in v for v in found), found)


class TestTheGeneratedQueryShape(unittest.TestCase):
    def _pivot_targets(self) -> list:
        out = []
        for item in BUILDER._panels:
            spec = item.get("spec") or {}
            if not str(spec.get("title", "")).startswith(pivots.TITLE_PREFIXES):
                continue
            out.extend(target["expr"] for target in spec.get("targets", []))
        return out

    def test_the_pivots_ship_queries_at_all(self):
        self.assertGreaterEqual(len(self._pivot_targets()), 2 * sum(
            len(e.keys) for e in pivots.ENTITIES))

    def test_every_pivot_query_is_the_one_correct_logql_shape(self):
        """#305 C3, and #90: an attribute in the stream selector matches zero
        rows SILENTLY."""
        selector = re.compile(r"\{([^}]*)\}")
        for expr in self._pivot_targets():
            with self.subTest(expr[:80]):
                self.assertTrue(expr.startswith("{service_name=\"graph2otel\"}")
                                or "{service_name=\"graph2otel\"}" in expr)
                for inner in selector.findall(expr):
                    labels = re.findall(r"([a-z_][a-z0-9_]*)\s*[=!~]", inner)
                    self.assertEqual(set(labels), {"service_name"}, expr)
                self.assertIn("| event_name=~`", expr)
                self.assertIn('| tenant_id=~"$tenant"', expr)

    def test_every_pivot_query_carries_the_tenant_and_no_hardcoded_tenant(self):
        for expr in self._pivot_targets():
            self.assertIn('tenant_id=~"$tenant"', expr)

    def test_an_empty_input_matches_nothing_rather_than_everything(self):
        """The trap this guard exists for.

        In LogQL an absent structured-metadata key equals the empty string, so
        ``| device_id=`` `` with an unset variable matches every record that has
        no device_id — the pivot would dump the entire estate instead of showing
        nothing. Each target therefore also requires the key to be non-empty.
        """
        for expr in self._pivot_targets():
            key = re.search(r"\| ([a-z_]+)=~`\.\+`", expr)
            self.assertIsNotNone(key, f"no non-empty guard: {expr}")
            self.assertIn(f"| {key.group(1)}=`$pivot_", expr)

    def test_each_entity_input_is_a_declared_dashboard_variable(self):
        declared = {var["spec"]["name"] for var in MANIFEST["spec"]["variables"]}
        for e in pivots.ENTITIES:
            with self.subTest(e.kind):
                self.assertIn(e.variable, declared)

    def test_no_identifier_is_ever_a_metric_label(self):
        """The hard rule: per-entity data lives in logs, aggregates in metrics.

        Both halves are checked — no cataloged metric carries an identifier, and
        no PromQL expression in the estate names one — because a collector that
        starts labelling by device would pass the first check the moment someone
        also wrote the panel.
        """
        keys = {k for e in pivots.ENTITIES for k in (*e.keys, *e.also_named_by)}
        for name, metric in CAT.metrics.items():
            for key in keys:
                self.assertNotIn(key, metric.keys, f"{name} labels by {key}")
        for expr in BUILDER._exprs:
            for key in keys:
                self.assertNotIn(key, expr, f"identifier {key} in PromQL: {expr}")


class TestTheInvestigationSurface(unittest.TestCase):
    def _overview(self) -> dict:
        return MANIFEST["spec"]["layout"]["spec"]["tabs"][0]

    def test_the_pivots_live_on_the_unconditional_landing_tab(self):
        """A pivot must never land on a tab the census can hide: a viewPanel or
        dtab into conditioned-away content renders a blank body with no message
        (measured, #399)."""
        overview = self._overview()
        self.assertEqual(overview["spec"]["title"], "Overview")
        self.assertNotIn("conditionalRendering", overview["spec"])
        for row in overview["spec"]["layout"]["spec"]["rows"]:
            self.assertNotIn("conditionalRendering", row["spec"])

    def test_every_entity_has_its_own_row_with_both_pivot_panels(self):
        rows = {row["spec"]["title"]: row
                for row in self._overview()["spec"]["layout"]["spec"]["rows"]}
        for e in pivots.ENTITIES:
            with self.subTest(e.kind):
                self.assertIn(e.row_title(), rows)
                items = rows[e.row_title()]["spec"]["layout"]["spec"]["items"]
                self.assertEqual(len(items), 2)

    def test_the_entity_rows_are_collapsed_by_default(self):
        """Six expanded rows would run every entity's queries for the five
        entities the analyst is not investigating."""
        rows = {row["spec"]["title"]: row
                for row in self._overview()["spec"]["layout"]["spec"]["rows"]}
        for e in pivots.ENTITIES:
            self.assertTrue(rows[e.row_title()]["spec"]["collapse"], e.kind)

    def test_the_landing_leaf_stays_within_the_per_leaf_panel_budget(self):
        counts = build_dashboard.leaf_panel_counts(MANIFEST)
        self.assertLessEqual(counts["Overview"],
                             build_dashboard.LEAF_PANEL_CEILING)
        self.assertEqual(build_dashboard.leaf_budget_violations(
            MANIFEST, build_dashboard.LEAF_WAIVERS), [])

    def test_pivot_panels_degrade_honestly_with_no_input(self):
        for item in BUILDER._panels:
            spec = item.get("spec") or {}
            if not str(spec.get("title", "")).startswith(pivots.TITLE_PREFIXES):
                continue
            with self.subTest(spec["title"]):
                self.assertEqual(spec["datasource"]["type"], "loki")
                no_value = spec["fieldConfig"]["defaults"]["noValue"]
                self.assertIn("paste", no_value.lower())
                self.assertTrue(
                    spec["fieldConfig"]["defaults"]["thresholds"]["steps"])

    def test_no_pivot_panel_claims_to_correlate(self):
        """#305's non-goal: a Loki link is navigation, never a join or a verdict.

        Every pivot panel has to say so, because "which signals name this
        device" reads like a correlation result and is not one.
        """
        for item in BUILDER._panels:
            spec = item.get("spec") or {}
            if not str(spec.get("title", "")).startswith(pivots.TITLE_PREFIXES):
                continue
            self.assertIn("not a join", spec["description"].lower(),
                          spec["title"])


class TestTheLinksIntoTheSurface(unittest.TestCase):
    def _links(self) -> list:
        return list(v2._panel_links(MANIFEST["spec"]["elements"]))

    def _pivot_links(self) -> dict:
        """element name -> the pivot links on it, by entity."""
        by_title = {e.link_title(): e for e in pivots.ENTITIES}
        out = {}
        for name, element in MANIFEST["spec"]["elements"].items():
            for link in element["spec"].get("links") or []:
                entity = by_title.get(link.get("title"))
                if entity is not None:
                    out.setdefault(name, []).append((entity, link))
        return out

    def test_every_entity_is_reachable_from_at_least_one_panel(self):
        """An unreachable pivot is a surface nobody finds."""
        reached = {e.kind for links in self._pivot_links().values()
                   for e, _ in links}
        self.assertEqual(reached, set(REQUIRED_KINDS))

    def test_every_pivot_link_states_the_direction_not_just_the_noun(self):
        for _, links in self._pivot_links().items():
            for entity, link in links:
                self.assertIn(entity.direction, link["title"])

    def test_every_pivot_link_targets_a_real_tab_slug(self):
        """A wrong ``dtab`` slug is ignored SILENTLY and falls back to the first
        tab, so it cannot be caught by clicking it (#307, measured #399)."""
        slugs = {v2.slug(tab["spec"]["title"])
                 for tab in MANIFEST["spec"]["layout"]["spec"]["tabs"]}
        checked = 0
        for _, links in self._pivot_links().items():
            for _, link in links:
                found = re.search(r"[?&]dtab=([^&]+)", link["url"])
                self.assertIsNotNone(found, link["url"])
                self.assertIn(found.group(1), slugs)
                checked += 1
        self.assertGreater(checked, 0)

    def test_every_pivot_link_preserves_tenant_and_time(self):
        """#305: a pivot that loses tenant scope or resets the range is wrong."""
        for _, links in self._pivot_links().items():
            for _, link in links:
                self.assertIn("from=${__from}", link["url"])
                self.assertIn("to=${__to}", link["url"])
                self.assertIn("${__all_variables}", link["url"])

    def test_a_link_only_claims_an_entity_its_panel_event_really_carries(self):
        self.assertEqual(pivots.link_violations(CAT, MANIFEST), [])

    def test_a_link_on_a_panel_whose_event_lost_the_key_fails_the_gate(self):
        """The check #307 could not make with a numeric id: resolving is not the
        same as being about the right thing."""
        man = copy.deepcopy(MANIFEST)
        entity = pivots.ENTITIES[0]
        victim = None
        for name, element in man["spec"]["elements"].items():
            titles = [link.get("title")
                      for link in element["spec"].get("links") or []]
            if entity.link_title() in titles:
                victim = name
                break
        self.assertIsNotNone(victim, "no panel carries the device pivot link")
        target = man["spec"]["elements"][victim]["spec"]["data"]["spec"]
        target["queries"][0]["spec"]["query"]["spec"]["expr"] = (
            '{service_name="graph2otel"} | event_name=`purview.dlp_policy`')
        found = pivots.link_violations(CAT, man)
        self.assertTrue(any(victim in v for v in found), found)


if __name__ == "__main__":
    unittest.main()
