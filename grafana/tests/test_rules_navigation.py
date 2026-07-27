"""Runbook links, dashboard/panel context, and annotation linting (#307).

Standard-library ``unittest`` only, same convention as ``test_build_rules.py``.
Auto-discovered by ``python3 -m unittest discover -s tests -t .``, so
``make grafana-check`` and CI run these.

# What these gates exist to prevent

Three failure modes, all silent:

* A ``runbook_url`` pointing at an anchor that does not exist on the docs site.
  Mid-incident an operator follows it and lands on the page top (or a 404) with
  no indication anything is wrong. An unreachable runbook is worse than none,
  because the link itself asserts that guidance exists.
* A ``dtab`` slug that names no tab. Measured (#399): Grafana **silently
  ignores** it and falls back to the first tab — no error, no message — so a
  typo cannot be found by clicking. Slugs are therefore derived from the
  generated manifest via ``v2.slug`` and cross-checked here, never hand-typed.
* Annotation prose that has rotted: a reference to ``README doc block N``,
  which is not clickable from Grafana, or the mangled ``for is 0m`` clause.
  Both render perfectly and read as noise to a responder.

Every loop below asserts a non-zero inspected count: a gate that cannot see its
subject reports coverage it does not have.
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_rules  # noqa: E402
import v2  # noqa: E402

ALL_RULES = build_rules.RULES + build_rules.DETECTIONS
MANIFEST = build_rules.load_manifest()


def _stub(uid: str, **annotations) -> dict:
    """A minimal rule-shaped dict for mutation tests."""
    base = {"summary": "A summary.", "description": "A description."}
    base.update(annotations)
    return {"uid": uid, "annotations": base, "data": []}


class TestRunbookReachability(unittest.TestCase):
    """Criterion 1: every rule has a reachable runbook URL."""

    def test_every_rule_including_paused_ones_has_a_runbook_url(self):
        self.assertEqual(len(ALL_RULES), 19, "19 rules: 14 alerts + 5 detections")
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                url = rule["annotations"].get("runbook_url", "")
                self.assertTrue(
                    url.startswith(build_rules.RUNBOOK_URL_BASE + "#"),
                    f"{rule['uid']}: runbook_url is {url!r}")

    def test_the_runbook_url_is_derived_from_the_uid_not_hand_typed(self):
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                self.assertEqual(
                    rule["annotations"]["runbook_url"],
                    build_rules.RUNBOOK_URL_BASE + "#" + rule["uid"])

    def test_every_runbook_anchor_exists_in_the_runbook_source(self):
        anchors = build_rules.runbook_sections()
        self.assertGreaterEqual(len(anchors), 19, "the runbook page has sections")
        checked = 0
        for rule in ALL_RULES:
            anchor = rule["annotations"]["runbook_url"].split("#", 1)[1]
            self.assertIn(anchor, anchors, f"{rule['uid']}: no runbook section")
            checked += 1
        self.assertEqual(checked, len(ALL_RULES))

    def test_the_runbook_page_has_no_section_for_a_rule_that_does_not_exist(self):
        """Both directions: an orphan section is a rule someone deleted."""
        uids = {rule["uid"] for rule in ALL_RULES}
        orphans = sorted(set(build_rules.runbook_sections()) - uids)
        self.assertEqual(orphans, [])

    def test_every_runbook_section_covers_the_four_mandatory_behaviours(self):
        """Criterion 4. A runbook that omits the no-data or error case sends the
        responder to investigate a rule state the page does not describe."""
        sections = build_rules.runbook_sections()
        self.assertTrue(sections)
        for uid, body in sorted(sections.items()):
            with self.subTest(uid=uid):
                for heading in build_rules.RUNBOOK_REQUIRED_SECTIONS:
                    self.assertIn(heading, body, f"{uid} omits {heading!r}")

    def test_a_dangling_anchor_is_reported_by_the_gate(self):
        rules = [_stub("nope", runbook_url=build_rules.RUNBOOK_URL_BASE + "#nope")]
        violations = build_rules.navigation_violations(rules, MANIFEST)
        self.assertTrue(any("nope" in v and "runbook" in v for v in violations),
                        violations)

    def test_a_missing_runbook_url_is_reported_by_the_gate(self):
        violations = build_rules.navigation_violations([_stub("bare")], MANIFEST)
        self.assertTrue(any("runbook_url" in v for v in violations), violations)


class TestDashboardPanelContext(unittest.TestCase):
    """Criterion 2: Grafana shows dashboard/panel links for mapped rules."""

    def test_every_rule_is_mapped_to_a_dashboard_panel(self):
        self.assertEqual(sorted(build_rules.DASHBOARD_TARGETS),
                         sorted(rule["uid"] for rule in ALL_RULES))

    def test_every_rule_carries_the_grafana_panel_link_annotations_together(self):
        """``__dashboardUid__`` and ``__panelId__`` must be set together — one
        alone is ignored by Grafana."""
        checked = 0
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                ann = rule["annotations"]
                self.assertEqual(ann.get("__dashboardUid__"),
                                 build_rules.DASHBOARD_UID)
                self.assertRegex(ann.get("__panelId__", ""), r"^\d+$")
                checked += 1
        self.assertEqual(checked, 19)

    def test_every_panel_id_is_a_real_panel_in_the_generated_manifest(self):
        ids = {el["spec"]["id"] for el in MANIFEST["spec"]["elements"].values()}
        self.assertGreater(len(ids), 100, "the manifest was actually read")
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                self.assertIn(int(rule["annotations"]["__panelId__"]), ids)

    def test_the_dashboard_uid_is_the_generated_manifests_own_name(self):
        self.assertEqual(build_rules.DASHBOARD_UID,
                         MANIFEST["metadata"]["name"])

    def test_every_dashboard_path_names_a_real_top_level_tab_slug(self):
        """A wrong ``dtab`` is silently ignored, so it is gated here."""
        slugs = {v2.slug(tab["spec"]["title"])
                 for tab in MANIFEST["spec"]["layout"]["spec"]["tabs"]}
        self.assertGreaterEqual(len(slugs), 7)
        checked = 0
        for rule in ALL_RULES:
            path = rule["annotations"]["dashboard_path"]
            slug = re.search(r"[?&]dtab=([^&]+)", path).group(1)
            with self.subTest(uid=rule["uid"]):
                self.assertIn(slug, slugs)
            checked += 1
        self.assertEqual(checked, 19)

    def test_dashboard_path_and_panel_id_annotation_agree(self):
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                path = rule["annotations"]["dashboard_path"]
                view = re.search(r"[?&]viewPanel=(\d+)", path).group(1)
                self.assertEqual(view, rule["annotations"]["__panelId__"])

    def test_the_linked_panel_really_sits_under_the_linked_tab(self):
        """A right panel id under the wrong tab still renders (viewPanel is
        full-screen), but the link would take an operator to the wrong place
        when they leave full-screen view."""
        index = build_rules.panel_index(MANIFEST)
        self.assertGreater(len(index), 100)
        by_id = {}
        for (tab, _title), panel_id in index.items():
            by_id.setdefault(panel_id, set()).add(tab)
        for rule in ALL_RULES:
            with self.subTest(uid=rule["uid"]):
                path = rule["annotations"]["dashboard_path"]
                slug = re.search(r"[?&]dtab=([^&]+)", path).group(1)
                owners = {v2.slug(t)
                          for t in by_id[int(rule["annotations"]["__panelId__"])]}
                self.assertIn(slug, owners)

    def test_panel_index_refuses_an_unknown_panel_title(self):
        with self.assertRaises(KeyError):
            build_rules.resolve_target(MANIFEST, "Self-obs", "No such panel")

    def test_panel_index_refuses_an_unknown_tab(self):
        with self.assertRaises(KeyError):
            build_rules.resolve_target(MANIFEST, "Nonexistent", "Compliance devices")

    def test_a_bad_tab_slug_is_reported_by_the_gate(self):
        rules = [_stub(
            "g2o-collector-staleness",
            runbook_url=build_rules.RUNBOOK_URL_BASE + "#g2o-collector-staleness",
            __dashboardUid__=build_rules.DASHBOARD_UID,
            __panelId__="351",
            dashboard_path="/d/graph2otel?dtab=Self-observability&viewPanel=351",
        )]
        violations = build_rules.navigation_violations(rules, MANIFEST)
        self.assertTrue(any("dtab" in v for v in violations), violations)

    def test_a_nonexistent_panel_id_is_reported_by_the_gate(self):
        rules = [_stub(
            "g2o-collector-staleness",
            runbook_url=build_rules.RUNBOOK_URL_BASE + "#g2o-collector-staleness",
            __dashboardUid__=build_rules.DASHBOARD_UID,
            __panelId__="99999",
            dashboard_path="/d/graph2otel?dtab=Self-obs&viewPanel=99999",
        )]
        violations = build_rules.navigation_violations(rules, MANIFEST)
        self.assertTrue(any("99999" in v for v in violations), violations)

    def test_a_lone_dashboard_uid_without_a_panel_id_is_reported(self):
        rules = [_stub(
            "g2o-collector-staleness",
            runbook_url=build_rules.RUNBOOK_URL_BASE + "#g2o-collector-staleness",
            __dashboardUid__=build_rules.DASHBOARD_UID,
        )]
        violations = build_rules.navigation_violations(rules, MANIFEST)
        self.assertTrue(any("__panelId__" in v for v in violations), violations)

    def test_the_real_rule_set_passes_the_navigation_gate(self):
        self.assertEqual(build_rules.navigation_violations(ALL_RULES, MANIFEST), [])


class TestTheLinkedPanelIsAboutTheRulesOwnSignal(unittest.TestCase):
    """A title check proves the label survived, not that the panel still plots
    the signal the rule evaluates. A panel retitled AND re-pointed would pass a
    title-only gate."""

    def test_every_rule_links_to_a_panel_querying_one_of_its_own_signals(self):
        queries = build_rules.panel_query_text(MANIFEST)
        self.assertGreater(len(queries), 100)
        checked = 0
        for rule in ALL_RULES:
            wanted = build_rules.rule_signal_tokens(rule)
            checked += 1
            with self.subTest(uid=rule["uid"]):
                self.assertTrue(wanted, "the rule names at least one signal")
                if rule["uid"] in build_rules.SIGNAL_MATCH_WAIVERS:
                    continue
                text = queries[int(rule["annotations"]["__panelId__"])]
                self.assertTrue(
                    any(t in text or t.replace(".", "_") in text for t in wanted),
                    f"{rule['uid']}: panel plots none of {sorted(wanted)}")
        self.assertEqual(checked, 19)

    def test_a_panel_about_another_signal_is_reported(self):
        """Sabotage in the shape the coordinator warned about: a link that still
        resolves but points somewhere unrelated."""
        rule = dict(build_rules.RULES[0])
        rule["annotations"] = dict(rule["annotations"])
        index = build_rules.panel_index(MANIFEST)
        unrelated = index[("Entra", "Teams total")] \
            if ("Entra", "Teams total") in index else index[("Entra", "Groups total")]
        rule["annotations"]["__panelId__"] = str(unrelated)
        rule["annotations"]["dashboard_path"] = \
            build_rules.dashboard_path("Entra", unrelated)
        violations = build_rules.navigation_violations([rule], MANIFEST)
        self.assertTrue(any("queries none of the rule's own signals" in v
                            for v in violations), violations)

    def test_every_signal_match_waiver_carries_a_reason(self):
        self.assertTrue(build_rules.SIGNAL_MATCH_WAIVERS)
        for uid, reason in build_rules.SIGNAL_MATCH_WAIVERS.items():
            with self.subTest(uid=uid):
                self.assertTrue(reason.strip())
                self.assertIn(uid, {r["uid"] for r in ALL_RULES})

    def test_an_unused_waiver_is_reported(self):
        with mock.patch.dict(build_rules.SIGNAL_MATCH_WAIVERS,
                             {"g2o-throttle-saturation": "no longer true"}):
            violations = build_rules.navigation_violations(ALL_RULES, MANIFEST)
        self.assertTrue(any("unused" in v for v in violations), violations)

    def test_a_renamed_panel_error_lists_the_tabs_real_titles(self):
        """The break this gate produces must be fixable in one pass."""
        with self.assertRaises(KeyError) as cm:
            build_rules.resolve_target(MANIFEST, "Self-obs", "Renamed away")
        message = str(cm.exception)
        self.assertIn("Self-obs", message)
        self.assertIn("Checkpoint persist error rate", message)


class TestAnnotationLint(unittest.TestCase):
    """Criterion 3: broken or stale annotation text fails a generator test."""

    def test_the_real_rule_set_passes_the_annotation_lint(self):
        self.assertEqual(build_rules.annotation_violations(ALL_RULES), [])

    def test_the_lint_inspects_a_non_zero_number_of_annotations(self):
        self.assertGreaterEqual(build_rules.linted_annotation_count(ALL_RULES), 40)

    def test_a_repo_file_reference_is_reported(self):
        """`README.md` is not clickable from a Grafana notification."""
        rules = [_stub("x", description="See README.md for the rationale.")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("README.md" in v for v in violations), violations)

    def test_a_doc_block_reference_is_reported(self):
        rules = [_stub("x", description="See doc block 4 for the ceilings.")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("doc block" in v for v in violations), violations)

    def test_the_mangled_rule_field_clause_is_reported(self):
        """The exact shipped defect: `Even one increment is worth knowing about
        — for is 0m.` A rule field used as a bare English subject."""
        rules = [_stub("x", description=(
            "Even one increment is worth knowing about — for is 0m."))]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("for" in v for v in violations), violations)

    def test_a_backticked_rule_field_is_accepted(self):
        rules = [_stub("x", description=(
            "It fires immediately because `for` is 0m."))]
        self.assertEqual(build_rules.annotation_violations(rules), [])

    def test_an_unbackticked_no_data_state_subject_is_reported(self):
        rules = [_stub("x", description="noDataState is OK here.")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("noDataState" in v for v in violations), violations)

    def test_a_placeholder_marker_is_reported(self):
        rules = [_stub("x", description="TODO: pick a threshold.")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("TODO" in v for v in violations), violations)

    def test_an_empty_summary_is_reported(self):
        rules = [_stub("x", summary="   ")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("summary" in v for v in violations), violations)

    def test_an_unterminated_description_is_reported(self):
        rules = [_stub("x", description="This sentence never ends")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("terminator" in v for v in violations), violations)

    def test_doubled_whitespace_is_reported(self):
        rules = [_stub("x", description="Two  spaces here.")]
        violations = build_rules.annotation_violations(rules)
        self.assertTrue(any("whitespace" in v for v in violations), violations)


class TestGateWiring(unittest.TestCase):
    """The gates must run in ``--check``, not merely exist as functions."""

    def test_main_runs_the_navigation_and_annotation_gates(self):
        import inspect
        src = inspect.getsource(build_rules.main)
        self.assertIn("navigation_violations", src)
        self.assertIn("annotation_violations", src)


if __name__ == "__main__":
    unittest.main()
