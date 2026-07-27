"""Tests for the audited presentation registry (#304).

The registry owns units, titles, value mappings and thresholds, keyed by
catalog metric. Three properties matter more than any individual entry, and
the mutation tests at the bottom prove each one fails CI independently:

1. **An uncited threshold or mapping cannot be constructed.** #304's binding
   term. A colour with no stated operational meaning is an opinion wearing the
   authority of a measurement.
2. **Every panel carries explicit thresholds.** Before this change all 331
   panels omitted them, which is not "no colour" — Grafana applies a default
   green base with red at 80, so a neutral inventory count of 95 devices
   rendered red. Absence of a threshold is a *choice of Grafana's*, not ours.
3. **A counter panel says and formats a rate.** Every sum instrument is plotted
   as ``rate()``, so a count unit and a count title both describe a quantity
   the panel is not showing. ``m365.message_trace.bytes`` was the worst case:
   bytes/sec formatted as ``bytes``.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import catalog as catalog_mod  # noqa: E402
import presentation  # noqa: E402

CAT = catalog_mod.load()


class TestCitationIsMandatory(unittest.TestCase):
    """The honesty gate. An uncited threshold must be unconstructible."""

    def test_a_threshold_without_evidence_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            presentation.Thresholds([("red", 1)], evidence="")
        self.assertIn("evidence", str(cm.exception))

    def test_a_threshold_with_whitespace_evidence_is_refused(self):
        with self.assertRaises(ValueError):
            presentation.Thresholds([("red", 1)], evidence="   ")

    def test_a_mapping_without_evidence_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            presentation.Mappings({0: "Off", 1: "On"}, evidence="")
        self.assertIn("cite", str(cm.exception))

    def test_a_threshold_needs_at_least_one_coloured_step(self):
        """A threshold whose only step is the neutral base colours nothing and
        is a citation with no effect."""
        with self.assertRaises(ValueError):
            presentation.Thresholds([], evidence="because")

    def test_an_unknown_colour_is_refused(self):
        """Colours come from a closed set so a typo cannot silently produce an
        uncoloured step that reads as deliberate."""
        with self.assertRaises(ValueError):
            presentation.Thresholds([("crimson", 1)], evidence="because")

    def test_every_shipped_threshold_and_mapping_carries_evidence(self):
        seen = 0
        for name, entry in presentation.ENTRIES.items():
            for cited in (entry.thresholds, entry.mappings):
                if cited is None:
                    continue
                seen += 1
                self.assertTrue(cited.evidence.strip(), name)
        # A gate that cannot see its subject reports coverage it does not have.
        self.assertGreater(seen, 0, "registry inspected nothing")


class TestRegistryIsKeyedByTheCatalog(unittest.TestCase):
    def test_every_registry_key_is_a_cataloged_metric(self):
        self.assertGreater(len(presentation.ENTRIES), 0)
        for name in presentation.ENTRIES:
            CAT.metric(name)  # KeyError if the metric no longer exists

    def test_the_registry_reports_an_entry_for_an_unknown_metric(self):
        found = presentation.violations(
            CAT, {"entra.users.total"},
            entries={"entra.does.not.exist": presentation.Presentation(unit="s")})
        self.assertTrue(any("entra.does.not.exist" in v for v in found), found)

    def test_the_registry_reports_an_entry_for_an_unpanelled_metric(self):
        """A registry entry for a metric on no panel is dead weight that reads
        as coverage — the same failure mode as a stale coverage waiver."""
        found = presentation.violations(
            CAT, set(),
            entries={"entra.users.total": presentation.Presentation(unit="s")})
        self.assertTrue(any("entra.users.total" in v for v in found), found)

    def test_the_shipped_registry_has_no_violations(self):
        builder, _, _ = build_dashboard.build_all(CAT)
        self.assertEqual(presentation.violations(CAT, builder.covered), [])

    def test_every_cited_mapping_and_threshold_reaches_a_panel(self):
        """Being panelled is not the same as being applied.

        Four thresholds were cited and only one reached the manifest: a
        hand-written raw() panel needs an explicit ``about=`` to know which
        metric it is about, and three call sites did not pass it. Nothing
        failed — the citation existed, the metric was covered, and the colour
        simply was not there. Found by reading the published dashboard back off
        a live stack, which is the only reason it was found at all.
        """
        self.assertEqual(presentation.unapplied(build_dashboard.render(CAT)), [])

    def test_a_cited_entry_that_reaches_no_panel_is_reported(self):
        man = build_dashboard.render(CAT)
        for element in man["spec"]["elements"].values():
            viz = element["spec"].get("vizConfig", {}).get("spec", {})
            defaults = viz.get("fieldConfig", {}).get("defaults", {})
            if (defaults.get("thresholds") or {}).get("steps", [{}]).__len__() > 1:
                # Strip the citation the way a dropped about= would.
                element["spec"]["description"] = ""
        found = presentation.unapplied(man)
        self.assertTrue(found, "unapplied entries went unreported")


class TestRateHonesty(unittest.TestCase):
    def test_a_byte_counter_rate_is_formatted_as_bytes_per_second(self):
        self.assertEqual(presentation.rate_unit("By"), "Bps")

    def test_a_counted_thing_rate_is_formatted_as_counts_per_second(self):
        self.assertEqual(presentation.rate_unit("{record}"), "cps")
        self.assertEqual(presentation.rate_unit("1"), "cps")

    def test_a_derived_counter_title_says_rate_and_drops_the_count_word(self):
        self.assertEqual(presentation.rate_title("Signin count"), "Signin rate")
        self.assertEqual(presentation.rate_title("Message trace messages"),
                         "Message trace messages rate")

    def test_a_title_that_already_says_rate_is_left_alone(self):
        self.assertEqual(presentation.rate_title("Scrape error rate"),
                         "Scrape error rate")

    def test_a_histogram_quantile_is_not_a_rate(self):
        """``histogram_quantile(0.95, sum by (le) (rate(x_bucket[5m])))``
        contains ``rate(`` but its result is in the bucket's unit — seconds,
        not seconds per second. Treating it as a rate would relabel every
        latency panel."""
        self.assertFalse(presentation.plots_a_rate(
            "histogram_quantile(0.95, sum by (le) (rate(x_bucket[$__rate_interval])))"))
        self.assertTrue(presentation.plots_a_rate("sum(rate(x_total[$__rate_interval]))"))


class TestTheGeneratedManifest(unittest.TestCase):
    """Assertions against the shipped artifact, not against the builder."""

    @classmethod
    def setUpClass(cls):
        cls.man = build_dashboard.render(CAT)
        cls.panels = presentation.panel_presentation(cls.man)

    def test_the_gate_saw_every_panel(self):
        self.assertGreater(len(self.panels), 300, len(self.panels))

    def test_no_panel_inherits_grafana_default_thresholds(self):
        """Omitting thresholds is not neutral: Grafana supplies a green base and
        a red step at 80, so an inventory count of 95 devices renders red."""
        missing = [p["title"] for p in self.panels if p["thresholds"] is None]
        self.assertEqual(missing, [])

    def test_a_panel_with_no_cited_threshold_is_neutral(self):
        """The overwhelming majority of the estate is inventory, and inventory
        gets no verdict. Only a panel whose description carries the citation may
        colour anything."""
        neutral = 0
        for p in self.panels:
            if presentation.CITATION_PREFIX in p["description"]:
                continue
            neutral += 1
            self.assertEqual(
                [s.get("color") for s in p["thresholds"]["steps"]],
                [presentation.NEUTRAL_COLOR], p["title"])
        self.assertGreater(neutral, 200, neutral)

    def test_only_a_handful_of_panels_are_coloured_at_all(self):
        """Restraint is the deliverable, not a side effect. A registry that
        coloured most of the estate would have stopped meaning anything."""
        coloured = [p["title"] for p in self.panels
                    if len((p["thresholds"] or {}).get("steps", [])) > 1]
        self.assertGreater(len(coloured), 0)
        self.assertLess(len(coloured), 20, coloured)

    def test_every_rate_panel_is_formatted_per_second(self):
        wrong = [(p["title"], p["unit"]) for p in self.panels
                 if p["rate"] and p["unit"] not in presentation.PER_SECOND_UNITS]
        self.assertEqual(wrong, [])

    def test_every_rate_panel_title_says_rate(self):
        wrong = [p["title"] for p in self.panels
                 if p["rate"] and not presentation.title_says_rate(p["title"])]
        self.assertEqual(wrong, [])

    def test_the_gate_saw_a_realistic_number_of_rate_panels(self):
        rated = [p for p in self.panels if p["rate"]]
        self.assertGreater(len(rated), 25, len(rated))

    def test_latency_panels_keep_their_time_unit(self):
        """The histogram exclusion, asserted on the artifact rather than in
        isolation: a p95 latency panel must still read in seconds."""
        seen = 0
        for p in self.panels:
            if not any("histogram_quantile(" in e for e in p["exprs"]):
                continue
            seen += 1
            self.assertNotIn(p["unit"], presentation.PER_SECOND_UNITS, p["title"])
        self.assertGreater(seen, 5, seen)

    def test_cited_mappings_reach_the_manifest(self):
        mapped = [p for p in self.panels if p["mappings"]]
        self.assertGreater(len(mapped), 5, len(mapped))


class TestMutation(unittest.TestCase):
    """#304's failure modes, each proven to fail the build independently."""

    def setUp(self):
        self.man = build_dashboard.render(CAT)
        self.panels = presentation.panel_presentation(self.man)

    def test_a_panel_with_NO_THRESHOLDS_fails_the_manifest_gate(self):
        for element in self.man["spec"]["elements"].values():
            viz = element["spec"].get("vizConfig", {}).get("spec", {})
            defaults = viz.get("fieldConfig", {}).get("defaults")
            if defaults and "thresholds" in defaults:
                del defaults["thresholds"]
                break
        else:
            self.fail("no panel with thresholds found to mutate")
        found = presentation.manifest_violations(self.man)
        self.assertTrue(any("threshold" in v for v in found), found)

    def test_a_RATE_PANEL_WITH_A_COUNT_UNIT_fails_the_manifest_gate(self):
        for element in self.man["spec"]["elements"].values():
            viz = element["spec"].get("vizConfig", {}).get("spec", {})
            queries = element["spec"].get("data", {}).get("spec", {}).get("queries", [])
            exprs = [q["spec"]["query"]["spec"].get("expr", "") for q in queries]
            if any(presentation.plots_a_rate(e) for e in exprs):
                viz["fieldConfig"]["defaults"]["unit"] = "short"
                break
        else:
            self.fail("no rate panel found to mutate")
        found = presentation.manifest_violations(self.man)
        self.assertTrue(any("per second" in v for v in found), found)

    def test_a_RATE_PANEL_TITLED_AS_A_COUNT_fails_the_manifest_gate(self):
        for name, element in self.man["spec"]["elements"].items():
            queries = element["spec"].get("data", {}).get("spec", {}).get("queries", [])
            exprs = [q["spec"]["query"]["spec"].get("expr", "") for q in queries]
            if any(presentation.plots_a_rate(e) for e in exprs):
                element["spec"]["title"] = "Total widgets"
                break
        else:
            self.fail("no rate panel found to mutate")
        found = presentation.manifest_violations(self.man)
        self.assertTrue(any("Total widgets" in v for v in found), found)

    def test_an_ALARM_COLOURED_NEUTRAL_INVENTORY_PANEL_fails_the_manifest_gate(self):
        for element in self.man["spec"]["elements"].values():
            viz = element["spec"].get("vizConfig", {}).get("spec", {})
            defaults = viz.get("fieldConfig", {}).get("defaults", {})
            steps = (defaults.get("thresholds") or {}).get("steps")
            if steps and len(steps) == 1:
                steps.append({"color": "red", "value": 80})
                break
        else:
            self.fail("no neutral panel found to mutate")
        found = presentation.manifest_violations(self.man)
        self.assertTrue(any("uncited" in v for v in found), found)


if __name__ == "__main__":
    unittest.main()
