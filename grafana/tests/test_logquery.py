"""Tests for the typed LogQL filter and group-key contract (#306).

The mutation tests at the bottom are the point of this file. #306's binding terms
require proof that a misspelled **filter** key and a misspelled **group** key each
fail CI *independently* — because before this change neither did. LogQL has no
schema, so a typo in an attribute name is a perfectly valid pipeline stage that
matches nothing, silently, forever. That is the same class of bug as #90, #143,
#158 and #160, and the generator's own docstring used to claim it was impossible.
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_dashboard  # noqa: E402
import catalog as catalog_mod  # noqa: E402
import logquery  # noqa: E402
from logquery import Raw, f  # noqa: E402

CAT = catalog_mod.load()
EVENT = "entra.signin"


class TestTypedFilters(unittest.TestCase):
    def test_each_operator_renders_the_logql_form(self):
        self.assertEqual(f("a", "eq", "1").render(), "a=`1`")
        self.assertEqual(f("a", "ne", "1").render(), "a!=`1`")
        self.assertEqual(f("a", "re", "x|y").render(), "a=~`x|y`")
        self.assertEqual(f("a", "nre", "x|y").render(), "a!~`x|y`")

    def test_an_unknown_operator_is_refused(self):
        """Named operators exist so a board module cannot smuggle `==` through as
        an opaque string."""
        with self.assertRaises(ValueError):
            f("a", "equals", "1")

    def test_a_bare_string_filter_is_refused(self):
        """Accepting one would silently reinstate the unvalidated path this whole
        contract exists to remove."""
        with self.assertRaises(TypeError):
            logquery.render_filters(["status_error_code!=`0`"])

    def test_typed_filters_render_in_order(self):
        self.assertEqual(
            logquery.render_filters([f("a", "eq", "1"), f("b", "ne", "2")]),
            ["a=`1`", "b!=`2`"])


class TestRawEscape(unittest.TestCase):
    """The escape hatch is deliberately expensive to use.

    A typed-only model would block legitimate LogQL (regex chains, line_format,
    unwrap). The rejected alternative — a raw string plus a key extractor — makes
    the extractor a partial LogQL parser, which either misses constructs and
    validates nothing, or rejects valid queries.
    """

    def test_a_raw_filter_renders_its_text_verbatim(self):
        raw = Raw("line_format `{{.user}}`", keys=["user"], reason="formatting")
        self.assertEqual(raw.render(), "line_format `{{.user}}`")

    def test_a_raw_filter_must_declare_the_keys_it_references(self):
        with self.assertRaises(ValueError):
            Raw("line_format `x`", keys=[], reason="because")

    def test_a_raw_filter_must_state_a_reason(self):
        """An escape hatch with no stated reason is an unvalidated string with
        extra steps — the same rule as the coverage waivers."""
        with self.assertRaises(ValueError):
            Raw("line_format `x`", keys=["a"], reason="   ")

    def test_declared_raw_keys_are_validated_like_a_typed_filter(self):
        bad = Raw("line_format `x`", keys=["nonexistent_attr"], reason="r")
        found = logquery.violations(CAT, EVENT, filters=[bad])
        self.assertTrue(any("nonexistent_attr" in v for v in found), found)


class TestFrameworkOverlay(unittest.TestCase):
    """tenant_id and ingest_transport are stamped at the emitter boundary, so
    they are on every record even when a per-event catalog row omits them."""

    def test_tenant_id_is_permitted_even_though_the_event_row_omits_it(self):
        self.assertNotIn("tenant_id", CAT.log(EVENT).keys)
        self.assertIn("tenant_id", logquery.permitted_keys(CAT, EVENT))
        self.assertEqual(
            logquery.violations(CAT, EVENT, filters=[f("tenant_id", "eq", "x")]),
            [])

    def test_ingest_transport_is_permitted(self):
        self.assertIn("ingest_transport", logquery.permitted_keys(CAT, EVENT))

    def test_event_name_is_permitted(self):
        """#305: it is the OTEL LogRecord EventName, stamped on every emitted
        record, and every query this package builds already filters on it. Its
        absence from the overlay meant the one grouping that makes a cross-event
        query readable — ``by=["event_name"]`` — was reported as an attribute the
        event does not carry."""
        self.assertNotIn("event_name", CAT.log(EVENT).keys)
        self.assertEqual(logquery.violations(CAT, EVENT, by=["event_name"]), [])

    def test_the_overlay_is_exactly_the_emitter_boundary_keys(self):
        """It is an overlay for emitter-boundary attributes, not a general
        escape from catalog validation."""
        self.assertEqual(set(logquery.FRAMEWORK_KEYS),
                         {"tenant_id", "ingest_transport", "event_name"})


class TestValidationAgainstTheCatalog(unittest.TestCase):
    def test_a_real_attribute_passes(self):
        self.assertEqual(
            logquery.violations(CAT, EVENT,
                                filters=[f("status_error_code", "ne", "0")],
                                by=["status_error_code"]),
            [])

    def test_a_misspelled_filter_key_is_reported(self):
        found = logquery.violations(
            CAT, EVENT, filters=[f("status_erorr_code", "ne", "0")])
        self.assertEqual(len(found), 1)
        self.assertIn("status_erorr_code", found[0])
        self.assertIn("zero rows silently", found[0])

    def test_a_misspelled_group_key_is_reported(self):
        found = logquery.violations(CAT, EVENT, by=["risk_levl"])
        self.assertEqual(len(found), 1)
        self.assertIn("risk_levl", found[0])

    def test_filter_and_group_violations_are_reported_together(self):
        """One build reports all of them rather than stopping at the first."""
        found = logquery.violations(CAT, EVENT,
                                    filters=[f("nope_a", "eq", "1")],
                                    by=["nope_b"])
        self.assertEqual(len(found), 2)


class TestTheEstateUsesOnlyValidatedQueries(unittest.TestCase):
    """Every shipped log panel, across every board, checked against the catalog.

    This is the assertion that would have caught #143/#158/#160 at build time.
    """

    def test_every_shipped_log_panel_filter_and_group_key_is_cataloged(self):
        builder, _, _ = build_dashboard.build_all(CAT)
        self.assertEqual(builder.violations, [])

    def test_the_gate_saw_a_realistic_number_of_log_panels(self):
        """A gate that cannot see its subject reports coverage it does not have
        (#139/#100). The estate ships 23 log panels."""
        import importlib  # noqa: PLC0415

        seen = 0
        for mod_name in build_dashboard.BOARDS:
            mod = importlib.import_module(mod_name)
            seen += len(getattr(mod, "LOGS", ()))
        self.assertGreaterEqual(seen, 20, seen)


class TestMutation(unittest.TestCase):
    """#306's binding requirement: prove each failure mode independently.

    Not a hypothetical — these run the real builder against a real board module
    whose declaration has been mutated, so they exercise the wiring, not just
    ``logquery.violations`` in isolation.
    """

    def _build_with_logs(self, logs):
        from types import SimpleNamespace  # noqa: PLC0415

        from boards import common  # noqa: PLC0415
        from builder import Builder  # noqa: PLC0415

        module = SimpleNamespace(
            __name__="boards.mutant",
            DOMAIN="Mutant",
            DESCRIPTION="d",
            AVAILABILITY_PATTERN=r"entra\..+",
            SECTIONS=[("S", ["entra.users.total"])],
            LOGS=logs,
        )
        builder = Builder(name="g", title="t", description="d", tags=[],
                          catalog=CAT)
        common.add(builder, module)
        return builder

    def test_a_correct_declaration_produces_no_violations(self):
        builder = self._build_with_logs([
            {"kind": "rate", "event": EVENT, "title": "T",
             "filters": [f("status_error_code", "ne", "0")],
             "by": ["status_error_code"]},
        ])
        self.assertEqual(builder.violations, [])

    def test_a_MISSPELLED_FILTER_KEY_fails_the_build(self):
        builder = self._build_with_logs([
            {"kind": "rate", "event": EVENT, "title": "T",
             "filters": [f("status_erorr_code", "ne", "0")],
             "by": ["status_error_code"]},
        ])
        self.assertTrue(any("status_erorr_code" in v for v in builder.violations),
                        builder.violations)

    def test_a_MISSPELLED_GROUP_KEY_fails_the_build(self):
        builder = self._build_with_logs([
            {"kind": "rate", "event": EVENT, "title": "T",
             "filters": [f("status_error_code", "ne", "0")],
             "by": ["status_erorr_code"]},
        ])
        self.assertTrue(any("status_erorr_code" in v for v in builder.violations),
                        builder.violations)


if __name__ == "__main__":
    unittest.main()
