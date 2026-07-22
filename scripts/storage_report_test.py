#!/usr/bin/env python3
"""Tests for storage-report.py's cost model.

Run:  python3 scripts/storage_report_test.py

Covers the pure functions only — everything that talks to `az` is out of scope. The
point of these is #228: the append-rate model used to be a pure guess anchored on a
hardcoded 7300 B/append, which came out 4.9x low once the Defender advanced-hunting
tables started streaming. The measured path must dominate, the modelled path must
survive as an honest fallback, and the two must agree when fed consistent inputs.
"""
from __future__ import annotations
import importlib.util
import os
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "storage_report", os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage-report.py"))
assert _SPEC and _SPEC.loader
sr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sr)

GIB = 1024 ** 3


def pricing(**over) -> dict:
    p = {
        "storage": 0.0145,
        "write_10k": 0.0447,
        "read_10k": 0.0036,
        "avg_append": 7300,
        "actual_retention": 1.0,
        "model_retention": 1.0,
        "volume_scale": 1.0,
        "per_container": {},
        "measured": None,
        "total_bytes": 0,
    }
    p.update(over)
    return p


class TestModelledAppendRate(unittest.TestCase):
    """The fallback path: back-solve appends from resident bytes."""

    def test_back_solves_from_bytes(self):
        p = pricing(avg_append=7300, actual_retention=2.0)
        # 7300 * 2 bytes resident == exactly 1 append/day held for 2 days
        self.assertAlmostEqual(sr.append_rate_per_day(7300 * 2, p), 1.0)

    def test_zero_retention_is_not_a_division_error(self):
        self.assertEqual(sr.append_rate_per_day(1000, pricing(actual_retention=0)), 0.0)


class TestMeasuredAppendRate(unittest.TestCase):
    """The measured path: a hard account-wide op count, allocated by byte share."""

    def test_allocates_measured_total_by_byte_share(self):
        p = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=1000)
        self.assertAlmostEqual(sr.append_rate_per_day(250, p), 84139.0 * 0.25)
        self.assertAlmostEqual(sr.append_rate_per_day(750, p), 84139.0 * 0.75)

    def test_shares_sum_to_the_measured_total(self):
        p = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=1000)
        parts = [sr.append_rate_per_day(b, p) for b in (500, 300, 200)]
        self.assertAlmostEqual(sum(parts), 84139.0)

    def test_measured_ignores_the_avg_append_constant_entirely(self):
        """The 7300 constant being wrong must no longer be able to move the op count."""
        base = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=1000)
        bad = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=1000, avg_append=1)
        self.assertEqual(sr.append_rate_per_day(500, base), sr.append_rate_per_day(500, bad))

    def test_empty_account_does_not_divide_by_zero(self):
        p = pricing(measured={"append_ops_per_day": 100.0}, total_bytes=0)
        self.assertEqual(sr.append_rate_per_day(0, p), 0.0)


class TestCalibration(unittest.TestCase):
    """avg_append is derived from Ingress/AppendBlock, never assumed."""

    def test_derives_the_live_measured_blend(self):
        # 2026-07-21 on graph2otelm7kni: 2994.5 MB ingress over 84,139 appends
        got = sr.calibrated_avg_append(2994.5e6, 84139)
        self.assertAlmostEqual(got, 35590, delta=10)

    def test_none_when_no_appends_observed(self):
        self.assertIsNone(sr.calibrated_avg_append(1234.0, 0))

    def test_none_when_no_ingress_observed(self):
        self.assertIsNone(sr.calibrated_avg_append(0.0, 500))


class TestCostRow(unittest.TestCase):
    def test_measured_steady_state_reproduces_resident_bytes(self):
        """rate x avg_append x retention must round-trip back to what's on disk."""
        resident = 3 * GIB
        p = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=resident,
                    avg_append=resident / 84139.0, actual_retention=1.0, model_retention=1.0)
        _, _, _, modeled = sr.cost_row(resident, 1.0, p)
        self.assertAlmostEqual(modeled, resident, delta=resident * 1e-9)

    def test_write_cost_matches_the_live_bill(self):
        """84,139 appends/day at £0.0447/10k must price to the observed ~£11.45/mo."""
        p = pricing(measured={"append_ops_per_day": 84139.0}, total_bytes=1000)
        _, write, _, _ = sr.cost_row(1000, 1.0, p)
        self.assertAlmostEqual(write, 11.45, delta=0.05)

    def test_scale_moves_writes_and_storage_together(self):
        p = pricing(measured={"append_ops_per_day": 1000.0}, total_bytes=1000)
        s1, w1, _, _ = sr.cost_row(1000, 1.0, p)
        s2, w2, _, _ = sr.cost_row(1000, 2.0, p)
        self.assertAlmostEqual(w2, w1 * 2)
        self.assertAlmostEqual(s2, s1 * 2)

    def test_model_retention_moves_storage_but_not_writes(self):
        """The headline lesson: retention is nearly free, volume is the bill."""
        base = pricing(measured={"append_ops_per_day": 1000.0}, total_bytes=1000,
                       actual_retention=1.0, model_retention=1.0)
        long = pricing(measured={"append_ops_per_day": 1000.0}, total_bytes=1000,
                       actual_retention=1.0, model_retention=7.0)
        s1, w1, _, _ = sr.cost_row(1000, 1.0, base)
        s7, w7, _, _ = sr.cost_row(1000, 1.0, long)
        self.assertAlmostEqual(w7, w1)
        self.assertAlmostEqual(s7, s1 * 7)


class TestOtherOpsCost(unittest.TestCase):
    """#228: listing is billed at the write rate and was silently excluded."""

    def test_list_ops_billed_at_the_write_rate(self):
        p = pricing()
        cost = sr.other_ops_cost({"list_ops_per_day": 9381.0, "read_ops_per_day": 0.0}, p)
        self.assertAlmostEqual(cost, (9381.0 * sr.DAYS_PER_MONTH / 10_000) * 0.0447, places=6)

    def test_reads_are_cheaper_than_writes(self):
        p = pricing()
        lists = sr.other_ops_cost({"list_ops_per_day": 1000.0, "read_ops_per_day": 0.0}, p)
        reads = sr.other_ops_cost({"list_ops_per_day": 0.0, "read_ops_per_day": 1000.0}, p)
        self.assertLess(reads, lists)

    def test_no_metrics_means_no_charge(self):
        self.assertEqual(sr.other_ops_cost(None, pricing()), 0.0)


class TestMetricParsing(unittest.TestCase):
    """Parse the `az monitor metrics list` envelope without an Azure round-trip."""

    ENVELOPE = {
        "value": [{
            "name": {"value": "Transactions"},
            "timeseries": [
                {"metadatavalues": [{"name": {"value": "apiname"}, "value": "AppendBlock"}],
                 "data": [{"timeStamp": "2026-07-20T00:00:00Z", "total": 75822.0},
                          {"timeStamp": "2026-07-21T00:00:00Z", "total": 84139.0}]},
                {"metadatavalues": [{"name": {"value": "apiname"}, "value": "ListBlobs"}],
                 "data": [{"timeStamp": "2026-07-20T00:00:00Z", "total": 9066.0},
                          {"timeStamp": "2026-07-21T00:00:00Z", "total": 9381.0}]},
            ],
        }]
    }

    def test_sums_by_api_name(self):
        got = sr.parse_transactions(self.ENVELOPE)
        self.assertAlmostEqual(got["AppendBlock"], 75822.0 + 84139.0)
        self.assertAlmostEqual(got["ListBlobs"], 9066.0 + 9381.0)

    def test_missing_totals_are_skipped_not_zeroed(self):
        env = {"value": [{"timeseries": [
            {"metadatavalues": [{"name": {"value": "apiname"}, "value": "AppendBlock"}],
             "data": [{"timeStamp": "2026-07-20T00:00:00Z"},
                      {"timeStamp": "2026-07-21T00:00:00Z", "total": 5.0}]}]}]}
        self.assertAlmostEqual(sr.parse_transactions(env)["AppendBlock"], 5.0)

    def test_last_bucket_picks_the_most_recent_whole_day(self):
        self.assertAlmostEqual(sr.last_bucket(self.ENVELOPE, "AppendBlock"), 84139.0)
        self.assertAlmostEqual(sr.last_bucket(self.ENVELOPE, "ListBlobs"), 9381.0)

    def test_last_bucket_none_for_an_absent_api(self):
        self.assertIsNone(sr.last_bucket(self.ENVELOPE, "DeleteBlob"))

    def test_last_bucket_ignores_ordering_in_the_payload(self):
        env = {"value": [{"timeseries": [
            {"metadatavalues": [{"name": {"value": "apiname"}, "value": "AppendBlock"}],
             "data": [{"timeStamp": "2026-07-21T00:00:00Z", "total": 84139.0},
                      {"timeStamp": "2026-07-19T00:00:00Z", "total": 61317.0}]}]}]}
        self.assertAlmostEqual(sr.last_bucket(env, "AppendBlock"), 84139.0)

    def test_empty_envelope_is_empty_dict(self):
        self.assertEqual(sr.parse_transactions({"value": []}), {})

    def test_scalar_totals_series_sums(self):
        env = {"value": [{"timeseries": [{"metadatavalues": [], "data": [
            {"timeStamp": "2026-07-20T00:00:00Z", "total": 1823.4e6},
            {"timeStamp": "2026-07-21T00:00:00Z", "total": 2994.5e6}]}]}]}
        self.assertAlmostEqual(sr.parse_scalar_total(env), 1823.4e6 + 2994.5e6)

    def test_scalar_total_of_empty_is_zero(self):
        self.assertEqual(sr.parse_scalar_total({"value": []}), 0.0)


class TestFullDayWindow(unittest.TestCase):
    """Only whole UTC days may be averaged — a part-day drags the rate down."""

    def test_window_excludes_today(self):
        start, end = sr.metric_window(days=3, now_epoch=1784678400.0)  # 2026-07-22T00:00Z
        self.assertEqual(end, "2026-07-22T00:00:00Z")
        self.assertEqual(start, "2026-07-19T00:00:00Z")

    def test_partial_day_is_truncated_away(self):
        # 2026-07-22T10:00Z — the window must still stop at midnight
        start, end = sr.metric_window(days=1, now_epoch=1784678400.0 + 36000)
        self.assertEqual(end, "2026-07-22T00:00:00Z")
        self.assertEqual(start, "2026-07-21T00:00:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
