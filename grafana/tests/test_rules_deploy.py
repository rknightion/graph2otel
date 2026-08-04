"""Tests for the App Platform rule deployer and its read-back (#294).

Standard-library ``unittest`` only. Every gcx interaction is faked, so these run
offline in CI; the live behaviours they encode were measured on 2026-07-27 and
are recorded on #294.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA = os.path.dirname(HERE)
sys.path.insert(0, GRAFANA)

import build_rules  # noqa: E402
import rules_deploy  # noqa: E402


def projected(uid="g2o-collector-staleness", group=None, index=6):
    rule = next(r for r in build_rules.RULES if r["uid"] == uid)
    return build_rules.to_app_platform(
        rule, group or build_rules.ALERT_GROUP, build_rules.GROUP_INTERVAL,
        index)


def as_live(manifest, **spec_overrides):
    """A live read-back of a manifest, with the server's own normalizations."""
    live = json.loads(json.dumps(manifest))
    if live["spec"].get("paused") is False:
        del live["spec"]["paused"]          # measured: server omits paused=false
    live["spec"].update(spec_overrides)
    return live


class TestReadsTheRuleDefinitionKindNotTheFiringInstances(unittest.TestCase):
    def test_kind_is_fully_qualified(self):
        """The short `alertrules` selector resolves to `alerting.ext.grafana.app`,
        which is the FIRING-INSTANCE view — it returns spec.alerts[] with live
        alert state and no rule definition. Comparing source against that would
        report nonsense rather than an error."""
        self.assertEqual(rules_deploy.RULE_KIND,
                         "alertrules.v0alpha1.rules.alerting.grafana.app")
        self.assertIn("rules.alerting.grafana.app", rules_deploy.RULE_KIND)
        self.assertNotIn("ext.grafana.app", rules_deploy.RULE_KIND)


class TestComparison(unittest.TestCase):
    def test_an_identical_rule_reports_no_difference(self):
        m = projected()
        self.assertEqual(rules_deploy.compare(m, as_live(m)), [])

    def test_absent_paused_is_treated_as_false(self):
        """Measured: the server drops `paused: false`. Without this the deployer
        would report all 7 enabled rules as permanently divergent, and a real
        difference would be lost in the noise."""
        m = projected()
        self.assertFalse(m["spec"]["paused"])
        live = as_live(m)
        self.assertNotIn("paused", live["spec"])
        self.assertEqual(rules_deploy.compare(m, live), [])

    def test_a_rule_that_should_be_paused_but_is_live_is_caught(self):
        """The normalization above must not become a blind spot: `paused: true`
        IS returned by the server, so an un-paused detection is a difference."""
        paused = next(r for r in build_rules.DETECTIONS)
        m = build_rules.to_app_platform(
            paused, build_rules.DETECTION_GROUP, build_rules.GROUP_INTERVAL, 0)
        self.assertTrue(m["spec"]["paused"])
        live = as_live(m)
        del live["spec"]["paused"]
        diffs = rules_deploy.compare(m, live)
        self.assertTrue(any("paused" in d for d in diffs), diffs)

    def test_the_exact_drift_this_issue_exists_to_close_is_caught(self):
        """#298's fix was committed 2026-07-26 and the live rule still read
        `execErrState: Ok` on 2026-07-27. A count gate can never see this: the
        rule is present, and only its content is stale."""
        m = projected()
        self.assertEqual(m["spec"]["execErrState"], "Error")
        diffs = rules_deploy.compare(m, as_live(m, execErrState="Ok"))
        self.assertEqual(len(diffs), 1)
        self.assertIn("execErrState", diffs[0])

    def test_a_stale_threshold_inside_the_expression_map_is_caught(self):
        """#299 changed a threshold from a fixed 3600 seconds to a 3x ratio. The
        change is buried in expressions.C.model.conditions, so a comparison that
        only checked top-level fields would call the pre-#299 live rule a match."""
        m = projected()
        live = as_live(m)
        stale = json.loads(json.dumps(live["spec"]["expressions"]))
        stale["C"]["model"]["conditions"][0]["evaluator"]["params"] = [3600]
        diffs = rules_deploy.compare(m, as_live(m, expressions=stale))
        self.assertTrue(any("expressions" in d for d in diffs), diffs)

    def test_a_missing_runbook_annotation_is_caught(self):
        """#307 added runbook_url and dashboard links to all 19 rules and none of
        them reached production."""
        m = projected()
        thin = {k: v for k, v in m["spec"]["annotations"].items()
                if k != "runbook_url"}
        diffs = rules_deploy.compare(m, as_live(m, annotations=thin))
        self.assertTrue(any("annotations" in d for d in diffs), diffs)

    def test_group_membership_is_reported_separately_from_content(self):
        """Group is not content: the App Platform API cannot place a rule it
        created into a named group (see rules_deploy.UNGROUPABLE), so a
        correctly-deployed new rule is legitimately un-grouped. Folding that into
        content drift would make every fresh deploy look broken; ignoring it
        would hide a rule sitting in the wrong group. It gets its own signal."""
        m = projected()
        live = as_live(m)
        self.assertEqual(rules_deploy.group_of(live), build_rules.ALERT_GROUP)
        del live["metadata"]["labels"]["grafana.com/group"]
        self.assertIsNone(rules_deploy.group_of(live))
        self.assertEqual(rules_deploy.compare(m, live), [])

    def test_an_ungrouped_rule_is_named_in_the_receipt_and_is_not_a_match(self):
        def fake_fetch(context, names):
            out = {}
            for index, rule in enumerate(build_rules.RULES):
                live = as_live(build_rules.to_app_platform(
                    rule, build_rules.ALERT_GROUP,
                    build_rules.GROUP_INTERVAL, index))
                if rule["uid"] == "g2o-record-integrity-loss":
                    del live["metadata"]["labels"]["grafana.com/group"]
                out[rule["uid"]] = live
            return out

        with mock.patch.object(rules_deploy, "fetch_live", fake_fetch):
            receipt = rules_deploy.readback("ctx", include_detections=False)
        self.assertEqual(receipt["status"], "matched_content_ungrouped")
        self.assertEqual(receipt["ungrouped"], ["g2o-record-integrity-loss"])
        self.assertEqual(receipt["divergent"], {})
        self.assertEqual(receipt["absent"], [])


class TestReadbackReceipt(unittest.TestCase):
    def test_absent_rules_are_named_individually(self):
        """#294's own diagnostic requirement: the live group holds 12 rules
        against the repository's 14, and identifying WHICH two are missing is
        part of the issue. A count would not."""
        missing = {"g2o-record-integrity-loss", "g2o-payload-type-mismatch"}

        def fake_fetch(context, names):
            out = {}
            for index, rule in enumerate(build_rules.RULES):
                if rule["uid"] in missing:
                    continue
                out[rule["uid"]] = as_live(build_rules.to_app_platform(
                    rule, build_rules.ALERT_GROUP,
                    build_rules.GROUP_INTERVAL, index))
            for index, rule in enumerate(build_rules.DETECTIONS):
                out[rule["uid"]] = as_live(build_rules.to_app_platform(
                    rule, build_rules.DETECTION_GROUP,
                    build_rules.GROUP_INTERVAL, index))
            return out

        with mock.patch.object(rules_deploy, "fetch_live", fake_fetch):
            receipt = rules_deploy.readback("ctx")
        self.assertEqual(receipt["status"], "drifted")
        self.assertEqual(set(receipt["absent"]), missing)
        self.assertEqual(receipt["divergent"], {})
        self.assertEqual(receipt["compared"],
                         len(build_rules.RULES) + len(build_rules.DETECTIONS))

    def test_a_fully_matching_stack_is_reported_matched(self):
        def fake_fetch(context, names):
            out = {}
            for index, rule in enumerate(build_rules.RULES):
                out[rule["uid"]] = as_live(build_rules.to_app_platform(
                    rule, build_rules.ALERT_GROUP,
                    build_rules.GROUP_INTERVAL, index))
            for index, rule in enumerate(build_rules.DETECTIONS):
                out[rule["uid"]] = as_live(build_rules.to_app_platform(
                    rule, build_rules.DETECTION_GROUP,
                    build_rules.GROUP_INTERVAL, index))
            return out

        with mock.patch.object(rules_deploy, "fetch_live", fake_fetch):
            receipt = rules_deploy.readback("ctx")
        self.assertEqual(receipt["status"], "matched")
        self.assertEqual(receipt["absent"], [])
        self.assertEqual(len(receipt["matching"]),
                         len(build_rules.RULES) + len(build_rules.DETECTIONS))


class TestFolderResolution(unittest.TestCase):
    def test_a_title_resolves_to_its_uid(self):
        folders = [{"metadata": {"name": "abc123"}, "spec": {"title": "graph2otel"}},
                   {"metadata": {"name": "zzz"}, "spec": {"title": "other"}}]
        self.assertEqual(
            rules_deploy.resolve_folder_uid(folders, "graph2otel"), "abc123")

    def test_a_missing_folder_is_an_error_naming_what_exists(self):
        folders = [{"metadata": {"name": "zzz"}, "spec": {"title": "other"}}]
        with self.assertRaises(rules_deploy.DeployError) as caught:
            rules_deploy.resolve_folder_uid(folders, "graph2otel")
        self.assertIn("other", str(caught.exception))

    def test_an_ambiguous_title_refuses_to_guess(self):
        """Filing 19 rules into the wrong one of two identically-titled folders
        is worse than not deploying."""
        folders = [{"metadata": {"name": "a"}, "spec": {"title": "graph2otel"}},
                   {"metadata": {"name": "b"}, "spec": {"title": "graph2otel"}}]
        with self.assertRaises(rules_deploy.DeployError):
            rules_deploy.resolve_folder_uid(folders, "graph2otel")


class TestFolderSubstitution(unittest.TestCase):
    def test_the_token_is_replaced(self):
        manifest = build_rules.render_app_platform()[
            "g2o-collector-staleness.yaml"]
        self.assertIn(build_rules.FOLDER_TOKEN.encode(), manifest)
        out = rules_deploy.substitute_folder(manifest, "efs83nfy641s0c")
        self.assertIn(b"efs83nfy641s0c", out)
        self.assertNotIn(build_rules.FOLDER_TOKEN.encode(), out)

    def test_a_manifest_without_the_token_is_refused_not_silently_pushed(self):
        with self.assertRaises(rules_deploy.DeployError):
            rules_deploy.substitute_folder(b"apiVersion: x\n", "uid")


class TestPushRequiresTheMeasuredFlags(unittest.TestCase):
    def test_push_omits_manager_fields(self):
        """Measured: without --omit-manager-fields the push fails with
        `409 Conflict: cannot update with provided provenance 'api', needs
        'api'`. The message is self-contradictory, so this flag is pinned by a
        test rather than left to be rediscovered."""
        seen = {}

        def fake_gcx(args, context, parse=True):
            seen["args"] = args
            return json.dumps({"type": "gcx.mutation_batch",
                               "summary": {"succeeded": 19}, "failures": []})

        folders = {build_rules.ALERT_GROUP: "uid",
                   build_rules.DETECTION_GROUP: "uid2"}
        with mock.patch.object(rules_deploy, "gcx", fake_gcx):
            result = rules_deploy.push(
                "ctx", folders, build_rules.render_app_platform(), absent=set())
        self.assertIn("--omit-manager-fields", seen["args"])
        self.assertEqual(result["pushed"], 19)  # whatever the fake reported

    def test_push_asks_for_json_output(self):
        """#413. gcx emits its `gcx.mutation_batch` document only in AGENT mode,
        auto-detected from CLAUDECODE / CLAUDE_CODE / CURSOR_AGENT /
        GITHUB_COPILOT / AMAZON_Q / GCX_AGENT_MODE. None of those exist on a
        GitHub Actions runner, so an unflagged push there prints a human
        one-liner instead — measured 2026-08-04. The two `resources get` calls
        already pass `-o json`; the write must too, or CI reads nothing."""
        seen = {}

        def fake_gcx(args, context, parse=True):
            seen["args"] = args
            return json.dumps({"type": "gcx.mutation_batch",
                               "summary": {"succeeded": 1}, "failures": []})

        with mock.patch.object(rules_deploy, "gcx", fake_gcx):
            rules_deploy.push(
                "ctx", {build_rules.ALERT_GROUP: "uid"},
                {"g2o-collector-staleness.yaml": build_rules.render_app_platform()[
                    "g2o-collector-staleness.yaml"]}, absent=set())
        args = seen["args"]
        self.assertIn("-o", args)
        self.assertEqual(args[args.index("-o") + 1], "json")


    def test_a_new_rule_is_created_without_its_group_label(self):
        """Measured: `403 cannot set group when creating a new rule`. The create
        phase therefore strips the group labels, and runs ONLY for rules that do
        not exist yet — so the steady state stays a single push."""
        pushes = []

        def fake_gcx(args, context, parse=True):
            path = args[args.index("-p") + 1]
            pushes.append(sorted(os.listdir(path)))
            for name in os.listdir(path):
                with open(os.path.join(path, name), encoding="utf-8") as f:
                    pushes.append((name, "grafana.com/group:" in f.read()))
            return json.dumps({"type": "gcx.mutation_batch",
                               "summary": {"succeeded": 1}, "failures": []})

        manifests = {"g2o-collector-staleness.yaml":
                     build_rules.render_app_platform()[
                         "g2o-collector-staleness.yaml"]}
        folders = {build_rules.ALERT_GROUP: "uid"}
        with mock.patch.object(rules_deploy, "gcx", fake_gcx):
            rules_deploy.push("ctx", folders, manifests,
                              absent={"g2o-collector-staleness"})
        grouped = [p[1] for p in pushes if isinstance(p, tuple)]
        self.assertEqual(grouped, [False, True],
                         "create phase must be group-less, group phase must not")

    def test_ungroupable_failures_are_not_counted_as_push_failures(self):
        def fake_gcx(args, context, parse=True):
            return json.dumps({
                "type": "gcx.mutation_batch",
                "summary": {"succeeded": 12},
                "failures": [{"target": {"name": "g2o-record-integrity-loss"},
                              "error": f"403 Forbidden: {rules_deploy.UNGROUPABLE}"}],
            })

        with mock.patch.object(rules_deploy, "gcx", fake_gcx):
            result = rules_deploy.push(
                "ctx", {build_rules.ALERT_GROUP: "uid"},
                {"g2o-collector-staleness.yaml": build_rules.render_app_platform()[
                    "g2o-collector-staleness.yaml"]}, absent=set())
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["ungrouped"], ["g2o-record-integrity-loss"])

    def test_an_ungroupable_rule_is_retried_without_its_group_so_content_lands(self):
        """An UNGROUPABLE failure must not leave the rule's CONTENT stale.

        The group phase pushes the manifest *with* its group label, so when the
        API refuses the grouping the whole update is rejected — annotations,
        query, thresholds and all. Reporting that as merely "differs in UI
        grouping" was wrong: a live readback against the m7kni stack caught two
        rules whose panel deep links stayed stale through a push that reported
        no failures. The fix is a third phase retrying exactly those rules
        group-less, the same shape the create phase already uses.
        """
        pushes = []

        def fake_gcx(args, context, parse=True):
            path = args[args.index("-p") + 1]
            grouped = False
            for name in sorted(os.listdir(path)):
                with open(os.path.join(path, name), encoding="utf-8") as f:
                    if "grafana.com/group:" in f.read():
                        grouped = True
            pushes.append(grouped)
            if grouped:
                return json.dumps({
                    "type": "gcx.mutation_batch", "summary": {"succeeded": 0},
                    "failures": [{"target": {"name": "g2o-record-integrity-loss"},
                                  "error": f"403 Forbidden: {rules_deploy.UNGROUPABLE}"}],
                })
            return json.dumps({"type": "gcx.mutation_batch",
                               "summary": {"succeeded": 1}, "failures": []})

        manifests = {"g2o-record-integrity-loss.yaml":
                     build_rules.render_app_platform()[
                         "g2o-record-integrity-loss.yaml"]}
        with mock.patch.object(rules_deploy, "gcx", fake_gcx):
            result = rules_deploy.push(
                "ctx", {build_rules.ALERT_GROUP: "uid"}, manifests, absent=set())

        self.assertEqual(result["failures"], [])
        self.assertEqual(result["ungrouped"], ["g2o-record-integrity-loss"])
        self.assertIn(
            "regroup", result["phases"],
            "an UNGROUPABLE rule must be retried group-less or its content never updates")
        self.assertEqual(result["phases"]["regroup"]["failures"], [])
        self.assertEqual(pushes, [True, False],
                         "the retry must push the SAME rule without its group label")

    def test_every_manifest_declares_api_provenance(self):
        """The other half of the same 409: without this annotation the update is
        refused with `provided provenance '', needs 'api'`."""
        for rule in build_rules.RULES + build_rules.DETECTIONS:
            m = build_rules.to_app_platform(
                rule, build_rules.ALERT_GROUP, build_rules.GROUP_INTERVAL, 0)
            self.assertEqual(
                m["metadata"]["annotations"]["grafana.com/provenance"], "api",
                rule["uid"])


class TestAnUnreadableResultIsNotAZero(unittest.TestCase):
    """#413's defect class, not just its instance.

    A push whose result could not be PARSED is an unknown outcome. Reporting an
    unknown outcome as `0 pushed, 0 failures` is what turned one missing flag
    into six days of silent drift on the m7kni stack: with no failures visible
    the UNGROUPABLE branch never fired, phase 3 never retried, and every rejected
    update left its rule's content stale while the run looked clean.

    Note what these fakes do differently from every other gcx fake in this file:
    they return what gcx ACTUALLY prints outside agent mode. The existing tests
    all feed a JSON `gcx.mutation_batch` string, so they assert one layer above
    the bug and could never have caught it."""

    def _push(self):
        return rules_deploy.push(
            "ctx", {build_rules.ALERT_GROUP: "uid"},
            {"g2o-collector-staleness.yaml": build_rules.render_app_platform()[
                "g2o-collector-staleness.yaml"]}, absent=set())

    def test_text_mode_output_raises_instead_of_reporting_nothing_pushed(self):
        with mock.patch.object(
                rules_deploy, "gcx",
                lambda args, context, parse=True: "15 resources pushed, 0 errors\n"):
            with self.assertRaises(rules_deploy.DeployError) as caught:
                self._push()
        # The diagnostic names what it could not find, so the next reader does
        # not have to rediscover the agent-mode contract from scratch.
        self.assertIn("gcx.mutation_batch", str(caught.exception))

    def test_empty_output_raises_too(self):
        """A silent gcx is the same unknown outcome as a chatty one."""
        with mock.patch.object(rules_deploy, "gcx",
                               lambda args, context, parse=True: ""):
            with self.assertRaises(rules_deploy.DeployError):
                self._push()


class TestAgentModeBannerIsToleratedOnReads(unittest.TestCase):
    """The mirror of #413, in the other direction.

    In agent mode gcx prepends a one-line `{"class":"hint",...}` banner ahead of
    the payload — measured 2026-08-04, and it does so even with `-o json`. A bare
    json.loads over that fails, so the deployer worked on a CI runner (no agent
    mode) and broke in a Claude Code / Cursor session, which is precisely the
    ambient-mode dependence #413 is about. scripts/grafana-prune-rules.py already
    strips it; the deployer must too, or `make rules-push` succeeds or fails
    depending on which terminal it was typed into."""

    PAYLOAD = {"items": [{"metadata": {"name": "u"}, "spec": {"title": "t"}}]}

    def _run(self, stdout):
        done = mock.Mock(returncode=0, stdout=stdout, stderr="")
        with mock.patch.object(rules_deploy.subprocess, "run", return_value=done):
            return rules_deploy.gcx(["resources", "get", "folders", "-o", "json"],
                                    "ctx")

    def test_a_leading_hint_banner_is_stripped(self):
        banner = json.dumps({"class": "hint", "summary": "use --json list …"})
        self.assertEqual(
            self._run(banner + "\n" + json.dumps(self.PAYLOAD)), self.PAYLOAD)

    def test_plain_json_still_parses(self):
        self.assertEqual(self._run(json.dumps(self.PAYLOAD)), self.PAYLOAD)

    def test_genuinely_unparseable_output_still_raises(self):
        """Stripping a banner must not become "skip the first line and hope"."""
        with self.assertRaises(rules_deploy.DeployError):
            self._run("NAME  TITLE\nfoo   bar\n")


class TestContextIsAlwaysPinned(unittest.TestCase):
    def test_gcx_is_invoked_with_an_explicit_context(self):
        """gcx's ambient current-context was found pointing at an unrelated
        customer stack, which returns a plausible inventory containing none of
        graph2otel's resources — indistinguishable from deletion."""
        captured = {}

        class FakeDone:
            returncode = 0
            stdout = "{}"
            stderr = ""

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return FakeDone()

        with mock.patch.object(rules_deploy.subprocess, "run", fake_run):
            rules_deploy.gcx(["resources", "get", "folders"], "m7kni")
        self.assertEqual(captured["cmd"][:3], ["gcx", "--context", "m7kni"])


if __name__ == "__main__":
    unittest.main()
