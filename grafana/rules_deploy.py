#!/usr/bin/env python3
"""Deploy graph2otel's generated alert rules and prove the stack matches (#294).

    python3 rules_deploy.py --context <gcx-context> --folder-title graph2otel
    python3 rules_deploy.py --context <gcx-context> --readback-only

Why this exists rather than a documented `gcx resources push`:

* The committed manifests carry `grafana.app/folder: REPLACE_WITH_FOLDER_UID`,
  because a folder UID is stack-specific and a public repository cannot know it.
  This tool resolves the UID from a folder TITLE at push time.
* Two non-obvious flags are mandatory and were found only by pushing: the
  manifest needs `grafana.com/provenance: api` and the push needs
  `--omit-manager-fields`. Both produce a `409 Conflict` when missing, and one of
  the two messages is literally self-contradictory
  (`provided provenance 'api', needs 'api'`).
* A push that reports success is not a deployment that matches source. The
  read-back below compares the PROJECTED CONTENT field by field, because the
  drift this issue exists to close was invisible to a count: the live recording
  rules were *present* with *stale content*, and the live alert group has held
  12 rules against the repository's 14 for the whole programme.

Standard library only, matching the rest of `grafana/`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build_rules  # noqa: E402

# The rule-definition kind. NOT `alertrules` — that short form resolves to
# `alerting.ext.grafana.app`, which is the FIRING-INSTANCE view (it returns
# `spec.alerts[]` with live alert state) and contains no rule definition at all.
# Reading the wrong one back would compare source against a completely different
# resource and report nonsense, so the fully-qualified form is used everywhere.
RULE_KIND = "alertrules.v0alpha1.rules.alerting.grafana.app"

# Fields compared on read-back. Deliberately the whole semantic surface rather
# than a sample: every one of these has either drifted live already or encodes a
# decision an earlier issue shipped (#298 execErrState, #299 the threshold inside
# expressions, #307 the runbook annotations, #293/#296 the routable labels).
COMPARED = ("title", "for", "noDataState", "execErrState", "trigger",
            "labels", "annotations", "expressions")


class DeployError(RuntimeError):
    """Operational failure: gcx, auth, transport, or a malformed response."""


def gcx(args: list, context: str, parse: bool = True):
    """Run gcx with the context PINNED. Never relies on the ambient context.

    The current-context has been found pointing at an unrelated customer stack,
    which returns a plausible-looking inventory with none of graph2otel's
    resources in it — a state that reads exactly like "everything was deleted".
    """
    cmd = ["gcx", "--context", context] + args
    try:
        done = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise DeployError(f"cannot execute gcx: {exc}") from exc
    # Exit 4 is gcx's documented PARTIAL-FAILURE code, and its stdout still
    # carries the per-resource failures. Treating it as operational would hide
    # exactly the diagnostic this tool exists to produce — which rules failed and
    # why — behind "gcx exited 4".
    if done.returncode not in (0, 4):
        detail = (done.stderr.strip() or done.stdout.strip() or "no diagnostic")
        raise DeployError(f"gcx {' '.join(args[:3])} exited "
                          f"{done.returncode}: {detail}")
    if not parse:
        return done.stdout
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        pass
    # In agent mode — auto-detected from CLAUDECODE / CLAUDE_CODE / CURSOR_AGENT
    # / GITHUB_COPILOT / AMAZON_Q / GCX_AGENT_MODE — gcx prepends a one-line
    # {"class":"hint",...} banner ahead of the payload, and does so even with
    # `-o json`. Without this the deployer parses on a CI runner and fails in a
    # Claude Code or Cursor session: the same command, succeeding or failing on
    # which terminal it was typed into. The banner is identified by content, not
    # by position — "drop the first line" would turn a genuinely unparseable
    # response into a silently truncated one.
    head, _, rest = done.stdout.partition("\n")
    if '"class"' in head and '"hint"' in head:
        try:
            return json.loads(rest)
        except json.JSONDecodeError as exc:
            raise DeployError(
                f"gcx {' '.join(args[:3])} returned invalid JSON after its "
                "agent-mode hint banner") from exc
    raise DeployError(f"gcx {' '.join(args[:3])} returned invalid JSON")


def resolve_folder_uid(folders: list, title: str) -> str:
    """Folder title -> UID, refusing to guess.

    An ambiguous title is an error rather than a first match: filing 19 rules
    into the wrong folder of two with the same name is worse than not deploying.
    """
    hits = [f for f in folders
            if (f.get("spec", {}).get("title") or f.get("title")) == title]
    if not hits:
        have = sorted(
            (f.get("spec", {}).get("title") or f.get("title") or "?")
            for f in folders)
        raise DeployError(
            f"no folder titled {title!r} on this stack. Create it first "
            f"(the deploy does not create folders). Present: {have}")
    if len(hits) > 1:
        raise DeployError(
            f"{len(hits)} folders are titled {title!r} — refusing to guess "
            f"which one the rules belong in. Pass --folder-uid explicitly.")
    uid = hits[0].get("metadata", {}).get("name") or hits[0].get("uid")
    if not uid:
        raise DeployError(f"folder {title!r} has no resolvable uid")
    return uid


def substitute_folder(manifest: bytes, folder_uid: str) -> bytes:
    """Replace the loud folder token with a real UID.

    Fails rather than silently no-opping when the token is absent: a manifest
    without it would be pushed with whatever folder it already names, which is
    the silent-wrong-placement outcome the token exists to prevent.
    """
    token = build_rules.FOLDER_TOKEN.encode()
    if token not in manifest:
        raise DeployError(
            f"manifest carries no {build_rules.FOLDER_TOKEN} token — refusing "
            f"to push a manifest whose folder was resolved somewhere else")
    return manifest.replace(token, folder_uid.encode())


# Measured 2026-07-27, and the reason this deployer cannot fully group a rule it
# just created:
#
#   create with a group  -> 403 "cannot set group when creating a new rule"
#   update into a group   -> 403 "cannot set group when updating un-grouped rule"
#
# So an alert rule created through this API is un-grouped and cannot be moved
# into a named group by it. `RuleSequence` is NOT the escape hatch — it is for
# mixed sequences and is refused with "rule sequence requires at least one
# recording rule", and #297 retired every recording rule this repository had.
#
# This costs nothing functional: `spec.trigger.interval` is per-rule and is set
# correctly, so an un-grouped rule evaluates on the same cadence. The group is a
# presentation/organisation concern. It is surfaced explicitly rather than hidden
# because an operator comparing the Grafana UI against this repository would
# otherwise be left to work out why two rules sit outside the group.
UNGROUPABLE = "cannot set group when updating un-grouped rule"

GROUP_LABEL = "grafana.com/group"
GROUP_INDEX_LABEL = "grafana.com/group-index"


def strip_group_labels(manifest: bytes) -> bytes:
    """Remove the group labels from a manifest.

    Measured 2026-07-27: creating a rule that names a group is refused with
    `403 Forbidden: cannot set group when creating a new rule`. Group membership
    can only be set on UPDATE, so a rule that does not exist yet has to be
    created group-less and then updated into its group — see `push()`.
    """
    kept = []
    for line in manifest.decode().splitlines():
        stripped = line.strip()
        if stripped.startswith((f"{GROUP_LABEL}:", f"{GROUP_INDEX_LABEL}:")):
            continue
        kept.append(line)
    return ("\n".join(kept) + "\n").encode()


def _mutation_batch(out: str):
    """Find gcx's mutation-batch document in either shape it is emitted in.

    `-o json` PRETTY-PRINTS one document across many lines; agent mode emits
    compact JSON-lines, optionally behind a `{"class":"hint",...}` banner. Both
    are real and both reach this code, so whole-document is tried first and
    line-at-a-time second. A line-only parser reads nothing from a pretty-printed
    document — its first line is a bare `{` — which is how the first attempt at
    #413 tripped its own guard against real CI output.
    """
    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        pass
    else:
        return doc if doc.get("type") == "gcx.mutation_batch" else None
    batch = None
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if doc.get("type") == "gcx.mutation_batch":
            batch = doc
    return batch


def _push_dir(context: str, files: dict) -> dict:
    """Push one directory of manifests and READ the result, or refuse.

    `-o json` is not optional. gcx emits its `gcx.mutation_batch` document only
    in agent mode, which it auto-detects from CLAUDECODE / CLAUDE_CODE /
    CURSOR_AGENT / GITHUB_COPILOT / AMAZON_Q / GCX_AGENT_MODE — none of which
    exist on a GitHub Actions runner, where it prints a human one-liner instead.
    The flag pins the format rather than depending on an env-var list that is
    gcx's to change. Same reason the two `resources get` calls carry it.

    A result that could not be parsed raises. It used to fall through to the
    initialisers and report `0 pushed, 0 failures`, which is not a null result
    but a WRONG one: an unread push looks identical to a push with nothing to do.
    That is what made #413 six days of silent drift instead of one red run — with
    no failures visible, the UNGROUPABLE branch below never fired, phase 3 never
    retried, and every rejected update left its rule's content stale.
    """
    with tempfile.TemporaryDirectory() as tmp:
        for fname, data in sorted(files.items()):
            with open(os.path.join(tmp, fname), "wb") as f:
                f.write(data)
        out = gcx(["resources", "push", "-p", tmp, "--omit-manager-fields",
                   "-o", "json"], context, parse=False)
    batch = _mutation_batch(out)
    if batch is None:
        raise DeployError(
            "gcx resources push returned no gcx.mutation_batch document, so the "
            "outcome of the push is unknown — refusing to report it as zero. "
            f"Output was: {out.strip()[:400] or '(empty)'}")
    return {"pushed": batch.get("summary", {}).get("succeeded", 0),
            "failures": batch.get("failures", [])}


def push(context: str, folder_uids: dict, manifests: dict,
         absent: set) -> dict:
    """Create-or-update every manifest by stable `metadata.name`.

    Never delete-then-create: `metadata.name` is the identity, so a repeat push
    updates in place and `resourceVersion` increments.

    Two phases, because creation and group assignment cannot happen together
    (see `strip_group_labels`). Phase 1 creates only the rules that do not exist
    yet, group-less. Phase 2 pushes every rule with its group, which is an update
    for all of them by then. Phase 1 is skipped entirely on a stack that already
    has every rule, so the steady state is a single push.
    """
    resolved = {}
    for fname, data in manifests.items():
        group = manifest_group(data)
        folder_uid = folder_uids[group]
        resolved[fname] = substitute_folder(data, folder_uid)

    phases = {}
    creating = {f: strip_group_labels(d) for f, d in resolved.items()
                if f[: -len(".yaml")] in absent}
    if creating:
        phases["create"] = _push_dir(context, creating)
        if phases["create"]["failures"]:
            return {"phases": phases, "pushed": phases["create"]["pushed"],
                    "failures": phases["create"]["failures"], "ungrouped": []}

    # Phase 2 pushes every rule WITH its group. For a rule that already belongs
    # to the group this is an ordinary update. For one this run just created it
    # fails with `cannot set group when updating un-grouped rule` — see
    # UNGROUPABLE. That is a genuine API limitation, not a defect in the push.
    phases["group"] = _push_dir(context, resolved)
    ungrouped, real_failures = [], []
    for failure in phases["group"]["failures"]:
        if UNGROUPABLE in failure.get("error", ""):
            ungrouped.append(failure["target"]["name"])
        else:
            real_failures.append(failure)

    # Phase 3 retries exactly the UNGROUPABLE rules with their group labels
    # stripped, so their CONTENT still lands.
    #
    # This phase exists because leaving it out was a live bug, not a
    # theoretical gap. A rejected push applies NOTHING — annotations, query,
    # thresholds and all — so an UNGROUPABLE rule kept whatever content it had
    # while the run reported zero failures. A read-back against the m7kni stack
    # on 2026-07-28 caught two rules whose dashboard deep links were still
    # pointing at panel ids from before the last dashboard change, through a
    # push that looked clean. The old comment here claimed such a rule "differs
    # only in its UI grouping"; that was true of the intent and false of the
    # effect.
    #
    # They stay named in `ungrouped` afterwards: the content is now current but
    # the rule genuinely is not in the group, and the read-back reports that as
    # its own signal rather than as content drift.
    retry = {fname: strip_group_labels(data)
             for fname, data in resolved.items()
             if fname[: -len(".yaml")] in set(ungrouped)}
    if retry:
        # Guarded on `retry`, not on `ungrouped`: a name reported by the API
        # that matches nothing in this push would otherwise send an EMPTY
        # directory to `gcx resources push`, which is a request that can only
        # produce noise — no rule to update, and any failure it reports is
        # about nothing.
        phases["regroup"] = _push_dir(context, retry)
        real_failures.extend(phases["regroup"]["failures"])

    return {"phases": phases, "pushed": phases["group"]["pushed"],
            "failures": real_failures, "ungrouped": sorted(ungrouped)}


def manifest_group(manifest: bytes) -> str:
    for line in manifest.decode().splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{GROUP_LABEL}:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    raise DeployError("manifest declares no rule group")


def fetch_live(context: str, names: list) -> dict:
    """name -> live spec, absent names simply missing (not an error).

    Fetched ONE AT A TIME on purpose. A batch selector returns a single `items`
    document that omits whatever does not exist, so a missing rule is
    indistinguishable from a short list — and identifying exactly which rules are
    absent is this issue's own diagnostic requirement.
    """
    live = {}
    for name in names:
        try:
            doc = gcx(["resources", "get", f"{RULE_KIND}/{name}", "-o", "json"],
                      context)
        except DeployError as exc:
            if "404" in str(exc) or "NotFound" in str(exc):
                continue
            raise
        if isinstance(doc, dict) and "spec" in doc:
            live[name] = doc
    return live


def compare(projected: dict, live: dict) -> list:
    """Semantic differences between one projected manifest and one live rule.

    Two normalizations, each for a measured server behaviour rather than to make
    the comparison pass:

    * `paused: false` is dropped by the server (omitempty), so absent == false.
      `paused: true` IS returned, so a rule that should be paused and is not is
      still caught.
    * The server adds no fields inside `expressions` but does echo durations in
      the exact spelling the generator emits, which is why the generator emits Go
      duration strings rather than normalizing here.
    """
    diffs = []
    want, got = projected["spec"], live["spec"]

    want_paused, got_paused = bool(want.get("paused")), bool(got.get("paused"))
    if want_paused != got_paused:
        diffs.append(f"paused: source {want_paused}, live {got_paused}")

    for field in COMPARED:
        if want.get(field) != got.get(field):
            diffs.append(f"{field}: source {want.get(field)!r} != "
                         f"live {got.get(field)!r}")

    return diffs


def group_of(live: dict):
    return live.get("metadata", {}).get("labels", {}).get(GROUP_LABEL)


def project_all(include_detections: bool = True) -> dict:
    """uid -> projected manifest, for every rule in scope."""
    projected = {}
    for index, rule in enumerate(build_rules.RULES):
        projected[rule["uid"]] = build_rules.to_app_platform(
            rule, build_rules.ALERT_GROUP, build_rules.GROUP_INTERVAL, index)
    if include_detections:
        for index, rule in enumerate(build_rules.DETECTIONS):
            projected[rule["uid"]] = build_rules.to_app_platform(
                rule, build_rules.DETECTION_GROUP, build_rules.GROUP_INTERVAL,
                index)
    return projected


def readback(context: str, include_detections: bool = True) -> dict:
    """Compare every generated rule against the stack. Content, not counts."""
    projected = project_all(include_detections)

    live = fetch_live(context, sorted(projected))
    receipt = {"compared": len(projected), "absent": [], "divergent": {},
               "matching": [], "ungrouped": [], "status": "matched"}
    for name in sorted(projected):
        if name not in live:
            receipt["absent"].append(name)
            continue
        diffs = compare(projected[name], live[name])
        want_group = projected[name]["metadata"]["labels"][GROUP_LABEL]
        if group_of(live[name]) != want_group:
            # Reported separately from content drift, and deliberately NOT as a
            # match: it is a real difference from source, it just has a known
            # cause (UNGROUPABLE) and no functional consequence.
            receipt["ungrouped"].append(name)
        if diffs:
            receipt["divergent"][name] = diffs
        else:
            receipt["matching"].append(name)
    if receipt["absent"] or receipt["divergent"]:
        receipt["status"] = "drifted"
    elif receipt["ungrouped"]:
        receipt["status"] = "matched_content_ungrouped"
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True,
                        help="gcx context name (NOT the server hostname)")
    parser.add_argument("--folder-title", default="graph2otel")
    parser.add_argument("--folder-uid", default=None,
                        help="skip title resolution and use this UID")
    parser.add_argument("--detections-folder-title", default="graph2otel detections")
    parser.add_argument("--include-detections", action="store_true",
                        help="also deploy the PAUSED portable detection pack. Off "
                             "by default: those are security-content examples an "
                             "operator opts into, not graph2otel health rules, and "
                             "they land in their own folder.")
    parser.add_argument("--readback-only", action="store_true",
                        help="compare source against the stack, change nothing")
    args = parser.parse_args()

    scope = project_all(args.include_detections)
    manifests = {f"{uid}.yaml": data
                 for uid, data in build_rules.render_app_platform().items()
                 for uid in [uid[: -len(".yaml")]] if uid in scope}

    try:
        if not args.readback_only:
            groups = {build_rules.ALERT_GROUP: args.folder_title}
            if args.include_detections:
                groups[build_rules.DETECTION_GROUP] = args.detections_folder_title
            folders = gcx(["resources", "get", "folders", "-o", "json"],
                          args.context)
            items = folders.get("items", folders) if isinstance(
                folders, dict) else folders
            folder_uids = {}
            for group, title in groups.items():
                folder_uids[group] = (
                    args.folder_uid if args.folder_uid
                    and group == build_rules.ALERT_GROUP
                    else resolve_folder_uid(items, title))

            # Which rules do not exist yet decides whether the create phase runs
            # at all, so it is read BEFORE any mutation rather than inferred from
            # a failure.
            existing = set(fetch_live(args.context, sorted(scope)))
            absent = set(scope) - existing

            result = push(args.context, folder_uids, manifests, absent)
            print(json.dumps({"push": result, "folders": folder_uids,
                              "created": sorted(absent)}, indent=2))
            if result["failures"]:
                return 1

        receipt = readback(args.context, args.include_detections)
    except DeployError as exc:
        print(json.dumps({"status": "operational_error", "error": str(exc)},
                         indent=2))
        return 2

    print(json.dumps(receipt, indent=2))
    if receipt["status"] == "matched_content_ungrouped":
        print(f"\n{len(receipt['matching'])} rules match the stack "
              f"semantically; {len(receipt['ungrouped'])} sit outside their "
              f"named group because this API cannot group a rule it created "
              f"({', '.join(receipt['ungrouped'])})", file=sys.stderr)
        return 0
    if receipt["status"] != "matched":
        print(f"\nSTACK DOES NOT MATCH SOURCE — {len(receipt['absent'])} absent, "
              f"{len(receipt['divergent'])} divergent", file=sys.stderr)
        return 1
    print(f"\n{receipt['compared']} rules match the stack semantically",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
