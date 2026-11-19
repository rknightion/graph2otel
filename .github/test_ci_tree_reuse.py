"""Exercise the CI decision with actual Git trees and synthetic GitHub metadata."""

import copy
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ci_tree_reuse import Fallback, main_proof, pr_witness


class TreeReuse(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        working_dir = os.getcwd()
        os.chdir(self.path)
        self.addCleanup(os.chdir, working_dir)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "fixture" + "@" + "example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.path / ".github/workflows").mkdir(parents=True)
        (self.path / ".github/workflows/ci.yml").write_text("same workflow\n")
        (self.path / ".github/ci_tree_reuse.py").write_text("same verifier\n")
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD")

        self.git("switch", "-qc", "topic")
        (self.path / "topic").write_text("change under test\n")
        self.commit("proposed change")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.git("switch", "-qc", "synthetic", "main")
        self.git("merge", "-q", "--no-ff", "--no-edit", "topic")
        self.synthetic = self.git("rev-parse", "HEAD")

        self.git("switch", "-q", "main")
        self.git("merge", "-q", "--squash", "topic")
        self.commit("squash merge")
        self.after = self.git("rev-parse", "HEAD")
        self.repo = {"id": 42}
        self.pull = {
            "number": 7, "state": "closed", "merged_at": "2026-01-01T01:03:00Z",
            "merge_commit_sha": self.after,
            "head": {"ref": "topic", "sha": self.head, "repo": self.repo},
            "base": {"ref": "main", "sha": self.base, "repo": self.repo},
        }
        self.event = {
            "before": self.base, "after": self.after, "ref": "refs/heads/main",
            "created": False, "deleted": False, "forced": False, "repository": self.repo,
        }
        self.env = {
            "GITHUB_REPOSITORY_ID": "42", "GITHUB_REPOSITORY": "example/project",
            "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": self.after,
            "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
            "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20260101.1",
        }
        self.routes = {
            f"/git/commits/{self.head}": {"sha": self.head, "tree": {"sha": self.tree}},
        }

    @staticmethod
    def git(*argv):
        return subprocess.check_output(["git", *argv], text=True, stderr=subprocess.PIPE).strip()

    def commit(self, subject):
        self.git("add", ".")
        self.git("commit", "-qm", subject)

    def api(self, path):
        return copy.deepcopy(self.routes[path])

    def witness(self, sha):
        self.git("switch", "-q", "--detach", sha)
        with patch.dict(os.environ, self.env | {
            "GITHUB_SHA": sha, "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/7/merge",
        }, clear=True):
            return pr_witness(self.api, {"pull_request": self.pull, "repository": self.repo})

    def test_same_tree_witness_uses_real_merge_checkout(self):
        fields = f"7:{self.head}:{self.base}:ubuntu24-20260101.1-X64"
        self.assertEqual(self.witness(self.synthetic), hashlib.sha256(fields.encode()).hexdigest())

    def test_independent_base_content_selects_full_suite(self):
        self.git("switch", "-qc", "different-base", self.base)
        (self.path / "base-only").write_text("independent base edit\n")
        self.commit("base change")
        self.pull["base"]["sha"] = self.git("rev-parse", "HEAD")
        self.git("merge", "-q", "--no-ff", "--no-edit", "topic")
        with self.assertRaisesRegex(Fallback, "tested tree differs"):
            self.witness(self.git("rev-parse", "HEAD"))

    def test_fork_checkout_has_no_witness(self):
        self.pull["head"]["repo"] = {"id": 43}
        with self.assertRaisesRegex(Fallback, "cross-repository"):
            self.witness(self.synthetic)

    def evidence(self):
        # Model GitHub's API boundary. This inventory is independent of the verifier,
        # and the native marker comes from the real Git merge checkout above.
        marker = self.witness(self.synthetic)
        self.commit_route = f"/commits/{self.after}/pulls?per_page=100"
        self.run_route = (
            "/actions/workflows/12/runs?event=pull_request"
            f"&head_sha={self.head}&per_page=100"
        )
        self.jobs_route = "/actions/runs/17/attempts/2/jobs?per_page=100"
        self.checks_route = f"/commits/{self.head}/check-runs?filter=all&per_page=100"
        complete = {"status": "completed", "completed_at": "2026-01-01T01:02:00Z"}
        green = complete | {"conclusion": "success"}
        job_names = (
            "build / vet / test", "golangci-lint", "govulncheck", "goreleaser build (snapshot)",
            "docker image builds", "helm lint + template", "Grafana assets + generated docs",
            "helm schema validate (kubeconform) / helm lint · template · kubeconform",
            "ac-evidence / Acceptance evidence", "privacy-sweep / Privacy sweep",
            "backlog/ is frozen", "zizmor / Run zizmor", "coverage (Codacy)", "ci-success",
        )
        jobs = [
            green | {"name": name, "run_attempt": 2, "run_id": 17, "head_sha": self.head, "id": index}
            for index, name in enumerate(job_names, start=80)
        ]
        jobs[-2]["conclusion"] = "skipped"
        jobs[0]["steps"] = [
            green | {"number": index, "name": name}
            for index, name in enumerate((
                f"Witness PR 7 {marker}", "go.mod tidy check", "go vet", "go build", "go test -race",
                "vet + test the tools modules", "Verify tree proof and fallback behavior",
            ), start=3)
        ]
        run = {
            "status": "completed", "conclusion": "success", "updated_at": "2026-01-01T01:02:00Z",
            "id": 17, "run_number": 3, "run_attempt": 2, "check_suite_id": 18, "workflow_id": 12,
            "path": ".github/workflows/ci.yml", "event": "pull_request",
            "head_sha": self.head, "head_branch": "topic", "pull_requests": [],
            "repository": self.repo, "head_repository": self.repo,
        }
        self.routes.update({
            self.commit_route: [self.pull],
            "/branches/main": {
                "name": "main", "protected": True, "protection": {
                    "enabled": False, "required_status_checks": {
                        "enforcement_level": "off", "contexts": [], "checks": [],
                    },
                },
            },
            "/rules/branches/main": [{
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False, "do_not_enforce_on_create": False,
                    "required_status_checks": [{"context": "ci-success", "integration_id": 15368}],
                },
            }],
            "/actions/workflows/ci.yml": {"id": 12, "state": "active", "path": ".github/workflows/ci.yml"},
            self.run_route: {"total_count": 2, "workflow_runs": [
                run | {"id": 16, "run_number": 2, "conclusion": "cancelled"}, run,
            ]},
            self.jobs_route: {"total_count": len(jobs), "jobs": jobs},
            self.checks_route: {"total_count": 1, "check_runs": [
                green | {"name": "ci-success", "id": jobs[-1]["id"], "app": {"id": 15368},
                         "head_sha": self.head, "check_suite": {"id": 18},
                         "details_url": f"https://github.com/example/project/actions/runs/17/job/{jobs[-1]['id']}"},
            ]},
        })

    def proof(self):
        self.git("switch", "-q", "--detach", self.event["after"])
        with patch.dict(os.environ, self.env, clear=True):
            return main_proof(self.api, self.event)

    def test_latest_complete_witness_authorizes_reuse(self):
        self.evidence()
        self.assertTrue(self.proof())

    def test_older_green_does_not_override_latest_failure(self):
        self.evidence()
        run_page = self.routes[self.run_route]
        runs = run_page["workflow_runs"]
        for status, conclusion in (("completed", "failure"), ("completed", "cancelled"), ("in_progress", None)):
            with self.subTest(status=status, conclusion=conclusion):
                runs.append(runs[1] | {"id": 19, "run_number": 4, "status": status, "conclusion": conclusion})
                run_page["total_count"] = len(runs)
                with self.assertRaisesRegex(Fallback, "latest CI run did not complete successfully"):
                    self.proof()
                runs.pop()

    def test_incomplete_or_wrong_attempt_and_step_fall_back(self):
        self.evidence()
        jobs = self.routes[self.jobs_route]["jobs"]
        for mutation, reason in (
            (lambda: jobs.pop(), "incomplete GitHub API"),
            (lambda: jobs[0].update(run_attempt=1), "all intended completed job results"),
            (lambda: jobs[0]["steps"][0].update(conclusion="skipped"), "fresh checkout witness"),
            (lambda: jobs[0]["steps"][0].update(name="Witness PR 7 missing"), "fresh checkout witness"),
            (lambda: jobs[0]["steps"][4].update(conclusion="failure"), "build and test results"),
        ):
            before = copy.deepcopy(jobs)
            mutation()
            with self.assertRaisesRegex(Fallback, reason):
                self.proof()
            jobs[:] = before

    def test_required_check_must_be_authentic_and_timely(self):
        self.evidence()
        checks = self.routes[self.checks_route]["check_runs"]
        for index, changes, reason in (
            (0, {"app": {"id": 15369}}, "app-bound required check evidence is missing"),
            (0, {"completed_at": "2026-01-01T01:03:01Z"}, "before merge"),
            (0, {"check_suite": {"id": 19}}, "witnessed CI attempt"),
            (0, {"id": checks[0]["id"] + 1}, "witnessed CI attempt"),
        ):
            with self.subTest(changes=changes):
                original = checks[index]
                checks[index] = original | changes
                with self.assertRaisesRegex(Fallback, reason):
                    self.proof()
                checks[index] = original

    def test_changed_policy_or_unrelated_protected_commit_must_run_full(self):
        self.evidence()
        self.git("switch", "-q", "main")
        self.git("reset", "-q", "--hard", self.base)
        (self.path / ".github/workflows/ci.yml").write_text("new workflow policy\n")
        self.commit("change policy")
        self.event["after"] = self.git("rev-parse", "HEAD")
        self.env["GITHUB_SHA"] = self.event["after"]
        with self.assertRaisesRegex(Fallback, "CI policy changed"):
            self.proof()
        self.event["forced"] = True
        with self.assertRaisesRegex(Fallback, "not an ordinary protected main push"):
            self.proof()

    def test_ambiguous_pr_and_wrong_runner_fall_back(self):
        self.evidence()
        self.routes[self.commit_route].append(self.pull | {"number": 8})
        with self.assertRaisesRegex(Fallback, "missing or ambiguous"):
            self.proof()
        self.routes[self.commit_route].pop()
        self.env["ImageVersion"] = "20260102.1"
        with self.assertRaisesRegex(Fallback, "fresh checkout witness"):
            self.proof()

    def test_changed_classic_and_ruleset_policy_fall_back(self):
        self.evidence()
        branch = self.routes["/branches/main"]
        protection = branch.pop("protection")
        with self.assertRaisesRegex(Fallback, "classic branch protection"):
            self.proof()
        branch["protection"] = protection
        branch["protection"]["enabled"] = True
        with self.assertRaisesRegex(Fallback, "classic branch protection"):
            self.proof()
        branch["protection"]["enabled"] = False
        branch["protection"]["required_status_checks"]["contexts"] = ["additional"]
        with self.assertRaisesRegex(Fallback, "classic branch protection"):
            self.proof()
        branch["protection"]["required_status_checks"]["contexts"] = []
        rules = self.routes["/rules/branches/main"]
        rules[0]["parameters"]["strict_required_status_checks_policy"] = True
        with self.assertRaisesRegex(Fallback, "effective required check policy changed"):
            self.proof()
