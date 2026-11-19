"""Use a completed same-repository CI witness only for an identical protected tree."""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from itertools import pairwise
from pathlib import Path

WORKFLOW = ".github/workflows/ci.yml"
POLICY = (WORKFLOW, ".github/ci_tree_reuse.py", ".github/test_ci_tree_reuse.py")
BUILD_JOB = "build / vet / test"
REQUIRED = "ci-success"
ACTIONS_APP = 15368

# Exact native CI job names, including reusable workflow children. Any workflow
# or provider naming change selects a full run until this inventory is checked.
PR_JOBS = {
    BUILD_JOB: "success",
    "golangci-lint": "success",
    "govulncheck": "success",
    "goreleaser build (snapshot)": "success",
    "docker image builds": "success",
    "helm lint + template": "success",
    "Grafana assets + generated docs": "success",
    "helm schema validate (kubeconform) / helm lint · template · kubeconform": "success",
    "ac-evidence / Acceptance evidence": "success",
    "privacy-sweep / Privacy sweep": "success",
    "backlog/ is frozen": "success",
    "zizmor / Run zizmor": "success",
    "coverage (Codacy)": "skipped",
    REQUIRED: "success",
}
BUILD_STEPS = (
    "go.mod tidy check", "go vet", "go build", "go test -race", "vet + test the tools modules",
    "Verify tree proof and fallback behavior",
)
SHA = re.compile(r"[a-f0-9]{40}")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


class Fallback(Exception):
    """The original full build and test job is still needed."""


def expect(condition, reason):
    if not condition:
        raise Fallback(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def github_api(path):
    repo = os.environ["GITHUB_REPOSITORY"]
    expect(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "invalid repository")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "graph2otel-ci-tree-reuse",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # The protected proof reads public API metadata. The PR witness can use the
    # existing contents-read token for its single Git commit request.
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}{path}", headers=headers)
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=5) as response:
        expect('rel="next"' not in response.headers.get("Link", ""), "incomplete GitHub API page")
        max_bytes = 2 * 1024 * 1024
        body = response.read(max_bytes + 1)
        expect(len(body) <= max_bytes, "GitHub API response exceeded 2 MiB")
    return json.loads(body)


def page(response, key):
    items = response[key]
    expect(isinstance(items, list) and response["total_count"] == len(items) < 100,
           "incomplete GitHub API results")
    return items


def git(*args):
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE, timeout=5).strip()


def checkout(sha):
    expect(SHA.fullmatch(sha) and git("rev-parse", "HEAD") == sha, "checkout differs from event SHA")
    # The commit object exposes parents even with the PR's existing depth-one checkout.
    headers = git("cat-file", "-p", sha).split("\n\n", 1)[0].splitlines()
    return (git("rev-parse", "HEAD^{tree}"),
            [line.removeprefix("parent ") for line in headers if line.startswith("parent ")])


def checked_pr(pull, repo_id):
    head, base = pull["head"], pull["base"]
    expect(head["repo"]["id"] == base["repo"]["id"] == repo_id, "cross-repository PR")
    expect(type(pull["number"]) is int and pull["number"] > 0 and SHA.fullmatch(head["sha"]),
           "invalid PR identity")
    return head["sha"]


def head_tree(api, head):
    commit = api(f"/git/commits/{head}")
    tree = commit["tree"]["sha"]
    expect(commit["sha"] == head and SHA.fullmatch(tree), "PR head tree is unavailable")
    return tree


def runner_image():
    image, version, arch = (os.environ[key] for key in ("ImageOS", "ImageVersion", "RUNNER_ARCH"))
    expect(re.fullmatch(r"ubuntu\d{2}", image) and re.fullmatch(r"\d+(\.\d+){1,3}", version)
           and arch == "X64", "runner image identity is unavailable")
    return f"{image}-{version}-{arch}"


def witness_key(pull, base, image):
    # A short, single step name binds the actual base, head and runner image.
    # Requiring the current protected parent binds the precise merge that was tested.
    fields = f"{pull['number']}:{pull['head']['sha']}:{base}:{image}"
    return hashlib.sha256(fields.encode()).hexdigest()


def pr_witness(api, event):
    repo_id = int(os.environ["GITHUB_REPOSITORY_ID"])
    pull = event["pull_request"]
    head = checked_pr(pull, repo_id)
    expect(os.environ["GITHUB_EVENT_NAME"] == "pull_request" and event["repository"]["id"] == repo_id
           and os.environ["GITHUB_REF"] == f"refs/pull/{pull['number']}/merge", "not a PR merge checkout")
    tree, parents = checkout(os.environ["GITHUB_SHA"])
    expect(parents == [pull["base"]["sha"], head], "checkout parents differ from PR event")
    expect(tree == head_tree(api, head), "tested tree differs from PR head tree")
    return witness_key(pull, parents[0], runner_image())


def merged_pull(api, repo_id, push, tree):
    associated = api(f"/commits/{push}/pulls?per_page=100")
    expect(isinstance(associated, list) and len(associated) == 1, "merged PR is missing or ambiguous")
    pull = associated[0]
    head = checked_pr(pull, repo_id)
    expect(pull["state"] == "closed" and UTC.fullmatch(pull["merged_at"] or "")
           and pull["merge_commit_sha"] == push and pull["base"]["ref"] == "main",
           "protected commit is not the recorded PR merge")
    expect(tree == head_tree(api, head), "protected tree differs from PR head tree")
    return pull


def latest_ci(api, pull, repo_id):
    branch = api("/branches/main")
    # Effective ruleset rules do not include classic branch protection.
    classic = branch.get("protection")
    expect(branch["name"] == "main" and branch["protected"] is True
           and isinstance(classic, dict) and classic.get("enabled") is False
           and classic.get("required_status_checks") == {
               "enforcement_level": "off", "contexts": [], "checks": [],
           }, "classic branch protection is active or unreadable")
    rules = api("/rules/branches/main")
    required = [rule["parameters"] for rule in rules if rule["type"] == "required_status_checks"]
    expect(required == [{
        "strict_required_status_checks_policy": False,
        "do_not_enforce_on_create": False,
        "required_status_checks": [{"context": REQUIRED, "integration_id": ACTIONS_APP}],
    }], "effective required check policy changed")

    workflow = api("/actions/workflows/ci.yml")
    workflow_id = workflow["id"]
    expect(workflow["path"] == WORKFLOW and workflow["state"] == "active"
           and type(workflow_id) is int and workflow_id > 0, "CI workflow identity changed")
    head = pull["head"]["sha"]
    runs = page(api(f"/actions/workflows/{workflow_id}/runs?event=pull_request"
                    f"&head_sha={head}&per_page=100"), "workflow_runs")
    numbers = {run["run_number"] for run in runs}
    expect(runs and len(numbers) == len(runs)
           and all(type(number) is int and number > 0 for number in numbers),
           "latest PR CI run is missing or ambiguous")
    run = max(runs, key=lambda item: item["run_number"])
    expect(run["event"] == "pull_request" and run["workflow_id"] == workflow_id
           and run["path"] == WORKFLOW and run["head_sha"] == head
           and run["head_branch"] == pull["head"]["ref"]
           and run["repository"]["id"] == run["head_repository"]["id"] == repo_id,
           "latest run does not belong to the exact same-repository CI head")
    associations = run["pull_requests"]
    expect(isinstance(associations, list) and
           (not associations or (len(associations) == 1 and associations[0]["number"] == pull["number"])),
           "latest run has conflicting PR association")
    expect(completed(run, pull) and run["conclusion"] == "success",
           "latest CI run did not complete successfully before merge")
    expect(all(type(run[key]) is int and run[key] > 0 for key in ("id", "run_attempt", "check_suite_id")),
           "latest run is missing an attempt identity")
    return run


def completed(item, pull):
    end = item.get("completed_at", item.get("updated_at"))
    return (item["status"] == "completed" and UTC.fullmatch(end or "")
            and end <= pull["merged_at"])


def witnessed_jobs(api, run, pull, base, image):
    run_id, attempt = run["id"], run["run_attempt"]
    jobs = page(api(f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"), "jobs")
    outcomes = {job["name"]: job["conclusion"] for job in jobs}
    expect(len(outcomes) == len(jobs) and outcomes == PR_JOBS
           and all(job["run_id"] == run_id and job["run_attempt"] == attempt
                   and job["head_sha"] == pull["head"]["sha"] and completed(job, pull) for job in jobs),
           "PR CI attempt does not contain all intended completed job results")

    build = next(job for job in jobs if job["name"] == BUILD_JOB)
    wanted = (f"Witness PR {pull['number']} {witness_key(pull, base, image)}", *BUILD_STEPS)
    steps = [step for step in build["steps"] if step["name"] in wanted]
    expect(tuple(step["name"] for step in steps) == wanted
           and all(completed(step, pull) and step["conclusion"] == "success" for step in steps)
           and all(a["number"] < b["number"] for a, b in pairwise(steps)),
           "fresh checkout witness or build and test results are missing")
    return next(job for job in jobs if job["name"] == REQUIRED)


def verify_checks(api, run, aggregate, pull):
    head = pull["head"]["sha"]
    checks = page(api(f"/commits/{head}/check-runs?filter=all&per_page=100"), "check_runs")
    matches = [check for check in checks if check["name"] == REQUIRED and check["app"]["id"] == ACTIONS_APP]
    expect(matches and all(type(check["id"]) is int and check["id"] > 0 for check in matches),
           "app-bound required check evidence is missing")
    check = max(matches, key=lambda item: item["id"])
    expect(sum(item["id"] == check["id"] for item in matches) == 1
           and check["head_sha"] == head and completed(check, pull) and check["conclusion"] == "success",
           "latest app-bound required check did not complete successfully before merge")
    repo = os.environ["GITHUB_REPOSITORY"]
    expect(check["id"] == aggregate["id"] and check["check_suite"]["id"] == run["check_suite_id"]
           and check["details_url"] == f"https://github.com/{repo}/actions/runs/{run['id']}/job/{check['id']}",
           "required verdict does not belong to the witnessed CI attempt")


def main_proof(api, event):
    repo_id = int(os.environ["GITHUB_REPOSITORY_ID"])
    after, before = event["after"], event["before"]
    expect(os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_REF_PROTECTED"] == "true"
           and event["ref"] == os.environ["GITHUB_REF"] == "refs/heads/main"
           and event["repository"]["id"] == repo_id and after == os.environ["GITHUB_SHA"]
           and all(event[key] is False for key in ("created", "deleted", "forced")) and SHA.fullmatch(before),
           "not an ordinary protected main push")
    image = runner_image()
    tree, parents = checkout(after)
    expect(parents == [before], "protected commit is not a single-parent squash")
    expect(not git("diff", "--name-only", before, after, "--", *POLICY), "CI policy changed")
    pull = merged_pull(api, repo_id, after, tree)
    run = latest_ci(api, pull, repo_id)
    verify_checks(api, run, witnessed_jobs(api, run, pull, before, image), pull)
    return True


def main():
    started = time.monotonic()
    command = sys.argv[1]
    try:
        with Path(os.environ["GITHUB_EVENT_PATH"]).open() as stream:
            event = json.load(stream)
        if command == "witness":
            result = f"key={pr_witness(github_api, event)}"
        elif command == "main":
            main_proof(github_api, event)
            result = "reuse=true"
        else:
            raise ValueError("unknown CI decision")
    except Fallback as error:
        print(f"Full build and test suite: {error}")
        return
    except (KeyError, IndexError, AttributeError, TypeError, ValueError, OSError,
            subprocess.SubprocessError) as error:
        print(f"Full build and test suite: evidence unavailable ({type(error).__name__})")
        return
    finally:
        print(f"Decision time: {time.monotonic() - started:.3f}s")

    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        print(result, file=output)
    print("Exact checkout evidence verified")


if __name__ == "__main__":
    main()
