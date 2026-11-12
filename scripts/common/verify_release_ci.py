"""Require successful CI on the exact release commit, including actual integration jobs."""

import argparse
import json
import subprocess


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def latest_run(runs, sha):
    eligible = [
        run
        for run in runs
        if run["head_sha"] == sha and run["event"] in ("push", "workflow_dispatch")
    ]
    if not eligible:
        raise ValueError("no push or manual CI run exists for the release commit")
    # Use the newest run, including pending/failed ones; never fall back to an older green run.
    return max(eligible, key=lambda run: run["id"])


def require_success(run, jobs, required_jobs=()):
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise ValueError(f"newest run is {run['status']}/{run['conclusion']}")
    outcomes = {job["name"]: job["conclusion"] for job in jobs}
    for name in required_jobs:
        if outcomes.get(name) != "success":
            raise ValueError(f"required job {name!r} is {outcomes.get(name, 'missing')}")


def check(repo, sha, plugin):
    # Binary Ninja has no licensed CI secrets yet, so its integration run cannot gate a release.
    required = {
        "pytest.yml": (),
        "ruff.yml": (),
    }
    if plugin == "ida":
        required["ida-tests.yml"] = [
            f"IDA {version} / Linux / headless and GUI"
            for version in ("9.0", "9.1", "9.2", "9.3", "9.4", "9.5")
        ]
    for workflow, jobs_needed in required.items():
        response = api(
            f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&per_page=100"
        )
        run = latest_run(response["workflow_runs"], sha)
        jobs = api(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
        require_success(run, jobs, jobs_needed)
        print(f"PASS {workflow} on {sha}: {run['html_url']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--plugin", required=True, choices=("ida", "binja"))
    args = parser.parse_args()
    try:
        check(args.repo, args.sha, args.plugin)
    except ValueError as error:
        raise SystemExit(
            f"Release CI gate failed: {error}. Run CI on this commit before releasing."
        )


if __name__ == "__main__":
    main()
