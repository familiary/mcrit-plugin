import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/common/verify_release_ci.py"
spec = importlib.util.spec_from_file_location("verify_release_ci", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def run(id=1, sha="verified", event="push", status="completed", conclusion="success"):
    return {"id": id, "head_sha": sha, "event": event, "status": status, "conclusion": conclusion}


def test_a_newer_failed_or_pending_run_cannot_be_hidden_by_an_old_green_run():
    for newest in (run(2, conclusion="failure"), run(2, status="in_progress", conclusion=None)):
        selected = ci.latest_run([run(), newest], "verified")
        with pytest.raises(ValueError, match="newest run"):
            ci.require_success(selected, [])


def test_pr_runs_or_other_commits_cannot_authorize_a_release():
    with pytest.raises(ValueError, match="no push or manual"):
        ci.latest_run([run(event="pull_request"), run(2, sha="different")], "verified")
    assert ci.latest_run([run(event="workflow_dispatch")], "verified")["id"] == 1


@pytest.mark.parametrize("conclusion", [None, "skipped", "failure", "cancelled"])
def test_a_green_summary_cannot_hide_a_missing_or_unexecuted_integration(conclusion):
    jobs = [{"name": "Integration result", "conclusion": "success"}]
    with pytest.raises(ValueError, match="missing"):
        ci.require_success(run(), jobs, ["actual integration"])
    jobs.append({"name": "actual integration", "conclusion": conclusion})
    with pytest.raises(ValueError, match="required job"):
        ci.require_success(run(), jobs, ["actual integration"])


def test_all_required_integrations_must_succeed_but_optional_jobs_can_skip():
    jobs = [
        {"name": "live", "conclusion": "success"},
        {"name": "optional", "conclusion": "skipped"},
    ]
    ci.require_success(run(), jobs, ["live"])
