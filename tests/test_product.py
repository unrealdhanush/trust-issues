"""Product features: relevant context, the target's interpreter, monitoring, pull requests."""

import shutil
import subprocess
import sys

import pytest
from conftest import ROOT, finding, scripted_patch

from trust import watch as watch_mod
from trust.context import relevant_files
from trust.prove import target_python
from trust.publish import github_repo, open_pr


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A git copy of the demo target, with a bare repo standing in for GitHub as origin."""
    for k, v in {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}.items():
        monkeypatch.setenv(k, v)
    work, remote = tmp_path / "repo", tmp_path / "remote.git"
    shutil.copytree(ROOT / "target", work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    sh(tmp_path, "git", "init", "-q", "--bare", str(remote))
    sh(work, "git", "init", "-q", "-b", "main")
    sh(work, "git", "add", ".")
    sh(work, "git", "commit", "-q", "-m", "init")
    sh(work, "git", "remote", "add", "origin", str(remote))
    sh(work, "git", "push", "-q", "-u", "origin", "main")
    return work, remote


def test_context_is_the_vulnerable_file_its_imports_and_its_tests():
    files = relevant_files(ROOT / "target", finding("admin", 14))
    assert list(files) == ["app/admin.py", "app/db.py", "tests/conftest.py", "tests/test_admin.py"]


def test_tests_run_in_the_targets_own_venv(tmp_path, monkeypatch):
    assert target_python(tmp_path) == sys.executable
    exe = tmp_path / ".venv" / "bin" / "python"
    exe.parent.mkdir(parents=True)
    exe.write_text("")
    assert target_python(tmp_path) == str(exe)
    monkeypatch.setenv("TRUST_TARGET_PYTHON", "/opt/py")
    assert target_python(tmp_path) == "/opt/py"


def test_intervals():
    assert [watch_mod.parse_interval(x) for x in ("30s", "15m", "6h", "1d", "90")] == [30, 900, 21600, 86400, 90]
    with pytest.raises(ValueError):
        watch_mod.parse_interval("soon")


def test_watch_fixes_new_findings_once_and_rechecks_changed_code(repo, tmp_path, monkeypatch):
    work, _ = repo
    monkeypatch.setattr(watch_mod, "STATE_FILE", tmp_path / "state.json")
    seen = []
    fixer = lambda f: seen.append(f.function) or "proven"
    state = watch_mod.load_state()

    watch_mod.cycle(work, fixer, state)
    assert sorted(seen) == ["list_orders", "search_users"]

    seen.clear()
    watch_mod.cycle(work, fixer, state)
    assert seen == []  # handled, code unchanged

    users = work / "app/users.py"
    users.write_text(users.read_text().replace('request.args.get("name", "")', 'request.args.get("name", "").strip()'))
    watch_mod.cycle(work, fixer, state)
    assert seen == ["search_users"]  # someone touched the vulnerable function: check it again


def test_watch_changed_only_looks_at_new_commits(repo, tmp_path, monkeypatch):
    work, _ = repo
    monkeypatch.setattr(watch_mod, "STATE_FILE", tmp_path / "state.json")
    seen = []
    state = watch_mod.load_state()
    watch_mod.cycle(work, lambda f: "held", state, changed_only=True)
    seen_first = state["targets"][str(work.resolve())]["handled"]
    assert len(seen_first) == 2

    admin = work / "app/admin.py"
    admin.write_text(admin.read_text().replace('request.args.get("sort", "id")', 'request.args.get("sort", "id") or "id"'))
    sh(work, "git", "commit", "-qam", "touch admin")
    watch_mod.cycle(work, lambda f: seen.append(f.path) or "held", state, changed_only=True)
    assert seen == ["app/admin.py"]


def test_open_pr_pushes_a_branch_without_touching_the_checkout(repo, monkeypatch):
    work, remote = repo
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    before = (work / "app/users.py").read_text()
    ref = open_pr(work, finding("users", 13), scripted_patch("users", "attempt-1"), "body")
    branch = "trust-issues/" + finding("users", 13).fix_id
    assert ref == branch  # not a GitHub remote: no PR API, the branch is the deliverable
    assert (work / "app/users.py").read_text() == before
    assert sh(work, "git", "status", "--porcelain") == ""
    assert sh(work, "git", "branch", "--show-current") == "main"
    pushed = sh(remote, "git", "show", f"{branch}:app/users.py")
    assert "WHERE name = ?" in pushed
    assert "Fix SQL injection in app/users.py (search_users)" in sh(remote, "git", "log", "-1", "--format=%s", branch)
    assert sh(work, "git", "worktree", "list").count("\n") == 0  # temporary worktree removed


def test_open_pr_outside_git_is_a_no_op(tmp_path):
    shutil.copytree(ROOT / "target", tmp_path / "plain")
    assert open_pr(tmp_path / "plain", finding("users", 13), scripted_patch("users", "attempt-1"), "b") is None


def test_github_remotes_parse():
    assert github_repo("git@github.com:acme/shop.git") == ("acme", "shop")
    assert github_repo("https://github.com/acme/shop") == ("acme", "shop")
    assert github_repo("/tmp/remote.git") is None


def test_watch_changed_only_works_when_the_target_is_a_subfolder(tmp_path, monkeypatch):
    """Inception: the target is target/ inside a bigger repo, as in this repo's own workflow."""
    for k, v in {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(watch_mod, "STATE_FILE", tmp_path / "state.json")
    outer = tmp_path / "outer"
    shutil.copytree(ROOT / "target", outer / "target", ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    sh(outer, "git", "init", "-q", "-b", "main")
    sh(outer, "git", "add", ".")
    sh(outer, "git", "commit", "-q", "-m", "init")
    state = watch_mod.load_state()
    watch_mod.cycle(outer / "target", lambda f: "held", state, changed_only=True)
    users = outer / "target/app/users.py"
    users.write_text(users.read_text().replace('request.args.get("name", "")', 'request.args.get("name", "").strip()'))
    sh(outer, "git", "commit", "-qam", "touch users")
    seen = []
    watch_mod.cycle(outer / "target", lambda f: seen.append(f.path) or "held", state, changed_only=True)
    assert seen == ["app/users.py"]


def test_pr_carries_the_exploit_as_a_regression_test(repo, tmp_path, monkeypatch):
    """The proof becomes a guard: the PR adds the exploit, it passes on the fix, and it fails
    the moment the vulnerable code comes back."""
    from trust import ledger as ledger_mod
    from trust import loop
    from trust.agent import ScriptedAgent
    from trust.ledger import FileLedger

    work, remote = repo
    monkeypatch.setattr(ledger_mod, "_ledger", FileLedger(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(loop, "RUNS_DIR", tmp_path / "runs")
    f = finding("users", 13)
    assert loop.fix(work, f, ScriptedAgent(), open_pr=True) == "proven"

    branch = f"trust-issues/{f.fix_id}"
    test_path = f"tests/test_security_{f.key.replace('-', '_')}.py"
    files = sh(remote, "git", "ls-tree", "-r", "--name-only", branch).splitlines()
    assert test_path in files
    assert "Adds `" + test_path in (tmp_path / "runs" / f.fix_id / "PR.md").read_text()

    clone = tmp_path / "clone"
    sh(tmp_path, "git", "clone", "-q", "-b", branch, str(remote), str(clone))
    run = lambda: subprocess.run([sys.executable, "-m", "pytest", "-q", test_path], cwd=clone,
                                 capture_output=True, text=True)
    assert run().returncode == 0, "the regression test passes on the fix"
    (clone / "app/users.py").write_text((ROOT / "target/app/users.py").read_text())
    assert run().returncode != 0, "and fails when the vulnerable code returns"


def test_a_bug_that_comes_back_is_a_new_incident(tmp_path, monkeypatch):
    """Same bug, same place, twice: two incidents in the ledger, neither overwriting the other."""
    from trust import ledger as ledger_mod
    from trust import loop
    from trust.agent import ScriptedAgent
    from trust.ledger import FileLedger

    led = FileLedger(tmp_path / "ledger.jsonl")
    monkeypatch.setattr(ledger_mod, "_ledger", led)
    monkeypatch.setattr(loop, "RUNS_DIR", tmp_path / "runs")
    first, second = finding("users", 13), finding("users", 13)
    first.run, second.run = "1009120000", "1009130000"
    assert loop.fix(ROOT / "target", first, ScriptedAgent()) == "proven"
    assert loop.fix(ROOT / "target", second, ScriptedAgent()) == "proven"

    assert first.key == second.key and first.fix_id != second.fix_id
    by_fix = {}
    for r in led.rows():
        by_fix.setdefault(r["fix_id"], []).append(r["verdict"])
    assert by_fix == {first.fix_id: ["proven"], second.fix_id: ["proven"]}
