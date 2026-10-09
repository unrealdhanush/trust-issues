"""#2 the no-slop scope check, and #3 telling new findings from old ones."""

import shutil

import pytest
from conftest import ROOT, exploit, finding, scripted_patch

from trust.models import FileEdit, Patch
from trust.prove import Harness

FIXED_SEARCH = (ROOT / "fixtures/scripted/users/attempt-1/app/users.py").read_text()


def users_patch(content):
    return Patch([FileEdit("app/users.py", content)])


def after_search(extra):
    """The proven users fix with `extra` appended at module level."""
    return users_patch(FIXED_SEARCH + extra)


def inside_search(old, new):
    assert old in FIXED_SEARCH
    return users_patch(FIXED_SEARCH.replace(old, new))


@pytest.mark.parametrize("patch, expect", [
    (after_search("\n\ndef _helper():\n    return 1\n"), "adds `_helper`, which nothing uses"),
    (after_search("\nUNUSED = 3\n"), "adds assignment `UNUSED`, which nothing uses"),
    (inside_search('    name = request.args.get("name", "")\n',
                   '    name = request.args.get("name", "")\n    # Use a bound parameter to prevent SQL injection\n'),
     "narrating the change"),
    (inside_search("from flask import", "import logging\nfrom flask import"), "imports a new module `logging`"),
    (inside_search("    conn = get_conn()\n", "    conn = get_conn()\n    print(name)\n"), "adds a print"),
    (after_search('\n\n@bp.route("/users/all")\ndef all_users():\n    return jsonify([])\n'),
     "new decorated function"),
])
def test_slop_fails_scope(users_harness, patch, expect):
    proof = users_harness.prove(1, patch, exploit("users"))
    assert any(expect in v for v in proof.slop), proof.slop
    assert proof.verdict == "failed"


def test_explaining_comment_is_fine(users_harness):
    patch = inside_search("    conn = get_conn()\n",
                          "    # The name is a bound parameter, never part of the SQL text.\n    conn = get_conn()\n")
    proof = users_harness.prove(1, patch, exploit("users"))
    assert proof.scope_clean, proof.slop


def test_touching_another_file_is_out_of_scope(users_harness):
    patch = scripted_patch("users", "attempt-1")
    db = (ROOT / "target/app/db.py").read_text()
    patch.edits.append(FileEdit("app/db.py", db.replace("def get_conn():", "def get_conn():  # noqa")))
    proof = users_harness.prove(1, patch, exploit("users"))
    assert "edits app/db.py, outside the vulnerable file" in proof.slop


def test_rewriting_a_neighbour_function_is_out_of_scope(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "target", target, ignore=shutil.ignore_patterns("__pycache__"))
    neighbour = '\n\n@bp.route("/users/count")\ndef count_users():\n    return jsonify(len(get_conn().execute("SELECT id FROM users").fetchall()))\n'
    (target / "app/users.py").write_text((target / "app/users.py").read_text() + neighbour)
    harness = Harness(target, finding("users", 13), tmp_path / "work")
    rewritten = neighbour.replace("SELECT id FROM users", "SELECT id FROM users WHERE 1 = 1")
    proof = harness.prove(1, users_patch(FIXED_SEARCH + rewritten), exploit("users"))
    assert any("rewrites `count_users`" in v for v in proof.slop), proof.slop


@pytest.fixture
def target_with_old_bug(tmp_path):
    """users.py gets a second, older SQLi in another function. Fixing search_users is still a fix."""
    target = tmp_path / "target"
    shutil.copytree(ROOT / "target", target, ignore=shutil.ignore_patterns("__pycache__"))
    old_bug = (
        '\n\n@bp.route("/users/by-email")\ndef by_email():\n'
        '    email = request.args.get("email", "")\n'
        '    rows = get_conn().execute(f"SELECT id FROM users WHERE email = \'{email}\'").fetchall()\n'
        '    return jsonify([dict(r) for r in rows])\n'
    )
    (target / "app/users.py").write_text((target / "app/users.py").read_text() + old_bug)
    return target, old_bug


def test_preexisting_finding_is_recorded_not_failed(target_with_old_bug, tmp_path):
    target, old_bug = target_with_old_bug
    harness = Harness(target, finding("users", 13), tmp_path / "work")
    proof = harness.prove(1, users_patch(FIXED_SEARCH + old_bug), exploit("users"))
    scan = proof.details["semgrep"]
    assert proof.semgrep_clear and proof.verdict == "proven", proof.reasons
    assert scan["preexisting"] and all("users.py" in f for f in scan["preexisting"])
    assert not scan["introduced"] and not scan["unfixed"]


def test_preexisting_finding_survives_line_shifts(target_with_old_bug, tmp_path):
    target, old_bug = target_with_old_bug
    harness = Harness(target, finding("users", 13), tmp_path / "work")
    # Same fix, plus a constant the function uses: everything below moves down a few lines.
    shifted = FIXED_SEARCH.replace(
        'bp = Blueprint("users", __name__)\n',
        'bp = Blueprint("users", __name__)\n\nSEARCH_SQL = "SELECT id, name, email FROM users WHERE name = ?"\n',
    ).replace('"SELECT id, name, email FROM users WHERE name = ?", (name,)', "SEARCH_SQL, (name,)")
    proof = harness.prove(1, users_patch(shifted + old_bug), exploit("users"))
    assert proof.details["semgrep"]["preexisting"] and not proof.details["semgrep"]["introduced"]
    assert proof.verdict == "proven", proof.reasons


def test_new_finding_introduced_by_the_patch_fails(users_harness):
    sneaky = inside_search(
        '    conn = get_conn()\n',
        '    conn = get_conn()\n    conn.execute(f"INSERT INTO audit VALUES (\'{name}\')")\n',
    )
    proof = users_harness.prove(1, sneaky, exploit("users"))
    assert not proof.semgrep_clear
    assert proof.details["semgrep"]["unfixed"] or proof.details["semgrep"]["introduced"]


def test_new_finding_in_another_function_is_introduced(users_harness):
    sneaky = after_search(
        '\n\n@bp.route("/users/export")\ndef export():\n'
        '    table = request.args.get("t", "users")\n'
        '    return jsonify(len(get_conn().execute("SELECT * FROM " + table).fetchall()))\n'
    )
    proof = users_harness.prove(1, sneaky, exploit("users"))
    assert proof.details["semgrep"]["introduced"], proof.details["semgrep"]
    assert not proof.semgrep_clear


def test_already_failing_test_does_not_count_against_the_fix(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(ROOT / "target", target, ignore=shutil.ignore_patterns("__pycache__"))
    (target / "tests/test_flaky.py").write_text("def test_known_red():\n    assert False\n")
    harness = Harness(target, finding("users", 13), tmp_path / "work")
    proof = harness.prove(1, scripted_patch("users", "attempt-1"), exploit("users"))
    assert proof.suite_pass and proof.verdict == "proven", proof.reasons
    assert proof.details["suite"]["already_failing"] == ["tests/test_flaky.py::test_known_red"]
