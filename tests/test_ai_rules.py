"""The AI-patch rule pack (rules/ai-patch.yml): Semgrep catching the ways an AI-written fix goes wrong."""

import subprocess

from conftest import ROOT, exploit, scripted_patch

from trust import semgrep
from trust.models import FileEdit, Patch

FIXED = (ROOT / "fixtures/scripted/users/attempt-1/app/users.py").read_text()
VULNERABLE_QUERY = '''    rows = conn.execute(
        "SELECT id, name, email FROM users WHERE name = ?", (name,)
    ).fetchall()'''


def users_patch(content):
    return Patch([FileEdit("app/users.py", content)])


def test_rule_pack_passes_semgreps_own_tests():
    out = subprocess.run(["semgrep", "--test", str(ROOT / "rules")], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_nosemgrep_cannot_hide_from_the_pack():
    hits = semgrep.scan_ai_rules([ROOT / "rules" / "ai-patch.py"])
    lines = {(h["check_id"].rsplit(".", 1)[-1], h["start"]["line"]) for h in hits}
    assert ("ai-patch-scanner-suppression", 9) in lines  # the line ending in `# nosemgrep`


def test_llm_style_escaping_fix_is_caught(users_harness):
    escaped = FIXED.replace(VULNERABLE_QUERY, '''    safe = name.replace("'", "''")
    rows = conn.execute(
        f"SELECT id, name, email FROM users WHERE name = '{safe}'"
    ).fetchall()''')
    proof = users_harness.prove(1, users_patch(escaped), exploit("users"))
    assert any("ai-patch-handrolled-sql-escaping" in f for f in proof.details["semgrep"]["ai_patch"])
    assert any("AI-patch rules caught the patch" in r for r in proof.reasons)
    assert proof.verdict == "failed"


def test_swallowed_db_error_is_caught(users_harness):
    swallowed = FIXED.replace(VULNERABLE_QUERY, '''    try:
        rows = conn.execute(
            "SELECT id, name, email FROM users WHERE name = ?", (name,)
        ).fetchall()
    except Exception:
        rows = []''')
    proof = users_harness.prove(1, users_patch(swallowed), exploit("users"))
    assert any("ai-patch-swallowed-db-error" in f for f in proof.details["semgrep"]["ai_patch"])
    assert not proof.semgrep_clear and proof.verdict == "failed"


def test_suppression_comment_is_caught_by_semgrep_not_just_the_guard(users_harness):
    suppressed = FIXED.replace('"SELECT id, name, email FROM users WHERE name = ?", (name,)',
                               '"SELECT id, name, email FROM users WHERE name = ?", (name,)  # nosemgrep')
    proof = users_harness.prove(1, users_patch(suppressed), exploit("users"))
    assert any("ai-patch-scanner-suppression" in f for f in proof.details["semgrep"]["ai_patch"])
    assert proof.tamper  # the guard flags it too: belt and braces


def test_a_clean_fix_trips_nothing(users_harness):
    proof = users_harness.prove(1, scripted_patch("users", "attempt-1"), exploit("users"))
    assert proof.details["semgrep"]["ai_patch"] == []
    assert proof.verdict == "proven", proof.reasons
