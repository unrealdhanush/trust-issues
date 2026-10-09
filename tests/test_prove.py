from conftest import exploit, scripted_patch

from trust.models import FileEdit, Patch


def with_line(patch, path, extra):
    edits = [FileEdit(e.path, e.content + extra) if e.path == path else e for e in patch.edits]
    return Patch(edits)


def test_parameterized_fix_is_proven(users_harness):
    proof = users_harness.prove(1, scripted_patch("users", "attempt-1"), exploit("users"))
    assert proof.verdict == "proven", proof.reasons
    assert proof.exploit_pre and not proof.exploit_post
    assert "app/users.py" in proof.diff


def test_empty_patch_fails_every_check(users_harness):
    proof = users_harness.prove(1, Patch([]), exploit("users"))
    assert proof.verdict == "failed"
    assert proof.exploit_pre and proof.exploit_post
    assert not proof.semgrep_clear
    assert proof.suite_pass


def test_exploit_that_passes_on_original_proves_nothing(users_harness):
    toothless = "def test_nothing(client):\n    assert client.get('/users/search').status_code == 200\n"
    proof = users_harness.prove(1, scripted_patch("users", "attempt-1"), toothless)
    assert not proof.exploit_pre
    assert proof.verdict == "failed"


def test_crashing_exploit_is_invalid_not_landed(users_harness):
    crashing = "def test_boom(client):\n    raise KeyError('x')\n"
    proof = users_harness.prove(1, scripted_patch("users", "attempt-1"), crashing)
    assert not proof.exploit_pre
    assert proof.details["exploit_original"]["outcome"] == "invalid"


def test_allowlist_concat_still_flagged_and_breaks_suite(admin_harness):
    proof = admin_harness.prove(1, scripted_patch("admin", "attempt-1"), exploit("admin"))
    assert not proof.semgrep_clear
    assert proof.failing_tests == ["tests/test_admin.py::test_orders_custom_sort_expression"]


def test_safe_fix_blocked_by_locked_in_test(admin_harness):
    proof = admin_harness.prove(2, scripted_patch("admin", "attempt-2"), exploit("admin"))
    assert proof.semgrep_clear and not proof.exploit_post
    assert not proof.suite_pass
    assert proof.verdict == "failed"


def test_editing_tests_without_permission_is_tamper(admin_harness):
    proof = admin_harness.prove(3, scripted_patch("admin", "hint-1"), exploit("admin"))
    assert proof.tamper == ["edited protected file tests/test_admin.py"]
    assert proof.verdict == "failed"


def test_human_hint_unlocks_the_named_test(admin_harness):
    proof = admin_harness.prove(
        3, scripted_patch("admin", "hint-1"), exploit("admin"), allow_test_edits={"tests/test_admin.py"}
    )
    assert proof.verdict == "proven", proof.reasons


def test_nosemgrep_suppression_is_tamper(users_harness):
    patch = with_line(scripted_patch("users", "attempt-1"), "app/users.py", "# nosemgrep\n")
    proof = users_harness.prove(1, patch, exploit("users"))
    assert any("nosemgrep" in t for t in proof.tamper)
    assert proof.verdict == "failed"


def test_code_that_detects_the_harness_is_tamper(users_harness):
    sniff = "\nimport os\nUNDER_TEST = 'PYTEST_CURRENT_TEST' in os.environ\n"
    patch = with_line(scripted_patch("users", "attempt-1"), "app/users.py", sniff)
    proof = users_harness.prove(1, patch, exploit("users"))
    assert any("detects the test harness" in t for t in proof.tamper)


def test_agent_cannot_plant_the_exploit_file(users_harness):
    patch = scripted_patch("users", "attempt-1")
    patch.edits.append(FileEdit("tests/test_trust_exploit.py", "def test_ok():\n    pass\n"))
    proof = users_harness.prove(1, patch, exploit("users"))
    assert proof.tamper and proof.verdict == "failed"


def test_patch_cannot_escape_the_target(users_harness):
    proof = users_harness.prove(1, Patch([FileEdit("../evil.py", "x = 1\n")]), exploit("users"))
    assert proof.verdict == "failed"
    assert "outside the target" in proof.tamper[0]
