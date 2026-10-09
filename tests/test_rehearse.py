import threading
import time

import pytest

from trust import ledger as ledger_mod
from trust import voice
from trust.ledger import FileLedger, pending_escalation
from trust.rehearse import PREFIX, rehearse
from trust.server import Decision, record_decision


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    led = FileLedger(tmp_path / "ledger.jsonl")
    monkeypatch.setattr(ledger_mod, "_ledger", led)
    for k in ("ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID", "ELEVENLABS_PHONE_NUMBER_ID", "ONCALL_PHONE_NUMBER"):
        monkeypatch.delenv(k, raising=False)
    return led


def answer_when_ringing(led, decision, hint=""):
    def run():
        for _ in range(100):
            waiting = pending_escalation(led.rows())
            if waiting:
                record_decision(Decision(fix_id=waiting["fix_id"], decision=decision, hint=hint))
                return
            time.sleep(0.05)
    t = threading.Thread(target=run)
    t.start()
    return t


def test_simulated_call_records_decision_then_cleans_up(ledger):
    t = answer_when_ringing(ledger, "retry", "you can update the admin sort test")
    row = rehearse(timeout=10)
    t.join()
    assert row["fix_id"].startswith(PREFIX)
    assert (row["decision"], row["hint"]) == ("retry", "you can update the admin sort test")
    assert ledger.rows() == []


def test_keep_leaves_rows_and_cleanup_prefix_removes_them(ledger):
    t = answer_when_ringing(ledger, "hold")
    row = rehearse(timeout=10, keep=True)
    t.join()
    assert {r["verdict"] for r in ledger.rows(row["fix_id"])} == {"failed", "escalated"}
    ledger.insert({"fix_id": "sqli-admin-real", "attempt": 1, "verdict": "proven"})
    ledger.delete(prefix=PREFIX)
    assert [r["fix_id"] for r in ledger.rows()] == ["sqli-admin-real"]


def test_live_call_refused_without_a_public_url(ledger, monkeypatch):
    for k in ("ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID", "ELEVENLABS_PHONE_NUMBER_ID"):
        monkeypatch.setenv(k, "x")
    monkeypatch.setenv("ONCALL_PHONE_NUMBER", "+15555550100")
    monkeypatch.setenv("PUBLIC_BASE_URL", "")
    assert rehearse(timeout=1) is None
    assert ledger.rows() == []


def test_opening_line_fills_the_brief():
    line = voice.first_message({"vuln_class": "SQL injection", "file": "app/admin.py",
                                "failed_check": "the fix breaks an existing test"})
    assert "SQL injection in app/admin.py: the fix breaks an existing test" in line
    assert "{{" not in line


def test_test_names_are_spoken_not_read():
    from trust.loop import failed_check
    from trust.models import Proof

    assert voice.spoken_test("tests/test_admin.py::test_orders_custom_sort_expression") == \
        "the admin test for orders custom sort expression"
    proof = Proof(True, False, True, False, failing_tests=["tests/test_admin.py::test_orders_custom_sort_expression"])
    line = failed_check(proof)
    assert "::" not in line and "_" not in line and "tests/" not in line


def test_transcript_keeps_tool_calls():
    conv = {"transcript": [
        {"role": "agent", "message": "Should I update that test?"},
        {"role": "user", "message": "Yes."},
        {"role": "agent", "message": None, "tool_calls": [
            {"tool_name": "write_decision", "params_as_json": '{"decision": "retry"}'}]},
    ]}
    text = voice.transcript_text(conv)
    assert "user: Yes." in text and 'agent: [write_decision {"decision": "retry"}]' in text
