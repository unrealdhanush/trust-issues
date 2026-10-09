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


def test_trial_twilio_falls_back_to_a_direct_call(monkeypatch):
    for k, v in {"ELEVENLABS_API_KEY": "k", "ELEVENLABS_AGENT_ID": "agent", "ELEVENLABS_PHONE_NUMBER_ID": "ph",
                 "ONCALL_PHONE_NUMBER": "+15555550100", "TWILIO_ACCOUNT_SID": "AC" + "0" * 32,
                 "TWILIO_AUTH_TOKEN": "0" * 32, "TWILIO_FROM_NUMBER": "+15555550199"}.items():
        monkeypatch.setenv(k, v)
    sent = []

    class Resp:
        def __init__(self, status, payload=None, text=""):
            self.status_code, self._payload, self.text = status, payload, text

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    def post(url, **kw):
        sent.append((url, kw))
        if url.endswith("/outbound-call"):
            return Resp(200, {"success": False, "message": "trial accounts have limited parameter access"})
        if url.endswith("/register-call"):
            return Resp(200, text='"<Response><Connect><Stream url=\\"wss://x\\"/></Connect></Response>"')
        return Resp(201, {"sid": "CA123"})

    monkeypatch.setattr(voice.httpx, "post", post)
    placed = voice.call_oncall({"fix_id": "f1", "file": "app/admin.py"})
    assert placed["via"] == "twilio" and placed["call_sid"] == "CA123" and "trial" in placed["note"]
    register = next(kw for url, kw in sent if url.endswith("/register-call"))
    assert register["json"]["direction"] == "outbound"
    assert register["json"]["conversation_initiation_client_data"]["dynamic_variables"]["fix_id"] == "f1"
    twilio = next(kw for url, kw in sent if url.endswith("/Calls.json"))
    assert twilio["data"]["Twiml"].startswith("<Response>") and twilio["data"]["To"] == "+15555550100"


def test_direct_twilio_call_fetches_instructions_from_our_server(monkeypatch):
    for k, v in {"ELEVENLABS_API_KEY": "k", "ELEVENLABS_AGENT_ID": "agent", "ONCALL_PHONE_NUMBER": "+15555550100",
                 "TWILIO_ACCOUNT_SID": "AC" + "0" * 32, "TWILIO_AUTH_TOKEN": "0" * 32,
                 "TWILIO_FROM_NUMBER": "+15555550199", "PUBLIC_BASE_URL": "https://tunnel.example",
                 "TRUST_WEBHOOK_TOKEN": "s3cret", "TRUST_CALL_VIA": "twilio"}.items():
        monkeypatch.setenv(k, v)
    sent = []

    class Resp:
        status_code = 201
        def json(self):
            return {"sid": "CA9"}

    monkeypatch.setattr(voice.httpx, "post", lambda url, **kw: sent.append((url, kw)) or Resp())
    assert voice.call_oncall({"fix_id": "rehearsal-1"})["call_sid"] == "CA9"
    (url, kw), = sent  # straight to Twilio: ElevenLabs is asked later, when Twilio fetches the URL
    assert url.endswith("/Calls.json") and "Twiml" not in kw["data"]
    assert kw["data"]["Url"] == "https://tunnel.example/twilio/connect?fix_id=rehearsal-1&t=s3cret"


def test_twilio_connect_serves_the_escalation_brief(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from trust import ledger as ledger_mod
    from trust.ledger import FileLedger
    from trust.server import app

    led = FileLedger(tmp_path / "l.jsonl")
    monkeypatch.setattr(ledger_mod, "_ledger", led)
    monkeypatch.setenv("TRUST_WEBHOOK_TOKEN", "s3cret")
    led.insert({"fix_id": "f1", "attempt": 2, "verdict": "escalated",
                "evidence": {"brief": {"fix_id": "f1", "failed_check": "breaks the admin test"}}})
    seen = {}
    monkeypatch.setattr(voice, "register_call", lambda d: seen.update(d) or "<Response/>")
    http = TestClient(app)
    assert http.post("/twilio/connect?fix_id=f1&t=wrong").status_code == 401
    r = http.post("/twilio/connect?fix_id=f1&t=s3cret")
    assert r.status_code == 200 and r.text == "<Response/>" and "xml" in r.headers["content-type"]
    assert seen["failed_check"] == "breaks the admin test"
    assert http.post("/twilio/connect?fix_id=nope&t=s3cret").status_code == 404
