import json

import pytest
from fastapi.testclient import TestClient

from trust import ledger as ledger_mod
from trust.ledger import FileLedger, pending_escalation


@pytest.fixture
def client(tmp_path, monkeypatch):
    led = FileLedger(tmp_path / "ledger.jsonl")
    monkeypatch.setattr(ledger_mod, "_ledger", led)
    from trust.server import app

    return TestClient(app), led


def attempt_row(n, verdict, **kw):
    return {"fix_id": "sqli-admin-x", "attempt": n, "file": "app/admin.py", "rule_id": "r",
            "exploit_pre": True, "exploit_post": False, "semgrep_clear": True, "suite_pass": False,
            "verdict": verdict, "failing_tests": ["tests/test_admin.py::test_sort"],
            "evidence": {"reasons": ["existing suite failed: tests/test_admin.py::test_sort"]}, **kw}


def test_latest_row_per_key_wins(tmp_path):
    led = FileLedger(tmp_path / "l.jsonl")
    led.insert(attempt_row(2, "escalated"))
    led.insert(attempt_row(2, "escalated", decision="hold"))
    rows = led.rows("sqli-admin-x")
    assert len(rows) == 1 and rows[0]["decision"] == "hold"
    assert pending_escalation(rows) is None


def test_read_ledger_answers_which_test_broke(client):
    http, led = client
    led.insert(attempt_row(1, "failed"))
    led.insert(attempt_row(2, "failed"))
    led.insert(attempt_row(2, "escalated"))
    out = http.post("/tools/read_ledger", json={"fix_id": "sqli-admin-x"}).json()
    assert out["file"] == "app/admin.py"
    assert [a["failing_tests"] for a in out["attempts"]] == [["tests/test_admin.py::test_sort"]] * 2
    assert out["escalations"] == [{"attempt": 2, "decision": "", "hint": ""}]


def test_unknown_fix_is_not_found(client):
    http, _ = client
    assert http.post("/tools/read_ledger", json={"fix_id": "nope"}).json() == {"found": False}


def test_write_decision_validates_and_records(client):
    http, led = client
    led.insert(attempt_row(2, "escalated"))
    assert http.post("/tools/write_decision", json={"fix_id": "sqli-admin-x", "decision": "merge"}).status_code == 422
    assert http.post("/tools/write_decision", json={"fix_id": "sqli-admin-x", "decision": "retry"}).status_code == 422
    ok = http.post("/tools/write_decision",
                   json={"fix_id": "sqli-admin-x", "decision": "Retry", "hint": "update the sort test"})
    assert ok.json()["decision"] == "retry"
    row = led.rows("sqli-admin-x")[-1]
    assert (row["decision"], row["hint"]) == ("retry", "update the sort test")
    # Nothing is waiting any more, so a second decision is refused.
    assert http.post("/tools/write_decision", json={"fix_id": "sqli-admin-x", "decision": "ship"}).status_code == 409


def test_token_is_enforced_when_set(client, monkeypatch):
    http, led = client
    monkeypatch.setenv("TRUST_WEBHOOK_TOKEN", "s3cret")
    assert http.post("/tools/read_ledger", json={"fix_id": "x"}).status_code == 401
    assert http.post("/tools/read_ledger", json={"fix_id": "x"}, headers={"x-trust-token": "s3cret"}).status_code == 200


def test_clickhouse_ledger_retries_once_on_a_fresh_connection(monkeypatch):
    from trust.ledger import ClickHouseLedger

    calls = {"connect": 0, "query": 0}

    class FlakyClient:
        def query(self, *a, **k):
            calls["query"] += 1
            if calls["query"] == 1:
                raise ConnectionResetError("stale pooled connection")
            class Res:
                def named_results(self):
                    return iter([])
            return Res()

    def connect(self):
        calls["connect"] += 1
        return FlakyClient()

    monkeypatch.setattr(ClickHouseLedger, "_connect", connect)
    monkeypatch.setattr("trust.ledger.time.sleep", lambda s: None)
    led = ClickHouseLedger("https://example.clickhouse.cloud:8443", "pw")
    assert led.rows("x") == []
    assert calls == {"connect": 2, "query": 2}
