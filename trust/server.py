"""Webhook tools for the voice agent, the dashboard and its API.

Expose it publicly (e.g. `cloudflared tunnel --url http://localhost:8000`) so ElevenLabs can
reach /tools/read_ledger and /tools/write_decision.
"""

import json
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .config import env
from .ledger import get_ledger, normalize, now, pending_escalation

app = FastAPI(title="Trust Issues")
DECISIONS = {"ship", "hold", "retry"}


def check_token(token):
    expected = env("TRUST_WEBHOOK_TOKEN")
    if expected and token != expected:
        raise HTTPException(401, "bad token")


class FixRef(BaseModel):
    fix_id: str


class Decision(BaseModel):
    fix_id: str
    decision: str
    hint: str = ""


def summarize(rows):
    """What the voice agent may say: facts from this fix's ledger rows only."""
    if not rows:
        return {"found": False}
    attempts = []
    for r in rows:
        if r["verdict"] not in ("proven", "failed"):
            continue
        ev = json.loads(r["evidence"] or "{}")
        attempts.append({
            "attempt": r["attempt"],
            "verdict": r["verdict"],
            "exploit_landed_on_original": r["exploit_pre"],
            "exploit_blocked_on_patch": not r["exploit_post"],
            "semgrep_clear": r["semgrep_clear"],
            "suite_pass": r["suite_pass"],
            "stays_in_scope": r["scope_clean"],
            "scope_problems": ev.get("slop", []),
            "failing_tests": r["failing_tests"],
            "findings_left_in_function": ev.get("semgrep", {}).get("unfixed", []),
            "findings_introduced_by_patch": ev.get("semgrep", {}).get("introduced", []),
            "findings_that_predate_patch": ev.get("semgrep", {}).get("preexisting", []),
            "why_it_failed": ev.get("reasons", []),
            "files_changed": ev.get("changed_files", []),
            "patch_summary": ev.get("explanation", ""),
        })
    first = rows[0]
    decisions = [{"attempt": r["attempt"], "decision": r["decision"], "hint": r["hint"]}
                 for r in rows if r["verdict"] == "escalated"]
    return {
        "found": True, "fix_id": first["fix_id"], "vuln_class": first["vuln_class"],
        "file": first["file"], "function": json.loads(first["evidence"] or "{}").get("function", ""), "rule_id": first["rule_id"], "attempts": attempts,
        "escalations": decisions,
    }


def record_decision(d: Decision):
    decision = d.decision.strip().lower()
    if decision not in DECISIONS:
        raise HTTPException(422, f"decision must be one of {sorted(DECISIONS)}")
    if decision == "retry" and not d.hint.strip():
        raise HTTPException(422, "a retry needs a hint")
    ledger = get_ledger()
    row = pending_escalation(ledger.rows(d.fix_id))
    if row is None:
        raise HTTPException(409, f"no escalation is waiting on a decision for {d.fix_id}")
    ledger.insert(normalize({**row, "decision": decision, "hint": d.hint.strip(), "ts": now()}))
    return {"ok": True, "fix_id": d.fix_id, "decision": decision, "hint": d.hint.strip()}


@app.post("/tools/read_ledger")
def read_ledger(ref: FixRef, x_trust_token: str = Header(default="")):
    check_token(x_trust_token)
    return summarize(get_ledger().rows(ref.fix_id))


@app.post("/tools/write_decision")
def write_decision(d: Decision, x_trust_token: str = Header(default="")):
    check_token(x_trust_token)
    return record_decision(d)


@app.get("/api/rows")
def api_rows(fix_id: str | None = None):
    return {"ledger": get_ledger().kind, "rows": get_ledger().rows(fix_id)}


@app.post("/api/decision")
def api_decision(d: Decision):
    return record_decision(d)


@app.get("/api/config")
def api_config():
    return {"agent_id": env("ELEVENLABS_AGENT_ID")}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text()
