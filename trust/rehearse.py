"""`trust call-test`: rehearse the escalation call without running the loop.

Writes a temporary failed fix into the ledger (demo bug 2: the safe fix to `list_orders`
breaks the admin sort test twice), checks that the voice agent's tools can reach this
ledger through PUBLIC_BASE_URL, then escalates with the same code the loop uses. Without
ElevenLabs settings the call is simulated in the terminal. The rows are removed afterwards
unless --keep.
"""

import httpx

from . import voice
from .config import env
from .ledger import get_ledger, now
from .loop import brief_for, escalate, proof_row, say
from .models import Finding, Patch, Proof

PREFIX = "rehearsal-"
FAILING = "tests/test_admin.py::test_orders_custom_sort_expression"


class RehearsalFinding(Finding):
    def __init__(self, fix_id, **kw):
        super().__init__(**kw)
        self._fix_id = fix_id

    @property
    def fix_id(self):
        return self._fix_id


def scenario(fix_id):
    finding = RehearsalFinding(
        fix_id,
        rule_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string",
        path="app/admin.py", line=14, function="list_orders",
        message="User input builds the ORDER BY clause of a SQL query.",
    )
    patch = Patch([], "Replaced the user-supplied ORDER BY with a fixed set of complete queries.")
    first = Proof(
        exploit_pre=True, exploit_post=False, semgrep_clear=False, suite_pass=False,
        failing_tests=[FAILING],
        reasons=[f"existing suite failed: {FAILING}",
                 "Semgrep still flags `list_orders`: tainted-sql-string app/admin.py:15"],
        details={"changed_files": ["app/admin.py"],
                 "semgrep": {"unfixed": ["tainted-sql-string app/admin.py:15"], "introduced": [], "preexisting": []}},
    )
    second = Proof(
        exploit_pre=True, exploit_post=False, semgrep_clear=True, suite_pass=False,
        failing_tests=[FAILING], reasons=[f"existing suite failed: {FAILING}"],
        details={"changed_files": ["app/admin.py"],
                 "semgrep": {"unfixed": [], "introduced": [], "preexisting": []}},
    )
    return finding, [first, second], patch


def preflight(fix_id):
    """Problems that would break a live call, found before the phone rings."""
    problems = []
    if not (voice.configured() or env("ELEVENLABS_AGENT_ID")):
        return problems  # nothing outside this machine will call the tools
    base = env("PUBLIC_BASE_URL").rstrip("/")
    if not base:
        return ["PUBLIC_BASE_URL is unset, so the agent's tools can't reach this machine"]
    try:
        resp = httpx.post(f"{base}/tools/read_ledger", json={"fix_id": fix_id},
                          headers={"x-trust-token": env("TRUST_WEBHOOK_TOKEN")}, timeout=10)
    except httpx.HTTPError as exc:
        return [f"can't reach {base} ({exc.__class__.__name__}); is `trust serve` running and the tunnel up?"]
    if resp.status_code == 401:
        problems.append("the server rejected TRUST_WEBHOOK_TOKEN; .env and the server disagree")
    elif resp.status_code != 200:
        problems.append(f"read_ledger returned HTTP {resp.status_code}: {resp.text[:200]}")
    elif not resp.json().get("found"):
        problems.append("the server can't see the rehearsal rows: it's using a different ledger "
                        "(check CLICKHOUSE_URL / TRUST_RUNS_DIR match in both terminals)")
    return problems


def rehearse(timeout=180, keep=False, force=False):
    fix_id = f"{PREFIX}{now().strftime('%H%M%S')}"
    finding, proofs, patch = scenario(fix_id)
    ledger = get_ledger()
    for attempt, proof in enumerate(proofs, 1):
        ledger.insert(proof_row(finding, attempt, proof, patch))
    say(f"rehearsal {fix_id}: two failed proofs written to the {ledger.kind} ledger")
    try:
        problems = preflight(fix_id)
        for p in problems:
            say(f"preflight: {p}")
        if problems and not force:
            say("not calling; fix the above or pass --force")
            return None
        if env("PUBLIC_BASE_URL") and (voice.configured() or env("ELEVENLABS_AGENT_ID")):
            say(f"preflight ok: tools reach this ledger through {env('PUBLIC_BASE_URL')}")
        if voice.configured():
            say(f"calling {env('ONCALL_PHONE_NUMBER')}")
        elif env("ELEVENLABS_AGENT_ID"):
            say("no phone number set: answer with the ElevenLabs widget on the dashboard "
                "(http://localhost:8000), or `trust-issues decide`")
        else:
            missing = [k for k in ("ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID",
                                   "ELEVENLABS_PHONE_NUMBER_ID", "ONCALL_PHONE_NUMBER") if not env(k)]
            say(f"simulated call (missing {', '.join(missing)}); answer from the dashboard or `trust decide`")
        brief = brief_for(finding, len(proofs), proofs[-1])
        say(f'the agent opens with: "{voice.first_message(brief)}"')
        row = escalate(finding, len(proofs), proofs[-1], patch, 1, timeout=timeout)
        if row.get("transcript"):
            print("\n" + row["transcript"] + "\n")
        elif voice.configured():
            say("no transcript came back; check the call in the ElevenLabs dashboard")
        return row
    finally:
        if keep:
            say(f"kept {fix_id} in the ledger; `trust call-test --cleanup` removes rehearsal rows")
        else:
            ledger.delete(fix_id=fix_id)
