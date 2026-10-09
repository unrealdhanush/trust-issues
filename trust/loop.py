"""The loop: detect -> patch -> prove -> (escalate) -> ship, hold or retry.

    trust run                         # every SQLi finding in ./target, one at a time
    trust run --only app/admin.py     # just one file
    trust decide <fix_id> retry --hint "you can update the admin sort test"
    trust ledger                      # print the ledger
    trust serve                       # webhook tools + dashboard on :8000
    trust call-test                   # rehearse the escalation call on a canned failed fix
"""

import argparse
import json
import shutil
import time
from pathlib import Path

from . import semgrep, voice
from .agent import get_agent
from .config import DECISION_TIMEOUT, MAX_ESCALATIONS, MAX_PROOFS, RUNS_DIR, ROOT
from .ledger import get_ledger, normalize, now, pending_escalation
from .models import Finding, Patch, Proof
from .prove import Harness


def say(msg):
    print(f"[trust] {msg}", flush=True)


def proof_row(finding: Finding, attempt, proof: Proof, patch: Patch, verdict=None):
    return {
        "fix_id": finding.fix_id, "attempt": attempt, "vuln_class": finding.vuln_class,
        "file": finding.path, "rule_id": finding.rule_id,
        "exploit_pre": proof.exploit_pre, "exploit_post": proof.exploit_post,
        "semgrep_clear": proof.semgrep_clear, "suite_pass": proof.suite_pass,
        "scope_clean": proof.scope_clean,
        "verdict": verdict or proof.verdict, "failing_tests": proof.failing_tests,
        "evidence": {
            "function": finding.function,
            "reasons": proof.reasons, "tamper": proof.tamper, "slop": proof.slop,
            "explanation": patch.explanation,
            "changed_files": proof.details.get("changed_files", []),
            "allow_test_edits": proof.details.get("allow_test_edits", []),
            "semgrep": proof.details.get("semgrep", {}), "diff": proof.diff[:8000],
        },
    }


def failed_check(proof: Proof):
    """One spoken sentence on why proof failed."""
    if proof.tamper:
        return "the patch tried to change what grades it"
    if not proof.exploit_pre:
        return "the exploit test didn't reproduce the bug on the original code"
    if proof.exploit_post:
        return "the exploit still works on the patched code"
    if not proof.suite_pass:
        names = ", ".join(t.rsplit("::", 1)[-1] for t in proof.failing_tests) or "the suite"
        return f"the fix breaks an existing test, {names}"
    if not proof.semgrep_clear:
        if proof.details.get("semgrep", {}).get("introduced"):
            return "the patch introduces a new security finding"
        return "Semgrep still flags the function after the patch"
    if proof.slop:
        return "the patch changes more than the vulnerable function"
    return "proof failed"


def save_artifacts(finding, attempt, proof, patch, status):
    out = RUNS_DIR / finding.fix_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "fix.diff").write_text(proof.diff)
    checks = [
        ("Exploit lands on the original code", proof.exploit_pre),
        ("Exploit is blocked on the patch", not proof.exploit_post),
        ("Semgrep re-scan is clean", proof.semgrep_clear),
        ("Existing suite passes", proof.suite_pass),
        ("Agent left tests and scan config alone", not proof.tamper),
        (f"Patch stays inside `{finding.function}`", proof.scope_clean),
    ]
    body = [
        f"# Fix {finding.vuln_class.upper()} in `{finding.path}`", "",
        f"Semgrep `{finding.rule_id}` (line {finding.line}). Status: **{status}** after attempt {attempt}.",
        "", patch.explanation, "", "## Proof", "",
        *[f"- [{'x' if ok else ' '}] {name}" for name, ok in checks],
    ]
    scan = proof.details.get("semgrep", {})
    if scan.get("preexisting"):
        body += ["", "Pre-existing findings, not introduced by this patch: "
                 + ", ".join(f"`{f}`" for f in scan["preexisting"])]
    approved = proof.details.get("allow_test_edits") or []
    if approved:
        body += ["", "Test files changed with on-call approval: " + ", ".join(f"`{t}`" for t in approved)]
    if proof.reasons:
        body += ["", "## Open issues", "", *[f"- {r}" for r in proof.reasons]]
    body += ["", "## Diff", "", "```diff", proof.diff, "```", ""]
    (out / "PR.md").write_text("\n".join(body))
    return out


def apply_to_target(target, patch: Patch):
    for edit in patch.edits:
        dest = Path(target) / edit.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(edit.content)


def wait_for_decision(fix_id, attempt, timeout=DECISION_TIMEOUT):
    ledger = get_ledger()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for r in ledger.rows(fix_id):
            if r["verdict"] == "escalated" and int(r["attempt"]) == attempt and r["decision"]:
                return r
        time.sleep(2)
    say(f"no decision within {timeout}s; holding")
    row = pending_escalation(ledger.rows(fix_id))
    return ledger.insert({**row, "decision": "hold", "hint": "timed out waiting for on-call", "ts": now()})


def fetch_transcript(conversation_id, timeout=90):
    deadline = time.time() + timeout
    conv = {}
    while time.time() < deadline:
        try:
            conv = voice.conversation(conversation_id)
        except Exception as exc:
            say(f"couldn't fetch the call transcript: {exc!r}")
            return ""
        if conv.get("status") in ("done", "failed"):
            break
        time.sleep(3)
    return voice.transcript_text(conv)


def brief_for(finding: Finding, attempt, proof: Proof):
    """The voice agent's dynamic variables: what it knows when the call connects."""
    return {
        "fix_id": finding.fix_id, "vuln_class": "SQL injection", "file": finding.path,
        "failed_check": failed_check(proof), "attempts": attempt,
        "failing_tests": ", ".join(proof.failing_tests) or "none",
    }


def escalate(finding: Finding, attempt, proof: Proof, patch: Patch, number, timeout=DECISION_TIMEOUT):
    """Write the escalation row, call on-call, and return the escalation row once decided."""
    ledger = get_ledger()
    ledger.insert(proof_row(finding, attempt, proof, patch, verdict="escalated"))
    brief = brief_for(finding, attempt, proof)
    conversation_id = None
    if voice.configured():
        say(f"escalation {number}: calling on-call about {finding.fix_id}")
        try:
            conversation_id = voice.call_oncall(brief)
        except Exception as exc:
            say(f"call failed ({exc!r}); decide from the dashboard instead")
    if not conversation_id:
        say(f"escalation {number}: {brief['failed_check']}")
        say(f"decide on the dashboard, or: trust decide {finding.fix_id} ship|hold|retry --hint '...'")
    row = wait_for_decision(finding.fix_id, attempt, timeout=timeout)
    if conversation_id:
        transcript = fetch_transcript(conversation_id)
        if transcript:
            row = ledger.insert({**row, "transcript": transcript, "ts": now()})
    say(f"decision: {row['decision']}" + (f" (hint: {row['hint']})" if row["hint"] else ""))
    return row


def fix(target, finding: Finding, agent, apply=False):
    ledger = get_ledger()
    say(f"{finding.fix_id}: {finding.rule_short} in {finding.path}:{finding.line} ({finding.function})")
    workdir = RUNS_DIR / finding.fix_id / "work"
    harness = Harness(target, finding, workdir)
    base_ran, base_failing = harness.baseline()
    if not base_ran:
        say("the target's suite doesn't run on the original code; can't prove anything against it")
        return "blocked"
    if base_failing:
        say(f"already failing before any patch (won't count against the fix): {', '.join(base_failing)}")

    exploit = agent.exploit(target, finding)
    history, hint, allow = [], "", set()
    failures, escalations, attempt = 0, 0, 0
    while True:
        attempt += 1
        patch = agent.patch(target, finding, history, hint=hint, allow_test_edits=allow)
        proof = harness.prove(attempt, patch, exploit, allow_test_edits=allow)
        ledger.insert(proof_row(finding, attempt, proof, patch))
        mark = lambda ok: "pass" if ok else "FAIL"
        say(f"attempt {attempt}: exploit-original {mark(proof.exploit_pre)} · exploit-patch "
            f"{mark(not proof.exploit_post)} · semgrep {mark(proof.semgrep_clear)} · suite "
            f"{mark(proof.suite_pass)} · guard {mark(not proof.tamper)} · scope "
            f"{mark(proof.scope_clean)} -> {proof.verdict}")
        for r in proof.reasons:
            say(f"  - {r}")

        if proof.proven:
            out = save_artifacts(finding, attempt, proof, patch, "proven")
            if apply:
                apply_to_target(target, patch)
            say(f"proven. PR body and diff in {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
            return "proven"

        if not proof.exploit_pre:
            exploit = agent.exploit(target, finding, feedback="\n".join(proof.reasons))
        history.append(proof)
        failures += 1
        if failures < MAX_PROOFS:
            continue
        if escalations >= MAX_ESCALATIONS:
            save_artifacts(finding, attempt, proof, patch, "held")
            say("out of escalations; holding")
            return "held"
        escalations += 1
        row = escalate(finding, attempt, proof, patch, escalations)
        decision, hint = row["decision"], row["hint"]
        if decision == "ship":
            out = save_artifacts(finding, attempt, proof, patch, "shipped without proof (on-call decision)")
            if apply:
                apply_to_target(target, patch)
            return "shipped"
        if decision == "hold":
            out = save_artifacts(finding, attempt, proof, patch, "held for review (on-call decision)")
            (out / "TICKET.md").write_text(
                f"# Review unproven fix {finding.fix_id}\n\n{failed_check(proof)}.\n\n"
                + "\n".join(f"- {r}" for r in proof.reasons) + "\n")
            return "held"
        # retry: the human's call unlocks the tests that broke, and only those.
        allow = {t.split("::", 1)[0] for t in proof.failing_tests}
        failures = 0


def cmd_run(args):
    target = Path(args.target).resolve()
    agent = get_agent()
    findings, engine = semgrep.sqli_findings(target)
    say(f"Semgrep ({engine}) found {len(findings)} SQL injection finding(s); agent: {agent.name}; "
        f"ledger: {get_ledger().kind}")
    if args.only:
        findings = [f for f in findings if f.path == args.only]
    if args.fresh:
        for f in findings:
            shutil.rmtree(RUNS_DIR / f.fix_id, ignore_errors=True)
    results = {f.fix_id: fix(target, f, agent, apply=args.apply) for f in findings}
    say("done: " + json.dumps(results))


def cmd_decide(args):
    from .server import Decision, record_decision

    print(record_decision(Decision(fix_id=args.fix_id, decision=args.decision, hint=args.hint)))


def cmd_ledger(args):
    for r in get_ledger().rows(args.fix_id):
        flags = " ".join(f"{k}={'Y' if r[k] else 'n'}" for k in ("exploit_pre", "exploit_post", "semgrep_clear", "suite_pass", "scope_clean"))
        extra = f" decision={r['decision']} hint={r['hint']!r}" if r["verdict"] == "escalated" else ""
        print(f"{r['ts'][:19]} {r['fix_id']} #{r['attempt']} {r['verdict']:<9} {flags}{extra}")


def cmd_call_test(args):
    import os

    from .rehearse import PREFIX, rehearse

    if args.cleanup:
        get_ledger().delete(prefix=PREFIX)
        say("removed every rehearsal row from the ledger")
        return
    if args.to:
        os.environ["ONCALL_PHONE_NUMBER"] = args.to
    row = rehearse(timeout=args.timeout, keep=args.keep, force=args.force)
    if row is None:
        raise SystemExit(1)


def cmd_serve(args):
    import uvicorn

    uvicorn.run("trust.server:app", host=args.host, port=args.port)


def main():
    p = argparse.ArgumentParser(prog="trust", description="It has trust issues, so you don't have to.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--target", default=str(ROOT / "target"))
    r.add_argument("--only", help="only fix the finding in this file, e.g. app/admin.py")
    r.add_argument("--apply", action="store_true", help="write proven (or shipped) fixes into the target")
    r.add_argument("--fresh", action="store_true", help="clear previous run artifacts for these fixes")
    r.set_defaults(func=cmd_run)
    d = sub.add_parser("decide")
    d.add_argument("fix_id")
    d.add_argument("decision", choices=["ship", "hold", "retry"])
    d.add_argument("--hint", default="")
    d.set_defaults(func=cmd_decide)
    l = sub.add_parser("ledger")
    l.add_argument("--fix-id")
    l.set_defaults(func=cmd_ledger)
    c = sub.add_parser("call-test", help="rehearse the escalation call")
    c.add_argument("--to", help="number to call instead of ONCALL_PHONE_NUMBER (E.164, e.g. +14155550123)")
    c.add_argument("--timeout", type=int, default=180, help="seconds to wait for a decision")
    c.add_argument("--keep", action="store_true", help="leave the rehearsal rows in the ledger")
    c.add_argument("--force", action="store_true", help="call even if the preflight finds problems")
    c.add_argument("--cleanup", action="store_true", help="remove all rehearsal rows and exit")
    c.set_defaults(func=cmd_call_test)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
