"""Monitoring: re-scan on a schedule, fix what's new, leave alone what's already handled.

A finding counts as handled once a fix for it reached an outcome (proven, shipped, held,
blocked). It comes back only when the vulnerable function's code changes, so a proven fix
waiting in review isn't re-proven every cycle, and a regression is.
"""

import hashlib
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import code, semgrep
from .config import RUNS_DIR

STATE_FILE = RUNS_DIR / "watch-state.json"


def say(msg):
    print(f"[watch] {msg}", flush=True)


def parse_interval(text):
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(text))
    if not m:
        raise ValueError(f"bad interval {text!r}; use e.g. 30s, 15m, 6h, 1d")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def git(target, *args):
    out = subprocess.run(["git", "-C", str(target), *args], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


def function_hash(target, finding):
    """Hash of the vulnerable function's source: changes when someone touches that code."""
    src = (Path(target) / finding.path).read_text()
    span = code.function_spans(src).get(finding.function)
    body = "\n".join(src.splitlines()[span[0] - 1:span[1]]) if span else src
    return hashlib.sha1(body.encode()).hexdigest()[:12]


def load_state(path=None):
    path = Path(path or STATE_FILE)
    return json.loads(path.read_text()) if path.exists() else {"targets": {}}


def save_state(state, path=None):
    path = Path(path or STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def cycle(target, fixer, state, changed_only=False, pull=False):
    """One pass: scan, skip handled findings, fix the rest. `fixer(finding) -> outcome`."""
    target = Path(target).resolve()
    tstate = state["targets"].setdefault(str(target), {"handled": {}})
    if pull and git(target, "rev-parse", "--git-dir"):
        say("pulling" if git(target, "pull", "--ff-only") is not None else "pull failed; scanning what's here")
    head = git(target, "rev-parse", "HEAD")

    findings, engine = semgrep.sqli_findings(target)
    if changed_only and head and tstate.get("last_sha") and tstate["last_sha"] != head:
        # --relative: paths relative to the target, which may be a subfolder of the repo
        changed = set((git(target, "diff", "--name-only", "--relative", tstate["last_sha"], head) or "").splitlines())
        findings = [f for f in findings if f.path in changed]
        say(f"{len(changed)} file(s) changed since {tstate['last_sha'][:7]}")
    elif changed_only and head and tstate.get("last_sha") == head:
        say(f"no new commits since {head[:7]}")
        findings = []

    results = {}
    for f in findings:
        digest = function_hash(target, f)
        prev = tstate["handled"].get(f.fix_id)
        if prev and prev["hash"] == digest:
            say(f"{f.fix_id}: already {prev['outcome']}, code unchanged; skipping")
            continue
        try:
            outcome = fixer(f)
        except Exception as exc:  # one bad fix shouldn't stop the watch; retried next cycle
            say(f"{f.fix_id}: error {exc!r}; will retry next cycle")
            continue
        tstate["handled"][f.fix_id] = {"hash": digest, "outcome": outcome, "file": f.path,
                                       "function": f.function, "at": datetime.now(timezone.utc).isoformat()}
        save_state(state)
        results[f.fix_id] = outcome
    tstate["last_sha"], tstate["last_scan"] = head, datetime.now(timezone.utc).isoformat()
    save_state(state)
    say(f"scan ({engine}): {len(findings)} finding(s), {len(results)} worked on: {json.dumps(results)}")
    return results


def watch(target, fixer, every="15m", once=False, changed_only=False, pull=False):
    interval = parse_interval(every)
    state = load_state()
    while True:
        cycle(target, fixer, state, changed_only=changed_only, pull=pull)
        if once:
            return
        say(f"next scan in {every}")
        time.sleep(interval)
