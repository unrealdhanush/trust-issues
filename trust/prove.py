"""The prove harness. A fix is done only when all of these hold:

1. the exploit test lands on the original code (fails with an AssertionError)
2. the same exploit test is blocked on the patched code (passes)
3. a Semgrep re-scan finds nothing left in the vulnerable function and no new security
   finding anywhere the patch touched (findings that predate the patch are recorded, not failed)
4. the existing test suite has no new failures compared with the original code
5. the agent did not touch tests, scan config or the harness (see guard.py)
6. the patch stays in scope: the vulnerable function, nothing else (see scope.py)
"""

import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from . import code, guard, scope, semgrep
from .config import ROOT
from .models import Finding, Patch, Proof

EXPLOIT_FILE = "tests/test_trust_exploit.py"
COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "*.pyc",
    "*.sqlite", ".venv", "venv", "node_modules", "dist", "build", "runs",
)


def target_python(target):
    """The interpreter that runs the target's tests: TRUST_TARGET_PYTHON, the repo's own
    .venv / venv, or this one."""
    from .config import env

    if env("TRUST_TARGET_PYTHON"):
        return env("TRUST_TARGET_PYTHON")
    for d in (".venv", "venv"):
        exe = Path(target) / d / "bin" / "python"
        if exe.exists():
            return str(exe)
    return sys.executable


def copy_tree(src, dst):
    if Path(dst).exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=COPY_IGNORE)
    return Path(dst)


def apply_patch(workspace, patch: Patch):
    workspace = Path(workspace).resolve()
    for edit in patch.edits:
        dest = (workspace / edit.path).resolve()
        if workspace not in dest.parents:
            raise ValueError(f"patch writes outside the target: {edit.path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(edit.content)


def run_pytest(workspace, args, timeout=120, python=None):
    """Run pytest in a workspace with the probe plugin. Returns the probe's record."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    env = {
        **os.environ,
        "TRUST_PROBE_OUT": out,
        "PYTHONPATH": os.pathsep.join([str(ROOT), str(workspace)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [python or sys.executable, "-m", "pytest", "-q", "-p", "trust.pytest_probe",
           "-p", "no:cacheprovider", *args]
    try:
        proc = subprocess.run(cmd, cwd=workspace, env=env, capture_output=True, text=True,
                              timeout=timeout)
        record = json.loads(Path(out).read_text()) if Path(out).stat().st_size else {}
    except subprocess.TimeoutExpired:
        return {"exitstatus": -1, "results": [], "output": "timed out"}
    finally:
        Path(out).unlink(missing_ok=True)
    record.setdefault("results", [])
    record["output"] = (proc.stdout + proc.stderr)[-3000:]
    return record


def exploit_outcome(workspace, exploit_src, python=None):
    """'landed', 'blocked' or 'invalid' for one exploit test module."""
    (Path(workspace) / EXPLOIT_FILE).parent.mkdir(parents=True, exist_ok=True)
    (Path(workspace) / EXPLOIT_FILE).write_text(exploit_src)
    rec = run_pytest(workspace, [EXPLOIT_FILE], python=python)
    results = [r for r in rec["results"] if r["nodeid"].startswith(EXPLOIT_FILE) or r["when"] == "collect"]
    calls = [r for r in results if r["when"] == "call"]
    broken = [r for r in results if r["outcome"] == "failed" and r["exc"] != "AssertionError"]
    if not calls or broken:
        # No test ran, or one crashed instead of asserting: that proves nothing either way.
        return "invalid", rec
    if any(r["outcome"] == "failed" for r in calls):
        return "landed", rec
    if all(r["outcome"] == "passed" for r in calls):
        return "blocked", rec
    return "invalid", rec


def run_suite(workspace, python=None):
    """(tests ran, failing node ids, probe record)."""
    rec = run_pytest(workspace, ["--ignore", EXPLOIT_FILE], python=python)
    failing = sorted({r["nodeid"] for r in rec["results"] if r["outcome"] == "failed"})
    ran = any(r["when"] == "call" for r in rec["results"])
    return ran, failing, rec


def describe(result, root):
    rel = Path(result["path"]).resolve().relative_to(Path(root).resolve()).as_posix()
    return f"{semgrep.rule_short(result)} {rel}:{result['start']['line']}"


def target_span(root, finding: Finding):
    path = Path(root) / finding.path
    if not path.exists():
        return None
    return code.function_spans(path.read_text()).get(finding.function)


def findings_delta(orig, patched, finding: Finding, changed_paths, cache=None):
    """Sort every finding on the patched code into unfixed, introduced or pre-existing.

    unfixed:      a SQLi finding still inside the vulnerable function
    pre-existing: matches a finding on the original code (rule + matched code, not line number)
    introduced:   matches nothing on the original code; fails the proof if security-relevant
    """
    cache = {} if cache is None else cache
    paths = sorted({finding.path, *[p for p in changed_paths
                                     if p.endswith(".py") and not guard.is_protected(p)]})

    def scan(root):
        files = [Path(root) / p for p in paths if (Path(root) / p).exists()]
        return semgrep.scan(files)

    key = tuple(paths)
    if key not in cache:
        cache[key] = scan(orig)[0]
    before = cache[key]
    after, engine = scan(patched)

    span = target_span(orig, finding)
    baseline, fixed = Counter(), []
    for r in before:
        rel = Path(r["path"]).resolve().relative_to(Path(orig).resolve()).as_posix()
        if rel == finding.path and span and span[0] <= r["start"]["line"] <= span[1] and semgrep.is_sqli(r):
            fixed.append(describe(r, orig))  # the bug we're fixing can't count as pre-existing
        else:
            baseline[semgrep.fingerprint(r, orig)] += 1

    span = target_span(patched, finding)
    unfixed, introduced, preexisting, notes = [], [], [], []
    for r in after:
        rel = Path(r["path"]).resolve().relative_to(Path(patched).resolve()).as_posix()
        fp = semgrep.fingerprint(r, patched)
        if rel == finding.path and span and span[0] <= r["start"]["line"] <= span[1] and semgrep.is_sqli(r):
            unfixed.append(describe(r, patched))
        elif baseline[fp] > 0:
            baseline[fp] -= 1
            preexisting.append(describe(r, patched))
        elif semgrep.is_security(r):
            introduced.append(describe(r, patched))
        else:
            notes.append(describe(r, patched))
    clear = not unfixed and not introduced
    return clear, {
        "engine": engine, "targeted": fixed, "unfixed": unfixed, "introduced": introduced,
        "preexisting": preexisting, "notes": notes,
    }


def unified_diff(orig, patched):
    chunks = []
    for path, (before, after) in sorted(guard.changed(orig, patched).items()):
        if path == EXPLOIT_FILE:
            continue
        chunks.extend(difflib.unified_diff(
            (before or "").splitlines(keepends=True), (after or "").splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}"))
    return "".join(chunks)


class Harness:
    """Proves fixes for one finding. Keeps one pristine copy of the original code."""

    def __init__(self, target, finding: Finding, workdir):
        self.target = Path(target).resolve()
        self.finding = finding
        self.workdir = Path(workdir)
        self.original = copy_tree(self.target, self.workdir / "original")
        self.python = target_python(self.target)
        self._baseline = None
        self._exploit_cache = {}
        self._scan_cache = {}

    def baseline(self):
        """The suite must be green before we judge anything against it."""
        if self._baseline is None:
            ran, failing, _ = run_suite(self.original, self.python)
            self._baseline = (ran, failing)
        return self._baseline

    def exploit_on_original(self, exploit_src):
        if exploit_src not in self._exploit_cache:
            scratch = copy_tree(self.original, self.workdir / "exploit-check")
            self._exploit_cache[exploit_src] = exploit_outcome(scratch, exploit_src, self.python)
        return self._exploit_cache[exploit_src]

    def prove(self, attempt, patch: Patch, exploit_src, allow_test_edits=frozenset()) -> Proof:
        reasons, details = [], {}
        patched = copy_tree(self.original, self.workdir / f"attempt-{attempt}")
        try:
            apply_patch(patched, patch)
        except ValueError as exc:
            return Proof(False, True, False, False, tamper=[str(exc)], reasons=[str(exc)])

        tamper = guard.check(self.original, patched, allow=frozenset(allow_test_edits))
        if any(EXPLOIT_FILE in t for t in tamper):
            reasons.append("patch touched the harness exploit file")
        diff = unified_diff(self.original, patched)
        changed_paths = list(guard.changed(self.original, patched))

        base_ran, base_failing = self.baseline()
        details["baseline_suite"] = {"ran": base_ran, "failing": base_failing}

        pre, pre_rec = self.exploit_on_original(exploit_src)
        exploit_pre = pre == "landed"
        if not exploit_pre:
            reasons.append(f"exploit is {pre} on the original code, so it proves nothing")
        details["exploit_original"] = {"outcome": pre, "output": pre_rec["output"][-1500:]}

        ran, all_failing, suite_rec = run_suite(patched, self.python)
        failing = [t for t in all_failing if t not in base_failing]  # failing before = not ours
        suite_ok = ran and not failing
        details["suite"] = {"pass": suite_ok, "failing": failing,
                            "already_failing": [t for t in all_failing if t in base_failing],
                            "output": suite_rec["output"][-1500:]}
        if not ran:
            reasons.append("existing suite failed: no tests ran")
        elif failing:
            reasons.append("existing suite failed: " + ", ".join(failing))

        post, post_rec = exploit_outcome(patched, exploit_src, self.python)
        exploit_post = post != "blocked"
        if exploit_post:
            reasons.append(f"exploit is {post} on the patched code")
        details["exploit_patched"] = {"outcome": post, "output": post_rec["output"][-1500:]}

        clear, scan = findings_delta(self.original, patched, self.finding, changed_paths, self._scan_cache)
        details["semgrep"] = scan
        if scan["unfixed"]:
            reasons.append(f"Semgrep still flags `{self.finding.function}`: {', '.join(scan['unfixed'])}")
        if scan["introduced"]:
            reasons.append(f"the patch introduces new findings: {', '.join(scan['introduced'])}")

        slop = scope.check(self.original, patched, self.finding)
        if slop:
            reasons.append("out of scope: " + "; ".join(slop))

        if tamper:
            reasons.append("agent edited what grades it: " + "; ".join(tamper))
        details["allow_test_edits"] = sorted(allow_test_edits)
        details["changed_files"] = sorted(changed_paths)

        return Proof(
            exploit_pre=exploit_pre, exploit_post=exploit_post, semgrep_clear=clear,
            suite_pass=suite_ok, tamper=tamper, slop=slop, failing_tests=failing, reasons=reasons,
            diff=diff, details=details,
        )
