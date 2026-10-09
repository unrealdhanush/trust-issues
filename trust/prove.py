"""The prove harness. A fix is done only when all of these hold:

1. the exploit test lands on the original code (fails with an AssertionError)
2. the same exploit test is blocked on the patched code (passes)
3. a Semgrep re-scan of the patched code is clean for this finding
4. the existing test suite still passes
5. the agent did not touch tests, scan config or the harness (see guard.py)
"""

import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import guard, semgrep
from .config import ROOT
from .models import Finding, Patch, Proof

EXPLOIT_FILE = "tests/test_trust_exploit.py"
COPY_IGNORE = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "*.sqlite", ".venv")


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


def run_pytest(workspace, args, timeout=120):
    """Run pytest in a workspace with the probe plugin. Returns the probe's record."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    env = {
        **os.environ,
        "TRUST_PROBE_OUT": out,
        "PYTHONPATH": os.pathsep.join([str(ROOT), str(workspace)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "trust.pytest_probe",
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


def exploit_outcome(workspace, exploit_src):
    """'landed', 'blocked' or 'invalid' for one exploit test module."""
    (Path(workspace) / EXPLOIT_FILE).write_text(exploit_src)
    rec = run_pytest(workspace, [EXPLOIT_FILE])
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


def run_suite(workspace):
    rec = run_pytest(workspace, ["--ignore", EXPLOIT_FILE])
    failing = sorted({r["nodeid"] for r in rec["results"] if r["outcome"] == "failed"})
    ran = any(r["when"] == "call" for r in rec["results"])
    return rec["exitstatus"] == 0 and ran and not failing, failing, rec


def semgrep_check(orig, patched, finding: Finding, changed_paths, cache=None):
    """Clear when the finding's file has no SQLi result and no other changed file gained one."""
    cache = {} if cache is None else cache

    def counts(root, rel_paths):
        files = [Path(root) / p for p in rel_paths if (Path(root) / p).exists()]
        results, engine = semgrep.scan(files)
        out = {}
        for r in filter(semgrep.is_sqli, results):
            rel = Path(r["path"]).resolve().relative_to(Path(root).resolve()).as_posix()
            out.setdefault(rel, []).append(f'{r["check_id"].rsplit(".", 1)[-1]}:{r["start"]["line"]}')
        return out, engine

    paths = sorted({finding.path, *[p for p in changed_paths if p.endswith(".py") and not guard.is_protected(p)]})
    key = tuple(paths)
    if key not in cache:
        cache[key] = counts(orig, paths)[0]
    before = cache[key]
    after, engine = counts(patched, paths)
    regressions = {p: hits for p, hits in after.items() if p != finding.path and len(hits) > len(before.get(p, []))}
    clear = not after.get(finding.path) and not regressions
    return clear, {"engine": engine, "remaining": after, "regressions": regressions}


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
        self._baseline = None
        self._exploit_cache = {}
        self._scan_cache = {}

    def baseline(self):
        """The suite must be green before we judge anything against it."""
        if self._baseline is None:
            ok, failing, _ = run_suite(self.original)
            self._baseline = (ok, failing)
        return self._baseline

    def exploit_on_original(self, exploit_src):
        if exploit_src not in self._exploit_cache:
            scratch = copy_tree(self.original, self.workdir / "exploit-check")
            self._exploit_cache[exploit_src] = exploit_outcome(scratch, exploit_src)
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

        base_ok, base_failing = self.baseline()
        details["baseline_suite"] = {"pass": base_ok, "failing": base_failing}

        pre, pre_rec = self.exploit_on_original(exploit_src)
        exploit_pre = pre == "landed"
        if not exploit_pre:
            reasons.append(f"exploit is {pre} on the original code, so it proves nothing")
        details["exploit_original"] = {"outcome": pre, "output": pre_rec["output"][-1500:]}

        suite_ok, failing, suite_rec = run_suite(patched)
        details["suite"] = {"pass": suite_ok, "failing": failing, "output": suite_rec["output"][-1500:]}
        if not suite_ok:
            reasons.append("existing suite failed: " + (", ".join(failing) or "no tests ran"))

        post, post_rec = exploit_outcome(patched, exploit_src)
        exploit_post = post != "blocked"
        if exploit_post:
            reasons.append(f"exploit is {post} on the patched code")
        details["exploit_patched"] = {"outcome": post, "output": post_rec["output"][-1500:]}

        clear, scan = semgrep_check(self.original, patched, self.finding, changed_paths, self._scan_cache)
        details["semgrep"] = scan
        if not clear:
            reasons.append(f"Semgrep still flags {self.finding.path}: {scan['remaining'].get(self.finding.path) or scan['regressions']}")

        if tamper:
            reasons.append("agent edited what grades it: " + "; ".join(tamper))
        details["allow_test_edits"] = sorted(allow_test_edits)
        details["changed_files"] = sorted(changed_paths)

        return Proof(
            exploit_pre=exploit_pre, exploit_post=exploit_post, semgrep_clear=clear,
            suite_pass=suite_ok, tamper=tamper, failing_tests=failing, reasons=reasons,
            diff=diff, details=details,
        )
