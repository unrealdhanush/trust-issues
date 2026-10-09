"""The no-slop check: a security fix changes the vulnerable function and nothing else.

Every violation fails the proof, and the reason goes back to the agent on the next attempt.
Tests the on-call engineer unlocked are out of scope here; guard.py polices tests.
"""

import difflib
import re

from . import code, guard
from .config import env
from .models import Finding

DIFF_BUDGET = int(env("TRUST_DIFF_BUDGET", "60"))

# A comment that narrates the change instead of explaining the code.
NARRATION = re.compile(
    r"\b(fix(e[sd])?|patch(ed)?|vulnerab\w*|injection|secur(e|ity)|sanitiz\w*|prevent\w*|"
    r"previously|no longer|now uses?|changed|updated|refactor\w*)\b",
    re.I,
)
ADDED_LINE_RULES = [
    (re.compile(r"^\s*except\s*(Exception\b.*)?:"), "adds a catch-all except"),
    (re.compile(r"^\s*print\("), "adds a print"),
    (re.compile(r"#\s*(TODO|FIXME|XXX)\b"), "leaves a TODO"),
]


def comment_of(line):
    """The comment on a line of Python, ignoring '#' inside simple string literals."""
    in_str = None
    for i, ch in enumerate(line):
        if in_str:
            if ch == in_str and line[i - 1] != "\\":
                in_str = None
        elif ch in "\"'":
            in_str = ch
        elif ch == "#":
            return line[i + 1:].strip()
    return None


def added_lines(before, after):
    return [l[1:] for l in difflib.unified_diff((before or "").splitlines(), (after or "").splitlines(),
                                                lineterm="", n=0)
            if l.startswith("+") and not l.startswith("+++")]


def changed_line_count(before, after):
    return sum(1 for l in difflib.unified_diff((before or "").splitlines(), (after or "").splitlines(),
                                               lineterm="", n=0)
               if l[:1] in "+-" and not l.startswith(("+++", "---")))


def related(name, target):
    """True for the target function, its enclosing classes and anything nested in it."""
    return name == target or target.startswith(name + ".") or name.startswith(target + ".")


def check_file(path, before, after, target):
    out = []
    old_tree, new_tree = code.parse(before), code.parse(after)
    if new_tree is None:
        return [f"{path} no longer parses"]
    if old_tree is None:
        return out

    old_defs, new_defs = code.definitions(before), code.definitions(after)
    used = code.used_names(new_tree)
    for name, (dump, _) in old_defs.items():
        if related(name, target):
            continue
        if name not in new_defs:
            out.append(f"removes `{name}`, which isn't the vulnerable function")
        elif new_defs[name][0] != dump:
            out.append(f"rewrites `{name}`, which isn't the vulnerable function")
    if target != "<module>" and target not in new_defs:
        out.append(f"removes or renames the vulnerable function `{target}`")
    for name, (_, decorated) in new_defs.items():
        if name in old_defs or related(name, target):
            continue
        short = name.rsplit(".", 1)[-1]
        if decorated:
            out.append(f"adds `{name}`, a new decorated function (a new endpoint?)")
        elif short not in used:
            out.append(f"adds `{name}`, which nothing uses")

    new_mods = code.imported_modules(new_tree) - code.imported_modules(old_tree)
    for mod in sorted(new_mods):
        out.append(f"imports a new module `{mod}`")
    old_bind, new_bind = code.module_bindings(old_tree), code.module_bindings(new_tree)
    for name, kind in new_bind.items():
        if name not in old_bind and name not in used:
            out.append(f"adds {kind} `{name}`, which nothing uses")

    for line in added_lines(before, after):
        comment = comment_of(line)
        if comment and NARRATION.search(comment):
            out.append(f"adds a comment narrating the change: `# {comment[:60]}`")
        for pattern, why in ADDED_LINE_RULES:
            if pattern.search(line):
                out.append(f"{why}: `{line.strip()[:60]}`")
    return out


def check(orig, patched, finding: Finding):
    """Scope violations for a patch, as sentences the agent and the on-call engineer can read."""
    violations, budget_used = [], 0
    for path, (before, after) in sorted(guard.changed(orig, patched).items()):
        if guard.is_protected(path):
            continue
        budget_used += changed_line_count(before, after)
        if path != finding.path:
            what = "creates" if before is None else "deletes" if after is None else "edits"
            violations.append(f"{what} {path}, outside the vulnerable file")
            continue
        if path.endswith(".py") and after is not None:
            violations += [f"{path}: {v}" for v in check_file(path, before, after, finding.function or "<module>")]
    if budget_used > DIFF_BUDGET:
        violations.append(f"changes {budget_used} lines; a fix like this should fit in {DIFF_BUDGET}")
    return violations
