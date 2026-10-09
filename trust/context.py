"""What the model gets to see: the vulnerable file, what it imports, and the tests that touch it.

Sending every file works on a demo app and overflows the context window on a real repo.
"""

import ast
from pathlib import Path

from .guard import is_protected, tree
from .models import Finding

BUDGET_CHARS = 60_000


def local_imports(root, rel_path, src):
    """Repo files that `rel_path` imports, resolved against the repo root and its own package."""
    root, here = Path(root), Path(rel_path).parent
    try:
        mod = ast.parse(src)
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(mod):
        names = []
        if isinstance(node, ast.ImportFrom):
            base = here
            for _ in range(max(node.level - 1, 0)):
                base = base.parent
            parts = (node.module or "").split(".") if node.module else []
            start = base if node.level else Path()
            names = [start.joinpath(*parts)] + [start.joinpath(*parts, a.name) for a in node.names]
        elif isinstance(node, ast.Import):
            names = [Path(*a.name.split(".")) for a in node.names]
        for n in names:
            for cand in (n.with_suffix(".py"), n / "__init__.py"):
                if (root / cand).is_file():
                    found.append(cand.as_posix())
    return list(dict.fromkeys(found))


def relevant_files(root, finding: Finding):
    """Ordered {path: content}: the vulnerable file, its local imports, conftests, related tests."""
    files = tree(root)
    target_src = files.get(finding.path, "")
    stem = Path(finding.path).stem
    picked = {finding.path: target_src}
    for p in local_imports(root, finding.path, target_src):
        picked.setdefault(p, files.get(p, ""))
    for p, c in sorted(files.items()):
        if p.endswith("conftest.py"):
            picked.setdefault(p, c)
    for p, c in sorted(files.items()):
        if p.endswith(".py") and is_protected(p) and (stem in c or (finding.function and finding.function.split(".")[-1] in c)):
            picked.setdefault(p, c)
    out, used = {}, 0
    for p, c in picked.items():
        if used + len(c) > BUDGET_CHARS and out:
            continue
        out[p], used = c, used + len(c)
    return out
