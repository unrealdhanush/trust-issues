"""The patch agent: writes the exploit test and the fix.

`OpenAIAgent` is the real one. `ScriptedAgent` replays fixtures/scripted so the loop can
be built and rehearsed without an LLM.
"""

from pathlib import Path

from pydantic import BaseModel, Field

from .config import OPENAI_MODEL, ROOT, env
from .context import relevant_files
from .guard import is_protected
from .models import FileEdit, Finding, Patch, Proof
from .prove import EXPLOIT_FILE

RULES = """Rules you must follow:
- Fix the vulnerability itself. Keep every existing behavior that isn't the vulnerability.
- Never build SQL by concatenating or formatting a variable into the query string, even a
  checked or allowlisted one: Semgrep's taint analysis can't see allowlists and will still flag it.
  Use bound parameters (`?`) for values. For identifiers such as ORDER BY columns, select one of
  several complete literal query strings.
- Never add `nosemgrep` or any other suppression.
- Never detect or special-case the test environment.
- You may not edit tests, conftest.py or test configuration unless the human explicitly unlocked
  a test file below. The harness rejects any other test edit.
- Return the complete new content of every file you change. Paths are relative to the repo root.

Scope (the harness rejects a patch that breaks any of these):
- Change only the vulnerable function. A new module-level constant or helper is fine if the
  function uses it. Don't touch other functions, files, imports of new modules, or formatting.
- Make the smallest change that fixes the bug. No refactors, renames, type hints, logging,
  prints, catch-all excepts or TODOs.
- Don't add comments that narrate the change ("fixed SQL injection", "now uses parameters").
  A comment is only for something the code can't say, such as why ORDER BY can't take a
  bound parameter."""


class FileOut(BaseModel):
    path: str
    content: str


class PatchOut(BaseModel):
    explanation: str = Field(description="One or two sentences on what changed and why it is safe.")
    files: list[FileOut]


class ExploitOut(BaseModel):
    explanation: str
    test_module: str = Field(description="A complete pytest module.")


def repo_context(target, finding: Finding):
    files = relevant_files(target, finding)
    app = {p: c for p, c in files.items() if not is_protected(p)}
    tests = {p: c for p, c in files.items() if is_protected(p)}

    def block(d):
        return "\n\n".join(f"### {p}\n```python\n{c}\n```" for p, c in sorted(d.items()))

    return (
        f"Semgrep finding `{finding.rule_id}` in `{finding.path}` line {finding.line}, "
        f"inside `{finding.function}`:\n"
        f"{finding.message}\n\n## Application code\n{block(app)}\n\n"
        f"## Existing tests (read-only)\n{block(tests)}"
    )


def failure_feedback(history: list[Proof]):
    if not history:
        return ""
    lines = ["## Previous attempts failed proof"]
    for i, proof in enumerate(history, 1):
        lines.append(f"Attempt {i}:")
        lines += [f"- {r}" for r in proof.reasons]
        suite_out = proof.details.get("suite", {}).get("output", "")
        if proof.failing_tests and suite_out:
            lines.append(f"Suite output (tail):\n```\n{suite_out[-1200:]}\n```")
    return "\n".join(lines)


class OpenAIAgent:
    name = "openai"

    def __init__(self, model=OPENAI_MODEL):
        from openai import OpenAI

        self.client = OpenAI()
        self.model = model

    def _parse(self, instructions, prompt, fmt):
        resp = self.client.responses.parse(
            model=self.model, instructions=instructions, input=prompt, text_format=fmt,
        )
        return resp.output_parsed

    def exploit(self, target, finding: Finding, feedback=""):
        instructions = (
            "You are a security engineer writing a regression test that proves a SQL injection "
            "is real. Write a pytest module that reaches the vulnerable code the same way the "
            "existing tests do: reuse the fixtures from the conftest.py files shown (a web test "
            "client, a database session) or call the function directly. Don't start servers or "
            "invent fixtures. Each test asserts the SAFE behavior, so it must FAIL "
            "with an AssertionError on the vulnerable code and PASS once the bug is fixed. Prefer "
            "an observable leak (extra rows, data from another table, or a response that changes "
            "with an injected condition) over checking error codes. Accept either a 400 or a "
            "harmless result on the fixed code; don't assume a specific fix. Use only the standard "
            "library and the fixture. No network, no sleeps."
        )
        prompt = repo_context(target, finding)
        if feedback:
            prompt += f"\n\n## Your previous exploit was rejected\n{feedback}"
        out = self._parse(instructions, prompt, ExploitOut)
        return out.test_module

    def patch(self, target, finding: Finding, history, hint="", allow_test_edits=()):
        instructions = "You are a senior engineer fixing a security vulnerability.\n\n" + RULES
        prompt = repo_context(target, finding) + "\n\n" + failure_feedback(history)
        if hint:
            prompt += f"\n\n## Hint from the on-call engineer\n{hint}"
        if allow_test_edits:
            prompt += ("\n\nThe on-call engineer unlocked these test files; you may update them "
                       "to match the safe behavior: " + ", ".join(sorted(allow_test_edits)))
        out = self._parse(instructions, prompt, PatchOut)
        edits = [FileEdit(f.path, f.content) for f in out.files if f.path != EXPLOIT_FILE]
        return Patch(edits, out.explanation)


class ScriptedAgent:
    name = "scripted"

    def __init__(self, root=ROOT / "fixtures" / "scripted"):
        self.root = Path(root)

    def _dir(self, finding):
        return self.root / Path(finding.path).stem

    def exploit(self, target, finding, feedback=""):
        return (self._dir(finding) / "exploit.py").read_text()

    def patch(self, target, finding, history, hint="", allow_test_edits=()):
        base = self._dir(finding)
        hinted = sum(1 for p in history if p.details.get("allow_test_edits"))
        steps = [f"hint-{hinted + 1}"] if hint else []
        steps += [f"attempt-{len(history) + 1}"]
        existing = sorted(p.name for p in base.iterdir() if p.is_dir())
        step = next((s for s in steps if (base / s).is_dir()), existing[-1])
        d = base / step
        edits = [FileEdit(p.relative_to(d).as_posix(), p.read_text()) for p in sorted(d.rglob("*.py"))]
        return Patch(edits, f"scripted {step}")


def get_agent():
    choice = env("TRUST_AGENT") or ("openai" if env("OPENAI_API_KEY") else "scripted")
    return OpenAIAgent() if choice == "openai" else ScriptedAgent()
