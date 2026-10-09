from pathlib import Path

import pytest

from trust.models import FileEdit, Finding, Patch
from trust.prove import Harness

ROOT = Path(__file__).resolve().parent.parent
SCRIPTED = ROOT / "fixtures" / "scripted"


@pytest.fixture(autouse=True)
def _cli_semgrep(monkeypatch):
    # The MCP server adds a few seconds per scan; the CLI runs the same rules.
    monkeypatch.setenv("TRUST_SEMGREP_MCP", "0")


def finding(stem, line):
    return Finding(
        rule_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string",
        path=f"app/{stem}.py", line=line, message="tainted SQL string",
    )


def scripted_patch(stem, step):
    d = SCRIPTED / stem / step
    return Patch([FileEdit(p.relative_to(d).as_posix(), p.read_text()) for p in sorted(d.rglob("*.py"))])


def exploit(stem):
    return (SCRIPTED / stem / "exploit.py").read_text()


@pytest.fixture
def users_harness(tmp_path):
    return Harness(ROOT / "target", finding("users", 13), tmp_path)


@pytest.fixture
def admin_harness(tmp_path):
    return Harness(ROOT / "target", finding("admin", 14), tmp_path)
