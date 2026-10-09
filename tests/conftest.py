from pathlib import Path

import pytest

from trust.models import FileEdit, Finding, Patch
from trust.prove import Harness

ROOT = Path(__file__).resolve().parent.parent
SCRIPTED = ROOT / "fixtures" / "scripted"


SERVICE_SETTINGS = [
    "OPENAI_API_KEY", "CLICKHOUSE_URL", "CLICKHOUSE_PASSWORD", "ELEVENLABS_API_KEY",
    "ELEVENLABS_AGENT_ID", "ELEVENLABS_PHONE_NUMBER_ID", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
    "TWILIO_FROM_NUMBER", "ONCALL_PHONE_NUMBER", "PUBLIC_BASE_URL", "TRUST_WEBHOOK_TOKEN", "TRUST_AGENT",
]


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    # Tests never touch real services, whatever the developer's .env holds.
    for key in SERVICE_SETTINGS:
        monkeypatch.delenv(key, raising=False)
    # The MCP server adds a few seconds per scan; the CLI runs the same rules.
    monkeypatch.setenv("TRUST_SEMGREP_MCP", "0")


FUNCTIONS = {"users": "search_users", "admin": "list_orders"}


def finding(stem, line, function=None):
    return Finding(
        rule_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string",
        path=f"app/{stem}.py", line=line, message="tainted SQL string",
        function=function or FUNCTIONS[stem],
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
