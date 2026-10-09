"""Vercel entry point: the dashboard, the voice agent's tools and /twilio/connect.

Stateless: every request reads and writes the ClickHouse ledger, so CLICKHOUSE_URL must be set.
The scanning loop (Semgrep, pytest, the patch agent) runs elsewhere: a laptop or GitHub Actions.
"""

import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trust.server import app as trust_app  # noqa: E402


async def app(scope, receive, send):
    """vercel.json rewrites every path to /api/index?__path=/<original path>, and the function
    sees only /api/index. Put the original path back before FastAPI routes the request."""
    if scope["type"] in ("http", "websocket"):
        query = parse_qsl(scope.get("query_string", b"").decode(), keep_blank_values=True)
        original = next((v for k, v in query if k == "__path"), None)
        if original is not None:
            rest = urlencode([(k, v) for k, v in query if k != "__path"]).encode()
            scope = {**scope, "path": original, "raw_path": original.encode(), "query_string": rest}
    await trust_app(scope, receive, send)
