"""Vercel entry point: the dashboard, the voice agent's tools and /twilio/connect.

Stateless: every request reads and writes the ClickHouse ledger, so CLICKHOUSE_URL must be set.
The scanning loop (Semgrep, pytest, the patch agent) runs elsewhere: a laptop or GitHub Actions.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trust.server import app  # noqa: E402,F401
