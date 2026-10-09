"""The ledger: one row per proof attempt, plus one per escalation.

Rows are keyed on (fix_id, attempt, verdict) and the newest `ts` wins, so the escalation
row can be rewritten as the decision and transcript arrive. ClickHouse does this with
ReplacingMergeTree; the local JSONL ledger (used when CLICKHOUSE_URL is unset) does the same
on read.
"""

import fcntl
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from .config import RUNS_DIR, env

TABLE = "fix_attempts"
COLUMNS = [
    "fix_id", "attempt", "vuln_class", "file", "rule_id", "exploit_pre", "exploit_post",
    "semgrep_clear", "suite_pass", "scope_clean", "verdict", "decision", "hint", "transcript",
    "failing_tests", "evidence", "ts",
]
DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    fix_id String,
    attempt UInt16,
    vuln_class LowCardinality(String),
    file String,
    rule_id String,
    exploit_pre Bool,
    exploit_post Bool,
    semgrep_clear Bool,
    suite_pass Bool,
    scope_clean Bool,
    verdict LowCardinality(String),
    decision LowCardinality(String),
    hint String,
    transcript String,
    failing_tests Array(String),
    evidence String,
    ts DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(ts)
ORDER BY (fix_id, attempt, verdict)
"""
DEFAULTS = {
    "attempt": 0, "vuln_class": "sqli", "file": "", "rule_id": "", "exploit_pre": False,
    "exploit_post": False, "semgrep_clear": False, "suite_pass": False, "scope_clean": True, "verdict": "",
    "decision": "", "hint": "", "transcript": "", "failing_tests": [], "evidence": "{}",
}


def now():
    return datetime.now(timezone.utc)


def normalize(row):
    row = {**DEFAULTS, **row}
    row.setdefault("ts", now())
    if isinstance(row["evidence"], dict):
        row["evidence"] = json.dumps(row["evidence"], default=str)
    return {c: row[c] for c in COLUMNS}


def _key(r):
    return (r["fix_id"], int(r["attempt"]), r["verdict"])


class FileLedger:
    kind = "local"

    def __init__(self, path=RUNS_DIR / "ledger.jsonl"):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()

    def setup(self):
        pass

    def insert(self, row):
        row = normalize(row)
        row["ts"] = row["ts"].isoformat()
        with open(self.path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(row) + "\n")
        return row

    def delete(self, fix_id=None, prefix=None):
        def doomed(r):
            return r["fix_id"] == fix_id or (prefix and r["fix_id"].startswith(prefix))

        with open(self.path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            keep = [l for l in f.read().splitlines() if l.strip() and not doomed(json.loads(l))]
            f.seek(0)
            f.truncate()
            f.write("".join(l + "\n" for l in keep))

    def rows(self, fix_id=None):
        latest = {}
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            r = {**DEFAULTS, **json.loads(line)}
            if fix_id and r["fix_id"] != fix_id:
                continue
            if _key(r) not in latest or r["ts"] >= latest[_key(r)]["ts"]:
                latest[_key(r)] = r
        return sorted(latest.values(), key=lambda r: r["ts"])


class ClickHouseLedger:
    kind = "clickhouse"

    def __init__(self, url, password, user="default", database="default"):
        import clickhouse_connect

        u = urlparse(url if "://" in url else f"https://{url}")
        self.client = clickhouse_connect.get_client(
            host=u.hostname, port=u.port or (8443 if u.scheme == "https" else 8123),
            username=u.username or user, password=password, secure=u.scheme == "https",
            database=database,
        )

    def setup(self):
        self.client.command(DDL)
        # Tables created before the scope check existed.
        self.client.command(f"ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS scope_clean Bool DEFAULT true AFTER suite_pass")

    def insert(self, row):
        row = normalize(row)
        self.client.insert(TABLE, [[row[c] for c in COLUMNS]], column_names=COLUMNS)
        return row

    def delete(self, fix_id=None, prefix=None):
        if fix_id:
            self.client.command(f"DELETE FROM {TABLE} WHERE fix_id = {{v:String}}", parameters={"v": fix_id})
        if prefix:
            self.client.command(f"DELETE FROM {TABLE} WHERE startsWith(fix_id, {{v:String}})",
                                parameters={"v": prefix})

    def rows(self, fix_id=None):
        where = "WHERE fix_id = {fix_id:String}" if fix_id else ""
        res = self.client.query(
            f"SELECT {', '.join(COLUMNS)} FROM {TABLE} FINAL {where} ORDER BY ts",
            parameters={"fix_id": fix_id} if fix_id else None,
        )
        out = []
        for r in res.named_results():
            r["ts"] = r["ts"].isoformat()
            out.append(r)
        return out


_ledger = None


def get_ledger():
    global _ledger
    if _ledger is None:
        url = env("CLICKHOUSE_URL")
        if url:
            _ledger = ClickHouseLedger(url, env("CLICKHOUSE_PASSWORD"), env("CLICKHOUSE_USER", "default"),
                                       env("CLICKHOUSE_DATABASE", "default"))
        else:
            _ledger = FileLedger()
        _ledger.setup()
    return _ledger


def pending_escalation(rows):
    """The newest escalation row still waiting on a decision, if any."""
    waiting = [r for r in rows if r["verdict"] == "escalated" and not r["decision"]]
    return waiting[-1] if waiting else None
