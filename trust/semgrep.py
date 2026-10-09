"""Semgrep access: the MCP server first (`semgrep mcp`), the CLI if MCP is unavailable."""

import asyncio
import json
import os
import subprocess
from pathlib import Path

from . import code
from .config import env
from .models import Finding

CLI_CONFIG = env("SEMGREP_CONFIG", "p/python")
PREFERRED_RULE = "tainted-sql-string"


async def _scan_mcp(paths):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command="semgrep", args=["mcp"])
    with open(os.devnull, "w") as quiet:
        async with stdio_client(params, errlog=quiet) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool(
                    "semgrep_scan", {"code_files": [{"path": str(p)} for p in paths]}
                )
    if res.is_error:
        raise RuntimeError(res.content[0].text if res.content else "MCP scan failed")
    return json.loads(res.content[0].text)["results"]


def _scan_cli(paths):
    out = subprocess.run(
        ["semgrep", "scan", "--config", CLI_CONFIG, "--metrics", "off", "--quiet", "--json",
         *map(str, paths)],
        capture_output=True, text=True, timeout=300,
    )
    if out.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed: {out.stderr[-500:]}")
    return json.loads(out.stdout)["results"]


def scan(paths, prefer_mcp=True):
    """Scan absolute file paths. Returns (results with absolute paths, engine used)."""
    paths = [Path(p).resolve() for p in paths]
    if not paths:
        return [], "none"
    engine = "cli"
    results = None
    if prefer_mcp and env("TRUST_SEMGREP_MCP", "1") == "1":
        try:
            results = asyncio.run(asyncio.wait_for(_scan_mcp(paths), timeout=180))
            engine = "mcp"
        except Exception as exc:  # fall back rather than stall the loop
            print(f"[semgrep] MCP scan failed ({exc!r}); using the CLI")
    if results is None:
        results = _scan_cli(paths)
    by_name = {}
    for p in paths:
        by_name.setdefault(p.name, []).append(p)
    for r in results:
        p = Path(r["path"])
        if not p.is_absolute():
            matches = [c for c in paths if str(c).endswith(str(p))] or by_name.get(p.name, [])
            if matches:
                r["path"] = str(matches[0])
    return results, engine


def is_sqli(result):
    cwes = result.get("extra", {}).get("metadata", {}).get("cwe", [])
    return any("CWE-89" in c for c in cwes) or "sql" in result["check_id"].lower()


def is_security(result):
    return is_sqli(result) or result.get("extra", {}).get("metadata", {}).get("category") == "security"


def rule_short(result):
    return result["check_id"].rsplit(".", 1)[-1]


def matched_code(result):
    """The matched source lines, whitespace-normalized: stable when line numbers shift."""
    try:
        lines = Path(result["path"]).read_text().splitlines()
    except OSError:
        return ""
    start, end = result["start"]["line"], result["end"]["line"]
    return "\n".join(l.strip() for l in lines[start - 1:end] if l.strip())


def fingerprint(result, root):
    rel = Path(result["path"]).resolve().relative_to(Path(root).resolve()).as_posix()
    return (rule_short(result), rel, matched_code(result))


def source_files(root):
    """App source files Semgrep should see: no tests, no virtualenvs."""
    root = Path(root)
    skip = {"tests", ".venv", "venv", "__pycache__", ".pytest_cache"}
    return sorted(
        p for p in root.rglob("*.py")
        if not skip.intersection(p.relative_to(root).parts)
        and not p.name.startswith("test_") and p.name != "conftest.py"
    )


def sqli_findings(root, prefer_mcp=True):
    """One finding per vulnerable function, keyed on the taint rule when it fires.

    Several rules often flag the same function (the taint rule, the cursor rule); they are
    one bug and one fix.
    """
    root = Path(root).resolve()
    results, engine = scan(source_files(root), prefer_mcp=prefer_mcp)
    grouped = {}
    for r in filter(is_sqli, results):
        src = Path(r["path"]).read_text()
        fn = code.enclosing_function(src, r["start"]["line"])
        grouped.setdefault((r["path"], fn), []).append(r)
    findings = []
    for (path, fn), rs in sorted(grouped.items()):
        rs.sort(key=lambda r: (PREFERRED_RULE not in r["check_id"], r["start"]["line"]))
        top = rs[0]
        findings.append(Finding(
            rule_id=top["check_id"],
            path=Path(path).resolve().relative_to(root).as_posix(),
            line=top["start"]["line"],
            message=top["extra"]["message"],
            related_rules=sorted({r["check_id"] for r in rs}),
            function=fn,
        ))
    return findings, engine
