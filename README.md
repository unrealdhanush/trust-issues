# Trust Issues

> It has trust issues, so you don't have to.

An autonomous loop that finds a vulnerability, patches it, and refuses to call the fix done until it proves it. When proof fails twice, it phones the on-call engineer for one decision.

Build brief (timeline, demo script, cut order, pre-flight): https://claude.ai/code/artifact/804f53f2-1849-4cbf-b041-54352a6d3d7d

## The loop

1. **Detect.** The Semgrep MCP server scans the target repo and returns one SQL injection finding.
2. **Patch.** An OpenAI agent writes the fix.
3. **Prove.** The fix isn't done until all three checks pass:
   - the generated exploit test succeeds against the original code and is blocked on the patch
   - a Semgrep re-scan comes back clean
   - the existing test suite still passes

   The agent may not edit tests.
4. **Escalate.** After two failed proofs, an ElevenLabs voice agent calls on-call through Twilio. It briefs the failed check, answers questions from the ledger, and records one decision: `ship`, `hold` or `retry` with a hint.

## Ledger (ClickHouse)

One table:

```
fix_attempts(fix_id, attempt, vuln_class, file, rule_id,
             exploit_pre, exploit_post, semgrep_clear, suite_pass,
             verdict, decision, hint, transcript, ts)
```

## Tracks

| Track | Owns |
| --- | --- |
| A · Detect + Patch | Target repo with two seeded SQLi bugs, Semgrep MCP, patch agent, hint on retry |
| B · Prove | Exploit test, Semgrep re-scan, suite run, verdict with evidence, test-edit guard |
| C · Ledger + Voice + Demo | ClickHouse table and dashboard, ElevenLabs agent with two webhook tools (read ledger / write decision), demo script |

## Setup

Copy `.env.example` to `.env` and fill it in:

```
OPENAI_API_KEY=
CLICKHOUSE_URL=
CLICKHOUSE_PASSWORD=
ELEVENLABS_API_KEY=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=
ONCALL_PHONE_NUMBER=
```

Install Semgrep and start its MCP server:

```
uv tool install semgrep        # or: pip install semgrep
semgrep mcp                    # stdio MCP server, built into semgrep >= 1.130
```

The standalone `uvx semgrep-mcp` package crashes on startup with current pydantic (`ImportError: eval_type_backport`). Use `semgrep mcp`, or pin pydantic: `uvx --with 'pydantic<2.12' semgrep-mcp`.

Offline scans use `semgrep scan --config p/python --metrics off`. The relevant rule is `python.flask.security.injection.tainted-sql-string.tainted-sql-string`.

## Known gotcha for Prove

Semgrep's taint rule (`tainted-sql-string`) still flags a correct allowlist fix for `ORDER BY`. Checked against semgrep 1.180 with `p/python`:

| Fix shape | Re-scan |
| --- | --- |
| `col = ALLOWED.get(sort, "id")`, then `"... ORDER BY " + col` | flagged |
| `col = sort_column(sort)` (a helper returning only literals), then `"... ORDER BY " + col` | flagged |
| Pick a whole literal query: `QUERIES["total"] if sort == "total" else QUERIES["id"]` | clean |

Rule of thumb: a fix only re-scans clean if no string concatenation builds the SQL. Steer the patch agent toward whole-query lookups or parameterized queries. Don't let it add `# nosemgrep`; that counts as editing the grader.
