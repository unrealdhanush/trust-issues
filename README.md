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

## Quickstart

```
uv sync                                   # Python deps, plus the `trust` CLI
uv tool install semgrep                   # Semgrep CLI + its built-in MCP server
cp .env.example .env                      # fill in what you have; everything is optional offline

uv run trust serve                        # dashboard + webhook tools on http://localhost:8000
uv run trust run --only app/users.py      # bug 1: proves itself, nobody is called
uv run trust run --only app/admin.py      # bug 2: fails proof twice, then escalates
uv run trust decide <fix_id> retry --hint "you can update the admin sort test"
uv run trust ledger                       # the proof trail
uv run trust call-test                    # rehearse the escalation call
uv run pytest -q                          # the harness's own tests
```

Use `semgrep mcp`, not `uvx semgrep-mcp`: the standalone package crashes on startup with current
pydantic (`ImportError: eval_type_backport`).

With no keys set, the loop runs fully offline: `TRUST_AGENT=scripted` replays `fixtures/scripted`,
the ledger is `runs/ledger.jsonl`, and the escalation is decided from the dashboard or `trust decide`.
Each piece switches to the real service as soon as its env vars are set.

| Piece | Offline default | Real service once set |
| --- | --- | --- |
| Patch + exploit agent | `fixtures/scripted` | OpenAI Responses API (`OPENAI_API_KEY`, `OPENAI_MODEL`) |
| Detect + re-scan | Semgrep MCP (`semgrep mcp`), CLI fallback | same |
| Ledger | `runs/ledger.jsonl` | ClickHouse (`CLICKHOUSE_URL`, `CLICKHOUSE_PASSWORD`) |
| Escalation | dashboard buttons / `trust decide` | ElevenLabs outbound call via Twilio (see below) |

### Voice setup (Track C)

1. `uv run trust serve`, then `cloudflared tunnel --url http://localhost:8000` and put the URL in `PUBLIC_BASE_URL`.
2. `uv run python scripts/setup_elevenlabs.py`: creates the `read_ledger` and `write_decision` webhook
   tools and the agent, imports the Twilio number, and prints `ELEVENLABS_AGENT_ID` and
   `ELEVENLABS_PHONE_NUMBER_ID` for `.env`.
3. Set `ONCALL_PHONE_NUMBER`. A Twilio trial account can only dial verified numbers.
4. Rehearse: `trust call-test` (or `--to +1...` for another phone). It writes a temporary failed fix
   (demo bug 2), checks that the agent's tools reach this ledger through the tunnel, places the
   call, waits for the decision, prints the transcript and deletes its rows. Without ElevenLabs
   settings it simulates the call; answer from the dashboard or with `trust decide`.
   `--keep` leaves the rows for inspection, and `--cleanup` removes every rehearsal row.

Homebrew's `p11-kit` also installs a `trust` command. Outside the venv, use `trust-issues`, an alias
for the same CLI, or `uv run trust`.

With `ELEVENLABS_AGENT_ID` set, the dashboard also shows the ElevenLabs web widget on a pending
escalation, which is the no-phone fallback.

## Layout

```
target/             seeded Flask app: bug 1 in app/users.py, bug 2 in app/admin.py (Track A)
trust/semgrep.py    detection and re-scan through the Semgrep MCP server, CLI fallback (A/B)
trust/agent.py      OpenAI patch + exploit agent, and the scripted stand-in (A)
trust/prove.py      the prove harness: exploit flip, re-scan, suite, verdict (B)
trust/guard.py      the agent may not edit what grades it (B)
trust/pytest_probe.py  pytest plugin that tells "exploit landed" from "test crashed" (B)
trust/loop.py       orchestrator + CLI: retries, escalation, ship/hold/retry (all)
trust/ledger.py     ClickHouse ledger with a local JSONL fallback (C)
trust/server.py     webhook tools for the voice agent, dashboard API (C)
trust/voice.py      ElevenLabs outbound call and transcript (C)
trust/dashboard.html  live ledger view and decision fallback (C)
scripts/setup_elevenlabs.py  one-time agent, tools and phone number setup (C)
fixtures/scripted/  deterministic agent output for rehearsal
tests/              tests for the harness, ledger and webhooks
```

## How proof works

A fix is proven only when all six checks hold:

| Check | Passes when |
| --- | --- |
| Exploit on original | the exploit test fails with an `AssertionError` (it "lands"). A test that crashes, or passes on the original, proves nothing and is rejected as invalid. |
| Exploit on patch | the same test passes (it's "blocked") |
| Semgrep | nothing is left in the vulnerable function, and the patch introduces no new security finding |
| Suite | no test fails that wasn't already failing on the original code |
| Guard | the agent left tests, conftest, pytest and Semgrep config, and the exploit file alone, added no `nosemgrep`, and doesn't detect the harness |
| Scope (no slop) | the patch changes only the vulnerable function: no other functions or files, no new modules, no unused code, no narrating comments, prints or catch-all excepts, within a diff budget (`TRUST_DIFF_BUDGET`, default 60 lines) |

**New vs. old findings.** Findings are grouped per function, so a file with an unrelated old bug
doesn't block a fix. Each finding on the patched code is labelled *unfixed* (still in the target
function), *pre-existing* (it matches a finding on the original by rule and matched code, not line
number, so it survives line shifts), or *introduced* (it matches nothing). Unfixed and introduced
fail the proof. Pre-existing findings are recorded in the ledger and the PR body. The voice agent can
then say "that one predates the patch."

A `retry` decision from on-call unlocks exactly the test files that failed in the last attempt,
and nothing else. Every attempt, escalation, decision, hint and transcript lands in the ledger.

## Known gotcha for Prove

Semgrep's taint rule (`tainted-sql-string`) still flags a correct allowlist fix for `ORDER BY`. Checked against semgrep 1.180 with `p/python`:

| Fix shape | Re-scan |
| --- | --- |
| `col = ALLOWED.get(sort, "id")`, then `"... ORDER BY " + col` | flagged |
| `col = sort_column(sort)` (a helper returning only literals), then `"... ORDER BY " + col` | flagged |
| Pick a whole literal query: `QUERIES["total"] if sort == "total" else QUERIES["id"]` | clean |

Rule of thumb: a fix only re-scans clean if no string concatenation builds the SQL. Steer the patch agent toward whole-query lookups or parameterized queries. Don't let it add `# nosemgrep`; that counts as editing the grader.
