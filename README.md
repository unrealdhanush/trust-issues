# Trust Issues

> It has trust issues, so you don't have to.

An autonomous loop that finds a vulnerability, patches it, and refuses to call the fix done until it proves it. When proof fails twice, it phones the on-call engineer for one decision.

Build brief (timeline, demo script, cut order, pre-flight): https://claude.ai/code/artifact/804f53f2-1849-4cbf-b041-54352a6d3d7d

## The loop

1. **Detect.** The Semgrep MCP server scans the target repo and returns one SQL injection finding.
2. **Patch.** An OpenAI agent writes the fix.
3. **Prove.** The fix isn't done until all six checks pass:
   - the generated exploit test reproduces the vulnerability on the original code
   - the same exploit is blocked on the patch
   - a Semgrep re-scan comes back clean
   - the existing test suite has no new failures
   - verification tests and configuration remain protected
   - the patch stays within the allowed scope

   The agent may not edit tests unless on-call explicitly unlocks the failing test files for a retry.
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

## Demo: a push brings a bug back

`scripts/demo_push.sh` stages the CI story on a scratch repo: a clean shop service (both seeded
bugs fixed), a local `origin`, and two "pushes" from a teammate that each bring one bug back.

```
scripts/demo_push.sh setup --clear-ledger   # clean repo at ~/trust-issues-demo, dashboard rows cleared
scripts/demo_push.sh watch                  # terminal 2: watches new commits every 15s
scripts/demo_push.sh push users             # bug 1 returns -> proven, PR branch pushed, nobody called
scripts/demo_push.sh push admin             # bug 2 returns -> fails proof twice -> on-call rings
scripts/demo_push.sh status                 # commits, and the PR branches Trust Issues pushed
```

Each push is caught on the next cycle and only the changed files are checked. Idle cycles don't
scan, so a short interval costs nothing. Run `setup` again to reset between rehearsals.

## Using it on your own repo

```
uv pip install -r /path/to/repo/requirements.txt      # or give the repo its own .venv: it's used automatically
trust-issues run   --target /path/to/repo --open-pr   # one pass: scan, prove, open a PR per proven fix
trust-issues watch --target /path/to/repo --every 15m --open-pr          # keep watching
trust-issues watch --target /path/to/repo --once --changed-only --pull   # one pass for cron/CI, new commits only
```

**How it finds bugs.** Each pass runs Semgrep (through its MCP server) over the repo's non-test
Python files, and groups findings per vulnerable function.

**How it monitors.** `watch` re-scans on the interval you give it. A finding is handled once a fix
reaches an outcome (proven, shipped, held). It's looked at again only when that function's
code changes: a proven fix waiting in review isn't re-proven every cycle, but a regression is.
`--changed-only` limits each pass to files changed in new commits. State lives in
`runs/watch-state.json`. For a schedule without a long-running process, run `watch --once` from
cron, or use `examples/github-action.yml` (daily, opens PRs with `GITHUB_TOKEN`).

**What it sends to the model.** The vulnerable file, the repo files it imports, the conftest files
and the tests that mention it, up to a budget. Not the whole repo.

**Where tests run.** In the target's own `.venv` or `venv` if it has one, or `TRUST_TARGET_PYTHON`,
otherwise in this environment. Each attempt runs on a copy without `.git`, virtualenvs or
`node_modules`.

**Regression tests.** Every delivered fix carries the exploit that proved it, as
`tests/test_security_<fix_id>.py`. It failed on the vulnerable code and passes on the fix, so if
the bug ever comes back, CI fails on exactly that attack. It's only added when the patch really
blocks the exploit.

**Pull requests.** `--open-pr` commits each proven fix (or one on-call chose to ship, marked
unproven) on a `trust-issues/<fix_id>` branch in a temporary git worktree, so your checkout is
never touched. It pushes the branch to `origin` and, with `GITHUB_TOKEN` set and a GitHub remote,
opens the PR with the proof as its body. Without a token it prints the compare link.

Still Python, pytest and SQL injection only. The harness checks are class-agnostic; new
vulnerability classes need their own detection filter and exploit prompt.

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
trust/watch.py      monitoring: scheduled scans, skip what's handled, re-check changed code
trust/publish.py    pull requests from a temporary git worktree
trust/context.py    what the model sees: the vulnerable file, its imports, its tests
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

## Semgrep rules for AI-written patches

Semgrep's built-in rules answer "is this code vulnerable?". `rules/ai-patch.yml` answers "did the
AI's patch fix the bug the way LLMs tend to, unsafely, or cheat the grader?":

| Rule | Catches |
| --- | --- |
| `ai-patch-scanner-suppression` | `# nosemgrep`, `# nosec`, `# noqa: S…` added to make a finding disappear |
| `ai-patch-handrolled-sql-escaping` | `.replace("'", "''")`, stripped `;` or `--`, `re.sub` scrubbing: an invented sanitizer instead of a bound parameter |
| `ai-patch-swallowed-db-error` | a catch-all `except` around a query that hides the failure |

The pack runs on the code before and after every patch. A hit that only exists after the patch is
recorded as "caught by Semgrep's AI-patch rules" and fails the proof. It runs with
`--disable-nosem`, so a patch can't opt out of the scan that judges it. That's also why it uses the
Semgrep CLI: the MCP server's custom-rule tool always honours `nosemgrep`. Semgrep's built-in
taint rule already sees through hand-escaping when user input flows in; the pack also catches it
when it doesn't (helpers, background jobs). Test the rules with `semgrep --test rules/`.

## Known gotcha for Prove

Semgrep's taint rule (`tainted-sql-string`) still flags a correct allowlist fix for `ORDER BY`. Checked against semgrep 1.180 with `p/python`:

| Fix shape | Re-scan |
| --- | --- |
| `col = ALLOWED.get(sort, "id")`, then `"... ORDER BY " + col` | flagged |
| `col = sort_column(sort)` (a helper returning only literals), then `"... ORDER BY " + col` | flagged |
| Pick a whole literal query: `QUERIES["total"] if sort == "total" else QUERIES["id"]` | clean |

Rule of thumb: a fix only re-scans clean if no string concatenation builds the SQL. Steer the patch agent toward whole-query lookups or parameterized queries. Don't let it add `# nosemgrep`; that counts as editing the grader.
