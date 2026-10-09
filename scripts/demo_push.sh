#!/usr/bin/env bash
# Stage the merge/push demo: a clean service repo, then "pushes" that bring each seeded bug back.
#
#   scripts/demo_push.sh setup [--clear-ledger]   clean repo (both bugs fixed) + a local origin
#   scripts/demo_push.sh watch                    terminal 2: Trust Issues watching new commits
#   scripts/demo_push.sh push users               bug 1 returns: proven, PR branch, nobody called
#   scripts/demo_push.sh push admin               bug 2 returns: fails proof twice, on-call rings
#   scripts/demo_push.sh status                   commits, and the PR branches Trust Issues pushed
#   scripts/demo_push.sh reset [--clear-ledger]   same as setup
#
# DEMO_DIR (default ~/trust-issues-demo) holds the repo; DEMO_DIR.git is its origin.
# EVERY (default 15s) is the watch interval. --clear-ledger removes earlier rows for these two
# fixes, so the dashboard starts empty for them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="${DEMO_DIR:-$HOME/trust-issues-demo}"
REMOTE="$DEMO.git"
EVERY="${EVERY:-15s}"
FIXED="$ROOT/fixtures/scripted"

say() { printf '[demo] %s\n' "$*"; }
ti_python() { uv run --project "$ROOT" python -c "$1"; }
commit() {  # commit as a teammate would, then push
  git -C "$DEMO" add -A
  git -C "$DEMO" -c user.name="Sam (shop team)" -c user.email="sam@shop.example" commit -q -m "$1"
  git -C "$DEMO" push -q origin main
  say "pushed $(git -C "$DEMO" rev-parse --short HEAD): $1"
}

setup() {
  rm -rf "$DEMO" "$REMOTE"
  mkdir -p "$DEMO"
  (cd "$ROOT/target" && tar --exclude=__pycache__ --exclude=.pytest_cache --exclude='*.sqlite' -cf - .) | tar -xf - -C "$DEMO"
  # Start clean: both seeded bugs already fixed, tests matching the safe behaviour.
  cp "$FIXED/users/attempt-1/app/users.py" "$DEMO/app/users.py"
  cp "$FIXED/admin/hint-1/app/admin.py" "$DEMO/app/admin.py"
  cp "$FIXED/admin/hint-1/tests/test_admin.py" "$DEMO/tests/test_admin.py"
  git init -q --bare "$REMOTE"
  git -C "$DEMO" init -q -b main
  git -C "$DEMO" remote add origin "$REMOTE"
  commit "Shop service: users and admin reports"
  ti_python "
import json
from pathlib import Path
from trust.watch import STATE_FILE
if STATE_FILE.exists():
    s = json.loads(STATE_FILE.read_text()); s['targets'].pop(str(Path('$DEMO').resolve()), None)
    STATE_FILE.write_text(json.dumps(s, indent=2))"
  if [[ "${1:-}" == "--clear-ledger" ]]; then
    ti_python "
from trust.ledger import get_ledger
from trust.models import Finding
ids = [Finding('', p, 0, '', function=f).fix_id for p, f in [('app/users.py', 'search_users'), ('app/admin.py', 'list_orders')]]
for i in ids: get_ledger().delete(fix_id=i)
print('[demo] cleared ledger rows for', ', '.join(ids))"
  fi
  say "clean repo at $DEMO (origin: $REMOTE). Next: '$0 watch' in another terminal."
}

push() {
  [[ -d "$DEMO/.git" ]] || { say "run '$0 setup' first"; exit 1; }
  case "${1:-}" in
    users)
      cp "$ROOT/target/app/users.py" "$DEMO/app/users.py"
      commit "Search: build the user lookup query inline" ;;
    admin)
      cp "$ROOT/target/app/admin.py" "$DEMO/app/admin.py"
      cp "$ROOT/target/tests/test_admin.py" "$DEMO/tests/test_admin.py"
      commit "Admin report: let ops sort by any SQL expression" ;;
    *) say "usage: $0 push users|admin"; exit 1 ;;
  esac
}

watch() {
  [[ -d "$DEMO/.git" ]] || { say "run '$0 setup' first"; exit 1; }
  say "watching $DEMO every $EVERY (new commits only, PR branches pushed to origin)"
  exec uv run --project "$ROOT" trust-issues watch --target "$DEMO" --changed-only --open-pr --every "$EVERY" "$@"
}

status() {
  git -C "$DEMO" log --oneline --format='  %h %an: %s'
  say "branches on origin:"
  git -C "$REMOTE" branch --format='  %(refname:short)'
}

case "${1:-}" in
  setup|reset) shift; setup "$@" ;;
  push) shift; push "$@" ;;
  watch) shift; watch "$@" ;;
  status) status ;;
  *) sed -n '2,13p' "$0"; exit 1 ;;
esac
