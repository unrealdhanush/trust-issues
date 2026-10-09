"""Open a pull request for a fix, without touching the user's checkout.

The fix is committed in a temporary git worktree on its own branch, pushed to `origin`, and
opened as a PR through the GitHub API when GITHUB_TOKEN is set. Otherwise the branch is
pushed (or kept locally) and the compare link is printed.
"""

import re
import subprocess
import tempfile
from pathlib import Path

import httpx

from .config import env
from .models import Finding, Patch


def say(msg):
    print(f"[pr] {msg}", flush=True)


def git(cwd, *args, check=True):
    out = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {out.stderr.strip()[-300:]}")
    return out.stdout.strip()


def github_repo(remote_url):
    m = re.search(r"github\.com[:/]([^/]+)/(.+?)(\.git)?$", remote_url or "")
    return (m.group(1), m.group(2)) if m else None


def open_pr(target, finding: Finding, patch: Patch, body, proven=True):
    """Returns the PR (or compare/branch) reference, or None if the target isn't a git repo."""
    target = Path(target).resolve()
    top = git(target, "rev-parse", "--show-toplevel", check=False)
    if not top:
        say(f"{target} isn't a git repository; the diff is in runs/{finding.fix_id}/")
        return None
    prefix = target.relative_to(Path(top).resolve())
    base = env("TRUST_PR_BASE") or git(top, "rev-parse", "--abbrev-ref", "HEAD")
    branch = f"trust-issues/{finding.fix_id}"
    title = f"{'' if proven else '[unproven, approved by on-call] '}Fix SQL injection in {finding.path} ({finding.function})"

    with tempfile.TemporaryDirectory(prefix="trust-pr-") as tmp:
        wt = Path(tmp) / "wt"
        git(top, "worktree", "add", "-B", branch, str(wt), "HEAD")
        try:
            paths = []
            for edit in patch.edits:
                dest = wt / prefix / edit.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(edit.content)
                paths.append(str(prefix / edit.path))
            git(wt, "add", "--", *paths)
            git(wt, "commit", "-q", "-m", title, "-m",
                f"{'Proven' if proven else 'Shipped on an on-call decision'} by Trust Issues. "
                f"Evidence: runs/{finding.fix_id}/PR.md")
            remote = git(top, "remote", "get-url", "origin", check=False)
            if not remote:
                say(f"no origin remote; committed on local branch {branch}")
                return branch
            git(wt, "push", "-q", "-f", "-u", "origin", branch)
        finally:
            git(top, "worktree", "remove", "--force", str(wt), check=False)

    gh = github_repo(remote)
    if gh and env("GITHUB_TOKEN"):
        owner, repo = gh
        resp = httpx.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls",
            headers={"Authorization": f"Bearer {env('GITHUB_TOKEN')}", "Accept": "application/vnd.github+json"},
            json={"title": title, "head": branch, "base": base, "body": body}, timeout=30,
        )
        if resp.status_code == 201:
            url = resp.json()["html_url"]
            say(f"opened {url}")
            return url
        if resp.status_code == 422 and "already exists" in resp.text:
            say(f"a PR for {branch} already exists; pushed the new commit to it")
            return branch
        say(f"GitHub refused the PR ({resp.status_code}): {resp.text[:200]}")
    link = f"https://github.com/{gh[0]}/{gh[1]}/compare/{base}...{branch}?expand=1" if gh else branch
    say(f"pushed {branch}; open the PR at {link}")
    return link
