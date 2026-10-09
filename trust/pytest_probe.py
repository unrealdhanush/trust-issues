"""pytest plugin the harness loads with `-p trust.pytest_probe`.

Records every test's outcome and exception type, so the harness can tell an exploit
that *landed* (an AssertionError) from a test that merely crashed.
"""

import json
import os

import pytest

_results = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or rep.outcome != "passed":
        exc = call.excinfo
        _results.append({
            "nodeid": rep.nodeid,
            "when": rep.when,
            "outcome": rep.outcome,
            "exc": exc.typename if exc else None,
            "message": str(exc.value)[:400] if exc else "",
        })


def pytest_collectreport(report):
    if report.failed:
        _results.append({
            "nodeid": report.nodeid, "when": "collect", "outcome": "failed",
            "exc": "CollectionError", "message": str(report.longrepr)[-400:],
        })


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("TRUST_PROBE_OUT")
    if out:
        with open(out, "w") as f:
            json.dump({"exitstatus": int(exitstatus), "results": _results}, f)
