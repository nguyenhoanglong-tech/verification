"""A stand-in for the GitHub API, so post(), github_main() and the review run end to end in a test."""
import io
import os
import re
import sys
import urllib.error
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import github  # noqa: E402
from verdict import render_text  # noqa: E402

GATE_APP = 777
ACTIONS_APP = 15368

ENV = {"GITHUB_REPOSITORY": "o/r", "HEAD_SHA": "h", "BASE_SHA": "b", "BASE_REF": "dev", "PR_NUMBER": "1",
       "RUN_URL": "https://example.invalid/run", "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "2",
       "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/caller.yml@refs/heads/main",
       "GATE_APP_ID": str(GATE_APP), "GH_TOKEN": "actions-token", "GATE_TOKEN": "app-token"}


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "fake", {}, io.BytesIO(b""))


def check(id: int, record: dict | None, completed_at="2026-11-18T10:00:00Z", status="completed", conclusion="neutral",
          app=GATE_APP) -> dict:
    return {"id": id, "status": status, "conclusion": conclusion, "completed_at": completed_at,
            "app": {"id": app}, "output": {"text": render_text(record) if record else None}}


class GitHub:
    def __init__(self, config='mode = "shadow"\n', files=(), checks=None, workflow_runs=(), fail=None):
        self.config, self.files = config, list(files)
        self.checks = checks or {}            # head sha -> check runs
        self.workflow_runs = list(workflow_runs)
        self.fail = fail or {}                # "METHOD path-fragment" -> exceptions raised in turn
        self.calls = []
        self.tokens = []                      # the token each check-run write was sent with

    def api(self, path, method="GET", body=None, raw=False, token=None):
        self.calls.append((method, path, body))
        if method in ("PATCH", "POST") and "check-runs" in path:
            self.tokens.append(token or os.environ["GH_TOKEN"])
        for key, errors in self.fail.items():
            verb, frag = key.split(" ", 1)
            if verb == method and frag in path and errors:
                raise errors.pop(0)
        if raw:
            return self.config
        if "/compare/" in path:
            return {"files": self.files}
        if "/actions/workflows/" in path:
            return {"workflow_runs": self.workflow_runs}
        if method == "GET" and re.fullmatch(r"repos/[^/]+/[^/]+/check-runs/\d+", path):
            own = int(path.rsplit("/", 1)[1])
            return next((c for runs in self.checks.values() for c in runs if c["id"] == own),
                        {"id": own, "status": "in_progress"})
        if "/check-runs?" in path:
            return {"check_runs": self.checks.get(path.split("/commits/")[1].split("/")[0], [])}
        if path == "graphql":
            if "closingIssuesReferences" in body["query"]:
                return {"data": {"repository": {"pullRequest": {"createdAt": "2026-11-18T00:00:00Z",
                                                                "closingIssuesReferences": {"nodes": []}}}}}
            return {"data": {"repository": {"pullRequests": {"nodes": []}}}}
        return {"id": 900}

    def writes(self) -> list[tuple[str, str, dict]]:
        return [(m, p, b) for m, p, b in self.calls if m in ("PATCH", "POST") and "check-runs" in p]


@contextmanager
def installed(fake: GitHub, **env):
    with mock.patch.object(github, "api", fake.api), mock.patch.dict(os.environ, {**ENV, **env}):
        yield


def run(fn, *args) -> tuple[int, str]:
    """(exit code, stdout) of an entry point that may return a code or call sys.exit."""
    out = io.StringIO()
    with redirect_stdout(out):
        try:
            code = fn(*args)
        except SystemExit as e:
            code = e.code
    return code or 0, out.getvalue()


def outside_stop_commands(log: str, needle: str) -> list[str]:
    """Lines holding needle that the Actions command parser would read: not inside a stop-commands block. A token
    used twice counts as outside, since a block must take a fresh token."""
    token, seen, out = None, set(), []
    for line in log.splitlines():
        if token is None and line.startswith("::stop-commands::"):
            token = line.removeprefix("::stop-commands::")
            if token in seen:
                out.append(f"token reused: {token}")
            seen.add(token)
        elif token is not None and line == f"::{token}::":
            token = None
        elif needle in line and token is None:
            out.append(line)
    if token is not None:
        out.append(f"block never closed: {token}")
    return out


def review_result(**over) -> dict:
    """A complete, valid review job result: the Bugs call ran and found nothing. Override any key."""
    return {"findings": [], "security": None, "spec": None, "cost_usd": 0.5, "subscription_cost_usd": 0.0,
            "billing": "api", "error": None, "budget_refused": False, "calls": ["bugs"], **over}
