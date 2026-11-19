"""The few GitHub API calls the engine makes, over urllib, so jobs need no gh or jq in their container."""
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from verdict import parse_text


def api(path: str, method: str = "GET", body: dict | None = None, raw: bool = False, token: str | None = None):
    url = path if path.startswith("https://") else f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com')}/{path}"
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None, headers={
        "Authorization": f"Bearer {token or os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read().decode()
    return data if raw else (json.loads(data) if data else None)


def graphql(query: str, **variables) -> dict:
    out = api("graphql", "POST", {"query": query, "variables": variables})
    if out.get("errors"):
        raise RuntimeError(f"GraphQL: {out['errors']}")
    return out["data"]


def gate_posted(run: dict) -> bool:
    """A `verification` check run the gate App (GATE_APP_ID) posted. Never one from GitHub Actions, the gate's poster
    before the App, not even an old one: any job holding checks: write, a PR's own included, can rewrite any GitHub
    Actions check run's conclusion and text (chrislongnguyen/dotfiles#3383)."""
    gate = os.environ.get("GATE_APP_ID", "")
    return gate.isdigit() and (run.get("app") or {}).get("id") == int(gate)


def verification_runs(repo: str, sha: str) -> list[dict]:
    """Every `verification` check run on this commit that the gate posted (gate_posted)."""
    runs, page = [], 1
    while True:
        got = api(f"repos/{repo}/commits/{sha}/check-runs?check_name=verification&filter=all&per_page=100&page={page}")
        runs += [r for r in got["check_runs"] if gate_posted(r)]
        if len(got["check_runs"]) < 100:
            return runs
        page += 1


# A gate run posts its record within this long of its Actions run starting: start, tier, review and gate time out at
# 5 + 5 + 40 + 5 minutes, and the gate can queue behind other gates on its head.
SPAN = timedelta(hours=6)


def when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def run_head(run: dict) -> str:
    """The PR head a gate run judged. Under pull_request_target a run's head_sha is the base tip, so the caller names
    the head in its run-name ("verification <sha>"); under pull_request head_sha is the head."""
    named = re.search(r"\b[0-9a-f]{40}\b", run.get("display_title") or "")
    return named.group(0) if named else run["head_sha"]


def month_records(repo: str, workflow_ref: str, now: datetime) -> list[tuple[str, dict]]:
    """(completed_at, record) from the gate runs of this caller workflow this month (D21's budget base).

    Read from the caller's Actions runs, not from pull requests, so a head force-pushed away or a closed PR still
    counts. Each record carries the running totals, so the newest one is enough (verdict.budget_base): the walk goes
    newest run first and stops at a run that started SPAN before the newest record it holds. Any failure raises, and
    the caller skips the paid review (fail closed). Two gate jobs finishing in the same seconds can each miss the
    other's cost; the org's Console spend limit is the hard cap (D21).
    """
    path = workflow_ref.split("@", 1)[0].split("/", 2)[-1]
    if not path.startswith(".github/workflows/"):
        raise RuntimeError(f"cannot name the caller workflow from GITHUB_WORKFLOW_REF={workflow_ref!r}")
    workflow = path.rsplit("/", 1)[1]
    # A run started up to SPAN before the month posts its record, and its spend, inside the month.
    since = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - SPAN
    out, seen, newest, page = [], set(), None, 1
    while True:
        got = api(f"repos/{repo}/actions/workflows/{workflow}/runs?created=%3E%3D{since:%Y-%m-%dT%H:%M:%SZ}&per_page=100&page={page}")
        for run in got["workflow_runs"]:
            if newest and when(run["created_at"]) < newest - SPAN:
                return out
            sha = run_head(run)
            if sha in seen:
                continue
            seen.add(sha)
            try:
                checks = verification_runs(repo, sha)
            except urllib.error.HTTPError as e:
                if e.code in (404, 422):  # the commit is gone, and its check runs with it
                    continue
                raise
            for check in checks:
                record = parse_text((check.get("output") or {}).get("text"))
                if record and check.get("completed_at"):
                    out.append((check["completed_at"], record))
                    newest = max(newest or when(check["completed_at"]), when(check["completed_at"]))
        if len(got["workflow_runs"]) < 100:
            return out
        page += 1
