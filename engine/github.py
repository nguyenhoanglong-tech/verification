"""The few GitHub API calls the engine makes, over urllib, so jobs need no gh or jq in their container."""
import json
import os
import urllib.request

from verdict import ACTIONS_APP, parse_text


def api(path: str, method: str = "GET", body: dict | None = None, raw: bool = False):
    url = path if path.startswith("https://") else f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com')}/{path}"
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None, headers={
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
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


def verification_runs(repo: str, sha: str) -> list[dict]:
    """Every `verification` check run on this commit from GitHub Actions, the only app the ruleset trusts."""
    runs, page = [], 1
    while True:
        got = api(f"repos/{repo}/commits/{sha}/check-runs?check_name=verification&filter=all&per_page=100&page={page}")
        runs += [r for r in got["check_runs"] if (r.get("app") or {}).get("id") == ACTIONS_APP]
        if len(got["check_runs"]) < 100:
            return runs
        page += 1


def recent_records(repo: str, prs: int = 20) -> list[tuple[str, dict]]:
    """(completed_at, record) from the gate runs on the heads of the most recently updated PRs.

    Each record carries the running totals, so the newest one is enough (verdict.budget_base). The newest gate run is
    on a recently pushed PR, and a push updates the PR, so 20 PRs reach it. Two gate jobs finishing in the same seconds
    can each miss the other's cost; the org's Console spend limit is the hard cap (D21).
    """
    out = []
    for pr in api(f"repos/{repo}/pulls?state=all&sort=updated&direction=desc&per_page={prs}"):
        for run in verification_runs(repo, pr["head"]["sha"]):
            record = parse_text((run.get("output") or {}).get("text"))
            if record and run.get("completed_at"):
                out.append((run["completed_at"], record))
    return out
