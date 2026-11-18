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


RECENT = """query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) {
  pullRequests(first: 20, orderBy: {field: UPDATED_AT, direction: DESC}) { nodes { commits(last: 10) { nodes { commit {
    checkSuites(first: 5, filterBy: {appId: %d}) { nodes { checkRuns(first: 10, filterBy: {checkName: "verification"}) {
      nodes { completedAt text } } } } } } } } } } }""" % ACTIONS_APP


def recent_records(repo: str) -> list[tuple[str, dict]]:
    """(completed_at, record) from the gate runs on the last 10 commits of the 20 most recently updated PRs.

    Each record carries the running totals, so the newest one is enough (verdict.budget_base). Earlier commits count
    because a PR pushed again keeps the totals its earlier heads paid for. The newest gate run is on a recently
    pushed PR, and a push updates the PR. Two gate jobs finishing in the same seconds can each miss the other's
    cost; the org's Console spend limit is the hard cap (D21).
    """
    owner, name = repo.split("/")
    out = []
    for pr in graphql(RECENT, owner=owner, name=name)["repository"]["pullRequests"]["nodes"]:
        for c in pr["commits"]["nodes"]:
            for suite in c["commit"]["checkSuites"]["nodes"]:
                for run in suite["checkRuns"]["nodes"]:
                    record = parse_text(run.get("text"))
                    if record and run.get("completedAt"):
                        out.append((run["completedAt"], record))
    return out
