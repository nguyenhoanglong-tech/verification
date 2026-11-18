#!/usr/bin/env python3
"""Compute the tiers a pull request owes from its diff, using rules read from the base branch.

The author never picks the tier: the files and line counts come from GitHub's compare API for
base...head, and the rules come from .github/verification.toml at the base SHA.

Usage:
  tier.py classify < files.json        # [{"filename", "previous_filename"?, "additions", "deletions"}]
  tier.py github                       # in Actions: reads env, writes $GITHUB_OUTPUT
"""
import base64
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone

import github
import verdict

DEFAULT_RULES = {
    "t2_lines": 300,
    "docs": ["**/*.md", "**/*.txt", "docs/**", "LICENSE"],
    "prompt": ["**/SKILL.md", "**/CLAUDE.md", "**/AGENTS.md", ".claude/rules/**"],
    "risk": [".github/**"],
}


def glob_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(path: str, patterns: list[str]) -> bool:
    return any(glob_regex(p).match(path) for p in patterns)


@dataclass
class Result:
    tiers: list[str]
    code_lines: int
    reasons: list[str] = field(default_factory=list)
    prompt_files: list[str] = field(default_factory=list)


def classify(files: list[dict], rules: dict, truncated: bool = False) -> Result:
    rules = {**DEFAULT_RULES, **rules}
    code_lines, prompt_files, risk_files, code_files = 0, [], [], []
    for f in files:
        names = [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") else [])
        lines = int(f.get("additions", 0)) + int(f.get("deletions", 0))
        prompt = any(matches(n, rules["prompt"]) for n in names)
        risk = any(matches(n, rules["risk"]) for n in names)
        if prompt:
            prompt_files.append(f["filename"])
        if risk:
            risk_files.append(f["filename"])
            code_lines += lines
        elif any(not matches(n, rules["prompt"]) and not matches(n, rules["docs"]) for n in names):
            code_files.append(f["filename"])
            code_lines += lines

    tiers, reasons = [], []
    if truncated:
        tiers.append("T2")
        reasons.append("compare API truncated the file list: treated as T2")
    elif risk_files:
        tiers.append("T2")
        reasons.append("risk path: " + ", ".join(risk_files[:5]))
    elif code_lines >= rules["t2_lines"]:
        tiers.append("T2")
        reasons.append(f"{code_lines} code lines >= {rules['t2_lines']}")
    elif code_files:
        tiers.append("T1")
        reasons.append(f"{code_lines} code lines in {len(code_files)} files")
    if prompt_files or truncated:
        tiers.append("TP")
        reasons.append("prompt files: " + ", ".join(prompt_files[:5]) if prompt_files else "file list truncated: TP owed")
    if not tiers:
        tiers.append("T0")
        reasons.append("docs only")
    return Result(tiers, code_lines, reasons, prompt_files)


class ConfigError(Exception):
    pass


def settings(config: dict, base_ref: str) -> dict:
    """mode, enforcement and live_checks from the base toml (D10, D27). An unknown value is an error, never a default."""
    mode = config.get("mode", "shadow")
    if mode == "observe":
        raise ConfigError('mode "observe" was renamed to "shadow" (shadow trial): set mode = "shadow" in .github/verification.toml')
    if mode not in ("shadow", "enforce"):
        raise ConfigError(f'mode must be "shadow" or "enforce", got {mode!r}')
    for check in config.get("check", []):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", str(check.get("name", ""))) or not check.get("run"):
            raise ConfigError(f"each [[check]] needs a plain name (A-Z a-z 0-9 . _ -) and a run command: {check}")
    live = config.get("live_checks", "owed")
    if live not in ("machine", "owed"):
        raise ConfigError(f'live_checks must be "machine" or "owed", got {live!r}')
    enforce = mode == "enforce" or base_ref in config.get("enforce_branches", [])
    review = config.get("review", {})
    return {
        "mode": "enforce" if enforce else "shadow",
        # An enforced base always runs every owed check.
        "live_checks": "owed" if enforce else live,
        "reviews_per_day": int(config.get("reviews_per_day", 5)),
        "budget_month_usd": float(config.get("budget_month_usd", 100)),
        "standards": review.get("standards", "CODING_STANDARDS.md"),
    }


DONE_WHEN = re.compile(r"^(#{1,6})\s+.*\b(done[ -]when|acceptance criteria)\b", re.I | re.M)


def done_when(body: str) -> str:
    """The done-when or acceptance-criteria section of an issue body, heading included; empty when there is none."""
    m = DONE_WHEN.search(body or "")
    if not m:
        return ""
    level = len(m.group(1))
    rest = body[m.end():]
    nxt = re.search(r"^#{1,%d}\s" % level, rest, re.M)
    return (body[m.start():m.end()] + (rest[:nxt.start()] if nxt else rest)).strip()


def body_at(issue: dict, when: str) -> str:
    """The issue body as it stood at `when`. GitHub keeps every version in userContentEdits, newest first."""
    for edit in issue.get("edits", []):
        if edit.get("diff") is not None and edit["editedAt"] <= when:
            return edit["diff"]
    return issue["body"] if not issue.get("edits") else ""


def switch(pr_created_at: str, issues: list[dict]) -> str:
    """D8: the done-when sections of the closed issues created before the PR, as their bodies stood when it opened."""
    parts = []
    for issue in issues:
        if issue["createdAt"] < pr_created_at:
            section = done_when(body_at(issue, pr_created_at))
            if section:
                parts.append(f"Issue #{issue['number']}:\n{section}")
    return "\n\n".join(parts)


CLOSING = """query($owner: String!, $name: String!, $pr: Int!) { repository(owner: $owner, name: $name) {
  pullRequest(number: $pr) { createdAt closingIssuesReferences(first: 10) { nodes {
    number createdAt body userContentEdits(first: 100) { nodes { editedAt diff } } } } } } }"""


def closing_issues(repo: str, pr: int) -> tuple[str, list[dict]]:
    owner, name = repo.split("/")
    data = github.graphql(CLOSING, owner=owner, name=name, pr=pr)["repository"]["pullRequest"]
    issues = [{**i, "edits": i["userContentEdits"]["nodes"]} for i in data["closingIssuesReferences"]["nodes"]]
    return data["createdAt"], issues


def load_config(repo: str, base_sha: str) -> dict:
    # No fallback: a config that cannot be read fails this job, and the gate fails closed on it.
    return tomllib.loads(github.api(f"repos/{repo}/contents/.github/verification.toml?ref={base_sha}", raw=True))


def compare_files(repo: str, base_sha: str, head_sha: str) -> tuple[list[dict], bool]:
    # The compare API returns at most 300 files, all on the first page (per_page pages commits, not files).
    # A list that reaches 300 may be cut short, so the caller owes every tier.
    files = github.api(f"repos/{repo}/compare/{base_sha}...{head_sha}").get("files", [])
    return files, len(files) >= 300


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def write_outputs(outputs: dict) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for k, v in outputs.items():
            out.write(f"{k}={' '.join(v.split())}\n")  # file names may hold newlines; one line per output


def github_main() -> None:
    repo, base_sha, head_sha = os.environ["GITHUB_REPOSITORY"], os.environ["BASE_SHA"], os.environ["HEAD_SHA"]
    print(f"base {base_sha}")
    config = load_config(repo, base_sha)
    try:
        s = settings(config, os.environ.get("BASE_REF", ""))
    except ConfigError as e:
        print(f"::error::{e}")
        write_outputs({"config_error": str(e)})
        sys.exit(1)
    files, truncated = compare_files(repo, base_sha, head_sha)
    result = classify(files, config.get("tiers", {}), truncated)
    t2 = "T2" in result.tiers
    code = t2 or "T1" in result.tiers
    review_cfg = config.get("review", {})
    skip, spec = "", ""
    budget = {"reviews_per_day": s["reviews_per_day"], "budget_month_usd": s["budget_month_usd"], "skipped": False}
    review = code and s["live_checks"] == "owed"
    if code and not review:
        skip = "machine only"
    if review:
        today, month = verdict.budget_base(github.recent_records(repo), datetime.now(timezone.utc))
        allowed = verdict.budget_allows(today, month, s["reviews_per_day"], s["budget_month_usd"])
        budget["skipped"] = not allowed
        print(f"budget: {today} paid reviews today of {s['reviews_per_day']}, ${month:.2f} this month of ${s['budget_month_usd']:.2f}")
        if not allowed:
            review, skip = False, verdict.BUDGET_SKIPPED
        else:
            spec = switch(*closing_issues(repo, int(os.environ["PR_NUMBER"])))
    outputs = {
        "base_sha": base_sha,
        "mode": s["mode"],
        "tiers": " ".join(result.tiers),
        "code_lines": str(result.code_lines),
        "reasons": "; ".join(result.reasons),
        "review": "true" if review else "false",
        "skip": skip,
        "switch_spec": "true" if spec else "false",
        "spec_text": json.dumps(spec),
        "budget": json.dumps(budget),
        "standards": re.sub(r"[^A-Za-z0-9/._-]", "", s["standards"]),
        "review_model": review_cfg.get("t2_model" if t2 else "t1_model", "claude-opus-5-5"),
        "review_level": review_cfg.get("t2_level" if t2 else "t1_level", "high" if t2 else "medium"),
        "review_effort": review_cfg.get("effort", "medium"),
        # name:command pairs, each base64, so the checks job (docker CLI image, no jq) can read them.
        "checks": " ".join(f"{b64(c['name'])}:{b64(c['run'])}" for c in config.get("check", [])),
        "has_checks": "true" if config.get("check") else "false",
        "anthropic": json.dumps(config.get("anthropic", {})),
    }
    print(json.dumps({"head": head_sha, **outputs}, indent=2))
    write_outputs(outputs)


if __name__ == "__main__":
    if sys.argv[1:] == ["github"]:
        github_main()
    elif sys.argv[1:2] == ["classify"]:
        rules = tomllib.load(open(sys.argv[2], "rb")).get("tiers", {}) if len(sys.argv) > 2 else {}
        r = classify(json.load(sys.stdin), rules)
        print(json.dumps({"tiers": r.tiers, "code_lines": r.code_lines, "reasons": r.reasons}))
    else:
        sys.exit(__doc__)
