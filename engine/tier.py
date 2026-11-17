#!/usr/bin/env python3
"""Compute the tiers a pull request owes from its diff, using rules read from the base branch.

The author never picks the tier: the files and line counts come from GitHub's compare API for
base...head, and the rules come from .github/verification.toml at the base SHA.

Usage:
  tier.py classify < files.json        # [{"filename", "previous_filename"?, "additions", "deletions"}]
  tier.py github                       # in Actions: reads env, writes $GITHUB_OUTPUT
"""
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field

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


def gh_api(path: str, raw: bool = False) -> str:
    cmd = ["gh", "api", path]
    if raw:
        cmd += ["-H", "Accept: application/vnd.github.raw"]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def load_config(repo: str, base_sha: str) -> dict:
    # No fallback: a config that cannot be read fails this job, and the gate fails closed on it.
    return tomllib.loads(gh_api(f"repos/{repo}/contents/.github/verification.toml?ref={base_sha}", raw=True))


def compare_files(repo: str, base_sha: str, head_sha: str) -> tuple[list[dict], bool]:
    # The compare API returns at most 300 files, all on the first page (per_page pages commits, not files).
    # A list that reaches 300 may be cut short, so the caller owes every tier.
    files = json.loads(gh_api(f"repos/{repo}/compare/{base_sha}...{head_sha}")).get("files", [])
    return files, len(files) >= 300


def github_main() -> None:
    repo, base_sha, head_sha = os.environ["GITHUB_REPOSITORY"], os.environ["BASE_SHA"], os.environ["HEAD_SHA"]
    base_ref = os.environ.get("BASE_REF", "")
    config = load_config(repo, base_sha)
    files, truncated = compare_files(repo, base_sha, head_sha)
    result = classify(files, config.get("tiers", {}), truncated)
    enforce = config.get("mode", "observe") == "enforce" or base_ref in config.get("enforce_branches", [])
    review = config.get("review", {})
    t2 = "T2" in result.tiers
    sample = int(config.get("observe_sample", 1))
    pr = int(os.environ.get("PR_NUMBER", "0"))
    sampled = enforce or sample <= 1 or pr % sample == 0
    if not sampled:
        result.reasons.append(f"observe: Claude checks run on 1 PR in {sample}; this one was not sampled")
    outputs = {
        "tiers": " ".join(result.tiers),
        "code_lines": str(result.code_lines),
        "reasons": "; ".join(result.reasons),
        "enforce": "true" if enforce else "false",
        "review": "true" if sampled and ("T1" in result.tiers or t2) else "false",
        "blast": "true" if sampled and t2 else "false",
        "tp": "true" if sampled and "TP" in result.tiers else "false",
        "prompt_files": ",".join(re.sub(r"[^A-Za-z0-9/._-]", "", p) for p in result.prompt_files),
        "sampled": "true" if sampled else "false",
        "review_model": review.get("t2_model" if t2 else "t1_model", "claude-opus-5-5" if t2 else "claude-sonnet-5-5"),
        "review_level": review.get("t2_level" if t2 else "t1_level", "high" if t2 else "medium"),
        "review_effort": review.get("effort", "medium"),
        "checks": json.dumps(config.get("check", [])),
        "has_checks": "true" if config.get("check") else "false",
        "anthropic": json.dumps(config.get("anthropic", {})),
        "allowed_bots": ",".join(config.get("allowed_bots", [])),
    }
    print(json.dumps({"head": head_sha, "base": base_sha, **outputs}, indent=2))
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for k, v in outputs.items():
            out.write(f"{k}={' '.join(v.split())}\n")  # file names may hold newlines; one line per output


if __name__ == "__main__":
    if sys.argv[1:] == ["github"]:
        github_main()
    elif sys.argv[1:2] == ["classify"]:
        rules = tomllib.load(open(sys.argv[2], "rb")).get("tiers", {}) if len(sys.argv) > 2 else {}
        r = classify(json.load(sys.stdin), rules)
        print(json.dumps({"tiers": r.tiers, "code_lines": r.code_lines, "reasons": r.reasons}))
    else:
        sys.exit(__doc__)
