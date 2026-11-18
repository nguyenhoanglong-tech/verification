#!/usr/bin/env python3
"""One verdict record per gate run (D25), the sticky rule (G4) and the budget pace (D21).

The record goes into the `verification` check run's output text after MARKER, as one fenced JSON block.
The sticky rule, the budget pace and the dotfiles finding log read that record, never `conclusion` alone.

  verdict.py post      # gate job: reads NEEDS, HEAD_SHA, RUN_URL; posts the verdict on this head
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

MARKER = "<!-- verification-record v1 -->"
ACTIONS_APP = 15368
BUDGET_SKIPPED = "review skipped: budget"


def render_text(record: dict) -> str:
    return f"{MARKER}\n```json\n{json.dumps(record, indent=1)}\n```\n"


def parse_text(text: str | None) -> dict | None:
    if not text or MARKER not in text:
        return None
    m = re.search(r"```json\n(.*?)\n```", text.split(MARKER, 1)[1], re.S)
    try:
        record = json.loads(m.group(1)) if m else None
    except ValueError:
        return None
    return record if isinstance(record, dict) and record.get("schema") == 1 else None


def prior_verdicts(check_runs: list[dict], own_id: int | None) -> list[str]:
    """Verdicts of the other gate runs on this head. A failure posted before records existed counts as FAIL."""
    out = []
    for run in check_runs:
        if run.get("id") == own_id or run.get("status") != "completed":
            continue
        record = parse_text((run.get("output") or {}).get("text"))
        if record:
            out.append(record["verdict"])
        elif run.get("conclusion") == "failure":
            out.append("FAIL")
    return out


def budget_base(dated_records: list[tuple[str, dict]], now: datetime) -> tuple[int, float]:
    """Paid reviews today and USD this month, carried by the newest record of this month."""
    newest = None
    for at, record in dated_records:
        when = datetime.fromisoformat(at.replace("Z", "+00:00"))
        if (when.year, when.month) == (now.year, now.month) and "month_usd" in (record.get("budget") or {}):
            if newest is None or when > newest[0]:
                newest = (when, record["budget"])
    if newest is None:
        return 0, 0.0
    when, budget = newest
    today = int(budget.get("reviews_today", 0)) if when.date() == now.date() else 0
    return today, float(budget.get("month_usd", 0))


def budget_allows(reviews_today: int, month_usd: float, reviews_per_day: int, budget_month_usd: float) -> bool:
    return reviews_today < reviews_per_day and month_usd < budget_month_usd


def spec_findings(spec: dict | None) -> list[dict]:
    """A done-when item answered No or Partly is a P0 (D25, amendment item 3)."""
    return [{"call": "spec", "severity": "P0", "file": "", "line": None, "summary": f"done-when item {i['status']}: {i['item']}",
             "failure": i.get("evidence", "")}
            for i in (spec or {}).get("items", []) if i.get("status") in ("No", "Partly")]


def decide(*, head_sha, base_sha, tiers, mode, switch_spec, machine, review, budget, errors, prior) -> dict:
    """Build the record. mode is None when the tier job failed, and then the gate fails closed as if enforcing.

    machine: [{name, result: pass|fail}]. review: None when no review ran, else {findings, spec, cost_usd}.
    errors: why this run could not judge (job failures, review errors). prior: verdicts of earlier runs on this head.
    """
    findings = list((review or {}).get("findings", [])) + spec_findings((review or {}).get("spec"))
    fail = (any(m["result"] != "pass" for m in machine) or any(f["severity"] == "P0" for f in findings)
            or "FAIL" in prior)
    verdict = "FAIL" if fail else "ERROR" if errors else "PASS"
    shadow = mode == "shadow"
    label = tiers or "tier unknown"
    if verdict == "PASS":
        title = f"{label} passed"
    elif verdict == "FAIL":
        title = f"{label} would block (shadow trial)" if shadow else f"{label} blocked"
    else:
        title = f"{label} error" if shadow else f"{label} error: re-run"
    if budget.get("skipped"):
        title += f" ({BUDGET_SKIPPED})"
    return {
        "schema": 1, "head_sha": head_sha, "base_sha": base_sha, "tier": tiers, "mode": mode or "enforce",
        "verdict": verdict, "title": title, "switch_spec": bool(switch_spec), "machine": machine,
        "findings": findings, "spec": (review or {}).get("spec"), "cost_usd": float((review or {}).get("cost_usd") or 0),
        "budget": budget, "error": "; ".join(errors) or None,
    }


def conclusion(record: dict) -> str:
    if record["verdict"] == "PASS":
        return "success"
    return "neutral" if record["mode"] == "shadow" else "failure"


def stamp(tiers: str, ran: list[str], skip: str) -> str:
    """D11: T0 stamps checks-T0; none only when owed checks did not run."""
    if tiers == "T0":
        return "checks-T0"
    if skip:
        return f"none ({skip})"
    return ",".join(ran) or "none (nothing ran)"


def summary(record: dict, stamp_text: str, reasons: str, run_url: str) -> str:
    lines = [f"Verified-by: {stamp_text} head={record['head_sha']}", "",
             f"verdict: {record['verdict']}", f"tiers: {record['tier']} ({reasons})", f"base: {record['base_sha']}",
             f"mode: {record['mode']}", f"spec call: {'yes' if record['switch_spec'] else 'no'}",
             f"cost_usd: {record['cost_usd']:.4f}",
             "budget: " + (BUDGET_SKIPPED if record["budget"].get("skipped") else
                           f"{record['budget'].get('reviews_today', 0)} paid reviews today, "
                           f"${record['budget'].get('month_usd', 0):.2f} this month"),
             "machine: " + (" ".join(f"{m['name']}={m['result']}" for m in record["machine"]) or "none")]
    if record["error"]:
        lines.append(f"error: {record['error']}")
    if record["findings"]:
        lines += ["", "findings:"] + [f"- [{f['severity']}] {f['call']} {f['file']}:{f['line'] or ''} {f['summary']}"
                                      for f in record["findings"]]
    if record["spec"]:
        lines += ["", f"spec: {record['spec'].get('answer')}", "| item | status | evidence |", "| --- | --- | --- |"]
        lines += [f"| {i['item']} | {i['status']} | {i.get('evidence', '')} |".replace("\n", " ") for i in record["spec"]["items"]]
    lines += ["", f"run: {run_url}"]
    return "\n".join(lines)[:60000]


def from_needs(needs: dict, head_sha: str) -> tuple[dict, list[str], list[str]]:
    """Read the job results into decide()'s inputs. Returns (inputs, ran, errors)."""
    tier = needs.get("tier", {})
    out = tier.get("outputs") or {}
    errors, ran = [], []
    for job in ("start", "tier"):
        if needs.get(job, {}).get("result") != "success":
            errors.append(f"{job} job {needs.get(job, {}).get('result')}")
    if out.get("config_error"):
        errors.append(out["config_error"])
    tier_ok = tier.get("result") == "success"

    def owed(job: str, flag: str) -> dict | None:
        res = needs.get(job, {}).get("result")
        if out.get(flag) != "true":
            if res not in (None, "skipped"):
                errors.append(f"{job} ran but was not owed ({res})")
            return None
        if res != "success":
            errors.append(f"{job} {res}")
            return None
        job_out = needs[job].get("outputs") or {}
        if job_out.get("head") != head_sha:
            errors.append(f"{job} ran on another head")
            return None
        ran.append(job)
        return job_out

    machine = []
    checks = owed("checks", "has_checks")
    if checks:
        try:
            machine = json.loads(checks.get("results") or "[]")
        except ValueError:
            errors.append("checks job output unreadable")
    review = None
    review_out = owed("review", "review")
    budget = json.loads(out.get("budget") or "{}") if tier_ok else {}
    if review_out:
        try:
            review = json.loads(review_out.get("result") or "")
        except ValueError:
            errors.append("review job output unreadable")
            review = None
        # The org's spend limit refused a call: that is the budget, not an error (coordinator, 2026-11-18).
        if review and review.get("budget_refused"):
            budget["skipped"] = True
        elif review and review.get("error"):
            errors.append(f"review: {review['error']}")
    inputs = dict(tiers=out.get("tiers", ""), base_sha=out.get("base_sha", ""),
                  mode=out.get("mode") if tier_ok else None, switch_spec=out.get("switch_spec") == "true",
                  machine=machine, review=review, budget=budget)
    return inputs, ran, errors


def post() -> None:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import github

    repo, head_sha, run_url = os.environ["GITHUB_REPOSITORY"], os.environ["HEAD_SHA"], os.environ["RUN_URL"]
    needs = json.loads(os.environ["NEEDS"])
    own_id = int((needs.get("start", {}).get("outputs") or {}).get("check_id") or 0) or None
    inputs, ran, errors = from_needs(needs, head_sha)
    runs = github.verification_runs(repo, head_sha)
    if inputs["budget"]:
        now = datetime.now(timezone.utc)
        today, month = budget_base(github.recent_records(repo), now)
        paid = 1 if (inputs["review"] or {}).get("cost_usd") else 0
        inputs["budget"].update(reviews_today=today + paid,
                                month_usd=round(month + float((inputs["review"] or {}).get("cost_usd") or 0), 4))
    record = decide(head_sha=head_sha, errors=errors, prior=prior_verdicts(runs, own_id), **inputs)
    out = (needs.get("tier", {}).get("outputs") or {})
    skip = out.get("skip") or (BUDGET_SKIPPED if record["budget"].get("skipped") else "")
    output = {"title": record["title"], "text": render_text(record),
              "summary": summary(record, stamp(record["tier"], ran, skip), out.get("reasons", ""), run_url)}
    result = conclusion(record)
    print(output["summary"])
    print(f"verdict={record['verdict']} conclusion={result}")
    # A FAIL is copied onto every gate run on this head, so a sibling still running keeps blocking. Other
    # verdicts touch only this run's check.
    ids = {own_id} if own_id else set()
    if record["verdict"] == "FAIL":
        ids |= {r["id"] for r in runs}
    body = {"status": "completed", "conclusion": result, "output": output}
    if not ids:
        github.api(f"repos/{repo}/check-runs", "POST", {"name": "verification", "head_sha": head_sha, **body})
    for i in sorted(ids):
        github.api(f"repos/{repo}/check-runs/{i}", "PATCH", body)
    sys.exit(1 if result == "failure" else 0)


if __name__ == "__main__":
    if sys.argv[1:] == ["post"]:
        post()
    else:
        sys.exit(__doc__)
