#!/usr/bin/env python3
"""One verdict record per gate run (D25), the sticky rule (G4) and the budget pace (D21).

The record goes into the `verification` check run's output text after MARKER, as one fenced JSON block.
The sticky rule, the budget pace and the dotfiles finding log read that record, never `conclusion` alone.

  verdict.py post      # gate job: reads NEEDS, HEAD_SHA, RUN_URL; posts the verdict on this head
"""
import base64
import json
import os
import re
import sys
import tomllib
from datetime import datetime, timezone
from urllib.parse import quote

MARKER = "<!-- verification-record v1 -->"
BUDGET_SKIPPED = "review skipped: budget"
LIMIT = 65000  # GitHub refuses a check run whose output text or summary passes 65,535 characters


def log_data(text: str) -> None:
    """Print text from the issue, the head or the model inside a stop-commands block, so no workflow command in it
    runs. Each block takes a fresh random token the text cannot know."""
    token = os.urandom(16).hex()
    print(f"::stop-commands::{token}\n{text}\n::{token}::", flush=True)


def fallback_mode(config: dict | None, base_ref: str) -> str:
    """The mode when the tier job could not settle it: shadow, unless the raw config enforces this base."""
    config = config or {}
    branches = config.get("enforce_branches")
    return "enforce" if config.get("mode") == "enforce" or (isinstance(branches, list) and base_ref in branches) else "shadow"


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


def prior_verdicts(check_runs: list[dict]) -> list[str]:
    """Verdicts of the earlier gate runs on this head. A failure posted before records existed counts as FAIL."""
    out = []
    for run in check_runs:
        if run.get("status") != "completed":
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
    """A done-when item answered No or Partly is a P0 (D25, amendment item 3), and so is an item the engine sent
    (spec["sent"], numbered from 1) that has no row: the call did not judge it."""
    if not spec:
        return []
    rows = spec.get("items", [])
    out = [{"call": "spec", "severity": "P0", "file": "", "line": None, "summary": f"done-when item {i['status']}: {i['item']}",
            "failure": i.get("evidence", "")} for i in rows if i.get("status") in ("No", "Partly")]
    judged = {i.get("n") for i in rows}
    return out + [{"call": "spec", "severity": "P0", "file": "", "line": None, "summary": f"item not judged: {item}",
                   "failure": "the Spec table has no row for this item"}
                  for n, item in enumerate(spec.get("sent", []), 1) if n not in judged]


def decide(*, head_sha, base_sha, tiers, mode, switch_spec, machine, review, budget, errors, prior) -> dict:
    """Build the record. mode is "shadow" or "enforce"; post() settles it with fallback_mode when the tier job could not.

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
        "schema": 1, "head_sha": head_sha, "base_sha": base_sha, "tier": tiers, "mode": mode,
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
             "budget: " + (BUDGET_SKIPPED + "".join(f" ({record['budget'][k]})" for k in ("read_error", "spec_skipped")
                                                    if record["budget"].get(k))
                           if record["budget"].get("skipped") else
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


def cut(text, cap: int):
    return text if not isinstance(text, str) or len(text) <= cap else text[:cap] + " [trimmed]"


def fit(record: dict) -> tuple[dict, str]:
    """The record and its rendered text within LIMIT. Free text (summaries, failures, evidence, items, the error) is
    cut first, then finding rows from the end; verdict, totals and cost stay exact. A cut record says so."""
    text = render_text(record)
    if len(text) <= LIMIT:
        return record, text
    record = json.loads(json.dumps(record))
    record["trimmed"] = True
    spec = record.get("spec") or {}
    for cap in (2000, 500, 200, 80, 20):
        for f in record["findings"]:
            f.update(summary=cut(f["summary"], cap), failure=cut(f.get("failure"), cap), file=cut(f.get("file"), max(cap, 200)))
        for i in spec.get("items", []):
            i.update(item=cut(i["item"], cap), evidence=cut(i.get("evidence"), cap))
        if spec.get("sent"):
            spec["sent"] = [cut(i, cap) for i in spec["sent"]]
        record["error"] = cut(record["error"], max(cap, 200))
        text = render_text(record)
        if len(text) <= LIMIT:
            return record, text
    dropped = 0
    while len(text) > LIMIT and record["findings"]:
        drop = max(1, len(record["findings"]) // 10)
        record["findings"], dropped = record["findings"][:-drop], dropped + drop
        record["findings_dropped"] = dropped
        text = render_text(record)
    return record, text


def check_names(checks: str) -> list[str] | None:
    """The machine check names the tier job read from the base config (its `checks` output); None when unreadable."""
    try:
        return [base64.b64decode(item.split(":", 1)[0], validate=True).decode() for item in checks.split()]
    except ValueError:
        return None


def from_needs(needs: dict, head_sha: str) -> tuple[dict, list[str], list[str]]:
    """Read the job results into decide()'s inputs. Returns (inputs, ran, errors). inputs["mode"] is None when the
    tier job gave none."""
    tier = needs.get("tier", {})
    out = tier.get("outputs") or {}
    errors, ran = [], []
    for job in ("start", "tier"):
        if needs.get(job, {}).get("result") != "success":
            errors.append(f"{job} job {needs.get(job, {}).get('result')}")
    if out.get("error"):
        errors.append(out["error"])
    tier_ok = tier.get("result") == "success" and not out.get("error")
    # An output Actions dropped reads as empty. Each of these says what is owed, so a missing one is an ERROR.
    missing = [k for k in ("mode", "has_checks", "review", "budget") if not out.get(k)]
    if tier_ok and missing:
        errors.append("tier outputs missing: " + ", ".join(missing))
        tier_ok = False

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
            got = json.loads(checks.get("results") or "")
        except ValueError:
            got = None
        machine = [m for m in got if isinstance(m, dict) and m.get("result") in ("pass", "fail")] if isinstance(got, list) else []
        expected = check_names(out.get("checks", ""))
        if not expected or [m.get("name") for m in machine] != expected:
            errors.append(f"machine results missing or short: expected {expected}, got {[m.get('name') for m in machine]}")
    review = None
    review_out = owed("review", "review")
    try:
        budget = json.loads(out.get("budget") or "{}") if tier_ok else {}
    except ValueError:
        budget = {}
    if review_out:
        try:
            review = json.loads(review_out.get("result") or "")
        except ValueError:
            errors.append("review job output unreadable")
            review = None
        # The org's spend limit refused a call, or the pace was reached before the Spec call: that is the budget,
        # not an error (coordinator, 2026-11-18).
        if review and (review.get("budget_refused") or review.get("spec_skipped")):
            budget["skipped"] = True
            if review.get("spec_skipped"):
                budget["spec_skipped"] = f"Spec call: {review['spec_skipped']}"
        if review and review.get("error"):
            errors.append(f"review: {review['error']}")
    mode = out.get("mode") if out.get("mode") in ("shadow", "enforce") else None
    inputs = dict(tiers=out.get("tiers", ""), base_sha=out.get("base_sha", ""), mode=mode,
                  switch_spec=out.get("switch_spec") == "true", machine=machine, review=review, budget=budget)
    return inputs, ran, errors


def base_config(github, repo: str, ref: str) -> dict | None:
    try:
        return tomllib.loads(github.api(f"repos/{repo}/contents/.github/verification.toml?ref={quote(ref, safe='')}", raw=True))
    except Exception:
        return None


def own_run() -> dict:
    """This gate run's Actions run, for the re-run job: it reads these fields, never a link in the summary."""
    return {"run_id": int(os.environ.get("GITHUB_RUN_ID") or 0) or None,
            "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT") or 0) or None}


def write_check(github, repo: str, head_sha: str, body: dict) -> None:
    """A new finished check run as the gate App, so a run never overwrites another run's record. Reads keep
    GH_TOKEN; only this write takes GATE_TOKEN, and with none it raises and nothing is posted."""
    github.api(f"repos/{repo}/check-runs", "POST", {"name": "verification", "head_sha": head_sha, **body},
               token=os.environ["GATE_TOKEN"])


def judge(github, needs: dict, repo: str, head_sha: str, run_url: str, base_ref: str) -> dict:
    inputs, ran, errors = from_needs(needs, head_sha)
    start = needs.get("start", {}).get("outputs") or {}
    if inputs["mode"] is None:
        inputs["mode"] = fallback_mode(base_config(github, repo, start.get("base_sha") or base_ref), base_ref)
        print(f"mode {inputs['mode']} (the tier job gave none; read from the base config)")
    runs = github.verification_runs(repo, head_sha)
    budget = inputs["budget"]
    if budget:
        cost = float((inputs["review"] or {}).get("cost_usd") or 0)
        now = datetime.now(timezone.utc)
        try:
            today, month = budget_base(github.month_records(repo, os.environ.get("GITHUB_WORKFLOW_REF", ""), now), now)
        except Exception as x:
            print(f"budget read failed: {x}; the totals carry on from the tier job's read")
            today, month = budget.get("reviews_today"), budget.get("month_usd")
        if month is not None:
            budget.update(reviews_today=int(today) + (1 if cost else 0), month_usd=round(float(month) + cost, 4))
    record = {**decide(head_sha=head_sha, errors=errors, prior=prior_verdicts(runs), **inputs), **own_run()}
    out = needs.get("tier", {}).get("outputs") or {}
    skip = out.get("skip") or (BUDGET_SKIPPED if record["budget"].get("skipped") else "")
    fitted, text = fit(record)
    output = {"title": record["title"], "text": text,
              "summary": summary(fitted, stamp(record["tier"], ran, skip), out.get("reasons", ""), run_url)}
    log_data(output["summary"])
    print(f"verdict={record['verdict']} conclusion={conclusion(record)}" + (" (record trimmed)" if fitted is not record else ""))
    return fitted, {"status": "completed", "conclusion": conclusion(record), "output": output}


def post() -> int:
    """Post this run's verdict on its own check run. Whatever fails, the check ends: ERROR, neutral in shadow trial."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import github

    repo, head_sha, run_url = os.environ["GITHUB_REPOSITORY"], os.environ["HEAD_SHA"], os.environ["RUN_URL"]
    base_ref = os.environ.get("BASE_REF", "")
    needs, record = {}, None
    try:
        needs = json.loads(os.environ["NEEDS"])
        record, body = judge(github, needs, repo, head_sha, run_url, base_ref)
        write_check(github, repo, head_sha, body)
        return 1 if body["conclusion"] == "failure" else 0
    except Exception as x:
        reason = f"the gate could not post its verdict: {type(x).__name__}: {x}"[:400]
        print(reason)
    start = needs.get("start", {}).get("outputs") or {}
    mode = (record or {}).get("mode") or fallback_mode(base_config(github, repo, start.get("base_sha") or base_ref), base_ref)
    failed = decide(head_sha=head_sha, base_sha=start.get("base_sha", ""), tiers=(record or {}).get("tier", ""), mode=mode,
                    switch_spec=False, machine=[], review={"cost_usd": (record or {}).get("cost_usd", 0)},
                    budget=(record or {}).get("budget", {}), errors=[reason], prior=[])
    failed.update(own_run())
    body = {"status": "completed", "conclusion": conclusion(failed),
            "output": {"title": failed["title"], "text": render_text(failed), "summary": f"verdict: ERROR\nerror: {reason}\n\nrun: {run_url}"}}
    write_check(github, repo, head_sha, body)
    return 1 if body["conclusion"] == "failure" else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["post"]:
        sys.exit(post())
    else:
        sys.exit(__doc__)
