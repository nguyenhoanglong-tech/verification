#!/usr/bin/env python3
"""One verdict record per gate run (D25), the sticky rule (G4), the budget pace (D21) and the billing route (D18).

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


def budget_base(dated_records: list[tuple[str, dict]], now: datetime) -> dict:
    """The running totals the newest record of this month carries: API-paid reviews today, API USD this month and
    subscription reviews today. A record written before D18's subscription route has no subscription count: 0."""
    newest = None
    for at, record in dated_records:
        when = datetime.fromisoformat(at.replace("Z", "+00:00"))
        if (when.year, when.month) == (now.year, now.month) and "month_usd" in (record.get("budget") or {}):
            if newest is None or when > newest[0]:
                newest = (when, record["budget"])
    if newest is None:
        return {"reviews_today": 0, "month_usd": 0.0, "subscription_today": 0}
    when, budget = newest
    same_day = when.date() == now.date()
    return {"reviews_today": int(budget.get("reviews_today", 0)) if same_day else 0,
            "month_usd": float(budget.get("month_usd", 0)),
            "subscription_today": int(budget.get("subscription_today", 0)) if same_day else 0}


def route(totals: dict, caps: dict, token: bool, refused: str = "") -> tuple[str | None, str]:
    """(billing, why) for the next paid call: "api" while the API pace and month cap allow and nothing refused the API,
    else "subscription" while the fallback is on, a token is present and its own daily pace allows, else None.
    why names every limit that moved the call off the API, empty on "api". caps is the tier job's budget."""
    hit = [refused] if refused else []
    if totals["reviews_today"] >= caps["reviews_per_day"]:
        hit.append(f"API daily pace {totals['reviews_today']}/{caps['reviews_per_day']}")
    if totals["month_usd"] >= caps["budget_month_usd"]:
        hit.append(f"API month cap ${totals['month_usd']:.2f}/${float(caps['budget_month_usd']):.2f}")
    if not hit:
        return "api", ""
    per_day = int(caps.get("subscription_per_day", 0))
    if not caps.get("subscription_fallback"):
        hit.append("subscription fallback off")
    elif not token:
        hit.append("no subscription token")
    elif totals["subscription_today"] >= per_day:
        hit.append(f"subscription daily pace {totals['subscription_today']}/{per_day}")
    else:
        return "subscription", "; ".join(hit)
    return None, "; ".join(hit)


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


def unrun_security() -> dict:
    """The security entry of a run that owes the pass, before the pass has run."""
    return {"ran": False, "findings": [], "cost_usd": 0.0, "subscription_cost_usd": 0.0}


def decide(*, head_sha, base_sha, tiers, mode, switch_spec, machine, review, budget, errors, prior,
           security_owed=False, owed=(), done=()) -> dict:
    """Build the record. mode is "shadow" or "enforce"; post() settles it with fallback_mode when the tier job could not.

    machine: [{name, result: pass|fail}]. review: None when no review ran, else {findings, security, spec, cost_usd,
    billing, subscription_cost_usd}. cost_usd is API spend only, every call included; a subscription call's cost is
    notional and kept apart. security_owed: the PR touches a risk path, so the record carries a security entry
    {ran, findings, cost_usd, subscription_cost_usd}; it is None when the pass is not owed.
    errors: why this run could not judge (job failures, review errors). prior: verdicts of earlier runs on this head.
    owed: the calls the tier job owed (bugs, security, spec); done: the calls the review job ran and parsed.

    The one verdict rule. FAIL: a machine check failed, a P0 was found, or an earlier run on this head failed. PASS:
    only when nothing failed, nothing went wrong, and every owed call is in done, or the budget refused the review
    (budget["skipped"] is True, set only from an explicit cap refusal). Everything else is ERROR.
    """
    findings = list((review or {}).get("findings", [])) + spec_findings((review or {}).get("spec"))
    security = (review or {}).get("security") or (unrun_security() if security_owed else None)
    p0 = sum(f["severity"] == "P0" for f in findings + (security or {}).get("findings", []))
    skipped = budget.get("skipped") is True
    unran = [c for c in owed if c not in done]
    errors = list(errors) + ([f"owed calls did not run: {', '.join(unran)}"] if unran and not skipped else [])
    fail = any(m["result"] != "pass" for m in machine) or p0 > 0 or "FAIL" in prior
    verdict = "FAIL" if fail else "PASS" if not errors else "ERROR"
    shadow = mode == "shadow"
    label = tiers or "tier unknown"
    if verdict == "PASS":
        title = f"{label} passed"
    elif verdict == "FAIL":
        title = f"{label} would block (shadow trial)" if shadow else f"{label} blocked"
    else:
        title = f"{label} error" if shadow else f"{label} error: re-run"
    if skipped:
        title += f" ({BUDGET_SKIPPED})"
    return {
        "schema": 1, "head_sha": head_sha, "base_sha": base_sha, "tier": tiers, "mode": mode,
        "verdict": verdict, "p0": p0, "title": title, "switch_spec": bool(switch_spec), "machine": machine,
        "calls_owed": sorted(owed), "calls_done": sorted(done),
        "findings": findings, "security": security, "spec": (review or {}).get("spec"),
        "cost_usd": float((review or {}).get("cost_usd") or 0),
        "billing": (review or {}).get("billing"), "refused": (review or {}).get("refused"),
        "subscription_cost_usd": float((review or {}).get("subscription_cost_usd") or 0),
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
             "security pass: " + ("not owed" if not record.get("security") else
                                  f"ran, cost_usd {record['security']['cost_usd']:.4f}"
                                  + (f" (subscription, notional: {record['security']['subscription_cost_usd']:.4f})"
                                     if record["security"].get("subscription_cost_usd") else "")
                                  if record["security"]["ran"]
                                  else "owed, did not run"),
             f"billing: {record.get('billing') or 'none'}"
             + (f" (API refused: {record['refused']})" if record.get("refused") else ""),
             f"cost_usd: {record['cost_usd']:.4f}" + (f" (subscription, notional: {record['subscription_cost_usd']:.4f})"
                                                       if record.get("subscription_cost_usd") else ""),
             "budget: " + (BUDGET_SKIPPED + (f" ({record['budget']['limit']})" if record["budget"].get("limit") else "")
                           if record["budget"].get("skipped") is True else
                           f"{record['budget'].get('reviews_today', 0)} paid reviews today, "
                           f"${record['budget'].get('month_usd', 0):.2f} this month, "
                           f"{record['budget'].get('subscription_today', 0)} subscription reviews today"),
             "machine: " + (" ".join(f"{m['name']}={m['result']}" for m in record["machine"]) or "none")]
    if record["error"]:
        lines.append(f"error: {record['error']}")
    findings = record["findings"] + (record.get("security") or {}).get("findings", [])
    if findings:
        lines += ["", "findings:"] + [f"- [{f['severity']}] {f['call']} {f['file']}:{f['line'] or ''} {f['summary']}"
                                      for f in findings]
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
    lists = [record["findings"]] + ([record["security"]["findings"]] if record.get("security") else [])
    for cap in (2000, 500, 200, 80, 20):
        for f in (f for rows in lists for f in rows):
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
    while len(text) > LIMIT and any(lists):
        rows = max(lists, key=len)
        drop = max(1, len(rows) // 10)
        del rows[-drop:]
        dropped += drop
        record["findings_dropped"] = dropped
        text = render_text(record)
    return record, text


SEVERITIES = ("P0", "P1")
STATUSES = ("Yes", "Partly", "No")
CALLS = ("bugs", "security", "spec")
REVIEW_KEYS = {"findings", "security", "spec", "cost_usd", "subscription_cost_usd", "billing", "error", "budget_refused",
               "calls"}
REVIEW_OPTIONAL = {"refused", "limit"}


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0


def _line(v) -> bool:
    return v is None or (isinstance(v, int) and not isinstance(v, bool))


def _rows(items, call: str) -> bool:
    keys = {"call", "severity", "file", "line", "summary", "failure"}
    return isinstance(items, list) and all(
        isinstance(x, dict) and set(x) == keys and x["call"] == call and x["severity"] in SEVERITIES
        and isinstance(x["file"], str) and _line(x["line"]) and isinstance(x["summary"], str)
        and isinstance(x["failure"], str) for x in items)


def _security(v) -> bool:
    return v is None or (isinstance(v, dict) and set(v) == {"ran", "findings", "cost_usd", "subscription_cost_usd"}
                         and isinstance(v["ran"], bool) and _rows(v["findings"], "security")
                         and _number(v["cost_usd"]) and _number(v["subscription_cost_usd"]))


def _spec(v) -> bool:
    item = lambda i: (isinstance(i, dict) and set(i) == {"n", "item", "status", "evidence"} and _line(i["n"])
                      and isinstance(i["item"], str) and i["status"] in STATUSES and isinstance(i["evidence"], str))
    return v is None or (isinstance(v, dict) and set(v) == {"answer", "items", "sent"} and v["answer"] in STATUSES
                         and isinstance(v["items"], list) and all(item(i) for i in v["items"])
                         and isinstance(v["sent"], list) and all(isinstance(i, str) for i in v["sent"]))


def parse_review(raw) -> tuple[dict | None, str]:
    """(the review job's result, "") when it validates against the schema review.py writes, else (None, why).
    Required keys present, no unknown key, booleans are bool, costs are numbers and never bool, every finding is a
    full object with a valid severity, and the calls list agrees with what the result holds. Nothing that fails here
    can count as "no findings"."""
    try:
        review = json.loads(raw)
    except (TypeError, ValueError):
        return None, "unreadable"
    if not isinstance(review, dict):
        return None, "not an object"
    keys = set(review)
    if not REVIEW_KEYS <= keys or keys - REVIEW_KEYS - REVIEW_OPTIONAL:
        return None, (f"keys wrong: missing {sorted(REVIEW_KEYS - keys)}, "
                      f"unknown {sorted(keys - REVIEW_KEYS - REVIEW_OPTIONAL)}")
    calls = review["calls"]
    shape = {"findings": _rows(review["findings"], "bugs"), "security": _security(review["security"]),
             "spec": _spec(review["spec"]), "cost_usd": _number(review["cost_usd"]),
             "subscription_cost_usd": _number(review["subscription_cost_usd"]),
             "billing": review["billing"] is None or isinstance(review["billing"], str),
             "error": review["error"] is None or (isinstance(review["error"], str) and review["error"] != ""),
             "budget_refused": isinstance(review["budget_refused"], bool),
             "calls": isinstance(calls, list) and all(c in CALLS for c in calls) and len(set(calls)) == len(calls),
             **{k: isinstance(review[k], str) for k in REVIEW_OPTIONAL if k in review}}
    bad = [k for k, ok in shape.items() if not ok]
    if bad:
        return None, "malformed: " + ", ".join(bad)
    security, finished = review["security"], review["error"] is None and not review["budget_refused"]
    agree = {"security": (security is not None and security["ran"]) == ("security" in calls),
             "spec": (review["spec"] is not None) == ("spec" in calls),
             "bugs": "bugs" in calls or not finished,
             "budget_refused": not (review["budget_refused"] and review["error"] is not None)}
    bad = [k for k, ok in agree.items() if not ok]
    if bad:
        return None, "calls disagree with the result: " + ", ".join(bad)
    return review, ""


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
    # An output Actions dropped reads as empty. Each of these says what is owed, so a missing one is an ERROR, and so
    # is a flag that is not exactly "true" or "false".
    flags = ("has_checks", "review", "security", "switch_spec")
    missing = [k for k in ("mode", *flags, "budget") if not out.get(k)]
    if tier_ok and missing:
        errors.append("tier outputs missing: " + ", ".join(missing))
        tier_ok = False
    invalid = [k for k in flags if out.get(k) not in ("true", "false")]
    if tier_ok and invalid:
        errors.append("tier outputs invalid: " + ", ".join(invalid))
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
    review, done = None, []
    review_out = owed("review", "review")
    budget = {}
    if tier_ok:
        try:
            budget = json.loads(out["budget"])
        except ValueError:
            budget = None
        if not isinstance(budget, dict) or not isinstance(budget.get("skipped", False), bool):
            errors.append("tier budget output unreadable")
            budget = {}
    flag = lambda k: tier_ok and out.get(k) == "true"
    owed_calls = ["bugs"] + ["security"] * flag("security") + ["spec"] * flag("switch_spec") if flag("review") else []
    if budget.get("skipped") is True and (flag("review") or out.get("skip") != BUDGET_SKIPPED):
        errors.append("tier budget says skipped, but the tier job did not skip the review for budget")
    if review_out:
        review, problem = parse_review(review_out.get("result") or "")
        if problem:
            errors.append(f"review job output {problem}")
        else:
            done = review["calls"]
            # Only an explicit cap refusal is a budget skip (coordinator, 2026-11-18; #77 round 3).
            if review["budget_refused"] is True:
                budget.update(skipped=True, limit=review.get("limit") or "a budget cap refused a call")
            if review["error"] is not None:
                errors.append(f"review: {review['error']}")
    mode = out.get("mode") if out.get("mode") in ("shadow", "enforce") else None
    inputs = dict(tiers=out.get("tiers", ""), base_sha=out.get("base_sha", ""), mode=mode,
                  switch_spec=out.get("switch_spec") == "true", machine=machine, review=review, budget=budget,
                  security_owed=out.get("security") == "true", owed=owed_calls, done=done)
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
        review = inputs["review"] or {}
        cost = float(review.get("cost_usd") or 0)
        on_subscription = "subscription" in (review.get("billing") or "")
        now = datetime.now(timezone.utc)
        try:
            totals = budget_base(github.month_records(repo, os.environ.get("GITHUB_WORKFLOW_REF", ""), now), now)
        except Exception as x:
            # The record still carries the tier job's totals for the next run's pace, but this verdict is an ERROR.
            print(f"budget read failed: {x}; the totals carry on from the tier job's read")
            errors.append(f"budget read failed while posting: {x}"[:300])
            totals = {k: budget.get(k) for k in ("reviews_today", "month_usd", "subscription_today")}
        if totals["month_usd"] is not None:
            # The subscription's cost is notional: it never adds to month_usd, which the API month cap reads.
            budget.update(reviews_today=int(totals["reviews_today"] or 0) + (1 if cost else 0),
                          month_usd=round(float(totals["month_usd"]) + cost, 4),
                          subscription_today=int(totals["subscription_today"] or 0) + (1 if on_subscription else 0))
    record = {**decide(head_sha=head_sha, errors=errors, prior=prior_verdicts(runs), **inputs), **own_run()}
    out = needs.get("tier", {}).get("outputs") or {}
    skip = out.get("skip") or (BUDGET_SKIPPED if record["budget"].get("skipped") is True else "")
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
    if record is not None:
        # The judge computed the verdict and the P0 count before the publish failed: post them as they are, never a
        # verdict recomputed from a record whose findings may be trimmed.
        failed = {**record, "error": "; ".join(filter(None, [record.get("error"), reason]))}
    else:
        start = needs.get("start", {}).get("outputs") or {}
        mode = fallback_mode(base_config(github, repo, start.get("base_sha") or base_ref), base_ref)
        failed = decide(head_sha=head_sha, base_sha=start.get("base_sha", ""), tiers="", mode=mode, switch_spec=False,
                        machine=[], review=None, budget={}, errors=[reason], prior=[],
                        security_owed=((needs.get("tier") or {}).get("outputs") or {}).get("security") == "true")
    failed.update(own_run())
    _, text = fit(failed)
    body = {"status": "completed", "conclusion": conclusion(failed),
            "output": {"title": failed["title"], "text": text,
                       "summary": f"verdict: {failed['verdict']}\nP0: {failed['p0']}\nerror: {reason}\n\nrun: {run_url}"}}
    write_check(github, repo, head_sha, body)
    return 1 if body["conclusion"] == "failure" else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["post"]:
        sys.exit(post())
    else:
        sys.exit(__doc__)
