#!/usr/bin/env python3
"""The review (D8, D16): the Bugs call, the security call when the PR touches a risk path (dotfiles#3408), then the
Spec call when the switch is on.

Each call is billed to the API (`claude --bare -p`, the federation token through apiKeyHelper) or, when the API budget
refuses, to the Claude subscription (D18 as amended 2026-11-19). The tier job picks the first route; a call the API
refuses for spend or credit is retried once on the subscription when the subscription may run.
The head never sits in a working directory: its files and diff are copied to $RUNNER_TEMP/review/data and read as data,
so no head CLAUDE.md, command, skill or setting can load (amendment item 9).
Writes one JSON `result` output: {findings, security, spec, cost_usd, subscription_cost_usd, billing, error,
budget_refused}. security is None when the pass is not owed.

  review.py
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
import github  # noqa: E402
from tier import done_items  # noqa: E402
from verdict import budget_base, log_data, route  # noqa: E402

# The org's Console spend limit refuses with this text (HTTP 400, invalid_request_error). It is the budget, not an error.
SPEND_LIMIT = re.compile(r"You have reached your specified (?:workspace )?API usage limits")
CREDIT = re.compile(r"credit balance is too low", re.I)
# On the subscription route only. The plan's own usage limit is the budget: "Claude AI usage limit reached",
# "You've hit your limit · resets 3pm". A token the CLI cannot use is an error: "Not logged in", or a 401.
PLAN_LIMIT = re.compile(r"Claude AI usage limit reached|You[’']ve hit your (?:\w+ )?limit", re.I)
AUTH = re.compile(r"Not logged in|authentication_error|OAuth (?:access )?token|\b401\b", re.I)
SEVERITIES = ("P0", "P1")
STATUSES = ("Yes", "Partly", "No")


def failure_kind(text: str, billing: str = "api") -> str:
    if billing == "subscription":
        return "plan" if PLAN_LIMIT.search(text) else "auth" if AUTH.search(text) else "error"
    if SPEND_LIMIT.search(text):
        return "budget"
    return "credit" if CREDIT.search(text) else "error"


def last_json(text: str):
    """The last JSON value in the CLI's output: the last line or ```json block that parses."""
    blocks = re.findall(r"```(?:json)?\s*\n(.*?)\n```", text or "", re.S)
    for chunk in reversed(blocks + (text or "").strip().splitlines()):
        try:
            return json.loads(chunk)
        except ValueError:
            continue
    return None


FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")
CONTAINER = re.compile(r"^ {0,3}([-+*]([ \t]|$)|\d{1,9}[.)]([ \t]|$)|>)")


def final_block(text: str) -> tuple[str, str] | None:
    """(info string, content) of the fenced code block that ends text, found by CommonMark's fence rules: a fence
    is 3+ backticks or tildes indented at most 3 spaces; it closes on a fence of the same character, at least as
    long, followed only by spaces or tabs; content lines lose up to the opener's indent. None when text does not
    end with a closed fenced block. Lists, block quotes and HTML blocks are not parsed: outside a fence, a line that
    could start an HTML block ("<") makes the reply an ERROR, and a list or quote does too once any fence line is
    indented."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").replace("\0", "\ufffd").split("\n")
    while lines and not lines[-1].strip(" \t"):
        lines.pop()
    opener, last, container, indented = None, None, False, False
    for i, line in enumerate(lines):
        m = FENCE.match(line)
        if opener is None:
            if m and not (m[2][0] == "`" and "`" in m[3]):
                opener, indented = (m[2], m[3].strip(" \t"), i, len(m[1])), indented or bool(m[1])
            elif re.match(r" {0,3}<", line):
                return None
            elif CONTAINER.match(line):
                container = True
        elif m and m[2][0] == opener[0][0] and len(m[2]) >= len(opener[0]) and not m[3].strip(" \t"):
            body = [re.sub(f"^ {{0,{opener[3]}}}", "", x) for x in lines[opener[2] + 1:i]]
            last, opener, indented = (opener[1], "\n".join(body), i), None, indented or bool(m[1])
    if opener is not None or last is None or last[2] != len(lines) - 1 or (container and indented):
        return None
    return last[0], last[1]


def findings_list(text: str) -> list | None:
    """The findings array in the ```json block that must end /code-review's reply. Anything else is an ERROR,
    never a guess."""
    block = final_block(text)
    if block is None or not re.match(r"json([ \t]|$)", block[0]):
        return None
    try:
        value = json.loads(block[1])
    except ValueError:
        return None
    return value if isinstance(value, list) else None


def findings_of(result: dict, head_dir: str, call: str = "bugs") -> list[dict]:
    """The Bugs and the security call return a JSON array in their result text. A finding with no valid severity is a
    P0: D8's review base counts every bug-hunt finding."""
    items = findings_list(result.get("result", ""))
    if not isinstance(items, list):
        raise ValueError(f"no findings list in the {call} call's output")
    findings = []
    for x in items:
        path = str(x.get("file") or "").removeprefix(head_dir.rstrip("/") + "/") if isinstance(x, dict) else ""
        if not path or not x.get("summary"):
            raise ValueError(f"malformed finding: {str(x)[:200]}")
        line = x.get("line")
        if x.get("severity") not in SEVERITIES:
            log_data(f"{call}: a finding had no valid severity ({x.get('severity')!r}); counted as P0")
        findings.append({"call": call, "severity": x.get("severity") if x.get("severity") in SEVERITIES else "P0",
                         "file": path, "line": line if isinstance(line, int) else None, "summary": str(x["summary"]),
                         "failure": str(x.get("failure") or x.get("failure_scenario") or "")})
    return findings


def spec_table(result: dict) -> dict:
    out = result.get("structured_output")
    if not (isinstance(out, dict) and out.get("answer") in STATUSES and isinstance(out.get("items"), list)
            and all(isinstance(i, dict) and i.get("status") in STATUSES and i.get("item") for i in out["items"])):
        raise ValueError("no Spec table in the Spec call's output")
    return {"answer": out["answer"], "items": [{"n": i.get("n"), "item": i["item"], "status": i["status"],
                                               "evidence": i.get("evidence", "")} for i in out["items"]]}


def outcome(proc_rc: int, stdout: str, stderr: str, billing: str = "api") -> tuple[dict | None, str]:
    """(CLI result, failure text). Failure text is empty when the call ran and returned a result."""
    result = last_json(stdout)
    if not isinstance(result, dict):
        return None, f"no result from the CLI (exit {proc_rc}): {stdout[-300:]} {stderr[-500:]}"
    if result.get("is_error") or proc_rc != 0:
        return result, f"{result.get('subtype', '')} {result.get('result', '')} {stderr[-300:]}".strip()
    # /code-review runs as a forked skill: an API error inside it comes back as result text with is_error false
    # ("API Error: 400 ...", or "Credit balance is too low" alone). Only the CLI writes that text when nothing was
    # billed; text the model wrote costs output tokens, so it is output, never a refusal (a stub run on 2.1.326:
    # the refusal reports total_cost_usd 0, the same sentence written by the model 0.00064).
    text = str(result.get("result", ""))
    if (not result.get("structured_output") and not result.get("total_cost_usd")
            and (text.startswith("API Error") or failure_kind(text, billing) != "error")):
        return result, f"{result.get('subtype', '')} {text} {stderr[-300:]}".strip()
    return result, ""


def exchange(anthropic: dict, token_file: Path) -> str:
    """Workload identity federation (D17, D26): one GitHub OIDC token, exchanged once for an Anthropic token.
    Returns an error text, or "" with the token written to token_file."""
    req = urllib.request.Request(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=https://api.anthropic.com",
                                 headers={"Authorization": f"bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"})
    jwt = json.load(urllib.request.urlopen(req, timeout=30))["value"]
    print(f"::add-mask::{jwt}")
    claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
    print("OIDC claims the federation rule sees:", json.dumps({k: claims.get(k) for k in (
        "sub", "aud", "repository_owner", "job_workflow_ref", "event_name")}))
    body = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt,
            "federation_rule_id": anthropic["federation_rule_id"], "organization_id": anthropic["organization_id"],
            **{k: anthropic[k] for k in ("service_account_id", "workspace_id") if anthropic.get(k)}}
    req = urllib.request.Request("https://api.anthropic.com/v1/oauth/token", data=json.dumps(body).encode(), headers={
        "Content-Type": "application/json",
        "anthropic-beta": "oauth-2025-04-20,oidc-federation-2026-04-01"})  # gitleaks:allow (public beta header names)
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as e:
        return f"token exchange failed with status {e.code}: {e.read().decode(errors='replace')[:300]}"
    token = resp.get("access_token", "")
    if not token:
        return "token exchange returned no access token"
    print(f"::add-mask::{token}")
    token_file.write_text(token)
    print(f"token exchange: ok, expires_in={resp.get('expires_in', '?')}")
    return ""


def prepare(head: Path, base_sha: str, data: Path) -> None:
    """Copy the head's tree (no .git) and its diff against the merge base out of the working directory."""
    git = ["git", "-c", "safe.directory=*", "-C", str(head)]
    merge_base = subprocess.run(git + ["merge-base", "HEAD", base_sha], check=True, capture_output=True, text=True).stdout.strip()
    # A head file need not be UTF-8: undecodable bytes become U+FFFD rather than a crash.
    diff = subprocess.run(git + ["diff", merge_base, "HEAD"], check=True, capture_output=True,
                          encoding="utf-8", errors="replace").stdout
    (data / "diff.patch").write_text(diff, encoding="utf-8")
    stat = subprocess.run(git + ["diff", "--shortstat", merge_base, "HEAD"], capture_output=True, text=True).stdout.strip()
    print(f"diff {merge_base[:12]}..HEAD: {stat}")
    # Symlinks are left out: a head link could point the reviewer's Read at a runner file. The diff still shows them.
    shutil.copytree(head, data / "head", symlinks=True,
                    ignore=lambda d, names: [n for n in names if n == ".git" or os.path.islink(os.path.join(d, n))])
    shutil.rmtree(head)


@dataclass
class Runner:
    token_file: Path  # the API token, written by exchange(); apiKeyHelper reads it
    home: Path        # fresh HOME and CLAUDE_CONFIG_DIR: no user config
    cwd: Path         # holds one fresh empty working directory per subscription call
    oauth: str = ""   # the subscription token; only the subscription call's env carries it


def isolated_cwd(cwd: Path) -> Path:
    """cwd, once it is empty with no CLAUDE.md or .claude in it or above it. Without --bare the CLI loads every
    CLAUDE.md it finds walking up from its cwd; --safe-mode skips them as well, and this check does not rest on that."""
    if any(cwd.iterdir()):
        raise RuntimeError(f"the subscription call's cwd {cwd} is not empty")
    for d in (cwd, *cwd.parents):
        for name in ("CLAUDE.md", "CLAUDE.local.md", ".claude"):
            if (d / name).exists():
                raise RuntimeError(f"{d / name} sits on the subscription call's cwd path")
    return cwd


SCRUBBED = ("GITHUB_TOKEN", "GH_TOKEN", "SUBSCRIPTION_TOKEN")


def claude(args: list[str], prompt: str, billing: str, runner: Runner) -> tuple[int, str, str]:
    if billing == "api":
        head = ["--bare", "-p", "--no-session-persistence", "--settings",
                json.dumps({"apiKeyHelper": f"cat '{runner.token_file}'"})]
        cwd, auth = None, {}
    else:
        # --bare reads no OAuth token ("Not logged in"), so this call runs without it and rebuilds what --bare turned
        # off: --safe-mode (no CLAUDE.md, skills, plugins, hooks or MCP from any settings), --strict-mcp-config, an
        # empty cwd and a fresh HOME. Measured on 2.1.326: /code-review still resolves under --safe-mode.
        head = ["-p", "--no-session-persistence", "--safe-mode", "--strict-mcp-config"]
        cwd = isolated_cwd(Path(tempfile.mkdtemp(dir=runner.cwd)))
        auth = {"CLAUDE_CODE_OAUTH_TOKEN": runner.oauth, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "ENABLE_TOOL_SEARCH": "false"}  # else the Spec call gets a deferred-tool placeholder --bare does not
    cmd = [str(Path.home() / ".local/bin/claude"), *head, *args, prompt]
    print(f"claude command ({billing}):", " ".join(json.dumps(a) if " " in a or not a else a for a in cmd[:-1]), "<prompt>")
    log_data(f"prompt: {prompt}")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ACTIONS_", "ANTHROPIC_", "CLAUDE_")) and k not in SCRUBBED}
    env.update(HOME=str(runner.home), CLAUDE_CONFIG_DIR=str(runner.home / ".claude"), **auth)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1500)
    except subprocess.TimeoutExpired:
        # A failure, not an exception: main still bills the call, so a hung subscription call counts against its cap.
        return 124, "", "claude timed out after 1500s"
    return p.returncode, p.stdout, p.stderr


def reroute(pace: dict, api_spent: float, token: bool, refused: str = "") -> tuple[str | None, str]:
    """(billing, why) for the next call, from the budget read again: other gate runs may have paid since the tier job
    read it. This run already counts as one review on whichever route it used. A failed read allows no paid call."""
    now = datetime.now(timezone.utc)
    try:
        totals = budget_base(github.month_records(os.environ["GITHUB_REPOSITORY"],
                                                  os.environ.get("GITHUB_WORKFLOW_REF", ""), now), now)
    except Exception as x:
        return None, "; ".join(filter(None, [refused, f"budget read failed: {x}"[:300]]))
    totals["month_usd"] += api_spent
    billing, why = route(totals, pace, token, refused)
    print(f"budget re-read: {totals['reviews_today']} other paid reviews today of {pace.get('reviews_per_day')}, "
          f"${totals['month_usd']:.2f} this month of ${float(pace.get('budget_month_usd', 0)):.2f}, "
          f"{totals['subscription_today']} other subscription reviews today of {pace.get('subscription_per_day', 0)}; "
          f"billing {billing or 'none'}" + (f" ({why})" if why else ""))
    return billing, why


def empty_result() -> dict:
    return {"findings": [], "security": None, "spec": None, "cost_usd": 0.0, "subscription_cost_usd": 0.0,
            "billing": None, "error": None, "budget_refused": False}


def main() -> dict:
    e = os.environ
    # Out of this process's env before any subprocess starts; only the subscription call's env gets it back.
    # The step's bash and this process keep it in /proc/<pid>/environ, which a Read-only call cannot reach.
    oauth = e.pop("SUBSCRIPTION_TOKEN", "")
    if oauth:
        print(f"::add-mask::{oauth}")
    tmp = Path(e["RUNNER_TEMP"]) / "review"
    data, secret, home, cwd = tmp / "data", tmp / "secret", tmp / "home", tmp / "cwd"
    for d in (data, secret, home, cwd):
        d.mkdir(parents=True, exist_ok=True)
    secret.chmod(0o700)
    out = empty_result()
    if e.get("SECURITY") == "true":
        out["security"] = {"ran": False, "findings": [], "cost_usd": 0.0, "subscription_cost_usd": 0.0}
    prepare(Path(e["HEAD_DIR"]), e["BASE_SHA"], data)
    runner = Runner(token_file=secret / "token", home=home, cwd=cwd, oauth=oauth)
    pace = json.loads(e.get("PACE") or "{}")
    billing, exchanged, used, refused = pace.get("route") or "api", False, [], ""
    base = Path.cwd()
    spec_text = json.loads(e.get("SPEC_TEXT") or '""')
    items = done_items(spec_text)
    standards = str(Path(e.get("STANDARDS", "CODING_STANDARDS.md")).resolve())
    common = ["--model", e["MODEL"], "--effort", e["EFFORT"], "--max-budget-usd", e.get("BUDGET_USD", "3"),
              # The base and the standards file are named by their own paths: the subscription call's cwd is empty.
              "--tools", "Read", "--allowedTools", f"Read(/{data}/**),Read(/{base}/**),Read(/{standards})",
              "--disallowedTools", "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task,Agent", f"Read(/{secret}/**)",
              "--permission-mode", "dontAsk", "--output-format", "json"]
    fill = lambda t: (t.replace("{{BASE_SHA}}", e["BASE_SHA"]).replace("{{BASE}}", str(base))
                      .replace("{{DIFF}}", str(data / "diff.patch"))
                      .replace("{{HEAD}}", str(data / "head")).replace("{{STANDARDS}}", standards)
                      .replace("{{SPEC}}", spec_text)
                      .replace("{{ITEMS}}", "\n".join(f"{n}. {i}" for n, i in enumerate(items, 1)) or
                               "The section has no list: give one row per requirement it states, n counting from 1."))
    # /code-review runs as a forked agent. Only this prompt reaches it: a system prompt flag does not, and a
    # --json-schema result never comes back from the fork, so its findings arrive as a JSON array in the result text.
    calls = [("bugs", common, f"/code-review {e.get('LEVEL', 'medium')} {data / 'diff.patch'}\n\n"
              + fill((ENGINE / "prompts/bugs.md").read_text()))]
    # Not /security-review: its prompt runs `git status` and `git diff` through Bash, which this sandbox never grants.
    if out["security"]:
        calls.append(("security", common, fill((ENGINE / "prompts/security.md").read_text())))
    if spec_text:
        calls.append(("spec", common + ["--json-schema", (ENGINE / "schema/spec.json").read_text()],
                      fill((ENGINE / "prompts/spec.md").read_text())))
    for name, args, prompt in calls:
        if name == "spec":
            billing, why = reroute(pace, out["cost_usd"], bool(oauth), refused)
            if billing is None:
                print(f"Spec call skipped: {why}")
                out["spec_skipped"] = why
                return out
        retried = False
        while True:
            if billing == "api" and not exchanged:
                err = exchange(json.loads(e["ANTHROPIC"]), runner.token_file)
                if err:
                    out["error"] = err
                    return out
                exchanged = True
            rc, stdout, stderr = claude(args, prompt, billing, runner)
            result, failure = outcome(rc, stdout, stderr, billing)
            cost = float((result or {}).get("total_cost_usd") or 0)
            spent = "cost_usd" if billing == "api" else "subscription_cost_usd"
            out[spent] = round(out[spent] + cost, 6)
            if name == "security":
                out["security"][spent] = round(out["security"][spent] + cost, 6)
            # A subscription call counts against its daily cap once it ran, whatever came back; an API call is
            # billed when it cost something or returned a result.
            if billing not in used and (billing == "subscription" or cost or not failure):
                used.append(billing)
                out["billing"] = "+".join(used)
            print(f"{name} ({billing}): exit {rc}, cost ${cost:.4f}"
                  + (" (notional: the subscription pays)" if billing == "subscription" else ""))
            if not failure and result is not None:
                break
            kind = failure_kind(failure, billing)
            text = " ".join(failure.split())[:400]
            if billing == "api" and kind in ("budget", "credit") and not retried:
                retried = True
                out["refused"] = "api spend limit" if kind == "budget" else "api credit"
                refused = "API spend limit refused the call" if kind == "budget" else "API credit balance too low"
                billing, why = reroute(pace, out["cost_usd"], bool(oauth), refused)
                if billing == "subscription":
                    print(f"{name} call: retried on the subscription ({why})")
                    continue
                if kind == "budget":
                    out.update(budget_refused=True, limit=why)
                    return out
            if kind == "plan":
                out.update(budget_refused=True, limit="; ".join(filter(None, [refused, "subscription plan limit"])))
                return out
            reason = "subscription token rejected: " if kind == "auth" and billing == "subscription" else ""
            out["error"] = f"{name} call: {reason}{text}"
            return out
        try:
            if name == "bugs":
                out["findings"] = findings_of(result, str(data / "head"))
            elif name == "security":
                out["security"].update(ran=True, findings=findings_of(result, str(data / "head"), "security"))
            else:
                out["spec"] = {**spec_table(result), "sent": items}
        except ValueError as x:
            fields = {k: result.get(k) for k in ("subtype", "num_turns", "local_command", "permission_denials",
                                                 "structured_output")}
            log_data(f"{name} call output: {json.dumps(fields)}\n{str(result.get('result', ''))[-4000:]}")
            out["error"] = f"{name} call: unparseable output: {x}"
            return out
    return out


if __name__ == "__main__":
    try:
        result = main()
    except Exception as x:  # a runner fault is an ERROR verdict, never a crash that hides the cost
        result = {**empty_result(), "error": f"review job fault: {type(x).__name__}: {x}"[:400]}
    finally:
        shutil.rmtree(Path(os.environ["RUNNER_TEMP"]) / "review" / "secret", ignore_errors=True)
    log_data(json.dumps(result, indent=1))
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"result={json.dumps(result)}\n")
    sys.exit(0)
