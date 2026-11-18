#!/usr/bin/env python3
"""The review (D8, D16): the Bugs call, then the Spec call when the switch is on, each as `claude --bare -p`.

The working directory is the base checkout. The head never sits inside it: its files and diff are copied to
$RUNNER_TEMP/review and read as data, so no head CLAUDE.md, command, skill or setting can load (amendment item 9).
Writes one JSON `result` output: {findings, spec, cost_usd, error, budget_refused, credit_error}.

  review.py
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
# The org's Console spend limit refuses with this text (HTTP 400, invalid_request_error). It is the budget, not an error.
SPEND_LIMIT = re.compile(r"You have reached your specified (?:workspace )?API usage limits")
CREDIT = re.compile(r"credit balance is too low", re.I)
SEVERITIES = ("P0", "P1")
STATUSES = ("Yes", "Partly", "No")


def failure_kind(text: str) -> str:
    if SPEND_LIMIT.search(text):
        return "budget"
    return "credit" if CREDIT.search(text) else "error"


def last_json(text: str):
    """The last JSON value in a CLI or model output: a ```json block, else the last line that parses."""
    blocks = re.findall(r"```(?:json)?\s*\n(.*?)\n```", text or "", re.S)
    for chunk in reversed(blocks + (text or "").strip().splitlines()):
        try:
            return json.loads(chunk)
        except ValueError:
            continue
    return None


def bugs_findings(result: dict, head_dir: str) -> list[dict]:
    """/code-review returns a JSON array (or the structured output, when the model used it). A finding with no
    valid severity is a P0: D8's review base counts every bug-hunt finding."""
    out = result.get("structured_output")
    items = out.get("findings") if isinstance(out, dict) else last_json(result.get("result", ""))
    if isinstance(items, dict):
        items = items.get("findings")
    if not isinstance(items, list):
        raise ValueError("no findings list in the Bugs call's output")
    findings = []
    for x in items:
        if not isinstance(x, dict) or not x.get("summary"):
            raise ValueError(f"malformed finding: {str(x)[:200]}")
        path = str(x.get("file", "")).removeprefix(head_dir.rstrip("/") + "/")
        line = x.get("line")
        if x.get("severity") not in SEVERITIES:
            print(f"bugs: a finding had no valid severity ({x.get('severity')!r}); counted as P0")
        findings.append({"call": "bugs", "severity": x.get("severity") if x.get("severity") in SEVERITIES else "P0",
                         "file": path, "line": line if isinstance(line, int) else None, "summary": str(x["summary"]),
                         "failure": str(x.get("failure") or x.get("failure_scenario") or "")})
    return findings


def spec_table(result: dict) -> dict:
    out = result.get("structured_output")
    if not (isinstance(out, dict) and out.get("answer") in STATUSES and isinstance(out.get("items"), list)
            and all(isinstance(i, dict) and i.get("status") in STATUSES and i.get("item") for i in out["items"])):
        raise ValueError("no Spec table in the Spec call's output")
    return {"answer": out["answer"], "items": [{"item": i["item"], "status": i["status"], "evidence": i.get("evidence", "")}
                                              for i in out["items"]]}


def outcome(proc_rc: int, stdout: str, stderr: str) -> tuple[dict | None, str]:
    """(CLI result, failure text). Failure text is empty when the call ran and returned a result."""
    result = last_json(stdout)
    if not isinstance(result, dict):
        return None, f"no result from the CLI (exit {proc_rc}): {stderr[-500:]}"
    # /code-review runs as a forked skill: an API error inside it comes back as result text with is_error false
    # ("API Error: 400 ...", or "Credit balance is too low" alone).
    text = str(result.get("result", ""))
    if result.get("is_error") or proc_rc != 0 or text.startswith("API Error") or failure_kind(text) != "error":
        return result, f"{result.get('subtype', '')} {result.get('result', '')} {stderr[-300:]}".strip()
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
    diff = subprocess.run(git + ["diff", merge_base, "HEAD"], check=True, capture_output=True, text=True).stdout
    (data / "diff.patch").write_text(diff)
    stat = subprocess.run(git + ["diff", "--shortstat", merge_base, "HEAD"], capture_output=True, text=True).stdout.strip()
    print(f"diff {merge_base[:12]}..HEAD: {stat}")
    # Symlinks are left out: a head link could point the reviewer's Read at a runner file. The diff still shows them.
    shutil.copytree(head, data / "head", symlinks=True,
                    ignore=lambda d, names: [n for n in names if n == ".git" or os.path.islink(os.path.join(d, n))])
    shutil.rmtree(head)


def claude(args: list[str], prompt: str, token_file: Path, home: Path) -> tuple[int, str, str]:
    settings = json.dumps({"apiKeyHelper": f"cat '{token_file}'"})
    cmd = [str(Path.home() / ".local/bin/claude"), "--bare", "-p", "--no-session-persistence", "--settings", settings,
           *args, prompt]
    print("claude command:", " ".join(json.dumps(a) if " " in a or not a else a for a in cmd[:-1]), "<prompt>")
    print("prompt:", prompt)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACTIONS_") and k != "GITHUB_TOKEN"}
    env["HOME"] = str(home)  # fresh: no user config
    p = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1500)
    return p.returncode, p.stdout, p.stderr


def main() -> dict:
    e = os.environ
    tmp = Path(e["RUNNER_TEMP"]) / "review"
    data, secret, home = tmp / "data", tmp / "secret", tmp / "home"
    for d in (data, secret, home):
        d.mkdir(parents=True, exist_ok=True)
    secret.chmod(0o700)
    out = {"findings": [], "spec": None, "cost_usd": 0.0, "error": None, "budget_refused": False, "credit_error": False}
    prepare(Path(e["HEAD_DIR"]), e["BASE_SHA"], data)
    token_file = secret / "token"
    err = exchange(json.loads(e["ANTHROPIC"]), token_file)
    if err:
        out["error"] = err
        return out
    spec_text = json.loads(e.get("SPEC_TEXT") or '""')
    standards = e.get("STANDARDS", "CODING_STANDARDS.md")
    common = ["--model", e["MODEL"], "--effort", e["EFFORT"], "--max-budget-usd", e.get("BUDGET_USD", "3"),
              "--tools", "Read", "--allowedTools", f"Read(/{data}/**)",
              "--disallowedTools", "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Task,Agent", f"Read(/{secret}/**)",
              "--permission-mode", "dontAsk", "--output-format", "json"]
    bugs_args = list(common)
    if Path(standards).is_file():
        bugs_args += ["--append-system-prompt-file", standards]
    bugs_args += ["--json-schema", (ENGINE / "schema/bugs.json").read_text()]
    fill = lambda t: (t.replace("{{BASE_SHA}}", e["BASE_SHA"]).replace("{{DIFF}}", str(data / "diff.patch"))
                      .replace("{{HEAD}}", str(data / "head")).replace("{{STANDARDS}}", standards)
                      .replace("{{SPEC}}", spec_text))
    calls = [("bugs", bugs_args, f"/code-review {e.get('LEVEL', 'medium')} {data / 'diff.patch'}\n\n"
              + fill((ENGINE / "prompts/bugs.md").read_text()))]
    if spec_text:
        calls.append(("spec", common + ["--json-schema", (ENGINE / "schema/spec.json").read_text()],
                      fill((ENGINE / "prompts/spec.md").read_text())))
    for name, args, prompt in calls:
        rc, stdout, stderr = claude(args, prompt, token_file, home)
        result, failure = outcome(rc, stdout, stderr)
        out["cost_usd"] = round(out["cost_usd"] + float((result or {}).get("total_cost_usd") or 0), 6)
        print(f"{name}: exit {rc}, cost ${float((result or {}).get('total_cost_usd') or 0):.4f}")
        if failure or result is None:
            kind = failure_kind(failure)
            out["budget_refused"] |= kind == "budget"
            out["credit_error"] |= kind == "credit"
            if kind != "budget":
                out["error"] = f"{name} call: {' '.join(failure.split())[:400]}"
            return out
        try:
            if name == "bugs":
                out["findings"] = bugs_findings(result, str(data / "head"))
            else:
                out["spec"] = spec_table(result)
        except ValueError as x:
            out["error"] = f"{name} call: unparseable output: {x}"
            return out
    return out


if __name__ == "__main__":
    try:
        result = main()
    except Exception as x:  # a runner fault is an ERROR verdict, never a crash that hides the cost
        result = {"findings": [], "spec": None, "cost_usd": 0.0, "error": f"review job fault: {type(x).__name__}: {x}"[:400],
                  "budget_refused": False, "credit_error": False}
    finally:
        shutil.rmtree(Path(os.environ["RUNNER_TEMP"]) / "review" / "secret", ignore_errors=True)
    # Model-written text goes to the log inside stop-commands, so a workflow command in it does not run.
    stop = os.urandom(16).hex()
    print(f"::stop-commands::{stop}")
    print(json.dumps(result, indent=1))
    print(f"::{stop}::")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"result={json.dumps(result)}\n")
        f.write(f"credit_error={'true' if result['credit_error'] else 'false'}\n")
    sys.exit(0)
