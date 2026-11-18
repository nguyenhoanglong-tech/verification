#!/usr/bin/env python3
"""Score one Claude check from the CLI's `--output-format json` result (D25).

PASS needs a schema-shaped structured result with no blocking finding that names every owed file as read.
FAIL is a blocking finding. Everything else (credit, auth, token exchange, no or malformed result, owed files
not read) is ERROR (D18, G4): never a pass, and never a FAIL, so it may re-run.

  score.py KIND RESULT_JSON STDERR_FILE OWED_FILE EXCHANGE_ERROR_FILE
"""
import json
import sys
from pathlib import Path


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def one_line(text, limit=300):
    return " ".join(text.split())[:limit]


def score(kind, result, owed, exchange_error="", stderr=""):
    """Return (verdict, cost, summary, findings_md)."""
    cost = (result or {}).get("total_cost_usd") or 0
    if exchange_error:
        return "ERROR", cost, f"{kind}: ERROR, token exchange failed: {one_line(exchange_error)}", ""
    if result is None:
        return "ERROR", cost, f"{kind}: ERROR, no result from the CLI: {one_line(stderr)}", ""
    out = result.get("structured_output")
    if (result.get("is_error") or not isinstance(out, dict)
            or not isinstance(out.get("findings"), list) or not isinstance(out.get("files_reviewed"), list)):
        why = result.get("result") or result.get("subtype") or ""
        return "ERROR", cost, f"{kind}: ERROR, no structured result: {one_line(str(why))}", ""
    findings = [x for x in out["findings"] if isinstance(x, dict)]
    blocking = sum(x.get("severity") == "blocking" for x in findings)
    minor = len(findings) - blocking
    unread = len(set(owed) - set(out["files_reviewed"]))
    if blocking:
        verdict = "FAIL"
    elif unread or not owed:
        verdict = "ERROR"
    else:
        verdict = "PASS"
    summary = f"{kind}: {blocking} blocking, {minor} minor, {unread} owed files not reported read, verdict {verdict}"
    md = "".join(f"- [{x.get('severity')}] {x.get('file')}:{x.get('line', '')} {x.get('summary')}\n" for x in findings)
    return verdict, cost, summary, md


def main():
    kind, result_file, stderr_file, owed_file, exchange_file = sys.argv[1:6]
    read = lambda p: Path(p).read_text() if Path(p).is_file() else ""
    owed = [line for line in read(owed_file).splitlines() if line]
    return score(kind, last_json(read(result_file)), owed, read(exchange_file).strip(), read(stderr_file))


if __name__ == "__main__":
    verdict, cost, summary, md = main()
    print(json.dumps({"verdict": verdict, "cost": cost, "summary": summary, "findings_md": md}))
