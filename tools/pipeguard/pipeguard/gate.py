"""Security gate: a CI exit code from the linker's findings (Phase 4, DECISIONS D12).

    python -m pipeguard gate PATH --repo OWNER/REPO [--fail-on critical|high|medium|low]
                             [--allow-unknown] [--format text|json|github]

Exit codes (README, D12):
    0  pass
    1  at least one finding at or above --fail-on (default: high)
    2  an UNKNOWN finding ("cannot verify") and --allow-unknown not given: fail closed
    3  usage or internal error (a crash never exits 0)
When both 1 and 2 apply, the exit code is 1: a known dangerous finding is the stronger answer.

The gate only decides an exit code; it blocks nothing by itself. GitHub blocks the merge when the
check is required by a ruleset or branch protection rule (docs/explain/demo_manual_ar.md).
Static only: it reads files; no AWS call, no network.

--format github prints workflow-command annotations (::error / ::warning). Every value is escaped
with the rules of GitHub's own actions/toolkit (packages/core/src/command.ts, read 2026-11-27):
data: % -> %25, CR -> %0D, LF -> %0A; properties: also ':' -> %3A and ',' -> %2C. Any other control
character is turned into a visible escape first (output.clean), so scanned text can never end the
line, start a new workflow command or add a property.
"""

import json

from pipeguard import linker
from pipeguard.output import clean, clean_tree

SCHEMA = "pipeguard.gate/1"
SEVERITY_RANK = linker.SEVERITY_RANK  # UNKNOWN 0, CRITICAL 1, HIGH 2, MEDIUM 3, LOW 4
LEVELS = ("critical", "high", "medium", "low")
EXIT_PASS, EXIT_FINDING, EXIT_UNKNOWN, EXIT_ERROR = 0, 1, 2, 3


def escape_data(text):
    """actions/toolkit escapeData, after making other control characters visible."""
    text = str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return clean(text)


def escape_property(text):
    """actions/toolkit escapeProperty (escapeData plus ':' and ',')."""
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def evaluate(result, fail_on="high", allow_unknown=False):
    """The gate decision for a linker result: findings with `blocking`, counts, exit code."""
    if fail_on not in LEVELS:
        raise ValueError(f"--fail-on must be one of {', '.join(LEVELS)}")
    limit = SEVERITY_RANK[fail_on.upper()]
    findings = []
    for f in result["findings"]:
        sev = f["severity"]
        known = sev != "UNKNOWN"
        blocking = (known and SEVERITY_RANK[sev] <= limit) or (not known and not allow_unknown)
        findings.append(dict(f, blocking=blocking))
    at_or_above = [f for f in findings if f["severity"] != "UNKNOWN" and f["blocking"]]
    unknown = [f for f in findings if f["severity"] == "UNKNOWN"]
    if at_or_above:
        code, reason = EXIT_FINDING, f"{len(at_or_above)} finding(s) at or above {fail_on.upper()}"
    elif unknown and not allow_unknown:
        code, reason = EXIT_UNKNOWN, (f"{len(unknown)} UNKNOWN finding(s): cannot verify, so the gate "
                                      "fails closed (--allow-unknown reports them as warnings)")
    else:
        code, reason = EXIT_PASS, f"no finding at or above {fail_on.upper()}" + (
            f"; {len(unknown)} UNKNOWN reported as warning(s) (--allow-unknown)" if unknown else "")
    counts = {sev: sum(f["severity"] == sev for f in findings) for sev in SEVERITY_RANK}
    return {"schema": SCHEMA, "fail_on": fail_on, "allow_unknown": allow_unknown, "exit_code": code,
            "result": "PASS" if code == EXIT_PASS else "FAIL", "reason": reason, "counts": counts,
            "findings": findings}


def _rel(file, root):
    return linker._relative(file, root) if file else ""


def _verdict(ev):
    counts = ", ".join(f"{k} {v}" for k, v in ev["counts"].items())
    return f"{ev['result']} (exit {ev['exit_code']}): {ev['reason']}. Findings: {counts}."


def format_text(ev, root, repo=None):
    c = clean
    out = [f"PipeGuard gate (static: no AWS call, no network): {c(root.as_posix())}"
           + (f", repository {c(repo)}" if repo else ""),
           f"Threshold: fail on {ev['fail_on'].upper()} or above; UNKNOWN "
           + ("is reported as a warning (--allow-unknown)" if ev["allow_unknown"] else
              "fails the gate (fail closed)")]
    for f in ev["findings"]:
        mark = "[BLOCK]" if f["blocking"] else "[warn ]"
        where = _rel(f["file"], root) + (f":{f['line']}" if f.get("line") else "")
        role = f" role {c(f['role'])}" if f.get("role") else ""
        out.append(f"  {mark} [{f['severity']}] {f['rule']} {c(where)}{role}: {c(f['message'])}")
    if not ev["findings"]:
        out.append("  no findings")
    out.append(f"Result: {_verdict(ev)}")
    return "\n".join(out)


def format_json(ev, root, repo=None):
    findings = [{"rule": f["rule"], "severity": f["severity"], "file": _rel(f["file"], root),
                 "line": f.get("line"), "role": f.get("role"), "job": f.get("job"),
                 "message": f["message"], "blocking": f["blocking"]} for f in ev["findings"]]
    data = {k: ev[k] for k in ("schema", "fail_on", "allow_unknown", "exit_code", "result", "reason",
                               "counts")}
    data.update(repo=repo, path=root.as_posix(), findings=findings)
    return json.dumps(clean_tree(data), indent=2, ensure_ascii=True)


def format_github(ev, root, repo=None):
    """One ::error / ::warning line per finding, then one constant summary line."""
    out = []
    for f in ev["findings"]:
        level = "error" if f["blocking"] else "warning"
        props = []
        file = _rel(f["file"], root)
        if file:
            props.append(f"file={escape_property(file)}")
        if isinstance(f.get("line"), int) and f["line"] > 0:
            props.append(f"line={f['line']}")
        props.append(f"title={escape_property('PipeGuard ' + f['rule'] + ' ' + f['severity'])}")
        role = f"role {f['role']}: " if f.get("role") else ""
        out.append(f"::{level} {','.join(props)}::{escape_data(role + f['message'])}")
    out.append(f"PipeGuard gate: {_verdict(ev)}")
    return "\n".join(out)


FORMATS = {"text": "format_text", "json": "format_json", "github": "format_github"}


def run(path, repo, fail_on="high", allow_unknown=False, fmt="text"):
    """(exit code, output text) for one repository folder."""
    result = linker.scan(path, repo)
    ev = evaluate(result, fail_on, allow_unknown)
    return ev["exit_code"], globals()[FORMATS[fmt]](ev, path, repo)
