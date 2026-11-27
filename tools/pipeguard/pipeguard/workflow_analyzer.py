"""Workflow side: keys vs OIDC, assumed role, triggers, permissions, action pins (Phase 1).

Reads GitHub Actions workflow files and produces, per file:
- FACTS for the linker (Phase 3): triggers, effective permissions per job, environment, AWS
  credential mode, role ARNs (literal or UNRESOLVED), every `uses:` with its pin kind, and the
  `sub` claims each role-assuming job is expected to present (DECISIONS D5, with the GitHub pages).
- FINDINGS PG-W00..PG-W06 with the severities of model D8 (accepted in D9).

It only reads files: it never runs anything from them and never calls GitHub or AWS.
YAML is read by pipeguard.safe_yaml (compose only, with limits). Anything it cannot resolve is
reported as PG-W00 UNKNOWN, never as safe.
"""

import re
from pathlib import Path

from pipeguard import config
from pipeguard.output import clean
from pipeguard.safe_yaml import YamlRejected, YMap, YSeq, load

SCHEMA = "pipeguard.workflow_scan/1"
PLACEHOLDER_REPO = "OWNER/REPO"
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")

# Severities: model D8, accepted by the student in D9 (PG-W02 is HIGH with a PR checkout, D6.1).
RULE_SEVERITY = {
    "PG-W00": "UNKNOWN",  # cannot verify: never reported as safe
    "PG-W01": "HIGH",  # long-lived AWS keys
    "PG-W02": "MEDIUM",  # role assumed in a pull_request / pull_request_target job
    "PG-W03": "LOW",  # action / reusable workflow / docker image not pinned immutably
    "PG-W04": "LOW",  # OIDC used and no permissions block for the job
    "PG-W05": "LOW",  # id-token: write at workflow level (D4, proposal P1)
    "PG-W06": "LOW",  # write-all permissions
}
SEVERITY_RANK = {"UNKNOWN": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Event names listed on GitHub's "Events that trigger workflows" page (opened 2026-11-25).
KNOWN_EVENTS = {
    "branch_protection_rule", "check_run", "check_suite", "create", "delete", "deployment",
    "deployment_status", "discussion", "discussion_comment", "fork", "gollum", "image_version",
    "issue_comment", "issues", "label", "merge_group", "milestone", "page_build", "public",
    "pull_request", "pull_request_review", "pull_request_review_comment", "pull_request_target",
    "push", "registry_package", "release", "repository_dispatch", "schedule", "status", "watch",
    "workflow_call", "workflow_dispatch", "workflow_run",
}
PR_EVENTS = ("pull_request", "pull_request_target")

AWS_CREDS_ACTION = "aws-actions/configure-aws-credentials"
CHECKOUT_ACTION = "actions/checkout"
# Inputs of actions/checkout that fetch the pull request's own code. The forms are the ones the
# GitHub changelog of 2026-06-18 lists as unsafe in pull_request_target (DECISIONS D6.1).
PR_CODE_MARKERS = {
    "ref": ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref",
            "github.head_ref", "refs/pull/"),
    "repository": ("github.event.pull_request.head.repo.full_name",),
}
KEY_ENV_NAMES = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
KEY_INPUT_NAMES = {"aws-access-key-id", "aws-secret-access-key"}
ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-f]{7,39}$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
USES_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/[^@\s]+)?@([^@\s]+)$")
PURE_EXPR_RE = re.compile(r"^\$\{\{[^'\"}]*\}\}$")
GLOB_CHARS = set("*?+![]")
COMMENT_RE = re.compile(r"^\s+#\s?(.*?)\s*$")

REDACTED = "<literal value, redacted>"
ID_TOKEN_DEFAULT = "default (not in the file)"

SUB_FORMAT_NOTE = (
    "Expected sub claims use GitHub's default subject format. A repository or organisation can "
    "customise the sub template, and repositories created after 2026-07-15 use an immutable "
    "format with owner and repository IDs; neither is visible in workflow files (DECISIONS D5)."
)


# --------------------------------------------------------------------------- helpers

def check_repo(repo):
    """Return the OWNER/REPO used in expected sub claims; raise ValueError on a malformed value."""
    if repo is None:
        return PLACEHOLDER_REPO
    if not REPO_RE.match(repo):
        raise ValueError("--repo must look like OWNER/REPO (letters, digits, '-', '.', '_')")
    return repo


def _is_expr(value):
    return isinstance(value, str) and "${{" in value


def _line_of(value, fallback=None):
    return getattr(value, "line", None) or fallback


class _Report:
    """Collects the findings of one file."""

    def __init__(self, file):
        self.file = file
        self.findings = []

    def add(self, rule, line, message, fact, job=None, severity=None):
        self.findings.append({
            "rule": rule,
            "severity": severity or RULE_SEVERITY[rule],
            "file": self.file,
            "job": None if job is None else str(job),
            "line": line,
            "message": message,
            "fact": fact,
        })

    def sorted(self):
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_RANK[f["severity"]], f["line"] or 0, f["rule"], f["job"] or ""),
        )


def _empty_result(file, status, reason=None):
    return {"file": file, "status": status, "reason": reason, "name": None, "triggers": [],
            "permissions": None, "jobs": [], "findings": []}


def _rejected(file, reason, line=None):
    result = _empty_result(file, "REJECTED", reason)
    report = _Report(file)
    report.add("PG-W00", line, f"File not analysed: {reason}.", {"status": "REJECTED"})
    result["findings"] = report.sorted()
    return result


# --------------------------------------------------------------------------- triggers

def _str_list(value, report, line, what):
    """A filter value as a list of strings: 'main' -> ['main']; a list of strings stays a list."""
    if value is None:
        return None
    if isinstance(value, str):
        return [str(value)]
    if isinstance(value, YSeq) and all(isinstance(v, str) for v in value):
        return [str(v) for v in value]
    report.add("PG-W00", _line_of(value, line), f"Trigger filter '{what}' is not readable.",
               {"filter": what})
    return None


def _trigger(event, config_value, line, report):
    trig = {"event": str(event), "line": line, "branches": None, "branches_ignore": None,
            "tags": None, "tags_ignore": None, "types": None}
    if event not in KNOWN_EVENTS:
        report.add("PG-W00", line, f"Unknown trigger event '{event}'.", {"event": str(event)})
    if isinstance(config_value, YMap):
        for key, field in [("branches", "branches"), ("branches-ignore", "branches_ignore"),
                           ("tags", "tags"), ("tags-ignore", "tags_ignore"), ("types", "types")]:
            if key in config_value:
                trig[field] = _str_list(config_value[key], report, line, f"{event}.{key}")
    return trig


def _triggers(data, report):
    if "on" not in data:
        report.add("PG-W00", 1, "No 'on' key: the triggers of this workflow are unknown.",
                   {"on": None})
        return []
    on = data["on"]
    line = data.key_lines["on"]
    if isinstance(on, str) and on.strip():
        return [_trigger(on, None, line, report)]
    if isinstance(on, YSeq) and on and all(isinstance(e, str) and e.strip() for e in on):
        return [_trigger(e, None, ln, report) for e, ln in zip(on, on.item_lines)]
    if isinstance(on, YMap) and on:
        return [_trigger(k, v, on.key_lines[k], report) for k, v in on.items()]
    report.add("PG-W00", line, "The 'on' value is not a readable trigger list.", {"on": "unreadable"})
    return []


# --------------------------------------------------------------------------- permissions

SCOPE_VALUES = {"read", "write", "none"}
ID_TOKEN_VALUES = {"write", "none"}  # GitHub workflow syntax: "id-token: write|none"


def _permissions(container, report, job=None):
    """Parse the `permissions` key of a workflow or a job into a small fact."""
    if "permissions" not in container:
        return {"kind": "ABSENT", "line": None, "scopes": None}
    value = container["permissions"]
    line = container.key_lines["permissions"]
    if isinstance(value, str) and value in ("read-all", "write-all"):
        kind = "READ_ALL" if value == "read-all" else "WRITE_ALL"
        return {"kind": kind, "line": line, "scopes": None}
    if isinstance(value, YMap):
        if not value:
            return {"kind": "EMPTY", "line": line, "scopes": None}
        # Values stay YStr (they keep their line); a non-text value becomes its text form.
        scopes = {str(k): (v if v is None or isinstance(v, str) else str(v))
                  for k, v in value.items()}
        for scope, v in value.items():
            if scope != scope.lower():
                # GitHub documents lower-case scope names; whether 'ID-Token' counts as id-token
                # is not verified, so it must not be read as "no id-token" (security review).
                report.add("PG-W00", value.key_lines[scope],
                           f"Permission scope '{scope}' is not written in lower case; whether "
                           "GitHub applies it is not verified.", {"scope": str(scope)}, job)
            allowed = ID_TOKEN_VALUES if scope == "id-token" else SCOPE_VALUES
            if not isinstance(v, str) or v not in allowed:
                report.add("PG-W00", value.key_lines[scope],
                           f"Permission '{scope}' has a value that is not recognised ({v}).",
                           {"scope": str(scope), "value": None if v is None else str(v)}, job)
        return {"kind": "MAP", "line": line, "scopes": scopes}
    report.add("PG-W00", line, "The permissions value is not recognised; the token's scopes are "
               "unknown.", {"permissions": None if value is None else str(value)}, job)
    return {"kind": "UNKNOWN", "line": line, "scopes": None, "raw": None if value is None else str(value)}


def _id_token(perm):
    kind = perm["kind"]
    if kind == "WRITE_ALL":
        return "YES"
    if kind in ("READ_ALL", "EMPTY"):
        return "NO"
    if kind == "MAP":
        if any(k.lower() == "id-token" and k != "id-token" for k in perm["scopes"]):
            return "UNKNOWN"  # e.g. 'ID-Token: write': not verified how GitHub reads it
        value = perm["scopes"].get("id-token")
        if value is None and "id-token" not in perm["scopes"]:
            return "NO"  # "all of those that are not specified are set to none" (workflow syntax)
        return {"write": "YES", "none": "NO"}.get(value, "UNKNOWN")
    return "UNKNOWN"  # ABSENT (repository/organisation default, not in the file) or UNKNOWN


def _permission_findings(perm, report, job=None):
    where = "workflow" if job is None else "job"
    if perm["kind"] == "WRITE_ALL":
        report.add("PG-W06", perm["line"],
                   f"permissions: write-all at {where} level gives write access on every scope "
                   "of GITHUB_TOKEN, including id-token (an OIDC token).",
                   {"permissions": "write-all", "level": where}, job)
    if job is None and perm["kind"] == "MAP" and perm["scopes"].get("id-token") == "write":
        report.add("PG-W05", perm["scopes"]["id-token"].line,
                   "id-token: write is set at workflow level, so every job in this file can "
                   "request an OIDC token; set it only on the job that assumes the role.",
                   {"permissions": "id-token: write", "level": "workflow"})


# --------------------------------------------------------------------------- AWS keys and roles

def _redact(value):
    """Keep a pure `${{ ... }}` expression (names a secret); never keep a literal value."""
    text = str(value).strip()
    return text if PURE_EXPR_RE.match(text) else REDACTED


def _keys_in(mapping, names, where, report, job, step=None):
    """Evidence of long-lived keys in an env / with / secrets mapping."""
    evidence = []
    if mapping is None:
        return evidence
    if not isinstance(mapping, YMap):
        if _is_expr(mapping):
            report.add("PG-W00", _line_of(mapping), f"The {where} is an expression; its variables "
                       "(possibly AWS keys) cannot be seen.", {"where": where}, job)
        return evidence
    for key, value in mapping.items():
        wanted = key.upper() if names is KEY_ENV_NAMES else key.lower()
        if wanted in names and value is not None and str(value).strip():
            item = {"where": where, "name": str(key), "value": _redact(value),
                    "line": mapping.key_lines[key]}
            if step is not None:
                item["step"] = step
            evidence.append(item)
    return evidence


def _w01(evidence, report, job):
    """One PG-W01 per place (env / with / secrets block) where keys appear."""
    groups = {}
    for item in evidence:
        groups.setdefault(item["where"], []).append(item)
    for where, items in groups.items():
        names = sorted({i["name"] for i in items})
        literal = any(i["value"] == REDACTED for i in items)
        message = (f"Long-lived AWS access keys ({', '.join(names)}) are used in the {where}; they "
                   "stay valid until rotated. Use OIDC (role-to-assume) instead.")
        if literal:
            message += " A literal value is written in the file (not shown)."
        report.add("PG-W01", min(i["line"] for i in items), message,
                   {"where": where, "names": names}, job)


def _role(value, line, via, action, step):
    raw = str(value).strip()
    resolved = bool(ROLE_ARN_RE.match(raw)) and not _is_expr(raw)
    return {"value": raw if resolved else None, "resolved": resolved,
            "raw": None if resolved else raw, "line": line, "via": via,
            "action": action, "step": step}


# --------------------------------------------------------------------------- uses / pins

def parse_uses(raw):
    """Split a `uses:` value into owner/repo/path/ref and classify how it is pinned."""
    raw = str(raw).strip()
    out = {"raw": raw, "owner": None, "repo": None, "path": None, "ref": None,
           "pin": "UNKNOWN", "digest": None}
    if _is_expr(raw):
        return out
    if raw.startswith("./"):
        out.update(path=raw, pin="LOCAL")
        return out
    if raw.startswith("docker://"):
        image = raw[len("docker://"):]
        out.update(ref=image, pin="DOCKER", digest=bool(DIGEST_RE.search(image)))
        return out
    m = USES_RE.match(raw)
    if not m:
        return out
    owner, repo, path, ref = m.groups()
    if FULL_SHA_RE.match(ref):
        pin = "FULL_SHA"
    elif SHORT_SHA_RE.match(ref):
        pin = "SHORT_SHA"
    else:
        pin = "TAG_OR_BRANCH"
    out.update(owner=owner, repo=repo, path=path[1:] if path else None, ref=ref, pin=pin)
    return out


def _comment_after(value, lines):
    """The comment written after a `uses:` value on the same line (recorded, never trusted)."""
    end_line, end_col = getattr(value, "end_line", None), getattr(value, "end_col", None)
    if not end_line or end_line > len(lines):
        return None
    m = COMMENT_RE.match(lines[end_line - 1][end_col:])
    return m.group(1) if m else None


def _uses(value, where, lines, report, job, fallback_line):
    line = _line_of(value, fallback_line)
    if not isinstance(value, str):
        report.add("PG-W00", line, "A 'uses' value is not a plain string.", {"uses": None}, job)
        return None
    item = parse_uses(value)
    item["where"] = where
    item["line"] = line
    item["comment"] = _comment_after(value, lines)
    pin, raw = item["pin"], item["raw"]
    if pin == "UNKNOWN":
        report.add("PG-W00", line, f"'{raw}' cannot be read as owner/repo@ref, ./path or docker://.",
                   {"uses": raw, "pin": pin}, job)
    elif pin == "DOCKER" and not item["digest"]:
        report.add("PG-W03", line, f"Docker image '{raw}' has no sha256 digest; whoever can push "
                   "that tag decides the code that runs here.", {"uses": raw, "pin": pin}, job)
    elif pin in ("SHORT_SHA", "TAG_OR_BRANCH"):
        kind = "a short SHA" if pin == "SHORT_SHA" else "a tag or branch"
        report.add("PG-W03", line, f"'{raw}' is pinned to {kind}, not a full 40-character commit "
                   "SHA; the code behind that ref can change without review.",
                   {"uses": raw, "pin": pin}, job)
    return item


# --------------------------------------------------------------------------- expected sub claims

def _sub_entry(kind, trigger, verified, note, sub=None, pattern=None):
    return {"kind": kind, "sub": sub, "pattern": pattern, "trigger": trigger,
            "verified": verified, "note": note}


def _has_glob(name):
    return any(c in GLOB_CHARS for c in name)


def _ref_subs(repo, trig, names_field, ignore_field, prefix, kind):
    out = []
    names, ignore = trig[names_field], trig[ignore_field]
    label = "branch" if prefix == "refs/heads/" else "tag"
    for name in names or []:
        if _has_glob(name):
            out.append(_sub_entry("ANY_REF", trig["event"], True,
                                  f"{label} filter '{name}' is a pattern, not one {label}",
                                  pattern=f"repo:{repo}:ref:{prefix}{name}"))
        else:
            out.append(_sub_entry(kind, trig["event"], True, f"push to {label} '{name}'",
                                  sub=f"repo:{repo}:ref:{prefix}{name}"))
    if ignore is not None:
        out.append(_sub_entry("ANY_REF", trig["event"], True,
                              f"{names_field.replace('_', '-')}-ignore: any {label} not listed",
                              pattern=f"repo:{repo}:ref:{prefix}*"))
    return out


def _subs_for_trigger(trig, repo):
    event = trig["event"]
    if event == "push":
        if all(trig[f] is None for f in ("branches", "branches_ignore", "tags", "tags_ignore")):
            return [_sub_entry("ANY_REF", event, True,
                               "push with no branch or tag filter runs for any branch or tag",
                               pattern=f"repo:{repo}:ref:*")]
        return (_ref_subs(repo, trig, "branches", "branches_ignore", "refs/heads/", "BRANCH")
                + _ref_subs(repo, trig, "tags", "tags_ignore", "refs/tags/", "TAG"))
    if event == "pull_request":
        return [_sub_entry("PULL_REQUEST", event, True,
                           "pull request event, job without environment",
                           sub=f"repo:{repo}:pull_request")]
    if event == "pull_request_target":
        return [_sub_entry("PULL_REQUEST", event, False,
                           "not verified: GitHub's OIDC page says 'pull request event' without "
                           "naming pull_request_target, whose GITHUB_REF is the default branch, "
                           "so the sub may be ref:refs/heads/<default branch> instead",
                           sub=f"repo:{repo}:pull_request")]
    if event == "workflow_dispatch":
        return [_sub_entry("ANY_REF", event, True,
                           "manual run on any branch or tag the user chooses",
                           pattern=f"repo:{repo}:ref:*")]
    if event == "schedule":
        return [_sub_entry("ANY_REF", event, True,
                           "scheduled runs use the default branch, whose name is not in "
                           "workflow files", pattern=f"repo:{repo}:ref:refs/heads/*")]
    if event == "release":
        return [_sub_entry("ANY_REF", event, True, "GITHUB_REF is the release tag",
                           pattern=f"repo:{repo}:ref:refs/tags/*")]
    if event == "workflow_call":
        return [_sub_entry("UNKNOWN", event, False,
                           "called workflow: the ref is the caller's, which is not visible in "
                           "this file")]
    return [_sub_entry("UNKNOWN", event, False,
                       f"event '{event}': the sub for this event is not verified")]


def expected_subs(environment, triggers, repo):
    """The sub claims a role-assuming job is expected to present (GitHub default template)."""
    if environment is not None:
        if environment["resolved"]:
            name = environment["name"].replace(":", "%3A")
            return [_sub_entry("ENVIRONMENT", "*", True,
                               "the job references an environment, so the environment form "
                               "replaces the ref and pull_request forms",
                               sub=f"repo:{repo}:environment:{name}")]
        return [_sub_entry("UNKNOWN", "*", False,
                           "the environment name is an expression, not visible in the file")]
    if not triggers:
        return [_sub_entry("UNKNOWN", None, False, "no readable trigger")]
    out, seen = [], set()
    for trig in triggers:
        for entry in _subs_for_trigger(trig, repo):
            key = (entry["kind"], entry["sub"], entry["pattern"], entry["trigger"])
            if key not in seen:
                seen.add(key)
                out.append(entry)
    return out


# --------------------------------------------------------------------------- jobs

def _environment(job, report, job_id):
    if "environment" not in job:
        return None
    value = job["environment"]
    line = job.key_lines["environment"]
    if isinstance(value, YMap):
        value = value.get("name")
    if not isinstance(value, str) or not value.strip():
        report.add("PG-W00", line, "The environment value is not readable.", {"environment": None},
                   job_id)
        return {"name": None, "resolved": False, "line": line}
    return {"name": str(value), "resolved": not _is_expr(value), "line": line}


def _steps(job, job_id, lines, report, facts):
    """Walk the steps of a normal job: uses, env and with keys, role-to-assume."""
    steps = job.get("steps")
    if not isinstance(steps, YSeq):
        report.add("PG-W00", job.key_lines.get("steps", job.line),
                   "The job has no readable 'steps' list.", {"steps": None}, job_id)
        facts["unknown"] = True
        return
    for number, (step, line) in enumerate(zip(steps, steps.item_lines), start=1):
        if not isinstance(step, YMap):
            report.add("PG-W00", line, f"Step {number} is not a mapping.", {"step": number}, job_id)
            facts["unknown"] = True
            continue
        uses = None
        if "uses" in step:
            uses = _uses(step["uses"], "step", lines, report, job_id, step.key_lines["uses"])
            if uses:
                uses["step"] = number
                facts["uses"].append(uses)
        facts["keys"] += _keys_in(step.get("env"), KEY_ENV_NAMES, f"step {number} env", report,
                                  job_id, number)
        with_ = step.get("with")
        if with_ is not None and not isinstance(with_, YMap):
            report.add("PG-W00", step.key_lines["with"], f"Step {number} 'with' is not a mapping.",
                       {"step": number}, job_id)
            facts["unknown"] = True
            continue
        if uses and uses["owner"] and f"{uses['owner']}/{uses['repo']}".lower() == CHECKOUT_ACTION:
            checkout = _pr_code_checkout(with_, number)
            if checkout:
                facts["pr_checkout"].append(checkout)
        key_inputs = _keys_in(with_, KEY_INPUT_NAMES, f"step {number} with", report, job_id, number)
        facts["keys"] += key_inputs
        role_keys = [k for k in (with_ or {}) if k.lower() == "role-to-assume"]
        if not role_keys:
            continue
        role_key = role_keys[0]
        if len(role_keys) > 1:
            # Inputs that differ only in case (role-to-assume / Role-To-Assume): which one the
            # action reads is not verified, so neither is trusted (security review 2026-11-25).
            report.add("PG-W00", with_.key_lines[role_keys[1]],
                       f"Step {number} has role-to-assume inputs that differ only in case "
                       f"({', '.join(role_keys)}); which one is used is not verified.",
                       {"inputs": [str(k) for k in role_keys]}, job_id)
        elif with_[role_key] is None or not str(with_[role_key]).strip():
            continue
        action = f"{uses['owner']}/{uses['repo']}".lower() if uses and uses["owner"] else None
        if key_inputs:
            via = "KEYS"
        elif action == AWS_CREDS_ACTION:
            via = "OIDC"
        else:
            via = "UNKNOWN"
        role = _role(with_[role_key], with_.key_lines[role_key], via,
                     uses["raw"] if uses else None, number)
        if len(role_keys) > 1:
            role.update(value=None, resolved=False,
                        raw=" | ".join(str(with_[k]) for k in role_keys))
        facts["roles"].append(role)
        if via == "UNKNOWN":
            report.add("PG-W00", role["line"], "role-to-assume is given to an action PipeGuard "
                       "does not recognise; how the role is assumed is unknown.",
                       {"action": role["action"]}, job_id)
        if not role["resolved"]:
            report.add("PG-W00", role["line"], f"The role ARN cannot be read from the file "
                       f"(role-to-assume: {role['raw']}); the trust policy cannot be matched.",
                       {"role": role["raw"]}, job_id)


INDEX_FORM_RE = re.compile(r"""\[\s*['"]([^'"\]]*)['"]\s*\]""")


def _normalise_expression(text):
    """Lower-case, drop whitespace, and turn ['x'] / ["x"] index forms into .x, so another
    spelling of the same context path is still recognised (security review 2026-11-26).
    Whether GitHub treats context names case-insensitively is not verified; matching every case
    is the conservative reading (it can only raise PG-W02 to HIGH, never hide it)."""
    text = INDEX_FORM_RE.sub(lambda m: "." + m.group(1), text)
    return re.sub(r"\s+", "", text).lower()


def _pr_code_checkout(with_, number):
    """The first actions/checkout input that fetches the pull request's code, or None."""
    for key, value in (with_ or {}).items():
        markers = PR_CODE_MARKERS.get(key.lower(), ())
        text = "" if value is None else str(value)
        if any(marker in _normalise_expression(text) for marker in markers):
            opt_out = next((v for k, v in with_.items() if k.lower() == "allow-unsafe-pr-checkout"),
                           None)
            return {"step": number, "input": str(key), "value": text,
                    "line": with_.key_lines[key],
                    "allow_unsafe_pr_checkout": str(opt_out).strip().lower() == "true"}
    return None


def _reusable(job, job_id, lines, report, facts):
    uses = _uses(job["uses"], "job", lines, report, job_id, job.key_lines["uses"])
    if uses:
        facts["uses"].append(uses)
    facts["keys"] += _keys_in(job.get("secrets") if isinstance(job.get("secrets"), YMap) else None,
                              KEY_ENV_NAMES, "job secrets", report, job_id)
    facts["keys"] += _keys_in(job.get("with"), KEY_INPUT_NAMES, "job with", report, job_id)
    facts["unknown"] = True
    raw = uses["raw"] if uses else None
    report.add("PG-W00", job.key_lines["uses"], f"The job calls a reusable workflow ({raw}); "
               "whether and how it assumes an AWS role cannot be seen from this file.",
               {"uses": raw}, job_id)


def _job(job_id, job, line, wf, lines, report, repo):
    out = {"id": str(job_id), "line": line, "kind": "UNKNOWN", "permissions": None,
           "id_token_write": "UNKNOWN", "id_token_source": None, "environment": None,
           "aws": {"mode": "UNKNOWN", "keys": [], "roles": []}, "uses": [], "expected_subs": []}
    if not isinstance(job, YMap):
        report.add("PG-W00", line, f"Job '{job_id}' is not a mapping.", {"job": str(job_id)}, job_id)
        return out

    # Effective permissions: the job's own block replaces the workflow's (GitHub workflow syntax).
    if "permissions" in job:
        perm = dict(_permissions(job, report, job_id), source="job")
        _permission_findings(perm, report, job_id)
        out["id_token_source"] = "job"
    elif wf["permissions"]["kind"] != "ABSENT":
        perm = dict(wf["permissions"], source="workflow")
        out["id_token_source"] = "workflow"
    else:
        perm = dict(wf["permissions"], source=ID_TOKEN_DEFAULT)
        out["id_token_source"] = ID_TOKEN_DEFAULT
    out["permissions"] = perm
    out["id_token_write"] = _id_token(perm)
    out["environment"] = _environment(job, report, job_id)

    facts = {"keys": list(wf["keys"]), "roles": [], "uses": [], "unknown": False,
             "pr_checkout": []}
    facts["keys"] += _keys_in(job.get("env"), KEY_ENV_NAMES, "job env", report, job_id)
    if "uses" in job:
        out["kind"] = "REUSABLE"
        _reusable(job, job_id, lines, report, facts)
    elif "steps" in job:
        out["kind"] = "STEPS"
        _steps(job, job_id, lines, report, facts)
    else:
        report.add("PG-W00", line, "The job has neither 'steps' nor 'uses'.", {"job": str(job_id)},
                   job_id)
        facts["unknown"] = True

    own_keys = [k for k in facts["keys"] if not k["where"].startswith("workflow")]
    _w01(own_keys, report, job_id)

    has_keys = bool(facts["keys"])
    has_oidc = any(r["via"] == "OIDC" for r in facts["roles"])
    has_unknown = facts["unknown"] or any(r["via"] == "UNKNOWN" for r in facts["roles"])
    if has_keys and has_oidc:
        mode = "BOTH"
    elif has_keys:
        mode = "LONG_LIVED_KEYS"
    elif has_oidc:
        mode = "OIDC"
    elif has_unknown:
        mode = "UNKNOWN"
    else:
        mode = "NONE"
    out["aws"] = {"mode": mode, "keys": facts["keys"], "roles": facts["roles"]}
    out["uses"] = facts["uses"]

    # Expected sub claims: for jobs that assume a role with an OIDC token, and (not verified) for
    # reusable-workflow jobs given id-token: write.
    reusable_oidc = out["kind"] == "REUSABLE" and out["id_token_write"] == "YES"
    if has_oidc or reusable_oidc:
        subs = expected_subs(out["environment"], wf["triggers"], repo)
        if reusable_oidc and not has_oidc:
            for entry in subs:
                entry["verified"] = False
                entry["note"] = ("reusable workflow; assumes its token carries the caller's "
                                 "sub (not verified): " + entry["note"])
        out["expected_subs"] = subs
        unknown = [s for s in subs if s["kind"] == "UNKNOWN"]
        if unknown and has_oidc:
            report.add("PG-W00", line, f"The expected sub claim cannot be determined: "
                       f"{unknown[0]['note']}.", {"expected_sub": "UNKNOWN"}, job_id)

    # PG-W02: a role is assumed in a pull_request / pull_request_target job.
    roles_used = [r for r in facts["roles"] if r["via"] in ("OIDC", "UNKNOWN")]
    # R2 (Phase 4, D12): a job-level `if:` may exclude the pull request event at run time, but
    # expressions are not evaluated statically: the finding and its severity stay, the message says
    # so and the fact carries has_if.
    has_if = "if" in job
    if_note = " Note: an if: condition is present and was not evaluated." if has_if else ""
    if roles_used:
        role_text = roles_used[0]["value"] or roles_used[0]["raw"]
        for trig in wf["triggers"]:
            if trig["event"] == "pull_request":
                report.add("PG-W02", roles_used[0]["line"],
                           f"The role {role_text} is assumed in a job triggered by pull_request: "
                           "code from a pull request branch runs with the role." + if_note,
                           {"trigger": "pull_request", "trigger_line": trig["line"],
                            "has_if": has_if}, job_id)
            elif trig["event"] == "pull_request_target" and facts["pr_checkout"]:
                # D6.1: HIGH when the same job checks out the pull request's code ("pwn
                # request", GitHub Security Lab). actions/checkout v7 refuses this for fork PRs
                # unless allow-unsafe-pr-checkout is true (GitHub changelog 2026-06-18), but the
                # checkout version behind a SHA pin cannot be verified, so it stays HIGH.
                pr = facts["pr_checkout"][0]
                guard = ("the checkout protection is switched off (allow-unsafe-pr-checkout: true)"
                         if pr["allow_unsafe_pr_checkout"] else
                         "actions/checkout v7 refuses this for fork pull requests unless "
                         "allow-unsafe-pr-checkout is true, but PipeGuard cannot verify the "
                         "checkout version from the file")
                report.add("PG-W02", roles_used[0]["line"],
                           f"The role {role_text} is assumed in a pull_request_target job whose "
                           f"step {pr['step']} checks out the pull request's code ({pr['input']}: "
                           f"{pr['value']}): a 'pwn request' (GitHub Security Lab); "
                           f"{guard}." + if_note,
                           {"trigger": "pull_request_target", "trigger_line": trig["line"],
                            "pr_checkout": pr, "has_if": has_if}, job_id, severity="HIGH")
            elif trig["event"] == "pull_request_target":
                report.add("PG-W02", roles_used[0]["line"],
                           f"The role {role_text} is assumed in a job triggered by "
                           "pull_request_target, which runs in the base repository's context "
                           "with a read/write GITHUB_TOKEN even from a public fork (GitHub "
                           "docs); pull request code run here gets the role." + if_note,
                           {"trigger": "pull_request_target", "trigger_line": trig["line"],
                            "has_if": has_if}, job_id)

    # PG-W04: OIDC used and no permissions block for this job anywhere.
    if has_oidc and perm["kind"] == "ABSENT":
        report.add("PG-W04", line, "OIDC is used but neither the workflow nor the job has a "
                   "permissions block: GITHUB_TOKEN gets the repository/organisation default, "
                   "which is not visible in the file.", {"permissions": "ABSENT"}, job_id)
    return out


# --------------------------------------------------------------------------- files

def analyze_text(text, display_path="<text>", repo=None):
    """Analyse the text of one workflow file. Returns the facts and findings as a dict."""
    repo = check_repo(repo)
    report = _Report(display_path)
    try:
        data = load(text)
    except YamlRejected as exc:
        return _rejected(display_path, exc.reason, exc.line)
    if not isinstance(data, YMap) or ("on" not in data and "jobs" not in data):
        return _empty_result(display_path, "NOT_A_WORKFLOW",
                             "not a workflow: the file has no 'on' and no 'jobs' key")

    result = _empty_result(display_path, "ANALYSED")
    name = data.get("name")
    result["name"] = str(name) if isinstance(name, str) else None
    result["triggers"] = _triggers(data, report)
    wf_perm = _permissions(data, report)
    _permission_findings(wf_perm, report)
    result["permissions"] = wf_perm
    wf_keys = _keys_in(data.get("env"), KEY_ENV_NAMES, "workflow env", report, None)
    _w01(wf_keys, report, None)
    wf = {"permissions": wf_perm, "keys": wf_keys, "triggers": result["triggers"]}

    jobs = data.get("jobs")
    if "jobs" not in data:
        report.add("PG-W00", 1, "No 'jobs' key: nothing to analyse.", {"jobs": None})
    elif not isinstance(jobs, YMap):
        report.add("PG-W00", data.key_lines["jobs"], "'jobs' is not a mapping.", {"jobs": None})
    else:
        lines = text.splitlines()
        result["jobs"] = [_job(job_id, job, jobs.key_lines[job_id], wf, lines, report, repo)
                          for job_id, job in jobs.items()]
    result["findings"] = report.sorted()
    return result


def analyze_file(path, display_path=None, repo=None):
    """Read one file with the size limit and analyse it. Never follows a symlink."""
    check_repo(repo)
    path = Path(path)
    display = display_path or path.as_posix()
    if path.is_symlink():
        return _rejected(display, "symlink not followed (it could point outside the scanned folder)")
    try:
        size = path.stat().st_size
        if size > config.MAX_FILE_BYTES:
            return _rejected(display, f"file too large ({size} bytes, limit "
                                      f"{config.MAX_FILE_BYTES})")
        with path.open("rb") as handle:
            raw = handle.read(config.MAX_FILE_BYTES + 1)
    except OSError as exc:
        return _rejected(display, f"cannot read the file ({type(exc).__name__})")
    if len(raw) > config.MAX_FILE_BYTES:
        return _rejected(display, f"file too large (limit {config.MAX_FILE_BYTES} bytes)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _rejected(display, "not valid UTF-8 text")
    return analyze_text(text, display, repo)


def collect_files(path):
    """The workflow files to scan under `path`, sorted by name, plus scan-level problems.

    A file is scanned as given. For a folder: `.github/workflows/*.yml|*.yaml` under it if that
    folder exists, else the *.yml / *.yaml files directly in the folder (not recursive).
    """
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        raise FileNotFoundError(str(path))
    if not path.is_dir():
        return [path], []
    workflows = path / ".github" / "workflows"
    base = workflows if workflows.is_dir() else path
    if base is workflows and (workflows.is_symlink() or workflows.parent.is_symlink()):
        problem = {"rule": "PG-W00", "severity": "UNKNOWN", "file": base.as_posix(), "job": None,
                   "line": None, "message": "The workflows folder is a symlink; not followed.",
                   "fact": {"symlink": True}}
        return [], [problem]
    files = sorted((p for p in base.iterdir()
                    if p.suffix.lower() in (".yml", ".yaml") and (p.is_symlink() or p.is_file())),
                   key=lambda p: p.name)
    return files, []


def scan(path, repo=None):
    """Scan a file or a folder; returns facts for every file and all findings, sorted."""
    repo = check_repo(repo)
    files, findings = collect_files(path)
    limit = config.MAX_WORKFLOW_FILES
    skipped = files[limit:]
    files = files[:limit]
    if skipped:
        findings.append({
            "rule": "PG-W00", "severity": "UNKNOWN", "file": Path(path).as_posix(), "job": None,
            "line": None, "fact": {"not_analysed": [p.name for p in skipped[:20]]},
            "message": f"{len(skipped)} file(s) not analysed: more than {limit} workflow files "
                       "in one scan.",
        })
    results = [analyze_file(p, repo=repo) for p in files]
    for result in results:
        findings.extend(result["findings"])
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["file"], f["line"] or 0, f["rule"]))
    summary = {
        "files": len(results),
        "analysed": sum(r["status"] == "ANALYSED" for r in results),
        "not_a_workflow": sum(r["status"] == "NOT_A_WORKFLOW" for r in results),
        "rejected": sum(r["status"] == "REJECTED" for r in results),
        "findings": {sev: sum(f["severity"] == sev for f in findings) for sev in SEVERITY_RANK},
    }
    return {"schema": SCHEMA, "repo": repo, "sub_format_note": SUB_FORMAT_NOTE,
            "files": results, "findings": findings, "summary": summary}


# --------------------------------------------------------------------------- text output

def _perm_text(perm):
    if perm is None:
        return "-"
    if perm["kind"] == "MAP":
        return "{" + ", ".join(f"{k}: {v}" for k, v in perm["scopes"].items()) + "}"
    return perm["kind"]


def _trigger_text(trig):
    parts = []
    for field in ("branches", "branches_ignore", "tags", "tags_ignore", "types"):
        if trig[field] is not None:
            parts.append(f"{field.replace('_', '-')}: {', '.join(trig[field])}")
    return trig["event"] + (f" ({'; '.join(parts)})" if parts else "")


def format_text(result):
    """Human-readable report. Every scanned string passes through clean() before printing."""
    c = clean
    out = ["PipeGuard workflow scan (read-only: nothing was run, no network)."]
    if result.get("repo"):
        out.append(f"Repository used in expected sub claims: {c(result['repo'])}")
        out.append(f"Note: {SUB_FORMAT_NOTE}")
    for res in result["files"]:
        out.append("")
        out.append(f"== {c(res['file'])}  [{res['status']}]")
        if res["reason"]:
            out.append(f"   {c(res['reason'])}")
        if res["status"] != "ANALYSED":
            continue
        if res["name"]:
            out.append(f"   name: {c(res['name'])}")
        out.append("   triggers: " + (", ".join(c(_trigger_text(t)) for t in res["triggers"]) or "-"))
        out.append(f"   workflow permissions: {c(_perm_text(res['permissions']))}")
        for job in res["jobs"]:
            out.append(f"   job {c(job['id'])} (line {job['line']}, {job['kind']})")
            if job["permissions"] is None:
                continue
            out.append(f"     permissions: {c(_perm_text(job['permissions']))} "
                       f"(from {job['permissions']['source']}); id-token write: "
                       f"{job['id_token_write']} (from {job['id_token_source']})")
            env = job["environment"]
            out.append("     environment: " + (c(env["name"] or "?") + ("" if env["resolved"]
                                                                       else " (UNRESOLVED)")
                                                if env else "-"))
            out.append(f"     AWS credentials: {job['aws']['mode']}")
            for key in job["aws"]["keys"]:
                out.append(f"       key: {c(key['name'])} = {c(key['value'])} "
                           f"({c(key['where'])}, line {key['line']})")
            for role in job["aws"]["roles"]:
                shown = role["value"] if role["resolved"] else f"UNRESOLVED {role['raw']}"
                out.append(f"       role: {c(shown)} (line {role['line']}, via {role['via']})")
            for use in job["uses"]:
                note = f", comment '{c(use['comment'])}', not trusted" if use["comment"] else ""
                out.append(f"     uses: {c(use['raw'])} -> {use['pin']} (line {use['line']}{note})")
            for sub in job["expected_subs"]:
                value = sub["sub"] or (f"pattern {sub['pattern']}" if sub["pattern"] else "?")
                state = "verified" if sub["verified"] else "NOT verified"
                out.append(f"     expected sub: {c(value)} [{sub['kind']}, from "
                           f"{c(sub['trigger'])}, {state}]")
    findings = result.get("findings", [])
    out.append("")
    out.append(f"Findings ({len(findings)}; severity model D8, accepted in D9):")
    for f in findings:
        where = f"{c(f['file'])}:{f['line']}" if f["line"] else c(f["file"])
        job = f" job {c(f['job'])}" if f["job"] else ""
        out.append(f"  [{f['severity']}] {f['rule']} {where}{job}: {c(f['message'])}")
    if not findings:
        out.append("  none")
    summary = result.get("summary")
    if summary:
        counts = ", ".join(f"{k} {v}" for k, v in summary["findings"].items())
        out.append("")
        out.append(f"Summary: {summary['files']} file(s): {summary['analysed']} analysed, "
                   f"{summary['not_a_workflow']} not a workflow, {summary['rejected']} rejected. "
                   f"Findings: {counts}.")
    return "\n".join(out)
