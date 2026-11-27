"""Fixer: a narrowed trust policy and a hardened workflow; never widens access (Phase 4, D12).

    python -m pipeguard fix PATH --repo OWNER/REPO --out DIR [--owner-id N --repo-id N]
                            [--resolve-pins] [--force]

The core rule is NEW ⊆ OLD: every request the new trust policy accepts was accepted by the old one.
It holds by construction, and it is checked again before anything is written:
- a new GitHub statement is an old GitHub Allow statement whose Principal, Action and other
  condition keys are copied unchanged; only its `sub` and `aud` conditions are replaced by
  StringEquals sub = values THIS statement already accepted (Phase 2 / 3 matcher) and
  StringEquals aud = sts.amazonaws.com, which this statement's own aud check already accepted;
- statements that are not GitHub trust statements, and every Deny statement, are copied unchanged;
- GitHub Allow statements that accept none of the kept values (dead or only wide) are removed;
- a needed value the old policy does not accept is NEVER added: it goes to NAME.NEEDS_DECISION.txt.
The fixer reads files only, never modifies the scanned folder and writes only under --out.
Network: only with --resolve-pins (read-only GET to api.github.com, token from pipeguard.config).
"""

import difflib
import json
import re
from pathlib import Path
from urllib.parse import quote

import requests

from pipeguard import config, linker, tf_reader, trust_analyzer, workflow_analyzer
from pipeguard.json_reader import load_json
from pipeguard.output import clean
from pipeguard.tf_reader import Unresolved
from pipeguard.trust_analyzer import NEGATED, glob_match

AUD = "sts.amazonaws.com"
SUB_KEY = trust_analyzer.KEY_PREFIX + "sub"
AUD_KEY = trust_analyzer.KEY_PREFIX + "aud"
FIX_RULES = ("PG-T01", "PG-T02", "PG-T03", "PG-T04", "PG-L01", "PG-L09")
ID_RE = re.compile(r"^[0-9]{1,20}$")
SAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9_.-]")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                    *(f"LPT{i}" for i in range(1, 10))}
API = "https://api.github.com"
SCOPE_VALUES = {"read", "write", "none"}
HEADER = ("PipeGuard fix summary (static: no AWS call; every file is a proposal, nothing was "
          "applied).")
RULE_TEXT = ("Rule (DECISIONS D12): every request the new trust policy accepts was accepted by the old "
             "one (NEW is a subset of OLD); a value the old policy rejects is never added (see "
             "NAME.NEEDS_DECISION.txt).")


class CannotFix(Exception):
    """This role's policy cannot be narrowed automatically (the reason is shown)."""


class FixRefused(Exception):
    """The command refuses to run or to write (usage problem; exit 2)."""


def load_token():
    return config.load_github_token()


# --------------------------------------------------------------------------- small helpers

def safe_name(name):
    """A file-name stem made of [A-Za-z0-9_.-] only, or None (empty or longer than 64 characters).
    Never a separator, never '..' at the start, never a Windows device name (CON, NUL, ...)."""
    if not name or len(name) > 64:
        return None
    out = SAFE_CHAR_RE.sub("_", str(name))
    if out.startswith("."):
        out = "_" + out[1:]
    if out.split(".")[0].upper() in WINDOWS_RESERVED:
        out = "_" + out
    return out


def to_plain(value):
    """An evaluated document (YMap / YSeq / YStr) as plain JSON values; Unresolved -> CannotFix."""
    if isinstance(value, Unresolved):
        raise CannotFix(f"a value is not resolvable ({value.text or value.reason}); it cannot be "
                        "copied into a new policy")
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    if isinstance(value, str):
        return str(value)
    return value


def check_ids(owner_id, repo_id):
    if owner_id is None and repo_id is None:
        return None
    if owner_id is None or repo_id is None:
        raise ValueError("--owner-id and --repo-id must be given together")
    for value in (owner_id, repo_id):
        if not ID_RE.match(str(value)):
            raise ValueError("--owner-id and --repo-id must be numbers (GitHub owner / repository IDs)")
    return str(owner_id), str(repo_id)


# --------------------------------------------------------------------------- acceptance

def _aud_record(record, aud):
    values = record["values"]
    if not values or any(not isinstance(v, str) for v in values):
        return None
    base = record["base"]
    if base == "Null":
        # Null: false = the key exists (it does: aud is in every token we consider); true = absent.
        return all(v.lower() == "false" for v in values)
    negated = base in NEGATED
    positive = base.replace("Not", "", 1) if negated else base
    if positive == "StringEquals":
        hit = aud in values
    elif positive == "StringLike":
        hit = any(glob_match(str(v), aud) for v in values)
    elif positive == "StringEqualsIgnoreCase":
        hit = aud.lower() in {str(v).lower() for v in values}
    else:
        return None
    return (not hit) if negated else hit


def aud_accepts(raw_statement, aud=AUD):
    """Does this statement's own aud check accept `aud`? True / False / None (cannot tell)."""
    claims, _, problem = trust_analyzer._parse_condition(raw_statement.get("Condition"))
    if problem:
        return None
    return linker._and(_aud_record(r, aud) for r in claims["aud"])


def _raw_statements(document):
    raw = document.get("Statement")
    return [raw] if isinstance(raw, dict) else list(raw or [])


def request_accepts(policy, raw_statements, sub, aud=AUD):
    """Would this policy accept a GitHub token with `sub` and `aud`? (Other keys: see D12.)"""
    results = []
    for facts, raw in zip(policy["statements"], raw_statements):
        if facts["class"] is None or facts["effect"] == "Deny":
            continue
        results.append(linker._and([linker._statement_accepts(facts, sub, False),
                                    aud_accepts(raw, aud)]))
    return linker._or(results)


# --------------------------------------------------------------------------- the narrowing (core)

def _rewrite(raw, values, aud):
    """A copy of one GitHub Allow statement whose sub and aud conditions are replaced."""
    condition = {"StringEquals": {AUD_KEY: aud, SUB_KEY: values[0] if len(values) == 1 else values}}
    for operator, block in to_plain(raw.get("Condition") or {}).items():
        kept = {k: v for k, v in block.items() if k.lower() not in (SUB_KEY, AUD_KEY)}
        if not kept:
            continue
        if operator == "StringEquals":
            condition["StringEquals"].update(kept)
        else:
            condition[operator] = kept
    out = {}
    for key, value in raw.items():
        out[str(key)] = condition if key == "Condition" else to_plain(value)
    if "Condition" not in out:
        out["Condition"] = condition
    return out


def narrow(document, policy, values, aud=AUD):
    """Build the narrowed policy from the old `document` and its Phase 2 `policy` facts.

    Each value goes to the FIRST GitHub Allow statement that accepts it (sub, Phase 2 matcher)
    and whose own aud check accepts `aud`. Returns {"document" (None if nothing is kept),
    "sources" (old statement index of every new statement), "kept", "refused", "reasons",
    "removed" (old indexes), "copied" (old indexes)}. Raises CannotFix."""
    raw_list = _raw_statements(document)
    facts = policy["statements"]
    if len(facts) != len(raw_list):
        raise CannotFix("the statements could not be matched to their facts")
    github = []
    for i, s in enumerate(facts):
        if s["class"] is None or s["effect"] == "Deny":
            continue
        if s["class"] in ("UNKNOWN", "JOB_WORKFLOW_REF"):
            reason = (s.get("evidence") or {}).get("reason") or s["class"]
            raise CannotFix(f"statement #{s['index']} cannot be evaluated ({reason}); the owner must "
                            "review it")
        github.append((i, aud_accepts(raw_list[i], aud)))
    assign, kept, refused, reasons = {}, [], [], {}
    for value in values:
        target = next((i for i, ok in github
                       if ok is True and linker._statement_accepts(facts[i], value, False) is True), None)
        if target is None:
            refused.append(value)
            if any(linker._statement_accepts(facts[i], value, False) is True for i, _ in github):
                reasons[value] = (f"only a statement whose aud check does not accept {aud} accepts it")
            elif any(linker._statement_accepts(facts[i], value, False) is None for i, _ in github):
                reasons[value] = "PipeGuard cannot verify that the current trust policy accepts it"
            else:
                reasons[value] = "the current trust policy does not accept it"
            continue
        if value not in assign.setdefault(target, []):
            assign[target].append(value)
        kept.append(value)
    result = {"document": None, "sources": [], "kept": kept, "refused": refused, "reasons": reasons,
              "removed": [], "copied": [], "narrowed": sorted(assign)}
    if not kept:
        return result
    statements = []
    for i, (s, raw) in enumerate(zip(facts, raw_list)):
        if s["class"] is None or s["effect"] == "Deny":
            statements.append(to_plain(raw))
            result["copied"].append(i)
        elif i in assign:
            statements.append(_rewrite(raw, sorted(assign[i]), aud))
        else:
            result["removed"].append(i)
            continue
        result["sources"].append(i)
    out = {}
    for key, value in document.items():
        out[str(key)] = statements if key == "Statement" else to_plain(value)
    result["document"] = out
    return result


# --------------------------------------------------------------------------- Terraform text

class _CannotExpress(Exception):
    pass


def hcl_string(text):
    """A quoted HCL string: escapes, and ${ / %{ doubled so no interpolation or directive starts."""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return '"' + "".join(out).replace("${", "$${").replace("%{", "%%{") + '"'


def _hcl_list(value):
    items = value if isinstance(value, list) else [value]
    if not items or any(not isinstance(v, str) for v in items):
        raise _CannotExpress("a value that is not text")
    return "[" + ", ".join(hcl_string(v) for v in items) + "]"


ATTRS = {"Action": "actions", "NotAction": "not_actions", "Resource": "resources",
         "NotResource": "not_resources"}


def to_tf(document, label, role_name):
    """The policy as a data "aws_iam_policy_document" block (text to paste, never applied)."""
    lines = [f"# Generated by PipeGuard (python -m pipeguard fix) for role {clean(role_name)}.",
             "# A proposal: PipeGuard applies nothing. Paste this block next to the role and set",
             f"#   assume_role_policy = data.aws_iam_policy_document.{label}.json",
             "# Rule: it accepts no request the old policy refused (DECISIONS D12). Review before use.",
             f'data "aws_iam_policy_document" "{label}" {{']
    for key in document:
        if key not in ("Version", "Statement"):
            raise _CannotExpress(f"policy element {key}")
    if "Version" in document:
        lines.append(f"  version = {hcl_string(document['Version'])}")
    for s in document["Statement"]:
        lines.append("")
        lines.append("  statement {")
        blocks = []
        for key, value in s.items():
            if key == "Sid":
                lines.append(f"    sid    = {hcl_string(value)}")
            elif key == "Effect":
                lines.append(f"    effect = {hcl_string(value)}")
            elif key in ATTRS:
                lines.append(f"    {ATTRS[key]} = {_hcl_list(value)}")
            elif key in ("Principal", "NotPrincipal"):
                if not isinstance(value, dict):
                    raise _CannotExpress(f"{key} that is not a mapping")
                kind = "principals" if key == "Principal" else "not_principals"
                for ptype, ids in value.items():
                    blocks += ["", f"    {kind} {{", f"      type        = {hcl_string(ptype)}",
                               f"      identifiers = {_hcl_list(ids)}", "    }"]
            elif key == "Condition":
                for operator, block in value.items():
                    for variable, values in block.items():
                        blocks += ["", "    condition {", f"      test     = {hcl_string(operator)}",
                                   f"      variable = {hcl_string(variable)}",
                                   f"      values   = {_hcl_list(values)}", "    }"]
            else:
                raise _CannotExpress(f"statement element {key}")
        lines += blocks
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def read_tf_text(text):
    """Read a generated block back with PipeGuard's own Terraform reader (plain JSON values)."""
    results = tf_reader.read_module([(Path("pipeguard_fix.tf"), "pipeguard_fix.tf", text)], Path("."))
    item = results["pipeguard_fix.tf"]
    if item["status"] != "ANALYSED" or len(item["items"]) != 1:
        raise CannotFix("the Terraform text does not read back")
    return to_plain(item["items"][0]["value"])


def _normal(document):
    def as_list(v):
        return sorted(v if isinstance(v, list) else [v], key=str)
    out = {"Version": document.get("Version"), "Statement": []}
    for s in _raw_statements(document):
        n = {"Effect": s.get("Effect", "Allow")}
        for key, value in s.items():
            if key in ATTRS:
                n[key] = as_list(value)
            elif key in ("Principal", "NotPrincipal") and isinstance(value, dict):
                n[key] = {t: as_list(i) for t, i in value.items()}
            elif key == "Condition":
                n[key] = {op: {k: as_list(v) for k, v in b.items()} for op, b in value.items()}
            elif key != "Effect":
                n[key] = value
        out["Statement"].append(n)
    return out


def same_policy(a, b):
    """Same statements, elements and values (a single value equals a one-item list)."""
    return _normal(a) == _normal(b)


# --------------------------------------------------------------------------- pins (network)

def commit_url(owner, repo, ref):
    """The API URL for the commit a ref points to; None if a name could leave /repos/OWNER/REPO."""
    for name in (owner, repo):
        if name in (".", "..") or not NAME_RE.match(str(name)):
            return None
    return f"{API}/repos/{owner}/{repo}/commits/{quote(str(ref), safe='')}"


def resolve_sha(owner, repo, ref, token):
    """(sha, None) or (None, reason). Read-only GET, timeout, no redirects; the token only goes
    into the Authorization header of a request to api.github.com and is never printed."""
    url = commit_url(owner, repo, ref)
    if url is None:
        return None, "the owner or repository name cannot be used in an API URL"
    headers = {"Accept": "application/vnd.github.sha", "Authorization": f"Bearer {token}",
               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PipeGuard"}
    try:
        resp = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
    except requests.RequestException as exc:
        return None, f"request failed ({type(exc).__name__})"
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"
    sha = str(resp.text).strip()
    if not workflow_analyzer.FULL_SHA_RE.match(sha):
        return None, "the answer is not a full commit SHA"
    return sha, None


# --------------------------------------------------------------------------- workflow hardening

KEY_LINE = r"^(\s*){key}:\s*(#.*)?(\r?\n)?$"


def _key_line(lines, line, key):
    if not line or line > len(lines):
        return None
    return re.match(KEY_LINE.format(key=re.escape(key)), lines[line - 1])


def _child_indent(lines, line):
    """Indentation of the first content line after `line` (1-based), or None."""
    for text in lines[line:]:
        if text.strip() and not text.lstrip().startswith("#"):
            return re.match(r"^(\s*)", text).group(1)
    return None


def _job_block(lines, job, scopes, nl):
    """Lines of a job-level permissions block inserted after the job key line, or None."""
    m = _key_line(lines, job["line"], job["id"])
    if not m:
        return None
    indent = m.group(1)
    child = _child_indent(lines, job["line"])
    if child is None or len(child) <= len(indent) or not set(child) <= {" "}:
        return None
    unit = " " * (len(child) - len(indent))
    return [f"{child}permissions:{nl}"] + [f"{child}{unit}{k}: {v}{nl}" for k, v in scopes]


def _needs_id_token(job):
    return job["kind"] == "REUSABLE" or any(r["via"] in ("OIDC", "UNKNOWN") for r in job["aws"]["roles"])


def _comparable(result):
    def trig(t):
        return {k: v for k, v in t.items() if k != "line"}
    jobs = []
    for j in result["jobs"]:
        env = j["environment"]
        jobs.append({"id": j["id"], "kind": j["kind"],
                     "environment": None if env is None else (env["name"], env["resolved"]),
                     "roles": [(r["value"], r["raw"], r["via"]) for r in j["aws"]["roles"]],
                     "keys": [(k["where"], k["name"]) for k in j["aws"]["keys"]],
                     "subs": [(s["kind"], s["sub"], s["pattern"]) for s in j["expected_subs"]],
                     "uses": [(u["owner"], u["repo"], u["path"], u["raw"] if u["pin"] in ("LOCAL", "DOCKER")
                               else None) for u in j["uses"]]})
    return {"status": result["status"], "triggers": [trig(t) for t in result["triggers"]], "jobs": jobs}


def harden(text, facts, rel, repo, resolver=None):
    """(new text or None, changes, notes, unpinned). Line edits only: triggers, environments and
    role ARNs are never touched; the result is analysed again and must keep the same facts."""
    changes, notes, unpinned = [], [], []
    if facts["status"] != "ANALYSED":
        return None, changes, [f"not patched: the file was not analysed ({facts['reason']})"], unpinned
    lines = text.splitlines(keepends=True)
    if not lines or not lines[-1].endswith("\n"):
        return None, changes, ["not patched: the file does not end with a newline"], unpinned
    nl = "\r\n" if lines[0].endswith("\r\n") else "\n"
    inserts, deletes, replaces = {}, set(), {}
    jobs = facts["jobs"]
    perm = facts["permissions"]

    # (a) id-token: write at workflow level (PG-W05) -> only the jobs that assume a role keep it.
    if perm["kind"] == "MAP" and perm["scopes"].get("id-token") == "write":
        id_line = getattr(perm["scopes"]["id-token"], "line", None)
        others = [(k, v) for k, v in perm["scopes"].items() if k != "id-token"]
        heirs = [j for j in jobs if j["id_token_source"] == "workflow" and _needs_id_token(j)]
        blocks = [_job_block(lines, j, others + [("id-token", "write")], nl) for j in heirs]
        ok = (_key_line(lines, perm["line"], "permissions") and id_line and
              re.match(r"^\s+id-token:\s*write\s*(#.*)?(\r?\n)?$", lines[id_line - 1]) and
              all(v in SCOPE_VALUES for _, v in others) and
              all(re.fullmatch(r"[a-z][a-z-]{0,40}", k) for k, _ in others) and
              all(b is not None for b in blocks))
        if ok:
            deletes.add(id_line)
            if not others:
                replaces[perm["line"]] = f"permissions: {{}}{nl}"
            for job, block in zip(heirs, blocks):
                inserts.setdefault(job["line"], []).extend(block)
            changes.append("id-token: write moved from the workflow level to the job(s) that assume a "
                           "role: " + (", ".join(j["id"] for j in heirs) or "none"))
            notes.append("jobs without a visible role use lose id-token: write; a job that requests a "
                         "token in a run: script (not read by PipeGuard) would need it back")
        else:
            notes.append("workflow-level id-token: write not moved: the file layout was not recognised")

    # (b) no permissions block anywhere -> contents: read at workflow level; a job that assumes a
    #     role with OIDC gets its own block (id-token: write, contents: read).
    if perm["kind"] == "ABSENT":
        bare = [j for j in jobs if j["id_token_source"] == workflow_analyzer.ID_TOKEN_DEFAULT]
        jobs_line = [i + 1 for i, t in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?(\r?\n)?$", t)]
        first = jobs[0] if jobs else None
        m = _key_line(lines, first["line"], first["id"]) if first else None
        unit = m.group(1) if m else ""
        roles = [j for j in bare if _needs_id_token(j)]
        blocks = [_job_block(lines, j, [("id-token", "write"), ("contents", "read")], nl) for j in roles]
        if any(j["kind"] == "REUSABLE" for j in bare):
            notes.append("permissions not added: a job calls a reusable workflow whose needs are not "
                         "visible; set its permissions by hand")
        elif len(jobs_line) == 1 and unit and set(unit) <= {" "} and all(b is not None for b in blocks):
            inserts.setdefault(jobs_line[0] - 1, []).extend(
                [f"permissions:{nl}", f"{unit}contents: read{nl}", nl])
            for job, block in zip(roles, blocks):
                inserts.setdefault(job["line"], []).extend(block)
            changes.append("permissions: contents: read added at workflow level" +
                           (" and id-token: write + contents: read on the job(s) that assume a role: "
                            + ", ".join(j["id"] for j in roles) if roles else ""))
        else:
            notes.append("permissions block not added: the file layout was not recognised")

    # (c) pins: tag / branch / short SHA -> full commit SHA, only with --resolve-pins.
    for job in jobs:
        for use in job["uses"]:
            if use["pin"] == "DOCKER" and not use["digest"]:
                unpinned.append((use["raw"], use["line"], "docker image without digest (not resolved)"))
            if use["pin"] not in ("TAG_OR_BRANCH", "SHORT_SHA") or not use["owner"]:
                continue
            if resolver is None:
                unpinned.append((use["raw"], use["line"], "run with --resolve-pins to pin it"))
                continue
            sha, why = resolver(use["owner"], use["repo"], use["ref"])
            target = f"{use['owner']}/{use['repo']}" + (f"/{use['path']}" if use["path"] else "")
            token = f"{target}@{use['ref']}"
            line = use["line"]
            current = replaces.get(line, lines[line - 1])
            tail = None
            if sha and current.count(token) == 1:
                before, after = current.split(token)
                tail = re.match(r"^(['\"]?)\s*(#.*)?(\r?\n)?$", after)
            if sha and tail:
                replaces[line] = f"{before}{target}@{sha}{tail.group(1)} # {use['ref']}{nl}"
                changes.append(f"{use['raw']} pinned to {sha} (resolved from {use['ref']} through "
                               "api.github.com)")
            else:
                unpinned.append((use["raw"], line, f"not resolved: {why or 'the line layout was not recognised'}"))

    if not (inserts or deletes or replaces):
        return None, changes, notes, unpinned
    new_lines = []
    for number, line in enumerate(lines, start=1):
        if number not in deletes:
            new_lines.append(replaces.get(number, line))
        new_lines += inserts.get(number, [])
    if 0 in inserts:
        new_lines = inserts[0] + new_lines
    new_text = "".join(new_lines)
    # Self-check: the same facts (triggers, environments, roles, keys, needed subs, actions).
    before = workflow_analyzer.analyze_text(text, rel, repo)
    after = workflow_analyzer.analyze_text(new_text, rel, repo)
    old_rules = {f["rule"] for f in before["findings"]}
    if (_comparable(before) != _comparable(after) or
            {f["rule"] for f in after["findings"]} - old_rules):
        return None, [], notes + ["not patched: the self-check found a changed fact"], unpinned
    return new_text, changes, notes, unpinned


# --------------------------------------------------------------------------- one role

def _policy_entry(result, link):
    for f in result["trust_scan"]["files"]:
        if f["file"] == link["trust_file"]:
            return f["policies"][link["policy_index"]]
    raise CannotFix("the linked policy was not found in the scan")


def _role_findings(result, name, link, policy):
    label = (policy["role"] or {}).get("address") or (policy["role"] or {}).get("name")
    out = []
    for f in result["findings"]:
        if f["rule"].startswith("PG-L") and f.get("role") == name:
            out.append(f)
        elif f["rule"].startswith("PG-T") and f["file"] == link["trust_file"] and f.get("role") == label:
            out.append(f)
    return out


def _minus(a, b):
    rest = list(b)
    out = []
    for item in a:
        if item in rest:
            rest.remove(item)
        else:
            out.append(item)
    return out


def _probe_subs(policy, needed, owner, repo):
    base = f"repo:{owner}/{repo}:"
    contexts = sorted({n["sub"][len(base):] for n in needed if n["sub"] and n["sub"].startswith(base)})
    pairs, owner_ids, _ = linker._policy_ids(policy, owner, repo)
    found = [s for s, _, _ in linker._candidates(policy, owner, repo, contexts or ["ref:refs/heads/main"],
                                                  pairs, owner_ids)]
    return sorted(set(found))


def _plan_role(role, result, owner, repo, ids, root):
    name = role["name"]
    out = {"name": name, "account": role["account"], "status": None, "reason": None,
           "trust_file": None, "trust_role": None, "old_class": None, "new_class": None,
           "resolved": [], "left": [], "kept": [], "decisions": [], "notes": [], "files": {},
           "old_document": None, "new_document": None, "probes": [], "needed_values": [],
           "checked": 0, "statements": None}
    status_reason = {
        "TRUST_NOT_FOUND": "TRUST_NOT_FOUND: the trust policy is not in the scanned files (PG-L03)",
        "ACCOUNT_MISMATCH": "ACCOUNT_MISMATCH: the policy found is for another account (PG-L06)",
        "AMBIGUOUS": "AMBIGUOUS: several trust policies match this role; which one is deployed cannot "
                     "be seen (PG-L08)",
        "KEYS_ONLY": "KEYS_ONLY: assumed only with long-lived keys (PG-L07); move the job to OIDC first",
    }
    if role["status"] != "LINKED":
        out.update(status="CANNOT_FIX", reason=status_reason.get(role["status"], role["status"]))
        return out
    link = role["links"][0]
    out["trust_file"] = linker._relative(link["trust_file"], root)
    out["trust_role"] = link["trust_role"]
    if link["recommended"]["status"] == "NOT_COMPUTED":
        out.update(status="CANNOT_FIX", reason="the link is over the size limits (PG-L00): not computed")
        return out
    policy = _policy_entry(result, link)
    out["old_class"] = policy["class"]
    try:
        out["old_document"] = to_plain(policy["document"])
    except CannotFix:
        out["old_document"] = None
    old_findings = _role_findings(result, name, link, policy)
    out["left"] = sorted((f["rule"], f["severity"], f["message"]) for f in old_findings)
    unknown = [s for s in policy["statements"] if s["class"] in ("UNKNOWN", "JOB_WORKFLOW_REF")
               and s["effect"] != "Deny"]
    if policy["class"] in ("UNKNOWN", "JOB_WORKFLOW_REF") or unknown:
        why = ((unknown[0].get("evidence") or {}).get("reason") if unknown else policy.get("reason"))
        out.update(status="CANNOT_FIX", reason=f"the trust policy cannot be verified ({why or 'UNKNOWN'}); "
                                               "PipeGuard never rewrites what it cannot evaluate",
                   left=[(f["rule"], f["severity"], f["message"]) for f in old_findings])
        return out
    if not any(f["rule"] in FIX_RULES for f in old_findings):
        out.update(status="NO_FIX_NEEDED", new_class=policy["class"],
                   left=[(f["rule"], f["severity"], f["message"]) for f in old_findings])
        return out
    needed = link["needed"]
    variants = [n["sub"] for n in needed if n["sub"]]
    if ids:
        variants += [linker._immutable(v, owner, repo, ids) for v in list(variants)]
    out["needed_values"] = variants
    out["probes"] = _probe_subs(policy, needed, owner, repo)
    for n in needed:
        jobs = ", ".join(f"{u['job']} in {linker._relative(u['file'], root)}" for u in n["used_by"])
        if n["kind"] == "UNKNOWN":
            out["decisions"].append((None, f"the sub claim of job {jobs} is unknown ({n['note']}): the "
                                           "set of needed values cannot be complete"))
        elif n["pattern"]:
            out["decisions"].append((n["pattern"], f"job {jobs} needs the pattern {n['pattern']} "
                                                   f"({n['note']}): narrow the workflow first (a branch "
                                                   "filter or an environment); PipeGuard never writes a "
                                                   "wildcard"))
    if out["decisions"]:
        out.update(status="NEEDS_DECISION", reason="a needed value is a pattern or unknown")
        return out
    document = policy["document"]
    try:
        res = narrow(document, policy, variants)
    except CannotFix as exc:
        out.update(status="CANNOT_FIX", reason=str(exc))
        return out
    for value in res["refused"]:
        used = next((n for n in needed if n["sub"] == value), None)
        who = (", ".join(f"job {u['job']} in {linker._relative(u['file'], root)}" for u in used["used_by"])
               + f" ({used['note']})") if used else "the immutable form of a needed value (--owner-id / --repo-id)"
        out["decisions"].append((value, f"needed by {who}; not added: {res['reasons'][value]}; adding it "
                                        "would widen access, so the owner decides"))
    out["kept"] = res["kept"]
    if res["document"] is None:
        out.update(status="NEEDS_DECISION", reason="the new policy would accept none of the needed values")
        return out
    new = res["document"]
    new_raw_doc = load_json(json.dumps(new))
    new_policy, new_t_findings = trust_analyzer.analyze_document(
        new_raw_doc, policy["role"], "pipeguard fix", policy["line"], link["trust_file"])
    # Self-check before writing (defence in depth; the tests prove the same property).
    old_raw = _raw_statements(document)
    new_raw = _raw_statements(new_raw_doc)
    checked = 0
    for sub in out["probes"] + variants + res["kept"]:
        for aud in (AUD, "evil"):
            checked += 1
            if request_accepts(new_policy, new_raw, sub, aud) is True and \
                    request_accepts(policy, old_raw, sub, aud) is not True:
                out.update(status="CANNOT_FIX", reason="internal self-check failed (the new policy would "
                                                       "accept a request the old one refuses); nothing "
                                                       "written")
                return out
    out["checked"] = checked
    new_link_findings = []
    linker.analyse_policy(name, needed, {"file": link["trust_file"], "index": link["policy_index"],
                                         "address": link["trust_role"], "policy": new_policy},
                          link["matched_by"], link["account_check"], owner, repo, new_link_findings)
    new_findings = new_t_findings + new_link_findings
    old_keys = sorted((f["rule"], f["severity"]) for f in old_findings)
    new_keys = sorted((f["rule"], f["severity"]) for f in new_findings)
    out.update(status="FIXED", new_class=new_policy["class"], new_document=new,
               resolved=_minus(old_keys, new_keys),
               left=sorted((f["rule"], f["severity"], f["message"]) for f in new_findings),
               statements=(len(res["narrowed"]), len(res["removed"]), len(res["copied"])))
    if ids is None and any(rule == "PG-L02" for rule, _, _ in out["left"]):
        out["notes"].append("the new policy accepts the classic sub format only; if this repository "
                            "uses the immutable format, run again with --owner-id and --repo-id (its "
                            "numeric IDs): the immutable value is added only if the old policy accepts it")
    if ids is None and link["immutable_ids"]:
        out["notes"].append("the old policy names immutable IDs (" + ", ".join(link["immutable_ids"]) +
                            "); pass --owner-id and --repo-id to keep immutable-format values")
    return out


# --------------------------------------------------------------------------- texts

def _decision_text(r):
    lines = [f"PipeGuard: decision needed for role {clean(r['name'])} (account {r['account']})",
             f"Trust policy: {clean(r['trust_file'] or '-')} ({clean(r['trust_role'] or 'JSON policy document')})",
             "",
             "PipeGuard never adds a value the current trust policy does not accept: that would let a",
             "workflow assume the role that cannot assume it today (it would widen access). Only the",
             "owner of the role can decide. PipeGuard never writes a wildcard either.", ""]
    for number, (value, why) in enumerate(r["decisions"], start=1):
        lines.append(f"{number}. {clean(value or 'unknown sub claim')}")
        lines.append(f"   {clean(why)}")
    lines.append("")
    if r["status"] == "FIXED":
        lines.append(f"A new trust policy was written for the values the current policy accepts: "
                     f"{safe_name(r['name'])}.trust.json.")
    else:
        lines.append("No new trust policy was written for this role.")
    return "\n".join(lines) + "\n"


def _summary(plan_result):
    c = clean
    out = [HEADER, f"Repository: {c(plan_result['repo'])}",
           f"Scanned folder: {c(plan_result['path'])} (not modified)", RULE_TEXT]
    for r in plan_result["roles"]:
        out.append("")
        out.append(f"== Role {c(r['name'])} (account {r['account']}): {r['status']}")
        if r["trust_file"]:
            out.append(f"   trust policy: {c(r['trust_file'])} ({c(r['trust_role'] or 'JSON policy document')})")
        if r["reason"]:
            out.append(f"   reason: {c(r['reason'])}")
        if r["status"] == "NO_FIX_NEEDED":
            out.append("   no trust-policy fix needed (no PG-T01..T04, PG-L01 or PG-L09 finding)")
        if r["old_class"]:
            out.append(f"   class: {r['old_class']} -> {r['new_class'] or 'no new policy'}")
        if r["kept"]:
            out.append("   sub values kept: " + ", ".join(c(v) for v in r["kept"]))
        if r["statements"]:
            n, rm, cp = r["statements"]
            out.append(f"   statements: {n} narrowed, {rm} removed (dead or wide), {cp} copied unchanged "
                       "(not GitHub trust, or Deny)")
        if r["resolved"]:
            out.append("   findings resolved: " + ", ".join(f"{a} {b}" for a, b in r["resolved"]))
        for rule, sev, msg in r["left"]:
            out.append(f"   finding left: {rule} {sev}: {c(msg)}")
        if r["checked"]:
            out.append(f"   self-check: {r['checked']} requests (probes and needed values x 2 aud "
                       "values); none is accepted by the new policy and refused by the old one")
        for value, why in r["decisions"]:
            out.append(f"   decision needed: {c(value or 'unknown sub claim')}: {c(why)}")
        for note in r["notes"]:
            out.append(f"   note: {c(note)}")
        out.append("   files: " + (", ".join(sorted(r["files"])) or "none"))
    if plan_result["unlinked"]:
        out.append("")
        out.append("== Trust policies not linked to a workflow (no policy written)")
        for t in plan_result["unlinked"]:
            who = t["role_address"] or "JSON policy document"
            name = f" (name {c(t['role_name'])})" if t["role_name"] else ""
            out.append(f"   {c(t['file'])}:{t['line']} {c(who)}{name}: class {t['policy_class']}; no workflow "
                       "in this repository names it (PG-L04), so who needs it is not known: delete the "
                       "role if it is unused, or narrow it by hand")
    if plan_result["unresolved"]:
        out.append("")
        out.append("== Role ARNs that cannot be read (PG-L05; no policy written)")
        for u in plan_result["unresolved"]:
            out.append(f"   {c(u['file'])}:{u['line']} job {c(u['job'])}: {c(u['raw'])}: the role ARN "
                       "cannot be read from the file, so it cannot be linked or fixed")
    out.append("")
    out.append("== Workflows (only changes that cannot change who can assume a role)")
    for w in plan_result["workflows"]:
        state = "patch " + w["patch"] if w["patch"] else "no patch"
        out.append(f"   {c(w['file'])}: {state}")
        for change in w["changes"]:
            out.append(f"     change: {c(change)}")
        for note in w["notes"]:
            out.append(f"     note: {c(note)}")
        for raw, line, why in w["unpinned"]:
            out.append(f"     unpinned: {c(raw)} (line {line}): {c(why)}")
    if not plan_result["workflows"]:
        out.append("   none analysed")
    other = [f for f in plan_result["other_findings"]]
    if other:
        out.append("")
        out.append("== Findings this command does not change (fix by hand)")
        for f in other:
            where = f"{c(f['file'])}:{f['line']}" if f.get("line") else c(f["file"])
            out.append(f"   [{f['severity']}] {f['rule']} {where}: {c(f['message'])}")
    counts = {k: sum(r["status"] == k for r in plan_result["roles"])
              for k in ("FIXED", "NEEDS_DECISION", "CANNOT_FIX", "NO_FIX_NEEDED")}
    out.append("")
    out.append(f"Summary: {len(plan_result['roles'])} role(s): {counts['FIXED']} fixed, "
               f"{counts['NEEDS_DECISION']} need a decision, {counts['CANNOT_FIX']} cannot be fixed, "
               f"{counts['NO_FIX_NEEDED']} need no fix; "
               f"{sum(1 for w in plan_result['workflows'] if w['patch'])} workflow patch(es).")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- plan and write

def plan(path, repo, owner_id=None, repo_id=None, resolve_pins=False, token=None):
    """Compute every output file in memory (nothing is written). Raises ValueError on bad input."""
    root = Path(path)
    repo = workflow_analyzer.check_repo(repo)
    ids = check_ids(owner_id, repo_id)
    if not root.is_dir():
        raise ValueError("PATH must be a repository folder")
    owner, name = repo.split("/")
    resolver = None
    if resolve_pins:
        token = token or load_token()
        cache, stop = {}, []

        def resolver(o, r, ref):
            key = (o, r, ref)
            if stop:
                return None, "stopped after a rate-limit answer"
            if key not in cache:
                cache[key] = resolve_sha(o, r, ref, token)
                if cache[key][1] in ("HTTP 403", "HTTP 429"):
                    stop.append(True)
            return cache[key]
    result = linker.scan(root, repo, keep_documents=True)
    roles = [_plan_role(r, result, owner, name, ids, root) for r in result["roles"]]
    # File names: sanitised, collisions refused (case-insensitive: Windows and macOS file systems).
    stems = {}
    for r in roles:
        if r["status"] in ("FIXED", "NEEDS_DECISION"):
            stem = safe_name(r["name"])
            stems.setdefault(None if stem is None else stem.lower(), []).append(r)
    for key, group in stems.items():
        if key is None or len(group) > 1:
            for r in group:
                r["notes"].append("no file written: the role name gives an unusable file name or a file "
                                  "name collision with another role")
                r["status"] = "CANNOT_FIX"
                r["reason"] = "file name collision or unusable role name"
            continue
        r = group[0]
        stem = safe_name(r["name"])
        if r["status"] == "FIXED":
            r["files"][f"{stem}.trust.json"] = json.dumps(r["new_document"], indent=2, ensure_ascii=True) + "\n"
            label = "pipeguard_" + re.sub(r"[^A-Za-z0-9_]", "_", r["name"])
            try:
                tf_text = to_tf(r["new_document"], label, r["name"])
                if not same_policy(read_tf_text(tf_text), r["new_document"]):
                    raise _CannotExpress("it does not read back as the same policy")
                r["files"][f"{stem}.tf.txt"] = tf_text
            except (_CannotExpress, CannotFix) as exc:
                r["notes"].append(f"no Terraform text: {exc}; use the JSON file")
        if r["decisions"]:
            r["files"][f"{stem}.NEEDS_DECISION.txt"] = _decision_text(r)
    workflows, patch_names = [], {}
    for f in result["workflow_scan"]["files"]:
        rel = linker._relative(f["file"], root)
        entry = {"file": rel, "patch": None, "changes": [], "notes": [], "unpinned": []}
        workflows.append(entry)
        if f["status"] != "ANALYSED":
            entry["notes"].append(f"not analysed: {f['reason']}")
            continue
        if not patch_path_ok(rel):
            entry["notes"].append("not patched: the file name is not plain ASCII letters, digits, '_', "
                                  "'.', '-' (it would be written into the patch header)")
            continue
        text, problem = _read_text(Path(f["file"]))
        if problem:
            entry["notes"].append(problem)
            continue
        new_text, entry["changes"], entry["notes"], entry["unpinned"] = harden(text, f, rel, repo, resolver)
        if new_text is None:
            continue
        patch = "".join(difflib.unified_diff(text.splitlines(keepends=True),
                                             new_text.splitlines(keepends=True),
                                             f"a/{rel}", f"b/{rel}"))
        stem = safe_name(Path(rel).name) or "workflow"
        patch_names.setdefault(stem.lower(), []).append((entry, f"workflows/{stem}.patch", patch))
    files = {}
    for group in patch_names.values():
        if len(group) > 1:
            for entry, _, _ in group:
                entry["notes"].append("no patch written: file name collision with another workflow")
                entry["changes"] = []
            continue
        entry, name_, patch = group[0]
        entry["patch"] = name_
        files[name_] = patch
    for r in roles:
        files.update(r["files"])
    plan_result = {"repo": repo, "path": root.as_posix(), "roles": roles, "workflows": workflows,
                   "unlinked": [dict(t, file=linker._relative(t["file"], root)) for t in result["unlinked_trust"]],
                   "unresolved": [dict(u, file=linker._relative(u["file"], root)) for u in result["unresolved_roles"]],
                   "other_findings": [dict(f, file=linker._relative(f["file"], root)) for f in result["findings"]
                                      if f["rule"].startswith("PG-W") or f["rule"] == "PG-L07"]}
    files["SUMMARY.txt"] = _summary(plan_result)
    plan_result["files"] = files
    return plan_result


PATCH_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")


def patch_path_ok(rel):
    """Only plain ASCII names without '..' go into a patch header (a newline in a file name would
    let a scanned repository write its own '+++' line: automated security review, 2026-11-27)."""
    return bool(PATCH_PATH_RE.match(rel)) and ".." not in rel.split("/")


def _read_text(path):
    if path.is_symlink():
        return None, "not patched: symlink not followed"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"not patched: cannot read the file ({type(exc).__name__})"
    if len(raw) > config.MAX_FILE_BYTES:
        return None, "not patched: file too large"
    try:
        return raw.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, "not patched: not valid UTF-8"


def check_out_dir(path, out):
    """Refuse an output folder that is, contains or is inside the scanned folder, or a symlink."""
    scanned, target = Path(path).resolve(), Path(out).resolve()
    if target == scanned or scanned in target.parents or target in scanned.parents:
        raise FixRefused("the output folder must not overlap the scanned folder (same folder, inside it, "
                         "or containing it): PipeGuard never writes into what it scans")
    if Path(out).is_symlink():
        raise FixRefused("the output folder is a symlink; not followed")
    if Path(out).exists() and not Path(out).is_dir():
        raise FixRefused("the output path exists and is not a folder")


def write(plan_result, path, out, force=False):
    """Write every planned file under `out`. All targets are checked before the first write, so a
    refusal leaves nothing half-written. Symlinks are refused even with --force."""
    check_out_dir(path, out)
    out = Path(out)
    targets = []
    for rel in sorted(plan_result["files"]):
        target = out / rel
        if target.is_symlink() or (target.parent != out and target.parent.is_symlink()):
            raise FixRefused(f"{rel} is a symlink in the output folder; not followed")
        if target.exists() and (not force or not target.is_file()):
            raise FixRefused(f"{rel} exists in the output folder; use --force to overwrite (files only)")
        targets.append((target, plan_result["files"][rel]))
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for target, text in targets:
        target.parent.mkdir(exist_ok=True)
        if target.parent.is_symlink():
            raise FixRefused("the workflows folder in the output folder is a symlink; not followed")
        try:
            with open(target, "w" if force else "x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except FileExistsError:
            raise FixRefused(f"{target.name} appeared in the output folder while writing") from None
        written.append(target.relative_to(out).as_posix())
    return written
