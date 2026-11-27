"""Trust side: IAM trust policies in JSON and Terraform, sub-condition classification (Phase 2).

For every role (or policy file) it answers: WHO CAN ASSUME IT through GitHub's OIDC provider.
Static only: it never calls AWS. Every semantics rule is cited in DECISIONS D7; the severities
are the model D8, accepted by the student in D9.

How a policy is read (AWS rules, D7):
- Only Allow statements whose Principal.Federated names token.actions.githubusercontent.com and
  whose Action covers sts:AssumeRoleWithWebIdentity are "GitHub trust statements".
- Any matching Allow statement lets the request in (union): the widest class is reported.
  Deny statements are recorded but never used to lower the class (conservative).
- Inside a statement, operators and keys are AND, several values of one key are OR.
- Condition key names are case-insensitive. StringLike: * = any sequence, ? = one character,
  full-string, case-sensitive. Negated operators do not restrict to an allowed set.

How a sub value is classified (decided by meaning, with "attacker probes" as evidence):
the literal prefix of the pattern (the text before the first wildcard) must fix the owner
("repo:OWNER/"), then the repository ("repo:OWNER/REPO:"), then the context type. Whatever is
not fixed by that prefix can be chosen by somebody else. For each class a concrete sub that an
outsider could produce is built and tested with the same IAM glob; it is reported as evidence.
"""

import os
import re
from pathlib import Path
from urllib.parse import unquote

from pipeguard import config, tf_reader
from pipeguard.json_reader import JsonRejected, load_json
from pipeguard.output import clean
from pipeguard.safe_yaml import YMap, YSeq
from pipeguard.tf_reader import Unresolved

SCHEMA = "pipeguard.trust_scan/1"
GITHUB_HOST = "token.actions.githubusercontent.com"
KEY_PREFIX = GITHUB_HOST + ":"
WEB_IDENTITY = "sts:AssumeRoleWithWebIdentity"
SKIP_FOLDERS = {".git", ".terraform", "node_modules"}
NOTE = ("Only JSON and Terraform files are read. CloudFormation templates and trust policies that "
        "exist only in AWS (console, API) are not read: a role whose trust policy is not in these "
        "files is \"trust side not found\", never safe (DECISIONS D7).")

POSITIVE = {"StringEquals", "StringLike", "StringEqualsIgnoreCase"}
NEGATED = {"StringNotEquals", "StringNotLike", "StringNotEqualsIgnoreCase"}
OPERATOR_RE = re.compile(r"^(?:(ForAnyValue|ForAllValues):)?([A-Za-z]+?)(IfExists)?$")

CLASS_RANK = {"EXACT": 0, "BRANCH_PATTERN": 1, "ANY_REF": 2, "ORG_WILDCARD": 3, "ANY_REPO": 4,
              "MISSING": 5}
CRITICAL_CLASSES = ("MISSING", "ANY_REPO")
SEVERITY = {"PG-T00": "UNKNOWN", "PG-T01": "CRITICAL", "PG-T02": "HIGH", "PG-T03": "MEDIUM",
            "PG-T04": "LOW"}
SEVERITY_RANK = {"UNKNOWN": 0, "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
DENY_NOTE = " (a Deny statement may narrow this; not evaluated)"
CONTEXT_PREFIXES = (("ref:refs/heads/", "BRANCH"), ("ref:refs/tags/", "TAG"),
                    ("environment:", "ENVIRONMENT"))
OUTSIDER_SUB = "repo:evil-org/evil-repo:ref:refs/heads/main"


# --------------------------------------------------------------------------- IAM glob

def glob_match(pattern, value, ignore_case=False):
    """IAM StringLike: * = any sequence (also empty, '/' and ':'), ? = one character, whole string.

    Whether * matches '/' and ':' and the empty string is not stated on the AWS page (D7); the
    wider reading is used because it can only report more, never hide a match."""
    # Two-pointer wildcard matcher (no regex): on a mismatch it backtracks only to the last '*',
    # so the work is at most len(pattern) * len(value) steps. A regex built from an untrusted
    # pattern such as '*a*a*a...b' can take super-linear time (security review 2026-11-26).
    if ignore_case:
        pattern, value = pattern.lower(), value.lower()
    p = v = 0
    star, mark = -1, 0
    while v < len(value):
        if p < len(pattern) and pattern[p] != "*" and (pattern[p] == "?" or pattern[p] == value[v]):
            p += 1
            v += 1
        elif p < len(pattern) and pattern[p] == "*":
            star, mark = p, v
            p += 1
        elif star >= 0:
            p = star + 1
            mark += 1
            v = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


# --------------------------------------------------------------------------- one sub value

def _exact_context(ctx):
    for prefix, label in CONTEXT_PREFIXES:
        if ctx.startswith(prefix):
            return label
    return "PULL_REQUEST" if ctx == "pull_request" else "OTHER"


def classify_value(value, operator):
    """Classify one sub value under one operator (a base operator name such as StringLike)."""
    value = str(value)
    base = operator.split(":")[-1].replace("IfExists", "")
    wildcard = base == "StringLike"
    ignore_case = base.endswith("IgnoreCase")
    result = {"class": None, "context": None, "pattern": value, "probe": None, "probe_kind": None,
              "note": None}
    if "${" in value:
        result.update({"class": "UNKNOWN", "note": "IAM policy variable ${...} in the value is not "
                                                    "resolved"})
        return result
    text = value.lower() if ignore_case else value
    has_wild = wildcard and any(c in text for c in "*?")
    lit = text[: min([i for i in (text.find("*"), text.find("?")) if i >= 0] or [len(text)])] \
        if wildcard else text
    if not lit.startswith("repo:"):
        if has_wild and "repo:".startswith(lit):
            cls = "ANY_REPO"
        else:
            result.update({"class": "UNKNOWN", "note": "not the default sub format (customised "
                                                       "sub template?); not classified"})
            return result
    else:
        rest = lit[len("repo:"):]
        if "/" not in rest:
            cls = "ANY_REPO" if has_wild else "EXACT"
            context = None if has_wild else "OTHER"
        else:
            after = rest[rest.index("/") + 1:]
            if ":" not in after:
                cls = "ORG_WILDCARD" if has_wild else "EXACT"
                context = None if has_wild else "OTHER"
            else:
                ctx_lit = after[after.index(":") + 1:]
                if not has_wild:
                    cls, context = "EXACT", _exact_context(ctx_lit)
                else:
                    cls = "ANY_REF"
                    full_ctx = text[len(lit) - len(ctx_lit):]
                    for prefix, _ in CONTEXT_PREFIXES:
                        if ctx_lit.startswith(prefix):
                            name = full_ctx[len(prefix):]
                            # A name made only of wildcards ('*', '?*', ...) fixes nothing:
                            # any branch / tag / environment (security review 2026-11-26).
                            cls = "ANY_REF" if set(name) <= {"*", "?"} else "BRANCH_PATTERN"
                    context = None
        result["context"] = context
    result["class"] = cls
    if cls != "EXACT":
        probe = _probe(text, cls, ignore_case)
        if probe is None:
            # Our reasoning and the glob disagree: never guess, report UNKNOWN.
            result.update({"class": "UNKNOWN", "note": "no outsider probe matched the pattern"})
            return result
        result["probe_kind"], result["probe"] = probe
    if ignore_case:
        result["note"] = ("IgnoreCase: an owner or repository name in other letter case also "
                          "matches; whether GitHub names are case-insensitive is not verified")
    return result


def _pieces(text):
    """Owner, repository and context literals of a pattern (wildcards cut off), for probes."""
    body = text[len("repo:"):] if text.startswith("repo:") else ""
    owner, _, rest = body.partition("/")
    repo, _, ctx = rest.partition(":")
    cut = lambda s: re.split(r"[*?]", s, maxsplit=1)[0]
    return cut(owner), cut(repo), ctx


def _complete_id(piece, filler="999999999"):
    """'site@' (the ID was cut off at a wildcard) -> 'site@999999999': a probe is a real-looking
    sub, so an ID part is never empty (D9, reviewer's Phase 2 check)."""
    name, at, ident = piece.partition("@")
    return f"{name}@{ident or filler}" if at else piece


def _probe(pattern, cls, ignore_case):
    """A concrete sub an outsider could produce that matches `pattern`, for class `cls`."""
    owner, cut_repo, ctx = _pieces(pattern)
    owner_name = owner.split("@")[0] or "acme"
    repo = _complete_id(cut_repo or "evil-repo", "999999998")
    repo_name = repo.split("@")[0]
    ctx_lit = re.split(r"[*?]", ctx, maxsplit=1)[0]
    tail = ctx if ctx and not any(c in ctx for c in "*?") else "ref:refs/heads/main"
    # Immutable format (NAME@ID): when the pattern has '@' in a piece, the "same name, other ID"
    # probe comes first, because that is what a wildcard in the ID part gives away (D6.3).
    # IDs are numeric; when the pattern fixes only the first digits of an ID ('acme@12*'), the
    # probe extends them with more digits: a different ID, i.e. a different account (D9).
    owner_id = [("owner name re-registered with another ID",
                 f"repo:{owner_name}@999999999/{repo}:{tail}")] if "@" in owner else []
    if "@" in owner and owner.split("@", 1)[1]:
        owner_id.append(("another owner ID with the same leading digits",
                         f"repo:{owner}99999/{repo}:{tail}"))
    owner = _complete_id(owner)
    repo_id = [("repository re-created with another ID",
                f"repo:{owner}/{repo_name}@999999999:{tail}")] if "@" in repo else []
    if "@" in cut_repo and cut_repo.split("@", 1)[1]:
        repo_id.append(("another repository ID with the same leading digits",
                        f"repo:{owner}/{repo}99999:{tail}"))
    candidates = {
        "ANY_REPO": owner_id + [
            ("any repository", OUTSIDER_SUB),
            ("any owner, same repository name", f"repo:evil-org/{repo}:{tail}"),
            ("owner name with a suffix", f"repo:{owner}-evil/evil-repo:ref:refs/heads/main"),
            ("owner name with a suffix", f"repo:{owner}-evil/{repo}:{tail}"),
        ],
        "ORG_WILDCARD": repo_id + [
            ("other repository of the same owner", f"repo:{owner}/evil-repo:ref:refs/heads/main"),
            ("other repository of the same owner", f"repo:{owner}/evil-repo:{tail}"),
            ("repository name with a suffix", f"repo:{owner}/{repo}-evil:{tail}"),
        ],
        "ANY_REF": [
            ("pull request", f"repo:{owner}/{repo}:pull_request"),
            ("other branch", f"repo:{owner}/{repo}:ref:refs/heads/evil-branch"),
            ("other tag", f"repo:{owner}/{repo}:ref:refs/tags/evil-tag"),
            ("other environment", f"repo:{owner}/{repo}:environment:evil-env"),
        ],
        "BRANCH_PATTERN": [
            ("branch name with a suffix", f"repo:{owner}/{repo}:{ctx_lit}evil"),
        ],
    }[cls]
    for kind, sub in candidates:
        if glob_match(pattern, sub, ignore_case):
            return kind, sub
    built = pattern.replace("*", "evil").replace("?", "x")
    if glob_match(pattern, built, ignore_case):
        return "a sub built from the pattern", built
    return None


# --------------------------------------------------------------------------- statements

def _as_list(value):
    if isinstance(value, list):
        return list(value)
    return [value]


def _text(value):
    return value.text if isinstance(value, Unresolved) and value.text else (
        f"<{value.reason}>" if isinstance(value, Unresolved) else str(value))


def _covers_web_identity(action):
    """True / False / Unresolved for an Action value (wildcards, case-insensitive: D7)."""
    for item in _as_list(action):
        if isinstance(item, Unresolved):
            return item
        if item is not None and glob_match(str(item), WEB_IDENTITY, ignore_case=True):
            return True
    return False


def _principal_facts(principal):
    """(principal summary, github: True/False/'UNKNOWN', note)."""
    if principal is None:
        return {}, False, None
    if isinstance(principal, str):
        return {"*": [str(principal)]}, ("UNKNOWN" if principal == "*" else False), \
            "wildcard principal" if principal == "*" else None
    if isinstance(principal, Unresolved):
        return {"?": [_text(principal)]}, "UNKNOWN", f"principal not resolvable: {principal.reason}"
    if not isinstance(principal, dict):
        return {}, "UNKNOWN", "principal is not readable"
    summary, github, note = {}, False, None
    for ptype, values in principal.items():
        items = _as_list(values)
        summary[str(ptype)] = [_text(v) for v in items]
        for item in items:
            if str(ptype) == "Federated" and isinstance(item, Unresolved):
                text = (item.text or "").lower()
                if text.endswith("oidc-provider/" + GITHUB_HOST):
                    github = True
                elif github is not True:
                    github, note = "UNKNOWN", f"Federated principal not resolvable: {item.reason}"
            elif str(item) == "*":
                github, note = "UNKNOWN", "wildcard principal"
            elif str(ptype) == "Federated" and str(item).lower().endswith("oidc-provider/" + GITHUB_HOST):
                github = True
    return summary, github, note


def _parse_condition(condition):
    """-> (constraints by claim, other keys, problem). Keys are matched case-insensitively."""
    claims = {"sub": [], "aud": [], "job_workflow_ref": []}
    other = []
    if condition is None:
        return claims, other, None
    if not isinstance(condition, dict):
        return claims, other, "Condition is not readable"
    for operator, block in condition.items():
        if isinstance(block, Unresolved) or not isinstance(block, dict):
            return claims, other, f"condition {operator} is not readable"
        m = OPERATOR_RE.match(str(operator))
        qualifier, base, if_exists = (m.group(1), m.group(2), m.group(3)) if m else (None, None, None)
        for key, values in block.items():
            name = str(key).lower()
            if not name.startswith(KEY_PREFIX):
                other.append(str(key))
                continue
            claim = name[len(KEY_PREFIX):]
            key_line = block.key_lines.get(key) if isinstance(block, YMap) else None
            record = {"operator": str(operator), "base": base, "qualifier": qualifier,
                      "if_exists": bool(if_exists), "values": _as_list(values),
                      "line": _value_line(values) or key_line}
            if claim in claims:
                claims[claim].append(record)
            else:
                other.append(str(key))
    return claims, other, None


def _value_line(values):
    for item in _as_list(values):
        if getattr(item, "line", None):
            return item.line
    return None


def _is_known(base):
    return base in POSITIVE or base in NEGATED or base == "Null"


def _classify_sub(claims, notes):
    """Statement class from its sub / job_workflow_ref constraints, plus the evidence."""
    subs = claims["sub"]
    for record in subs + claims["job_workflow_ref"]:
        if not _is_known(record["base"]):
            return "UNKNOWN", {"reason": f"operator {record['operator']} on a GitHub claim is not "
                                         "evaluated"}, record
    for record in subs:
        if record["qualifier"]:
            notes.append(f"{record['qualifier']}: AWS warns against set operators on single-valued "
                         "keys; classified like the base operator")
        if record["if_exists"]:
            notes.append(f"{record['operator']}: IfExists is true when the key is absent; GitHub "
                         "tokens are assumed to carry sub (not verified)")
        if record["base"] in NEGATED:
            notes.append(f"{record['operator']} is a negated operator: it excludes values but "
                         "does not restrict sub to an allowed set")
    nulls = [r for r in subs if r["base"] == "Null"]
    for record in nulls:
        if any(str(v).lower() == "true" for v in record["values"]):
            return "UNKNOWN", {"reason": "Null: true on sub requires a token without sub; whether "
                                         "GitHub ever sends one is not verified"}, record
    positive = [r for r in subs if r["base"] in POSITIVE]
    if not positive:
        if any(r["base"] in POSITIVE for r in claims["job_workflow_ref"]):
            jwr = next(r for r in claims["job_workflow_ref"] if r["base"] in POSITIVE)
            return "JOB_WORKFLOW_REF", {"reason": "only job_workflow_ref is checked"}, jwr
        return "MISSING", {"probe": OUTSIDER_SUB, "probe_kind": "any repository (no sub condition)",
                           "pattern": None}, None
    # AND of constraints: the narrowest known one bounds the statement (conservative).
    best = None
    for record in positive:
        outcome = _classify_constraint(record)
        if outcome[0] == "UNKNOWN":
            continue
        if best is None or CLASS_RANK[outcome[0]] < CLASS_RANK[best[0]]:
            best = outcome + (record,)
    if best is None:
        outcome = _classify_constraint(positive[0])
        return "UNKNOWN", outcome[1], positive[0]
    return best[0], best[1], best[2]


def _classify_constraint(record):
    """OR over the values of one constraint: the widest value decides."""
    widest, unknown = None, None
    for value in record["values"]:
        if isinstance(value, Unresolved):
            unknown = {"reason": f"sub value not resolvable: {value.reason}",
                       "pattern": _text(value)}
            continue
        if value is None:
            unknown = {"reason": "sub value is null", "pattern": None}
            continue
        if isinstance(value, (dict, list)):
            unknown = {"reason": "sub value is not a string", "pattern": None}
            continue
        out = classify_value(value, record["base"])
        out["line"] = getattr(value, "line", None) or record["line"]
        if out["class"] == "UNKNOWN":
            unknown = {"reason": out["note"], "pattern": str(value), "line": out["line"]}
            continue
        if widest is None or CLASS_RANK[out["class"]] > CLASS_RANK[widest["class"]]:
            widest = out
    if unknown and (widest is None or CLASS_RANK[widest["class"]] < CLASS_RANK["ANY_REPO"]):
        return "UNKNOWN", unknown
    if widest is None:
        return "UNKNOWN", {"reason": "no sub value", "pattern": None}
    return widest["class"], widest


def _aud_state(claims):
    records = claims["aud"]
    if any(isinstance(v, Unresolved) for r in records for v in r["values"]):
        return "UNKNOWN"
    if any(r["base"] in POSITIVE for r in records):
        return "CHECKED"
    if any(not _is_known(r["base"]) for r in records):
        return "UNKNOWN"
    return "NOT_CHECKED"


def analyze_statement(statement, index):
    """Facts for one statement. `class` is None for statements that are not GitHub trust."""
    out = {"index": index, "sid": None, "line": getattr(statement, "line", None), "effect": None,
           "principal": {}, "github": False, "web_identity": None, "class": None, "context": [],
           "sub": [], "job_workflow_ref": [], "aud": None, "other_condition_keys": [],
           "evidence": None, "evidence_line": None, "notes": []}
    if not isinstance(statement, dict):
        out.update({"class": "UNKNOWN", "github": "UNKNOWN",
                    "evidence": {"reason": "statement is not an object"}})
        return out
    sid = statement.get("Sid")
    out["sid"] = None if sid is None else _text(sid)
    effect = statement.get("Effect")
    out["effect"] = None if effect is None else _text(effect)
    summary, github, note = _principal_facts(statement.get("Principal"))
    out["principal"] = summary
    claims, other, problem = _parse_condition(statement.get("Condition"))
    out["other_condition_keys"] = other
    # A Federated principal that cannot be resolved but conditions on GitHub claims is treated as
    # GitHub (inferred), so its sub is still classified.
    has_github_keys = any(claims[c] for c in claims)
    wildcard = any("*" == v for values in summary.values() for v in values)
    if github == "UNKNOWN" and has_github_keys and "Federated" in summary and not wildcard:
        github = True
        out["notes"].append("GitHub trust inferred from the token.actions.githubusercontent.com "
                            f"condition keys ({note})")
        note = None
    out["github"] = github
    if note:
        out["notes"].append(note)
    for element in ("NotPrincipal", "NotAction"):
        if element in statement and str(effect) == "Allow":
            out.update({"class": "UNKNOWN", "github": "UNKNOWN",
                        "evidence": {"reason": f"{element} in an Allow statement is not evaluated"}})
            return out
    unknown_case = [k for k in statement if str(k).lower() in
                    ("effect", "principal", "action", "condition") and
                    str(k) not in ("Effect", "Principal", "Action", "Condition")]
    if unknown_case:
        out.update({"class": "UNKNOWN", "github": "UNKNOWN",
                    "evidence": {"reason": f"element {unknown_case[0]} is not spelt as AWS defines it"}})
        return out
    covers = _covers_web_identity(statement.get("Action"))
    if isinstance(covers, Unresolved):
        out.update({"class": "UNKNOWN", "evidence": {"reason": f"Action not resolvable: {covers.reason}"}})
        return out
    out["web_identity"] = covers
    if github is False or not covers:
        return out  # not a GitHub trust statement: recorded, not classified
    if effect is None or isinstance(effect, Unresolved) or str(effect) not in ("Allow", "Deny"):
        out.update({"class": "UNKNOWN", "evidence": {"reason": f"Effect {out['effect']!r} is not "
                                                               "Allow or Deny"}})
        return out
    if github == "UNKNOWN":
        out.update({"class": "UNKNOWN", "evidence": {"reason": "the principal may include GitHub's "
                                                               "OIDC provider; not verifiable"}})
        return out
    if problem:
        out.update({"class": "UNKNOWN", "evidence": {"reason": problem}})
        return out
    out["sub"] = [{"operator": r["operator"], "values": [_text(v) for v in r["values"]],
                   "line": r["line"]} for r in claims["sub"]]
    out["job_workflow_ref"] = [{"operator": r["operator"], "values": [_text(v) for v in r["values"]]}
                               for r in claims["job_workflow_ref"]]
    out["aud"] = _aud_state(claims)
    if other:
        out["notes"].append("other condition keys are not evaluated (they can only narrow): "
                            + ", ".join(other))
    if str(effect) == "Deny":
        return out  # recorded; never used to lower the class
    cls, evidence, record = _classify_sub(claims, out["notes"])
    out["class"] = cls
    if isinstance(evidence, dict) and evidence.get("note"):
        out["notes"].append(evidence["note"])
    out["evidence"] = {k: evidence.get(k) for k in ("pattern", "probe", "probe_kind", "reason")
                       if evidence.get(k) is not None} if isinstance(evidence, dict) else None
    out["evidence_line"] = (evidence.get("line") if isinstance(evidence, dict) else None) or \
        (record["line"] if record else None) or out["line"]
    if cls == "EXACT":
        out["context"] = sorted({c for r in claims["sub"] if r["base"] in POSITIVE
                                 for c in [classify_value(v, r["base"])["context"]
                                           for v in r["values"] if isinstance(v, str)] if c})
    return out


# --------------------------------------------------------------------------- policies

def _policy_class(statements):
    github_allow = [s for s in statements if s["class"] is not None and s["effect"] != "Deny"]
    classes = [s["class"] for s in github_allow]
    critical = [c for c in classes if c in CRITICAL_CLASSES]
    if critical:
        return max(critical, key=CLASS_RANK.get)
    if "UNKNOWN" in classes:
        return "UNKNOWN"
    if "JOB_WORKFLOW_REF" in classes:
        return "JOB_WORKFLOW_REF"
    known = [c for c in classes if c in CLASS_RANK]
    return max(known, key=CLASS_RANK.get) if known else "NO_GITHUB_TRUST"


def analyze_document(doc, role, source, line, file, notes=None, keep_document=False):
    """Facts and findings for one trust policy document (a YMap) or an Unresolved value.

    keep_document (Phase 4 fixer): also return the evaluated document itself under "document"
    (not JSON-serialisable when it holds Unresolved values; never part of the scan output)."""
    policy = {"role": role, "source": source, "line": line, "status": "ANALYSED", "reason": None,
              "class": None, "aud": None, "deny_statements": 0, "statements": [],
              "notes": list(notes or [])}
    if keep_document:
        policy["document"] = doc
    findings = []
    role_label = role.get("address") or role.get("name")

    def unknown(reason, at_line):
        policy.update({"status": "UNKNOWN", "reason": reason, "class": "UNKNOWN"})
        findings.append(_finding("PG-T00", file, role_label, None, at_line,
                                 f"The trust policy cannot be verified: {reason}.", "UNKNOWN"))
        return policy, findings

    if isinstance(doc, Unresolved):
        return unknown(doc.reason, doc.line or line)
    if not isinstance(doc, dict):
        return unknown("the policy is not a JSON object", line)
    keys = {str(k).lower(): k for k in doc}
    if "Statement" not in doc:
        if "statement" in keys:
            return unknown(f"element {keys['statement']} is not spelt as AWS defines it (Statement)", line)
        return unknown("the policy has no Statement", line)
    raw_statements = doc["Statement"]
    if isinstance(raw_statements, Unresolved):
        return unknown(raw_statements.reason, raw_statements.line or line)
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        return unknown("Statement is not a list or an object", line)
    statements = [analyze_statement(s, i) for i, s in enumerate(raw_statements, start=1)]
    policy["statements"] = statements
    policy["deny_statements"] = sum(1 for s in statements if s["effect"] == "Deny")
    policy["class"] = _policy_class(statements)
    github_allow = [s for s in statements if s["class"] is not None and s["effect"] != "Deny"]
    auds = [s["aud"] for s in github_allow if s["aud"] is not None]
    policy["aud"] = ("UNKNOWN" if "UNKNOWN" in auds else "NOT_CHECKED" if "NOT_CHECKED" in auds
                     else "CHECKED" if auds else None)
    deny = DENY_NOTE if policy["deny_statements"] else ""
    for s in github_allow:
        findings += _statement_findings(s, file, role_label, deny)
    return policy, findings


def _statement_label(s):
    return f"#{s['index']}" + (f" {s['sid']}" if s["sid"] else "")


def _statement_findings(s, file, role, deny):
    ev = s["evidence"] or {}
    at = s.get("evidence_line") or s["line"]
    label = _statement_label(s)
    pattern, probe, kind = ev.get("pattern"), ev.get("probe"), ev.get("probe_kind")
    seen = f"probe '{probe}' ({kind}) matches" if probe else ""
    out = []
    cls = s["class"]
    if cls == "MISSING":
        out.append(_finding("PG-T01", file, role, label, at,
                            "No sub condition: a workflow in any repository on github.com can "
                            f"assume this role; probe '{probe}' matches{deny}.", cls, pattern,
                            probe, kind))
    elif cls == "ANY_REPO":
        out.append(_finding("PG-T01", file, role, label, at,
                            f"sub pattern '{pattern}' lets a repository outside the owner's "
                            f"control assume this role: {seen}{deny}.", cls, pattern, probe, kind))
    elif cls == "ORG_WILDCARD":
        out.append(_finding("PG-T02", file, role, label, at,
                            f"sub pattern '{pattern}' lets other repositories of the same owner "
                            f"assume this role: {seen}{deny}.", cls, pattern, probe, kind))
    elif cls == "ANY_REF":
        out.append(_finding("PG-T03", file, role, label, at,
                            f"sub pattern '{pattern}' accepts any branch, tag, environment or pull "
                            f"request of the repository: {seen}{deny}.", cls, pattern, probe, kind))
    elif cls == "BRANCH_PATTERN":
        out.append(_finding("PG-T04", file, role, label, at,
                            f"sub pattern '{pattern}' accepts every branch, tag or environment "
                            f"whose name matches: {seen}{deny}.", cls, pattern, probe, kind))
    elif cls == "EXACT" and "PULL_REQUEST" in s["context"]:
        out.append(_finding("PG-T03", file, role, label, at,
                            "sub accepts the pull_request context: every pull request of the "
                            "repository gets the role (whether pull requests from forks get a "
                            f"token is not verified){deny}.", cls,
                            next((v for sub in s["sub"] for v in sub["values"]
                                  if v.endswith(":pull_request")), None), None, None))
    elif cls == "JOB_WORKFLOW_REF":
        out.append(_finding("PG-T00", file, role, label, at,
                            "Only job_workflow_ref is checked (AWS accepts sub or job_workflow_ref): "
                            "who can call that reusable workflow is not visible here; cannot "
                            f"verify{deny}.", cls, ev.get("pattern"), None, None))
    elif cls == "UNKNOWN":
        out.append(_finding("PG-T00", file, role, label, at,
                            f"Cannot verify who can assume this role: {ev.get('reason', 'unknown')}"
                            f"{deny}.", cls, ev.get("pattern"), None, None))
    if s["aud"] == "NOT_CHECKED":
        out.append(_finding("PG-T04", file, role, label, s["line"],
                            "aud is not checked; a workflow can choose its audience (GitHub OIDC "
                            "reference), so this is hygiene and does not change the sub class.",
                            cls, None, None, None))
    return out


def _finding(rule, file, role, statement, line, message, cls=None, pattern=None, probe=None,
             probe_kind=None):
    return {"rule": rule, "severity": SEVERITY[rule], "file": file, "role": role,
            "statement": statement, "line": line, "class": cls, "pattern": pattern,
            "probe": probe, "probe_kind": probe_kind, "message": message}


def _sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["file"], f["line"] or 0,
                                           f["rule"]))


# --------------------------------------------------------------------------- JSON files

def _file_result(file, kind, status="ANALYSED", reason=None):
    return {"file": file, "kind": kind, "status": status, "reason": reason, "policies": [],
            "findings": []}


def _rejected(file, kind, reason, line=None):
    result = _file_result(file, kind, "REJECTED", reason)
    result["findings"] = [_finding("PG-T00", file, None, None, line,
                                   f"File not analysed: {reason}.", "UNKNOWN")]
    return result


def _json_documents(doc):
    """(role name, policy document) pairs found in a JSON value; [] if it is not a policy."""
    if isinstance(doc, YMap):
        lower = {str(k).lower() for k in doc}
        if "statement" in lower:
            return [(None, doc)]
        if "AssumeRolePolicyDocument" in doc:
            return [(doc.get("RoleName"), _decode_document(doc["AssumeRolePolicyDocument"]))]
        if isinstance(doc.get("Role"), YMap) and "AssumeRolePolicyDocument" in doc["Role"]:
            role = doc["Role"]
            return [(role.get("RoleName"), _decode_document(role["AssumeRolePolicyDocument"]))]
        if isinstance(doc.get("Roles"), YSeq):
            return [pair for item in doc["Roles"] for pair in _json_documents(item)]
    return []


def _decode_document(value):
    """AssumeRolePolicyDocument may be an object or a (URL-encoded) JSON string."""
    if isinstance(value, YMap):
        return value
    if isinstance(value, str):
        for text in (str(value), unquote(str(value))):
            try:
                return load_json(text)
            except JsonRejected:
                continue
        return Unresolved("AssumeRolePolicyDocument string is not valid JSON",
                          getattr(value, "line", None))
    return Unresolved("AssumeRolePolicyDocument is not a policy", None)


def analyze_json_text(text, display_path="<text>", keep_documents=False):
    try:
        doc = load_json(text)
    except JsonRejected as exc:
        return _rejected(display_path, "json", exc.reason, exc.line)
    pairs = _json_documents(doc)
    if not pairs:
        return _file_result(display_path, "json", "NOT_A_POLICY",
                            "no Statement, AssumeRolePolicyDocument or Role in this JSON file")
    result = _file_result(display_path, "json")
    for name, document in pairs:
        role = {"address": None, "name": None if name is None else str(name), "line": None}
        policy, findings = analyze_document(document, role, "json",
                                            getattr(document, "line", None), display_path,
                                            keep_document=keep_documents)
        result["policies"].append(policy)
        result["findings"] += findings
    result["findings"] = _sort_findings(result["findings"])
    return result


def _read(path, display):
    """Read a file with the size limit; return (text, None) or (None, rejected result)."""
    kind = "terraform" if path.suffix.lower() == ".tf" else "json"
    if path.is_symlink():
        return None, _rejected(display, kind, "symlink not followed (it could point outside the "
                                              "scanned folder)")
    try:
        size = path.stat().st_size
        if size > config.MAX_FILE_BYTES:
            return None, _rejected(display, kind, f"file too large ({size} bytes, limit "
                                                  f"{config.MAX_FILE_BYTES})")
        with path.open("rb") as handle:
            raw = handle.read(config.MAX_FILE_BYTES + 1)
    except OSError as exc:
        return None, _rejected(display, kind, f"cannot read the file ({type(exc).__name__})")
    if len(raw) > config.MAX_FILE_BYTES:
        return None, _rejected(display, kind, f"file too large (limit {config.MAX_FILE_BYTES} bytes)")
    try:
        return raw.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, _rejected(display, kind, "not valid UTF-8 text")


def analyze_file(path, display_path=None, root=None, keep_documents=False):
    """One JSON or Terraform file (a Terraform file is read alone: no other file of its folder)."""
    path = Path(path)
    display = display_path or path.as_posix()
    text, rejected = _read(path, display)
    if rejected:
        return rejected
    if path.suffix.lower() == ".tf":
        return _terraform_results([(path, display, text)], root or path.parent, keep_documents)[display]
    return analyze_json_text(text, display, keep_documents)


# --------------------------------------------------------------------------- Terraform

def _terraform_results(files, root, keep_documents=False):
    raw = tf_reader.read_module(files, root)
    out = {}
    for display, item in raw.items():
        if item["status"] == "REJECTED":
            out[display] = _rejected(display, "terraform", item["reason"], item["line"])
            out[display]["modules_not_followed"] = []
            continue
        result = _file_result(display, "terraform", item["status"], item["reason"])
        result["modules_not_followed"] = item["modules_not_followed"]
        for entry in item["items"]:
            policy, findings = analyze_document(entry["value"], entry["role"], entry["source"],
                                                entry["line"], display, entry["notes"],
                                                keep_document=keep_documents)
            result["policies"].append(policy)
            result["findings"] += findings
        result["findings"] = _sort_findings(result["findings"])
        out[display] = result
    return out


# --------------------------------------------------------------------------- scan

def collect_files(path):
    """(files, skipped folder names). Recursive; symlinked folders are not followed."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        raise FileNotFoundError(str(path))
    if not path.is_dir():
        return [path], []
    files, skipped = [], []
    for current, dirs, names in os.walk(path):
        for name in sorted(dirs):
            if name in SKIP_FOLDERS:
                skipped.append(name)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_FOLDERS)
        for name in sorted(names):
            if Path(name).suffix.lower() in (".json", ".tf"):
                files.append(Path(current) / name)
    return files, skipped


def scan(path, repo=None, keep_documents=False):
    """Scan a file or a folder of JSON / Terraform files (keep_documents: see analyze_document)."""
    path = Path(path)
    files, skipped = collect_files(path)
    root = path if path.is_dir() else path.parent
    findings = []
    limit = config.MAX_TRUST_FILES
    if len(files) > limit:
        extra = files[limit:]
        files = files[:limit]
        findings.append(_finding("PG-T00", path.as_posix(), None, None, None,
                                 f"{len(extra)} file(s) not analysed: more than {limit} JSON / "
                                 "Terraform files in one scan.", "UNKNOWN"))
    results = {}
    folders = {}
    for p in files:
        display = p.as_posix()
        if p.suffix.lower() == ".tf":
            text, rejected = _read(p, display)
            if rejected:
                rejected["modules_not_followed"] = []
                results[display] = rejected
            else:
                folders.setdefault(p.parent, []).append((p, display, text))
        else:
            results[display] = analyze_file(p, display, keep_documents=keep_documents)
    for folder_files in folders.values():
        results.update(_terraform_results(folder_files, root, keep_documents))
    ordered = [results[p.as_posix()] for p in files]
    for result in ordered:
        findings += result["findings"]
    findings = _sort_findings(findings)
    summary = {
        "files": len(ordered),
        "analysed": sum(r["status"] == "ANALYSED" for r in ordered),
        "not_a_policy": sum(r["status"] == "NOT_A_POLICY" for r in ordered),
        "rejected": sum(r["status"] == "REJECTED" for r in ordered),
        "findings": {sev: sum(f["severity"] == sev for f in findings) for sev in SEVERITY_RANK},
    }
    return {"schema": SCHEMA, "note": NOTE, "skipped_folders": skipped, "files": ordered,
            "findings": findings, "summary": summary}


# --------------------------------------------------------------------------- text output

def format_text(result):
    """Human-readable report; every scanned string passes through clean()."""
    c = clean
    out = ["PipeGuard trust-policy scan (read-only: nothing was run, no AWS call, no network).",
           f"Note: {NOTE}"]
    if result.get("skipped_folders"):
        out.append("Skipped folders (tool or vendor data): " + ", ".join(c(n) for n in result["skipped_folders"]))
    for res in result["files"]:
        out.append("")
        out.append(f"== {c(res['file'])}  [{res['status']}, {res['kind']}]")
        if res["reason"]:
            out.append(f"   {c(res['reason'])}")
        for mod in res.get("modules_not_followed", []):
            out.append(f"   module {c(mod['name'])} (line {mod['line']}): not followed")
        for pol in res["policies"]:
            role = pol["role"]
            who = role.get("address") or role.get("name") or "role unknown (JSON file)"
            name = f", name {c(role['name'])}" if role.get("name") and role.get("address") else ""
            out.append(f"   policy for {c(who)}{name} (source {c(pol['source'])}, line {pol['line']}): "
                       f"class {pol['class']}, aud {pol['aud'] or '-'}"
                       + (f", {pol['deny_statements']} Deny statement(s)" if pol["deny_statements"] else ""))
            if pol["reason"]:
                out.append(f"     {c(pol['reason'])}")
            for note in pol["notes"]:
                out.append(f"     note: {c(note)}")
            for s in pol["statements"]:
                kind = ("GitHub" if s["github"] is True else
                        "principal unknown" if s["github"] == "UNKNOWN" else "not GitHub")
                cls = s["class"] or "not classified"
                ctx = f" ({', '.join(s['context'])})" if s["context"] else ""
                out.append(f"     statement {c(_statement_label(s))} (line {s['line']}, "
                           f"{c(str(s['effect']))}, {kind}): {cls}{ctx}")
                for sub in s["sub"]:
                    out.append(f"       sub {c(sub['operator'])}: {c(', '.join(sub['values']))}")
                for jwr in s["job_workflow_ref"]:
                    out.append(f"       job_workflow_ref {c(jwr['operator'])}: {c(', '.join(jwr['values']))}")
                ev = s["evidence"] or {}
                if ev.get("probe"):
                    out.append(f"       probe matched ({c(ev['probe_kind'])}): {c(ev['probe'])}")
                for note in s["notes"]:
                    out.append(f"       note: {c(note)}")
    findings = result.get("findings", [])
    out.append("")
    out.append(f"Findings ({len(findings)}; severity model D8, accepted in D9):")
    for f in findings:
        where = f"{c(f['file'])}:{f['line']}" if f["line"] else c(f["file"])
        role = f" role {c(f['role'])}" if f["role"] else ""
        stmt = f" statement {c(f['statement'])}" if f["statement"] else ""
        out.append(f"  [{f['severity']}] {f['rule']} {where}{role}{stmt}: {c(f['message'])}")
    if not findings:
        out.append("  none")
    summary = result.get("summary")
    if summary:
        counts = ", ".join(f"{k} {v}" for k, v in summary["findings"].items())
        out.append("")
        out.append(f"Summary: {summary['files']} file(s): {summary['analysed']} analysed, "
                   f"{summary['not_a_policy']} not a policy, {summary['rejected']} rejected. "
                   f"Findings: {counts}.")
    return "\n".join(out)
