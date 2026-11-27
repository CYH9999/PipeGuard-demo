"""Chain linker: who NEEDS each role (workflows) vs who CAN assume it (trust policy) (Phase 3, D10).

It runs both analyzers on ONE repository folder, joins their facts and reports the gap:

    workflow side (Phase 1)                     trust side (Phase 2)
    role ARN arn:aws:iam::ACCOUNT:role/NAME     Terraform name = "NAME", JSON RoleName, or a
    + the sub claims its jobs present (NEEDED)  .pipeguard.yml mapping  -> GitHub statements (ACCEPTED)
                    \\                                  /
                     match by role NAME (exact), then compare the ACCOUNT
                                       |
          coverage (NEEDED accepted?)  excess (ACCEPTED, not NEEDED)  recommended exact sub set

Rules (DECISIONS D10):
- Matching is by the role NAME, exact and case-sensitive; never fuzzy. A name that differs only in
  letter case is shown as a hint, never linked. The account in the role ARN must equal the account
  of the GitHub OIDC provider in the trust policy; a mismatch is a finding (PG-L06), never a link.
- Acceptance uses the same IAM semantics as Phase 2 (union of Allow statements, AND of operators,
  OR of values, StringLike globs, negated operators). Anything not evaluable is None ("cannot
  tell"), never False-and-safe.
- Excess = probes (outsider, other repository, other context, needed name + suffix) and the literal
  values written in the policy that the policy accepts but no workflow needs. Its widest category
  gives PG-L01's severity. Unknown AND-constraints count as satisfied there (wider reading).
- The recommended sub set only contains exact values the current policy already accepts, so a fix
  built from it can only narrow (security guidance rule 4). It is data for the Phase 4 fixer.

Static only: it reads files; it never calls AWS or GitHub. The mapping file is untrusted input.
"""

import re
from functools import lru_cache
from pathlib import Path

from pipeguard import config, trust_analyzer, workflow_analyzer
from pipeguard.output import clean
from pipeguard.safe_yaml import YamlRejected, YMap, load
from pipeguard.trust_analyzer import NEGATED, OPERATOR_RE, POSITIVE, glob_match

SCHEMA = "pipeguard.link_scan/1"
MAPPING_FILE = ".pipeguard.yml"
SEVERITY_RANK = trust_analyzer.SEVERITY_RANK  # UNKNOWN 0, CRITICAL 1, HIGH 2, MEDIUM 3, LOW 4
RULE_SEVERITY = {"PG-L00": "UNKNOWN", "PG-L02": "LOW", "PG-L03": "UNKNOWN", "PG-L04": "LOW",
                 "PG-L05": "UNKNOWN", "PG-L06": "UNKNOWN", "PG-L07": "MEDIUM", "PG-L08": "UNKNOWN",
                 "PG-L09": "LOW"}
# PG-L01 takes the severity of its widest excess category (D10).
CATEGORY_SEVERITY = {"OUTSIDE_OWNER": "CRITICAL", "OTHER_REPO": "HIGH", "OTHER_CONTEXT": "MEDIUM",
                     "NAME_SUFFIX": "LOW"}
CATEGORY_TEXT = {"OUTSIDE_OWNER": "a repository outside the owner",
                 "OTHER_REPO": "another repository of the owner",
                 "OTHER_CONTEXT": "another branch, tag, environment or pull request",
                 "NAME_SUFFIX": "a name that extends a needed name"}

ROLE_ARN_RE = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):role/((?:[\w+=,.@-]+/)*)([\w+=,.@-]+)$",
                         re.ASCII)
PROVIDER_RE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):oidc-provider/"
                         r"token\.actions\.githubusercontent\.com$", re.IGNORECASE)
ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$", re.ASCII)
SUB_RE = re.compile(r"^repo:([^/:]+)/([^:]+):(.+)$")
CTX_PREFIXES = ("ref:refs/heads/", "ref:refs/tags/", "environment:")
GENERIC_IDS = ("100000001", "100000002")  # an owner/repository ID pair no policy names
IMMUTABLE_TEMPLATE_IDS = ("<OWNER-ID>", "<REPO-ID>")
IMMUTABLE_NOTE = ("repositories created after 2026-07-15 (or opted in) send the immutable format "
                  "repo:OWNER@OWNER-ID/REPO@REPO-ID:...; which format this repository uses is not "
                  "visible in its files (DECISIONS D6.3)")
LINK_NOTE = ("Roles are linked by their name (the last part of the role ARN), exactly; the account in "
             "the ARN must equal the account of the OIDC provider in the trust policy. JSON policy "
             "documents carry no role name: map them in .pipeguard.yml (DECISIONS D10).")


# --------------------------------------------------------------------------- three-valued logic

def _or(values):
    values = list(values)
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def _and(values):
    values = list(values)
    if any(v is False for v in values):
        return False
    return None if any(v is None for v in values) else True


def _not(value):
    return None if value is None else not value


# --------------------------------------------------------------------------- small parsers

def parse_role_arn(arn):
    """{'partition', 'account', 'path', 'name'} of an IAM role ARN, or None."""
    m = ROLE_ARN_RE.match(str(arn))
    if not m:
        return None
    return {"partition": m.group(1), "account": m.group(2), "path": m.group(3), "name": m.group(4)}


def _github_allow(policy):
    """The GitHub trust statements that can allow (Deny ones are never used to narrow, D7 S5)."""
    return [s for s in policy.get("statements", []) if s["class"] is not None and s["effect"] != "Deny"]


def provider_accounts(policy):
    """(literal accounts of GitHub's OIDC provider in the policy, True if one is not literal)."""
    accounts, unresolved = set(), False
    for s in _github_allow(policy):
        principal = s.get("principal") or {}
        if "?" in principal:
            unresolved = True
        for value in principal.get("Federated", []):
            m = PROVIDER_RE.match(value)
            if m:
                accounts.add(m.group(1))
            elif value.lower().endswith("oidc-provider/" + trust_analyzer.GITHUB_HOST) or "${" in value:
                unresolved = True
    return accounts, unresolved


# --------------------------------------------------------------------------- acceptance

def _value_matches(positive, value, sub):
    """Does one policy value accept `sub` under a positive operator? None if not evaluable."""
    if not isinstance(value, str) or "${" in value:
        return None
    if _unknown_value(str(value), positive):
        return None  # custom sub template, unresolved text, ... : never guessed
    if positive == "StringLike":
        return glob_match(value, sub)
    if positive == "StringEqualsIgnoreCase":
        return value.lower() == sub.lower()
    return value == sub


@lru_cache(maxsize=4096)
def _unknown_value(value, positive):
    """Phase 2 cannot classify this value (cached: one policy value is checked against many probes)."""
    return trust_analyzer.classify_value(value, positive)["class"] == "UNKNOWN"


def _record_accepts(record, sub):
    m = OPERATOR_RE.match(record["operator"])
    base = m.group(2) if m else None
    if base == "Null":
        values = [str(v).lower() for v in record["values"]]
        return True if values and all(v == "false" for v in values) else None
    negated = base in NEGATED
    positive = base.replace("Not", "", 1) if negated else base
    if positive not in POSITIVE:
        return None
    hit = _or(_value_matches(positive, v, sub) for v in record["values"])
    return _not(hit) if negated else hit


def _statement_accepts(statement, sub, upper_bound):
    if statement["class"] in ("UNKNOWN", "JOB_WORKFLOW_REF"):
        return None
    results = [_record_accepts(r, sub) for r in statement["sub"]]
    if upper_bound:
        # An AND-constraint that cannot be evaluated can only narrow: for EXCESS take it as
        # satisfied (the wider reading, as Phase 2 does when it reports the narrowest known one).
        results = [True if r is None else r for r in results]
    return _and(results)  # no sub constraint at all (MISSING) -> True


def policy_accepts(policy, sub, upper_bound=False):
    """True / False / None (cannot tell): would this trust policy accept a token with `sub`?

    Other condition keys (aud, job_workflow_ref next to sub, aws:...) are not evaluated: they can
    only narrow. Deny statements are not used (D7 S5)."""
    if policy.get("status") == "UNKNOWN" and not policy.get("statements"):
        return None
    return _or(_statement_accepts(s, sub, upper_bound) for s in _github_allow(policy))


# --------------------------------------------------------------------------- mapping file

def _reject_mapping(display, reason, line=None):
    finding = _finding("PG-L00", display, line, f"The mapping file is not used: {reason}.",
                       fact={"mapping": "REJECTED"})
    return {"file": display, "status": "REJECTED", "reason": reason, "entries": []}, [finding]


def read_mapping(root):
    """Read PATH/.pipeguard.yml (untrusted): ({file, status ABSENT|READ|REJECTED, entries}, findings).

    Format (README): `version: 1` and `roles:` a mapping role-name -> relative path of a JSON trust
    policy inside PATH. Read with safe_yaml (compose only, same limits); a symlink is not followed;
    any structural problem rejects the whole file (nothing is half-applied)."""
    path = Path(root) / MAPPING_FILE
    display = path.as_posix()
    if path.is_symlink():
        return _reject_mapping(display, "it is a symlink; not followed")
    if not path.exists():
        return {"file": None, "status": "ABSENT", "reason": None, "entries": []}, []
    try:
        size = path.stat().st_size
        if size > config.MAX_FILE_BYTES:
            return _reject_mapping(display, f"file too large ({size} bytes, limit {config.MAX_FILE_BYTES})")
        with path.open("rb") as handle:
            raw = handle.read(config.MAX_FILE_BYTES + 1)
        if len(raw) > config.MAX_FILE_BYTES:
            return _reject_mapping(display, f"file too large (limit {config.MAX_FILE_BYTES} bytes)")
        text = raw.decode("utf-8-sig")
    except OSError as exc:
        return _reject_mapping(display, f"cannot read the file ({type(exc).__name__})")
    except UnicodeDecodeError:
        return _reject_mapping(display, "not valid UTF-8 text")
    try:
        data = load(text)
    except YamlRejected as exc:
        return _reject_mapping(display, exc.reason, exc.line)
    if not isinstance(data, YMap):
        return _reject_mapping(display, "it must be a mapping with the keys version and roles")
    for key in data:
        if key not in ("version", "roles"):
            return _reject_mapping(display, f"unknown key '{key}' (allowed: version, roles)",
                                   data.key_lines[key])
    if data.get("version") != "1":
        return _reject_mapping(display, f"version must be 1 (found: {data.get('version')})")
    roles = data.get("roles")
    if not isinstance(roles, YMap):
        return _reject_mapping(display, "roles must be a mapping role-name: path",
                               data.key_lines.get("roles"))
    if len(roles) > config.MAX_MAPPING_ENTRIES:
        return _reject_mapping(display, f"more than {config.MAX_MAPPING_ENTRIES} entries")
    entries = []
    for name, target in roles.items():
        line = roles.key_lines[name]
        if not ROLE_NAME_RE.match(name):
            return _reject_mapping(display, f"role name '{name}' is not a valid IAM role name", line)
        if not isinstance(target, str) or not target.strip():
            return _reject_mapping(display, f"the path for role '{name}' is not a text value", line)
        entries.append({"role": str(name), "path": str(target), "line": line})
    return {"file": display, "status": "READ", "reason": None, "entries": entries}, []


def _check_target(root, target, scanned):
    """Why a mapping target cannot be used, or None. Never leaves the scanned folder."""
    if len(target) > config.MAX_MAPPING_PATH or target.count("/") >= config.MAX_MAPPING_SEGMENTS:
        return (f"the path is too long (limit {config.MAX_MAPPING_PATH} characters, "
                f"{config.MAX_MAPPING_SEGMENTS} segments)")
    if "\\" in target:
        return "use '/' in the path (a backslash is not allowed)"
    if target.startswith("/") or re.match(r"^[A-Za-z]:", target):
        return "the path must be relative to the scanned folder"
    parts = target.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "path segments '', '.' and '..' are not allowed"
    if clean(target) != target:
        return "the path contains control characters"
    if not target.lower().endswith(".json"):
        return ("mappings are for JSON trust policies; Terraform roles are matched by their name "
                "attribute")
    current = Path(root)
    for part in parts:
        current = current / part
        if current.is_symlink():
            return f"'{part}' in the path is a symlink; not followed"
    try:
        inside = (Path(root) / target).resolve().is_relative_to(Path(root).resolve())
    except (OSError, RuntimeError):  # RuntimeError: symlink loop on Python < 3.13
        inside = False
    if not inside:
        return "the path leaves the scanned folder"
    if target not in scanned:
        return "the path is not one of the scanned trust files"
    return None


# --------------------------------------------------------------------------- findings

def _finding(rule, file, line, message, role=None, job=None, fact=None, severity=None):
    return {"rule": rule, "severity": severity or RULE_SEVERITY[rule], "file": file, "line": line,
            "role": role, "job": job, "message": message, "fact": fact or {}}


def _sort(findings):
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["file"], f["line"] or 0,
                                           f["rule"]))


# --------------------------------------------------------------------------- collecting facts

def _relative(display, root):
    try:
        return Path(display).relative_to(Path(root)).as_posix()
    except ValueError:
        return Path(display).as_posix()


def _trust_entries(trust, root):
    """One entry per policy found by the trust analyzer, with what the linker needs."""
    out = []
    for file in trust["files"]:
        for index, policy in enumerate(file["policies"]):
            role = policy["role"]
            accounts, unresolved = provider_accounts(policy)
            address = role.get("address")
            out.append({
                "file": file["file"], "rel": _relative(file["file"], root), "kind": file["kind"],
                "index": index, "policy": policy, "address": address, "name": role.get("name"),
                "name_raw": role.get("name_raw"),
                "name_source": ("the Terraform name attribute" if address and
                                address.startswith("aws_iam_role.") else "RoleName in the JSON file"),
                "trusts_github": policy["class"] not in (None, "NO_GITHUB_TRUST"),
                "accounts": accounts, "account_unresolved": unresolved, "mapped": []})
    return out


def _role_uses(wf):
    uses, key_jobs = [], []
    for file in wf["files"]:
        if file["status"] != "ANALYSED":
            continue
        for job in file["jobs"]:
            env = job.get("environment")
            for r in job["aws"]["roles"]:
                parsed = parse_role_arn(r["value"]) if r["resolved"] else None
                uses.append({"file": file["file"], "job": job["id"], "line": r["line"],
                             "via": r["via"], "arn": r["value"], "raw": r["raw"], "parsed": parsed,
                             "environment": env["name"] if env else None,
                             "needed": job["expected_subs"]})
            if job["aws"]["mode"] in ("LONG_LIVED_KEYS", "BOTH"):
                key_jobs.append({"file": file["file"], "job": job["id"], "mode": job["aws"]["mode"],
                                 "keys": job["aws"]["keys"], "roles": job["aws"]["roles"]})
    return uses, key_jobs


def _apply_mapping(mapping, entries, trust_files, root, findings):
    """Attach each valid mapping entry to the one policy of its JSON file; report the others."""
    if mapping["status"] != "READ":
        return
    by_file = {}
    for e in entries:
        by_file.setdefault(e["rel"], []).append(e)
    status = {_relative(f["file"], root): f["status"] for f in trust_files}
    for item in mapping["entries"]:
        problem = _check_target(root, item["path"], status)
        if problem is None:
            problem = _attach(item, by_file.get(item["path"], []), status[item["path"]])
        if problem:
            findings.append(_finding("PG-L00", mapping["file"], item["line"],
                                     f"Mapping entry '{item['role']}: {item['path']}' is not used: "
                                     f"{problem}.", role=item["role"],
                                     fact={"path": item["path"], "problem": problem}))


def _attach(item, in_file, file_status):
    role = item["role"]
    if not in_file:
        return f"the mapped file holds no trust policy (status {file_status})"
    if len(in_file) > 1:
        if any(e["name"] == role for e in in_file):
            return None  # the file names the role itself: matched by name already
        return f"the mapped file holds {len(in_file)} policies; the mapping cannot choose one"
    entry = in_file[0]
    if entry["name"] and entry["name"] != role:
        return f"the mapped file names the role '{entry['name']}', not '{role}'"
    entry["mapped"].append({"role": role, "line": item["line"]})
    return None


# --------------------------------------------------------------------------- needed, coverage

def _needed(uses):
    out, seen = [], {}
    for use in uses:
        subs = use["needed"]
        if not subs and use["via"] == "UNKNOWN":
            subs = [{"kind": "UNKNOWN", "sub": None, "pattern": None, "trigger": None,
                     "verified": False, "note": "the role is given to an action PipeGuard does not "
                                                "recognise; its sub claim is not known"}]
        for s in subs:
            key = (s["kind"], s["sub"], s["pattern"])
            if key not in seen:
                seen[key] = dict(s, used_by=[])
                out.append(seen[key])
            ref = {"file": use["file"], "job": use["job"]}
            if ref not in seen[key]["used_by"]:
                seen[key]["used_by"].append(ref)
    return out


def _policy_ids(policy, owner, repo):
    """Owner/repository ID pairs (and owner IDs) the policy writes for this repository."""
    pairs, owner_ids, repo_ids = set(), set(), set()
    pair_re = re.compile(rf"^repo:{re.escape(owner)}@(\d+)/{re.escape(repo)}@(\d+):")
    owner_re = re.compile(rf"^repo:{re.escape(owner)}@(\d+)/")
    for s in _github_allow(policy):
        for record in s["sub"]:
            for value in record["values"]:
                if m := pair_re.match(value):
                    pairs.add(m.groups())
                    repo_ids.add(m.group(2))
                if m := owner_re.match(value):
                    owner_ids.add(m.group(1))
    return sorted(pairs), owner_ids, repo_ids


def _immutable(sub, owner, repo, ids):
    return sub.replace(f"repo:{owner}/{repo}:", f"repo:{owner}@{ids[0]}/{repo}@{ids[1]}:", 1)


def _samples(pattern, owner, repo):
    """Concrete subs inside a needed pattern (they are needed by definition), or None."""
    base = f"repo:{owner}/{repo}:"
    if not pattern.startswith(base):
        return None
    rest = pattern[len(base):]
    known = {"ref:*": ["ref:refs/heads/main", "ref:refs/heads/feature-x", "ref:refs/tags/v1.0.0"],
             "ref:refs/heads/*": ["ref:refs/heads/main", "ref:refs/heads/feature-x"],
             "ref:refs/tags/*": ["ref:refs/tags/v1.0.0"]}
    if rest in known:
        return [base + r for r in known[rest]]
    if any(c in rest for c in "+![]"):
        return None  # GitHub filter syntax PipeGuard does not sample
    sample = base + re.sub(r"[*?]+", "x", rest)
    return [sample] if glob_match(pattern, sample) else None


def _coverage(policy, needed, owner, repo, pairs):
    ids = pairs or [GENERIC_IDS]
    out = []
    for n in needed:
        entry = {"kind": n["kind"], "value": n["sub"] or n["pattern"], "classic": None,
                 "immutable": None, "samples": None, "failed": None}
        if n["sub"]:
            subs = [n["sub"]]
        elif n["pattern"]:
            subs = _samples(n["pattern"], owner, repo)
            entry["samples"] = subs
        else:
            subs = None
        if subs:
            classic = {s: policy_accepts(policy, s) for s in subs}
            immutable = {s: _or(policy_accepts(policy, _immutable(s, owner, repo, i)) for i in ids)
                         for s in subs}
            entry["classic"] = _and(classic.values())
            entry["immutable"] = _and(immutable.values())
            failed = [s for s in subs if classic[s] is False or immutable[s] is False]
            entry["failed"] = failed or None
        out.append(entry)
    return out


# --------------------------------------------------------------------------- excess

def _candidates(policy, owner, repo, contexts, pairs, owner_ids):
    out = []

    def add(sub, kind, source="probe"):
        out.append((sub, kind, source))

    o, r = owner, repo
    add("repo:evil-org/evil-repo:ref:refs/heads/main", "any repository")
    for ctx in contexts:
        add(f"repo:evil-org/{r}:{ctx}", "any owner, same repository name")
        add(f"repo:{o}-evil/{r}:{ctx}", "owner name with a suffix")
        add(f"repo:{o}@999999999/{r}@999999998:{ctx}", "owner name re-registered with another ID")
        add(f"repo:{o}/evil-repo:{ctx}", "other repository of the same owner")
        add(f"repo:{o}/{r}-evil:{ctx}", "repository name with a suffix")
        for oid in sorted(owner_ids):
            add(f"repo:{o}@{oid}/{r}@999999998:{ctx}", "repository re-created with another ID")
            add(f"repo:{o}@{oid}/evil-repo@999999997:{ctx}", "other repository of the same owner")
    for base in [f"repo:{o}/{r}"] + [f"repo:{o}@{a}/{r}@{b}" for a, b in pairs]:
        add(f"{base}:pull_request", "pull request")
        add(f"{base}:ref:refs/heads/feature-x", "other branch")
        add(f"{base}:ref:refs/tags/evil-tag", "other tag")
        add(f"{base}:environment:evil-env", "other environment")
        for ctx in contexts:
            for prefix in CTX_PREFIXES:
                if ctx.startswith(prefix) and len(ctx) > len(prefix):
                    name = ctx[len(prefix):]
                    add(f"{base}:{prefix}{name}-evil", "needed name with a suffix")
                    add(f"{base}:{prefix}evil-{name}", "needed name with a prefix")
    for s in _github_allow(policy):  # the Phase 2 evidence probes
        ev = s.get("evidence") or {}
        if ev.get("probe"):
            add(ev["probe"], ev.get("probe_kind") or "Phase 2 probe", "Phase 2 probe")
    for s in _github_allow(policy):  # literal values written in the policy
        for record in s["sub"]:
            m = OPERATOR_RE.match(record["operator"])
            base = m.group(2) if m else None
            if base not in POSITIVE:
                continue
            for value in record["values"]:
                wild = base == "StringLike" and any(c in value for c in "*?")
                if value.startswith("repo:") and not wild and "${" not in value:
                    add(value, "value written in the policy", "policy value")
    return out


def _is_name_variant(ctx, needed_contexts):
    for n in needed_contexts:
        for prefix in CTX_PREFIXES:
            if n.startswith(prefix) and ctx.startswith(prefix):
                name, cand = n[len(prefix):], ctx[len(prefix):]
                if name and cand != name and (cand.startswith(name) or cand.endswith(name)):
                    return True
    return False


def _category(sub, source, owner, repo, owner_ids, repo_ids, needed_contexts, needed_patterns):
    """OUTSIDE_OWNER / OTHER_REPO / OTHER_CONTEXT / NAME_SUFFIX, None if needed, 'UNPARSED'."""
    m = SUB_RE.match(sub)
    if not m:
        return "UNPARSED"
    owner_part, repo_part, ctx = m.groups()
    oname, _, oid = owner_part.partition("@")
    rname, _, rid = repo_part.partition("@")
    if oname != owner or (oid and oid not in owner_ids):
        return "OUTSIDE_OWNER"
    if rname != repo or (rid and rid not in repo_ids):
        return "OTHER_REPO"
    classic = f"repo:{owner}/{repo}:{ctx}"
    if ctx in needed_contexts or any(glob_match(p, classic) for p in needed_patterns):
        return None
    # The LOW category is for a wildcard inside a needed name: only probes can show it; a literal
    # value written in the policy is an exact other branch / environment (MEDIUM).
    if source != "policy value" and _is_name_variant(ctx, needed_contexts):
        return "NAME_SUFFIX"
    return "OTHER_CONTEXT"


def _excess(policy, needed, owner, repo, pairs, owner_ids, repo_ids):
    base = f"repo:{owner}/{repo}:"
    contexts = sorted({n["sub"][len(base):] for n in needed if n["sub"] and n["sub"].startswith(base)})
    patterns = [n["pattern"] for n in needed if n["pattern"]]
    found, unknown, seen = [], [], set()
    for sub, kind, source in _candidates(policy, owner, repo, contexts or ["ref:refs/heads/main"],
                                         pairs, owner_ids):
        if sub in seen:
            continue
        seen.add(sub)
        category = _category(sub, source, owner, repo, owner_ids, repo_ids, contexts, patterns)
        if category in (None, "UNPARSED"):
            continue
        accepted = policy_accepts(policy, sub, upper_bound=True)
        if accepted is True:
            found.append({"sub": sub, "kind": kind, "source": source, "category": category,
                          "severity": CATEGORY_SEVERITY[category]})
        elif accepted is None:
            unknown.append(sub)
    # Widest first; inside one severity the probe order above is kept (stable sort), so the
    # plainest probe ("any repository") is the headline. Deterministic: the order is fixed in code.
    found.sort(key=lambda e: SEVERITY_RANK[e["severity"]])
    return found, unknown


# --------------------------------------------------------------------------- recommendation

def _recommend(policy, needed, coverage, owner, repo, pairs):
    rec = {"status": "OK", "classic": [], "immutable": [], "immutable_template": [],
           "not_recommended": [], "notes": []}
    if not needed or any(n["kind"] == "UNKNOWN" for n in needed):
        rec["status"] = "INCOMPLETE"
        rec["notes"].append("the sub of at least one job using this role is unknown; the set below "
                            "cannot be complete")
    patterns = [n for n in needed if n["pattern"]]
    for n in patterns:
        rec["notes"].append(f"the workflow needs the pattern {n['pattern']} (trigger "
                            f"{n['trigger']}: {n['note']}); narrow the workflow first (a branch "
                            "filter or an environment); no wildcard is recommended")
    if patterns and rec["status"] == "OK":
        rec["status"] = "NARROW_WORKFLOW_FIRST"
    for n, cov in zip(needed, coverage):
        if not n["sub"]:
            continue
        if cov["classic"] is True:
            rec["classic"].append(n["sub"])
        else:
            reason = ("the current policy does not accept it; adding it would widen access: the owner "
                      "decides" if cov["classic"] is False else
                      "PipeGuard cannot verify that the current policy accepts it")
            rec["not_recommended"].append({"sub": n["sub"], "reason": reason})
            continue
        named = [_immutable(n["sub"], owner, repo, ids) for ids in pairs]
        accepted = [s for s in named if policy_accepts(policy, s) is True]
        if accepted:
            rec["immutable"] += accepted
        else:
            rec["immutable_template"].append(_immutable(n["sub"], owner, repo, IMMUTABLE_TEMPLATE_IDS))
        if n["kind"] == "PULL_REQUEST":
            rec["notes"].append(f"{n['sub']} is needed by a pull request job: every pull request of the "
                                "repository gets the role (PG-W02, PG-T03); an environment is narrower")
    for key in ("classic", "immutable", "immutable_template"):
        rec[key] = sorted(set(rec[key]))
    if rec["immutable_template"]:
        rec["notes"].append("immutable-format values need the owner and repository IDs, which are not "
                            "in the files: the template is not a value to deploy as is")
    if rec["status"] == "OK" and not rec["classic"]:
        rec["status"] = "NOTHING_ACCEPTED"
    return rec


# --------------------------------------------------------------------------- dead statements (R1)

def needed_variants(needed, coverage, owner, repo, pairs):
    """Every concrete needed sub in both formats, or None when a need is not concrete (unknown
    sub, or a pattern PipeGuard does not sample): then no statement can be called dead."""
    ids = pairs or [GENERIC_IDS]
    subs = []
    for n, cov in zip(needed, coverage):
        if n["sub"]:
            subs.append(n["sub"])
        elif cov["samples"]:
            subs += cov["samples"]
        else:
            return None
    return [v for s in subs for v in [s] + [_immutable(s, owner, repo, i) for i in ids]]


def statement_liveness(policy, variants):
    """[(statement, True | False | None)]: does each GitHub Allow statement accept a needed value?"""
    return [(s, _or(_statement_accepts(s, v, False) for v in variants)) for s in _github_allow(policy)]


def _dead_statement_findings(policy, needed, coverage, owner, repo, pairs, file, at, name):
    """PG-L09 (R1, D12): a GitHub Allow statement that accepts none of the needed values, in a policy
    with at least two such statements (one statement that accepts nothing is PG-L02's case)."""
    variants = needed_variants(needed, coverage, owner, repo, pairs)
    if not variants or len(_github_allow(policy)) < 2:
        return []
    states = statement_liveness(policy, variants)
    live = [s for s, ok in states if ok is True]
    wide_only = bool(live) and all(s["class"] != "EXACT" for s in live)
    out = []
    for s, ok in states:
        if ok is not False:
            continue  # accepts a needed value, or cannot tell: never called dead
        label = f"#{s['index']}" + (f" ({s['sid']})" if s["sid"] else "")
        msg = (f"In this trust policy, statement {label} accepts none of the needed values "
               f"({_needed_text(needed)}) in the classic or the immutable format: it is dead, and the "
               "fixer does not keep it.")
        if wide_only:
            which = ", ".join(f"#{w['index']} (class {w['class']})" for w in live)
            noun = "statement" if len(live) == 1 else "statements"
            msg += (f" The needed values are accepted only by the wide {noun} {which}: removing that "
                    "wide statement alone would break the deployment; replace it with the exact needed "
                    "values (python -m pipeguard fix).")
        out.append(_finding("PG-L09", file, s["line"] or at, msg, role=name,
                            fact={"statement": s["index"], "live_statements": [w["index"] for w in live],
                                  "wide_only": wide_only}))
    return out


# --------------------------------------------------------------------------- one link

def _needed_text(needed):
    values = [n["sub"] or n["pattern"] for n in needed if n["sub"] or n["pattern"]]
    return ", ".join(values[:3]) + (f" and {len(values) - 3} more" if len(values) > 3 else "")


def _too_large(policy, needed):
    values = sum(len(r["values"]) for s in _github_allow(policy) for r in s["sub"])
    if values > config.MAX_LINK_SUB_VALUES:
        return f"{values} sub values in the trust policy (limit {config.MAX_LINK_SUB_VALUES})"
    if len(needed) > config.MAX_LINK_NEEDED:
        return f"{len(needed)} needed sub values for this role (limit {config.MAX_LINK_NEEDED})"
    return None


def _analyse_link(group, entry, matched_by, account_check, owner, repo, findings):
    return analyse_policy(group["name"], _needed(group["uses"]), entry, matched_by, account_check,
                          owner, repo, findings)


def analyse_policy(name, needed, entry, matched_by, account_check, owner, repo, findings):
    """Coverage, excess, recommendation and link findings of ONE policy for one role's needs.
    `entry` holds file, index, address and the Phase 2 `policy` facts. The Phase 4 fixer calls it
    again on the narrowed policy, so the before/after comparison uses exactly the same rules."""
    policy = entry["policy"]
    too_large = _too_large(policy, needed)
    if too_large:
        findings.append(_finding(
            "PG-L00", entry["file"], policy["line"],
            f"The link for role '{name}' is too large to compute ({too_large}): coverage, "
            "excess and the recommended sub set are not computed; cannot verify.",
            role=name, fact={"too_large": too_large}))
        return {"trust_file": entry["file"], "trust_role": entry["address"],
                "policy_index": entry["index"], "policy_line": policy["line"],
                "policy_class": policy["class"], "matched_by": matched_by,
                "account_check": account_check, "needed": needed, "coverage": [],
                "formats_covered": [], "immutable_ids": [], "immutable_note": IMMUTABLE_NOTE,
                "excess": [], "excess_not_evaluated": [],
                "recommended": {"status": "NOT_COMPUTED", "classic": [], "immutable": [],
                                "immutable_template": [], "not_recommended": [], "notes": []},
                "notes": [f"not computed: {too_large}"]}
    pairs, owner_ids, repo_ids = _policy_ids(policy, owner, repo)
    coverage = _coverage(policy, needed, owner, repo, pairs)
    known = [c for c in coverage if c["classic"] is not None or c["immutable"] is not None]
    formats = [fmt for fmt in ("classic", "immutable")
               if known and all(c[fmt] is True for c in known)]
    notes = []
    if any(c["classic"] is None and c["immutable"] is None for c in coverage):
        notes.append("coverage could not be verified for every needed value (unknown sub or a "
                     "policy value PipeGuard cannot evaluate)")
    if policy["deny_statements"]:
        notes.append("Deny statements are not evaluated: coverage may be optimistic, excess is not "
                     "reduced")
    if any(n["sub"] or n["pattern"] for n in needed):
        excess, unknown = _excess(policy, needed, owner, repo, pairs, owner_ids, repo_ids)
    else:
        excess, unknown = [], []
        notes.append("excess not computed: no needed sub value is known")
    rec = _recommend(policy, needed, coverage, owner, repo, pairs)
    link = {"trust_file": entry["file"], "trust_role": entry["address"],
            "policy_index": entry["index"], "policy_line": policy["line"],
            "policy_class": policy["class"], "matched_by": matched_by,
            "account_check": account_check, "needed": needed, "coverage": coverage,
            "formats_covered": formats,
            "immutable_ids": [f"{a}/{b}" for a, b in pairs],
            "immutable_note": IMMUTABLE_NOTE + (
                "" if pairs else f"; the immutable format was tested with an ID pair the policy "
                                 f"does not name ({GENERIC_IDS[0]}/{GENERIC_IDS[1]})"),
            "excess": excess, "excess_not_evaluated": unknown, "recommended": rec, "notes": notes}
    at = policy["line"] or (policy["role"] or {}).get("line")
    if excess:
        widest = excess[0]
        extra = (" (if another repository of the owner also uses this role, this scan cannot see it)"
                 if widest["category"] == "OTHER_REPO" else "")
        findings.append(_finding(
            "PG-L01", entry["file"], at,
            f"The trust policy accepts more than the workflows in this repository need: "
            f"{widest['kind']} '{widest['sub']}' ({CATEGORY_TEXT[widest['category']]}) is accepted, "
            f"while the workflows need only {_needed_text(needed)}{extra}.",
            role=name, severity=widest["severity"],
            fact={"excess": [e["sub"] for e in excess], "needed": _needed_text(needed)}))
    findings += _dead_statement_findings(policy, needed, coverage, owner, repo, pairs, entry["file"], at,
                                         name)
    for n, cov in zip(needed, coverage):
        if cov["classic"] is not False and cov["immutable"] is not False:
            continue
        both = cov["classic"] is False and cov["immutable"] is False
        if both:
            fmt = ("the classic or the immutable format: the deployment would fail whatever format "
                   "the repository uses")
        elif cov["classic"] is False:
            fmt = ("the classic format (accepted in the immutable format): the deployment would fail "
                   "if the repository uses the classic format (created before 2026-07-15 and not "
                   "opted in)")
        else:
            fmt = ("the immutable format (accepted in the classic format): the deployment would fail "
                   "if the repository uses the immutable format (created after 2026-07-15, or opted in)")
        jobs = ", ".join(f"{u['job']} in {u['file']}" for u in n["used_by"])
        if n["sub"]:
            what = f"Needed sub '{n['sub']}' (job {jobs})"
        else:
            what = (f"Needed pattern '{n['pattern']}' (job {jobs}): the sample '{cov['failed'][0]}'")
        unverified = "" if n["verified"] else " (this needed value is not verified: " + n["note"] + ")"
        findings.append(_finding("PG-L02", entry["file"], at,
                                 f"{what} is not accepted by the trust policy in {fmt}{unverified}.",
                                 role=name, fact={"needed": cov["value"], "classic": cov["classic"],
                                                  "immutable": cov["immutable"]}))
    return link


# --------------------------------------------------------------------------- the scan

def _account_check(entry, account):
    if entry["accounts"]:
        if account in entry["accounts"]:
            return True, f"same account ({account})"
        return False, None
    if not entry["trusts_github"]:
        return True, "not compared: the trust policy has no GitHub trust statement"
    if entry["account_unresolved"]:
        return True, "not compared: the provider ARN's account is not a literal value"
    return True, "not compared: no provider account found"


def _matched_by(entry, name):
    ways = []
    if entry["name"] == name:
        ways.append(f"role name '{name}' in {entry['name_source']}")
    for m in entry["mapped"]:
        if m["role"] == name:
            ways.append(f"mapping in {MAPPING_FILE}, line {m['line']} (a claim written in the "
                        "repository, not verified against AWS)")
    return "; ".join(ways)


def _empty_workflow_scan(repo):
    return {"schema": workflow_analyzer.SCHEMA, "repo": repo, "files": [], "findings": [],
            "summary": {"files": 0, "analysed": 0, "not_a_workflow": 0, "rejected": 0,
                        "findings": {}}}


def scan(path, repo, keep_documents=False):
    """Link the workflows and trust policies of one repository folder. `repo` is OWNER/REPO.
    keep_documents: the trust scan keeps each evaluated policy document (for the fixer)."""
    root = Path(path)
    repo = workflow_analyzer.check_repo(repo)
    owner, name = repo.split("/")
    notes = [LINK_NOTE, trust_analyzer.NOTE, workflow_analyzer.SUB_FORMAT_NOTE]
    workflows = root / ".github" / "workflows"
    if workflows.is_dir() or workflows.is_symlink():
        wf = workflow_analyzer.scan(root, repo=repo)
    else:
        wf = _empty_workflow_scan(repo)
        notes.append("No .github/workflows folder under PATH: no workflow was scanned.")
    trust = trust_analyzer.scan(root, keep_documents=keep_documents)
    link_findings = []
    mapping, mapping_findings = read_mapping(root)
    link_findings += mapping_findings
    entries = _trust_entries(trust, root)
    _apply_mapping(mapping, entries, trust["files"], root, link_findings)
    uses, key_jobs = _role_uses(wf)

    # Unresolved role ARNs (PG-L05).
    unresolved = [u for u in uses if u["parsed"] is None]
    for u in unresolved:
        link_findings.append(_finding(
            "PG-L05", u["file"], u["line"],
            f"The role ARN cannot be read from the file (role-to-assume: {u['raw'] or u['arn']}); "
            "it cannot be linked to a trust policy, so who can assume it cannot be verified.",
            job=u["job"], fact={"raw": u["raw"]}))

    # Group the readable role uses by (account, name).
    groups = {}
    for u in uses:
        if u["parsed"]:
            key = (u["parsed"]["account"], u["parsed"]["name"])
            groups.setdefault(key, {"account": key[0], "name": key[1], "arns": [], "uses": [],
                                    "all_uses": []})
            g = groups[key]
            g["all_uses"].append(u)
            if u["via"] in ("OIDC", "UNKNOWN"):
                g["uses"].append(u)
            if u["arn"] not in g["arns"]:
                g["arns"].append(u["arn"])

    named_by_workflow = set()
    roles = []
    for (account, role_name), g in sorted(groups.items()):
        entry_out = {"name": role_name, "account": account, "arns": g["arns"],
                     "uses": [{k: u[k] for k in ("file", "job", "line", "via")} for u in g["all_uses"]],
                     "status": None, "links": [], "notes": []}
        roles.append(entry_out)
        candidates = [e for e in entries if e["name"] == role_name or
                      any(m["role"] == role_name for m in e["mapped"])]
        for e in candidates:
            named_by_workflow.add(id(e))
        if not g["uses"]:
            entry_out["status"] = "KEYS_ONLY"
            entry_out["notes"].append("assumed only with long-lived keys; not linked (see PG-L07)")
            continue
        first = g["uses"][0]
        if not candidates:
            entry_out["status"] = "TRUST_NOT_FOUND"
            link_findings.append(_finding("PG-L03", first["file"], first["line"],
                                          _not_found_message(role_name, account, entries),
                                          role=role_name, job=first["job"]))
            continue
        matched, mismatched = [], []
        for e in candidates:
            ok, check = _account_check(e, account)
            (matched if ok else mismatched).append((e, check))
        for e, _ in mismatched:
            entry_out["notes"].append(
                f"{e['file']} ({e['address'] or 'JSON policy'}) names '{role_name}' but trusts the "
                f"OIDC provider of account {', '.join(sorted(e['accounts']))}, not {account}: not "
                "linked")
        if not matched:
            entry_out["status"] = "ACCOUNT_MISMATCH"
            for e, _ in mismatched:
                link_findings.append(_finding(
                    "PG-L06", first["file"], first["line"],
                    f"The workflow assumes '{first['arn']}' (account {account}), but the trust policy "
                    f"for '{role_name}' in {e['file']} uses GitHub's OIDC provider of account "
                    f"{', '.join(sorted(e['accounts']))}: not the same role, so they are not linked; "
                    f"the trust policy of the role in account {account} was not found.",
                    role=role_name, job=first["job"],
                    fact={"workflow_account": account, "trust_accounts": sorted(e["accounts"]),
                          "trust_file": e["file"]}))
            continue
        if len(matched) > 1:
            entry_out["status"] = "AMBIGUOUS"
            link_findings.append(_finding(
                "PG-L08", first["file"], first["line"],
                f"{len(matched)} trust policies in the scanned files match role '{role_name}' "
                f"(account {account}): {', '.join(e['file'] for e, _ in matched)}; which one is "
                "deployed cannot be seen from the files. Each one is analysed.",
                role=role_name, job=first["job"],
                fact={"candidates": [e["file"] for e, _ in matched]}))
        else:
            entry_out["status"] = "LINKED"
        for e, check in matched:
            entry_out["links"].append(_analyse_link(g, e, _matched_by(e, role_name), check, owner,
                                                    name, link_findings))

    # Trust policies that trust GitHub and that no workflow names (PG-L04). A policy named by a
    # workflow but in another account is covered by PG-L06 instead.
    rejected_wf = sum(f["status"] == "REJECTED" for f in wf["files"])
    unlinked = []
    for e in entries:
        if not e["trusts_github"] or id(e) in named_by_workflow:
            continue
        shown = _entry_name(e)
        unlinked.append({"file": e["file"], "role_address": e["address"], "role_name": shown,
                         "policy_class": e["policy"]["class"], "line": e["policy"]["line"]})
        link_findings.append(_finding("PG-L04", e["file"], e["policy"]["line"],
                                      _unlinked_message(e, len(unresolved), rejected_wf),
                                      role=shown or e["address"]))

    link_findings += _key_findings(key_jobs, uses, entries)
    findings = _sort(wf["findings"] + trust["findings"] + link_findings)
    summary = {
        "roles": len(roles),
        "linked": sum(r["status"] == "LINKED" for r in roles),
        "ambiguous": sum(r["status"] == "AMBIGUOUS" for r in roles),
        "trust_not_found": sum(r["status"] == "TRUST_NOT_FOUND" for r in roles),
        "account_mismatch": sum(r["status"] == "ACCOUNT_MISMATCH" for r in roles),
        "keys_only": sum(r["status"] == "KEYS_ONLY" for r in roles),
        "unresolved_role_arns": len(unresolved),
        "unlinked_trust_policies": len(unlinked),
        "workflow_files": wf["summary"]["files"],
        "trust_files": trust["summary"]["files"],
        "findings": {sev: sum(f["severity"] == sev for f in findings) for sev in SEVERITY_RANK},
    }
    return {"schema": SCHEMA, "repo": repo, "notes": notes,
            "mapping": {k: mapping[k] for k in ("file", "status", "reason", "entries")},
            "roles": roles,
            "unresolved_roles": [{k: u[k] for k in ("file", "job", "line", "raw")} for u in unresolved],
            "unlinked_trust": unlinked, "findings": findings, "summary": summary,
            "workflow_scan": wf, "trust_scan": trust}


def _not_found_message(role_name, account, entries):
    msg = (f"The workflow assumes role '{role_name}' (account {account}), but its trust policy is not "
           "in the scanned files: trust side not found; it may be in the AWS console or another "
           "repository. Who can assume it cannot be verified.")
    near = sorted({e["name"] for e in entries if e["name"] and e["name"] != role_name
                   and e["name"].lower() == role_name.lower()})
    for other in near:
        msg += (f" A trust policy for '{other}' exists (differs only in letter case); it is not "
                "linked, because IAM's case rules for role names are not verified here.")
    unnamed = sum(1 for e in entries if e["trusts_github"] and not e["name"] and not e["name_raw"]
                  and e["kind"] == "json" and not e["mapped"])
    if unnamed:
        msg += (f" {unnamed} JSON trust policy file(s) carry no role name; map one to this role in "
                f"{MAPPING_FILE} if it belongs to it.")
    unreadable = sum(1 for e in entries if e["trusts_github"] and e["name_raw"])
    if unreadable:
        msg += (f" {unreadable} Terraform role name(s) cannot be read (expressions); one of them may "
                "be this role.")
    return msg


def _entry_name(entry):
    """The role name of a trust entry: from the file, else from the mapping file."""
    return entry["name"] or (entry["mapped"][0]["role"] if entry["mapped"] else None)


def _unlinked_message(entry, unresolved, rejected_wf):
    if _entry_name(entry):
        msg = (f"Role '{_entry_name(entry)}' trusts GitHub's OIDC provider, but no workflow in this "
               "repository names it in a readable role ARN; remove it if it is no longer used (its "
               "own trust findings still apply).")
    else:
        why = (f"its role name cannot be read (Terraform: {entry['name_raw']})" if entry["name_raw"]
               else f"its role name is not in the file (add a {MAPPING_FILE} mapping)")
        msg = (f"This trust policy ({entry['address'] or 'JSON policy document'}) trusts GitHub's "
               f"OIDC provider, but {why}, so it is not linked to any workflow (its own trust "
               "findings still apply).")
    if unresolved:
        msg += f" {unresolved} role ARN(s) in workflows could not be read (PG-L05); one of them may be this role."
    if rejected_wf:
        msg += f" {rejected_wf} workflow file(s) were not analysed; one of them may use it."
    return msg


def _key_findings(key_jobs, uses, entries):
    """PG-L07: long-lived keys while an OIDC role exists (same role, or the same account)."""
    oidc = {(u["parsed"]["account"], u["parsed"]["name"]) for u in uses
            if u["parsed"] and u["via"] == "OIDC"}
    trusting = {(acct, e["name"] or e["address"] or e["file"]) for e in entries if e["trusts_github"]
                for acct in (sorted(e["accounts"]) or ["(account not literal)"])}
    out = []
    for job in key_jobs:
        line = min((k["line"] for k in job["keys"]), default=None)
        keys_roles = [parse_role_arn(r["value"]) for r in job["roles"]
                      if r["via"] == "KEYS" and r["resolved"]]
        keys_roles = [r for r in keys_roles if r]
        same = [r for r in keys_roles if (r["account"], r["name"]) in oidc]
        if same:
            msg = (f"Job {job['job']} assumes role '{same[0]['name']}' with long-lived keys, while "
                   "another job assumes the same role with OIDC: migrate this job to OIDC "
                   "(role-to-assume without keys).")
        elif job["mode"] == "BOTH":
            msg = (f"Job {job['job']} already assumes a role with OIDC and also has long-lived AWS keys; "
                   "remove the keys if the role covers what they were used for.")
        else:
            accounts = {r["account"] for r in keys_roles}
            existing = sorted({f"{n} (account {a})" for a, n in oidc} | {f"{n} (account {a})"
                                                                         for a, n in trusting})
            if accounts:
                existing = sorted({f"{n} (account {a})" for a, n in oidc | trusting if a in accounts})
            if not existing:
                continue
            msg = (f"Job {job['job']} uses long-lived AWS keys while an OIDC role exists: "
                   f"{', '.join(existing[:3])}; migrate this job to the existing role.")
            if not accounts:
                msg += " The account of the keys is not visible in the files."
        out.append(_finding("PG-L07", job["file"], line, msg, job=job["job"],
                            fact={"mode": job["mode"]}))
    return out


# --------------------------------------------------------------------------- text output

def _yes(value):
    return {True: "yes", False: "NO", None: "cannot tell"}[value]


def format_text(result):
    """Human-readable report. Every scanned string passes through clean() before printing."""
    c = clean
    out = ["PipeGuard scan (read-only: nothing was run, no AWS call, no network).",
           f"Repository used in expected sub claims: {c(result['repo'])}"]
    for note in result["notes"]:
        out.append(f"Note: {c(note)}")
    m = result["mapping"]
    if m["status"] == "ABSENT":
        out.append(f"Mapping file: {MAPPING_FILE} not present.")
    elif m["status"] == "READ":
        out.append(f"Mapping file: {c(m['file'])} read ({len(m['entries'])} entr"
                   f"{'y' if len(m['entries']) == 1 else 'ies'}).")
    else:
        out.append(f"Mapping file: {c(m['file'])} REJECTED: {c(m['reason'])}")
    for r in result["roles"]:
        out.append("")
        out.append(f"== Role {c(r['name'])} (account {r['account']})  [{r['status']}]")
        for u in r["uses"]:
            out.append(f"   used by: {c(u['file'])}:{u['line']} job {c(u['job'])} (via {u['via']})")
        for note in r["notes"]:
            out.append(f"   note: {c(note)}")
        for lk in r["links"]:
            out += _link_text(lk)
    if result["unresolved_roles"]:
        out.append("")
        out.append("== Role ARNs that cannot be read (not linked)")
        for u in result["unresolved_roles"]:
            out.append(f"   {c(u['file'])}:{u['line']} job {c(u['job'])}: {c(u['raw'])}")
    if result["unlinked_trust"]:
        out.append("")
        out.append("== Trust policies that trust GitHub but are not linked to a workflow")
        for t in result["unlinked_trust"]:
            who = t["role_address"] or "JSON policy document"
            name = f" (name {c(t['role_name'])})" if t["role_name"] else ""
            out.append(f"   {c(t['file'])}:{t['line']} {c(who)}{name}: class {t['policy_class']}")
    findings = result["findings"]
    out.append("")
    out.append(f"Findings ({len(findings)}; workflow PG-W, trust PG-T, link PG-L; severity model D8/D9, "
               "link rules D10):")
    for f in findings:
        where = f"{c(f['file'])}:{f['line']}" if f.get("line") else c(f["file"])
        role = f" role {c(f['role'])}" if f.get("role") else ""
        job = f" job {c(f['job'])}" if f.get("job") else ""
        stmt = f" statement {c(f['statement'])}" if f.get("statement") else ""
        out.append(f"  [{f['severity']}] {f['rule']} {where}{role}{job}{stmt}: {c(f['message'])}")
    if not findings:
        out.append("  none")
    s = result["summary"]
    counts = ", ".join(f"{k} {v}" for k, v in s["findings"].items())
    out.append("")
    out.append(f"Summary: {s['roles']} role(s): {s['linked']} linked, {s['ambiguous']} ambiguous, "
               f"{s['trust_not_found']} trust not found, {s['account_mismatch']} account mismatch, "
               f"{s['keys_only']} keys only; {s['unresolved_role_arns']} unreadable role ARN(s); "
               f"{s['unlinked_trust_policies']} unlinked trust polic(ies). Findings: {counts}.")
    return "\n".join(out)


def _link_text(lk):
    c = clean
    out = [f"   trust policy: {c(lk['trust_file'])}:{lk['policy_line']} "
           f"{c(lk['trust_role'] or 'JSON policy document')}, class {lk['policy_class']}",
           f"     matched by: {c(lk['matched_by'])}",
           f"     account: {c(lk['account_check'])}"]
    for n in lk["needed"]:
        value = n["sub"] or (f"pattern {n['pattern']}" if n["pattern"] else "unknown")
        state = "" if n["verified"] else ", NOT verified"
        out.append(f"     needed: {c(value)} [{n['kind']}, from {c(n['trigger'] or '?')}{state}]")
    for cov in lk["coverage"]:
        sample = f" (samples: {c(', '.join(cov['samples']))})" if cov["samples"] else ""
        out.append(f"     accepted? {c(cov['value'] or 'unknown')}: classic {_yes(cov['classic'])}, "
                   f"immutable {_yes(cov['immutable'])}{sample}")
    ids = ", ".join(lk["immutable_ids"]) or "none named in the policy"
    out.append(f"     formats covered: {', '.join(lk['formats_covered']) or 'none'} "
               f"(immutable IDs: {c(ids)})")
    if lk["excess"]:
        out.append(f"     accepted but not needed ({len(lk['excess'])}):")
        shown = set()
        for e in lk["excess"]:
            if e["category"] in shown:
                continue
            shown.add(e["category"])
            more = sum(x["category"] == e["category"] for x in lk["excess"]) - 1
            out.append(f"       [{e['severity']}] {c(e['kind'])}: {c(e['sub'])}"
                       + (f" (+{more} more of this kind)" if more else ""))
    else:
        out.append("     accepted but not needed: none found")
    if lk["excess_not_evaluated"]:
        out.append(f"     probes PipeGuard could not evaluate: {len(lk['excess_not_evaluated'])}")
    rec = lk["recommended"]
    out.append(f"     recommended sub set [{rec['status']}] (input of python -m pipeguard fix; no file "
               "written):")
    for sub in rec["classic"]:
        out.append(f"       classic:   {c(sub)}")
    for sub in rec["immutable"]:
        out.append(f"       immutable: {c(sub)}")
    for sub in rec["immutable_template"]:
        out.append(f"       immutable (template, IDs not in the files): {c(sub)}")
    for item in rec["not_recommended"]:
        out.append(f"       not recommended: {c(item['sub'])} ({c(item['reason'])})")
    for note in rec["notes"] + lk["notes"]:
        out.append(f"     note: {c(note)}")
    return out
