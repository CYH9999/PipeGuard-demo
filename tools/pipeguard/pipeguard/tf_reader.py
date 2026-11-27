"""Terraform reader for trust policies (Phase 2, DECISIONS D7). Static: never runs Terraform.

python-hcl2 parses the file into a syntax tree (lark). We walk that tree ourselves and evaluate
only *literal* values:
- strings (with HCL escapes), numbers, true/false/null, objects, tuples;
- `jsonencode(<literal>)`;
- heredoc JSON (`<<EOT` / `<<-EOT`);
- `data.aws_iam_policy_document.NAME.json` when that data block is in the same folder (module);
- `file("x.json")` / `file("${path.module}/x.json")` when the file is inside the scanned folder.
Everything else (variables, locals, modules, other functions, for-expressions, dynamic blocks,
template directives, interpolations) becomes `Unresolved(reason)`: the policy is then UNKNOWN,
never SAFE. An interpolation inside a string is kept as text (`${var.repo}`) so the reason can
name it; inside a Federated principal only the account part may be unresolved (see trust_analyzer).
"""

import re
from pathlib import Path

import hcl2
from lark import Token, Tree

from pipeguard import config
from pipeguard.json_reader import JsonRejected, load_json
from pipeguard.safe_yaml import YMap, YSeq, YStr

DOC_REF_RE = re.compile(r"^data\.aws_iam_policy_document\.([A-Za-z_][A-Za-z0-9_-]*)\.json$")
ESCAPE_RE = re.compile(r"\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)", re.DOTALL)
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
MERGED_DOC_ATTRS = ("source_policy_documents", "override_policy_documents", "source_json",
                    "override_json")
MARKER = "__PIPEGUARD_EXPR_{}__"
MARKER_RE = re.compile(r"__PIPEGUARD_EXPR_(\d+)__")


class TfRejected(Exception):
    def __init__(self, reason, line=None):
        super().__init__(reason)
        self.reason = reason
        self.line = line


class Unresolved:
    """A value PipeGuard cannot know from the files. `pieces` (for a string template) is a list of
    ("lit", text) / ("expr", source) parts, used to show and to embed the template."""

    def __init__(self, reason, line=None, pieces=None):
        self.reason = reason
        self.line = line
        self.pieces = pieces

    @property
    def text(self):
        if self.pieces is None:
            return None
        return "".join(t if k == "lit" else "${" + t + "}" for k, t in self.pieces)

    def __repr__(self):
        return f"Unresolved({self.reason!r})"


class Block:
    def __init__(self, kind, labels, line):
        self.kind = kind
        self.labels = labels
        self.line = line
        self.attrs = {}  # name -> (expression tree, line)
        self.blocks = []
        self.duplicate_attr = None


# --------------------------------------------------------------------------- tree helpers

def _tokens(node):
    if isinstance(node, Token):
        return [node]
    return list(node.scan_values(lambda v: isinstance(v, Token)))


def _line(node):
    lines = [t.line for t in _tokens(node) if getattr(t, "line", None)]
    return min(lines) if lines else None


def _source(node):
    return "".join(str(t) for t in _tokens(node)).strip()


def _kids(tree):
    return [c for c in tree.children
            if not (isinstance(c, Tree) and c.data == "new_line_or_comment")]


def _tree_kids(tree):
    return [c for c in _kids(tree) if isinstance(c, Tree)]


def _name(tree):
    """The text of an `identifier` tree."""
    return str(_tokens(tree)[0])


def _unescape(text):
    def repl(m):
        code = m.group(1)
        if code[0] in "uU" and len(code) > 1:
            return chr(int(code[1:], 16))
        if code in SIMPLE_ESCAPES:
            return SIMPLE_ESCAPES[code]
        raise ValueError(f"invalid escape \\{code}")
    return ESCAPE_RE.sub(repl, text)


# --------------------------------------------------------------------------- parsing

def parse_file(text):
    """Parse Terraform text into a list of top-level Blocks, or raise TfRejected."""
    try:
        tree = hcl2.parses_to_tree(text)
    except RecursionError:
        raise TfRejected("Terraform nesting too deep for the parser") from None
    except Exception as exc:  # a parser failure must never look like "nothing found"
        line = getattr(exc, "line", None)
        raise TfRejected(f"Terraform syntax error ({type(exc).__name__})", line) from None
    body = next((c for c in _tree_kids(tree) if c.data == "body"), None)
    return _body_blocks(body) if body is not None else ([], {})


def _body_blocks(body):
    blocks, attrs = [], {}
    for item in _tree_kids(body):
        if item.data == "block":
            blocks.append(_block(item))
        elif item.data == "attribute":
            parts = _tree_kids(item)
            attrs[_name(parts[0])] = (parts[-1], _line(item))
    return blocks, attrs


def _block(tree):
    parts = _kids(tree)
    kind = _name(parts[0])
    labels = []
    for part in parts[1:]:
        if isinstance(part, Tree) and part.data == "string":
            labels.append("".join(_string_pieces_text(part)))
        elif isinstance(part, Tree) and part.data == "identifier":
            labels.append(_name(part))
    block = Block(kind, labels, _line(tree))
    body = next((p for p in parts if isinstance(p, Tree) and p.data == "body"), None)
    if body is not None:
        for item in _tree_kids(body):
            if item.data == "block":
                block.blocks.append(_block(item))
            elif item.data == "attribute":
                kids = _tree_kids(item)
                name = _name(kids[0])
                if name in block.attrs:
                    block.duplicate_attr = name
                block.attrs[name] = (kids[-1], _line(item))
    return block


def _string_pieces_text(tree):
    """Literal text of a block label (labels never contain interpolations in valid HCL)."""
    out = []
    for part in _tree_kids(tree):
        for tok in _tokens(part):
            if tok.type == "STRING_CHARS":
                out.append(tok)
    return out


# --------------------------------------------------------------------------- evaluation

class Context:
    """What an expression may refer to: the module folder, its policy documents, the scan root."""

    def __init__(self, root, directory, documents):
        self.root = Path(root).resolve()
        self.directory = Path(directory)
        self.documents = documents  # name -> (Block, file display path) or "DUPLICATE"
        self.referenced = set()


def evaluate(node, ctx, depth=0):
    """Evaluate a literal HCL expression; anything else is Unresolved (never an exception)."""
    if depth > config.MAX_YAML_DEPTH:
        return Unresolved("expression nesting too deep", _line(node))
    if isinstance(node, Token):
        return Unresolved(f"token {node!s} is not evaluated", getattr(node, "line", None))
    kind = node.data
    line = _line(node)
    if kind == "expr_term":
        kids = _kids(node)
        trees = [k for k in kids if isinstance(k, Tree)]
        if len(trees) == 1 and len(kids) == 1:
            return evaluate(trees[0], ctx, depth + 1)
        if len(trees) == 1 and [str(k) for k in kids if isinstance(k, Token)] == ["(", ")"]:
            return evaluate(trees[0], ctx, depth + 1)
        return Unresolved(f"expression {_source(node)[:80]} is not evaluated", line)
    if kind == "string":
        return _string(node, line)
    if kind in ("int_lit", "float_lit"):
        value = YStr(str(_tokens(node)[0]))
        value.line = line
        return value
    if kind == "literal_value":
        word = str(_tokens(node)[0])
        if word == "null":
            return None
        value = YStr(word)
        value.line = line
        return value
    if kind == "object":
        return _object(node, ctx, depth, line)
    if kind == "tuple":
        out = YSeq()
        out.line = line
        for item in _tree_kids(node):
            out.append(evaluate(item, ctx, depth + 1))
            out.item_lines.append(_line(item))
        return out
    if kind == "function_call":
        return _function(node, ctx, depth, line)
    if kind == "get_attr_expr_term":
        text = _source(node)
        m = DOC_REF_RE.match(text)
        if m:
            return document(m.group(1), ctx, line)
        return Unresolved(f"reference {text} is not evaluated", line)
    if kind == "identifier":
        return Unresolved(f"reference {_name(node)} is not evaluated", line)
    if kind in ("heredoc_template", "heredoc_template_trim"):
        return _heredoc(str(_tokens(node)[0]), kind.endswith("trim"), line)
    return Unresolved(f"expression {_source(node)[:80]} is not evaluated", line)


def _string(tree, line):
    pieces = []
    for part in _tree_kids(tree):
        inner = [k for k in part.children if isinstance(k, (Tree, Token))]
        for item in inner:
            if isinstance(item, Token):
                if item.type == "STRING_CHARS":
                    try:
                        pieces.append(("lit", _unescape(str(item))))
                    except ValueError as exc:
                        return Unresolved(f"string with {exc}", line)
                elif item.type == "ESCAPED_INTERPOLATION":
                    pieces.append(("lit", "${" + str(item)[3:]))
                elif item.type == "ESCAPED_DIRECTIVE":
                    pieces.append(("lit", "%{" + str(item)[3:]))
                else:
                    pieces.append(("lit", str(item)))
            elif item.data == "interpolation":
                expr = _source(item)
                pieces.append(("expr", expr[2:-1].strip() if expr.startswith("${") else expr))
            else:
                return Unresolved(f"template directive in a string ({_source(item)[:40]})", line)
    if any(k == "expr" for k, _ in pieces):
        unresolved = Unresolved("interpolation in a string", line, pieces)
        unresolved.reason = f"interpolation in a string: {unresolved.text}"
        return unresolved
    value = YStr("".join(t for _, t in pieces))
    value.line = line
    return value


def _object(tree, ctx, depth, line):
    out = YMap()
    out.line = line
    for elem in _tree_kids(tree):
        if elem.data != "object_elem":
            continue
        key_tree, value_tree = _tree_kids(elem)[0], _tree_kids(elem)[-1]
        key_expr = _tree_kids(key_tree)[0] if _tree_kids(key_tree) else key_tree
        inner = _tree_kids(key_expr)
        if key_expr.data == "expr_term" and len(inner) == 1 and inner[0].data == "identifier":
            key = _name(inner[0])
        elif key_expr.data == "expr_term" and len(inner) == 1 and inner[0].data == "string":
            key = _string(inner[0], line)
            if isinstance(key, Unresolved):
                return Unresolved(f"object key is not literal ({key.text})", _line(elem))
        elif key_expr.data == "identifier":
            key = _name(key_expr)
        else:
            return Unresolved(f"object key {_source(key_tree)[:60]} is not literal", _line(elem))
        key = YStr(str(key))
        if key in out:
            return Unresolved(f"duplicate key '{key}' in an HCL object (a duplicate can hide a "
                              "value)", _line(elem))
        out[key] = evaluate(value_tree, ctx, depth + 1)
        out.key_lines[key] = _line(elem)
    return out


def _function(tree, ctx, depth, line):
    parts = _tree_kids(tree)
    name = _name(parts[0])
    args_tree = next((p for p in parts if p.data == "arguments"), None)
    args = _tree_kids(args_tree) if args_tree is not None else []
    if name == "jsonencode" and len(args) == 1:
        return evaluate(args[0], ctx, depth + 1)
    if name == "file" and len(args) == 1:
        return _file(evaluate(args[0], ctx, depth + 1), ctx, line)
    return Unresolved(f"function {name}() is not evaluated", line)


def _file(arg, ctx, line):
    if isinstance(arg, Unresolved):
        pieces = arg.pieces or []
        if (len(pieces) == 2 and pieces[0] == ("expr", "path.module")
                and pieces[1][0] == "lit" and pieces[1][1].startswith("/")):
            rel = pieces[1][1][1:]
        else:
            return Unresolved(f"file() path is not literal ({arg.text or arg.reason})", line)
    elif isinstance(arg, str):
        rel = str(arg)
    else:
        return Unresolved("file() argument is not a string", line)
    target = ctx.directory / rel
    try:
        resolved = target.resolve()
        resolved.relative_to(ctx.root)
    except (OSError, ValueError):
        return Unresolved(f"file(\"{rel}\") is outside the scanned folder; not read", line)
    if not resolved.is_file():
        return Unresolved(f"file(\"{rel}\") not found in the scanned folder", line)
    if resolved.stat().st_size > config.MAX_FILE_BYTES:
        return Unresolved(f"file(\"{rel}\") is too large (limit {config.MAX_FILE_BYTES} bytes)", line)
    try:
        text = resolved.read_bytes()[: config.MAX_FILE_BYTES + 1].decode("utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return Unresolved(f"file(\"{rel}\") cannot be read as UTF-8", line)
    value = YStr(text)
    value.line = line
    value.source_file = rel
    return value


def _heredoc(token_text, trim, line):
    lines = token_text.split("\n")
    marker = lines[0].lstrip("<-").strip()
    body = lines[1:]
    while body and not body[-1].strip():
        body = body[:-1]  # the token may end with the newline after the closing marker
    if body and body[-1].strip() == marker:
        body = body[:-1]
    if trim:
        indents = [len(ln) - len(ln.lstrip(" \t")) for ln in body if ln.strip()]
        cut = min(indents) if indents else 0
        body = [ln[cut:] for ln in body]
    return _template("\n".join(body), (line or 0) + 1)


def _template(text, first_line):
    """Split a heredoc template into literal text and ${...} interpolations."""
    pieces, i, lit = [], 0, []
    while i < len(text):
        if text.startswith("$${", i):
            lit.append("${")
            i += 3
        elif text.startswith("%%{", i):
            lit.append("%{")
            i += 3
        elif text.startswith("%{", i):
            return Unresolved("template directive %{...} in a heredoc", first_line)
        elif text.startswith("${", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            if depth:
                return Unresolved("unclosed interpolation in a heredoc", first_line)
            if lit:
                pieces.append(("lit", "".join(lit)))
                lit = []
            pieces.append(("expr", text[i + 2:j - 1].strip()))
            i = j
        else:
            lit.append(text[i])
            i += 1
    if lit:
        pieces.append(("lit", "".join(lit)))
    if any(k == "expr" for k, _ in pieces):
        unresolved = Unresolved("interpolation in a heredoc", first_line, pieces)
        unresolved.reason = "interpolation in a heredoc"
        unresolved.heredoc = True
        return unresolved
    value = YStr("".join(t for _, t in pieces))
    value.line = first_line
    value.heredoc = True
    return value


# --------------------------------------------------------------------------- policy documents

def document(name, ctx, line):
    """`data.aws_iam_policy_document.NAME.json` -> a policy (YMap) or Unresolved."""
    found = ctx.documents.get(name)
    if found is None:
        return Unresolved(f"data.aws_iam_policy_document.{name} not found in this folder", line)
    if found == "DUPLICATE":
        return Unresolved(f"data.aws_iam_policy_document.{name} is defined twice", line)
    ctx.referenced.add(name)
    block, _ = found
    return document_from_block(block, ctx)


def document_from_block(block, ctx):
    if block.duplicate_attr:
        return Unresolved(f"attribute {block.duplicate_attr} set twice", block.line)
    for attr in MERGED_DOC_ATTRS:
        if attr in block.attrs:
            return Unresolved(f"{attr} merges other documents; not evaluated", block.attrs[attr][1])
    statements = YSeq()
    statements.line = block.line
    for child in block.blocks:
        if child.kind == "dynamic":
            return Unresolved("dynamic block in aws_iam_policy_document; not evaluated", child.line)
        if child.kind != "statement":
            return Unresolved(f"unexpected block {child.kind} in aws_iam_policy_document", child.line)
        statement = _statement_from_block(child, ctx)
        if isinstance(statement, Unresolved):
            return statement
        statements.append(statement)
        statements.item_lines.append(child.line)
    doc = YMap()
    doc.line = block.line
    version = block.attrs.get("version")
    doc[YStr("Version")] = evaluate(version[0], ctx) if version else YStr("2012-10-17")
    doc.key_lines["Version"] = block.line
    doc[YStr("Statement")] = statements
    doc.key_lines["Statement"] = block.line
    return doc


STATEMENT_ATTRS = {"sid": "Sid", "effect": "Effect", "actions": "Action", "not_actions": "NotAction",
                   "resources": "Resource", "not_resources": "NotResource"}


def _statement_from_block(block, ctx):
    if block.duplicate_attr:
        return Unresolved(f"attribute {block.duplicate_attr} set twice", block.line)
    out = YMap()
    out.line = block.line
    for attr, element in STATEMENT_ATTRS.items():
        if attr in block.attrs:
            expr, line = block.attrs[attr]
            out[YStr(element)] = evaluate(expr, ctx)
            out.key_lines[element] = line
    if "Effect" not in out:
        # The aws_iam_policy_document default (Allow) is the wider assumption (not verified).
        out[YStr("Effect")] = YStr("Allow")
        out.key_lines["Effect"] = block.line
    principals = {"principals": YMap(), "not_principals": YMap()}
    conditions = YMap()
    for child in block.blocks:
        if child.kind == "dynamic":
            return Unresolved("dynamic block in a statement; not evaluated", child.line)
        if child.kind in principals:
            ptype = evaluate(child.attrs["type"][0], ctx) if "type" in child.attrs else None
            ids = evaluate(child.attrs["identifiers"][0], ctx) if "identifiers" in child.attrs else None
            if not isinstance(ptype, str):
                return Unresolved("principals type is not literal", child.line)
            target = principals[child.kind]
            items = list(ids) if isinstance(ids, list) else [ids]
            existing = list(target.get(ptype, []))
            seq = YSeq()
            seq.line = child.line
            for item in existing + items:
                seq.append(item)
                seq.item_lines.append(child.line)
            target[YStr(ptype)] = seq
            target.key_lines[str(ptype)] = child.line
        elif child.kind == "condition":
            test = evaluate(child.attrs["test"][0], ctx) if "test" in child.attrs else None
            var = evaluate(child.attrs["variable"][0], ctx) if "variable" in child.attrs else None
            values = evaluate(child.attrs["values"][0], ctx) if "values" in child.attrs else None
            if not isinstance(test, str) or not isinstance(var, str):
                return Unresolved("condition test or variable is not literal", child.line)
            group = conditions.get(test)
            if group is None:
                group = YMap()
                group.line = child.line
                conditions[YStr(test)] = group
                conditions.key_lines[str(test)] = child.line
            if var in group:
                return Unresolved(f"two condition blocks with test {test} and variable {var}; "
                                  "how they combine is not verified", child.line)
            group[YStr(var)] = values
            group.key_lines[str(var)] = child.line
        else:
            return Unresolved(f"unexpected block {child.kind} in a statement", child.line)
    for kind, element in (("principals", "Principal"), ("not_principals", "NotPrincipal")):
        if principals[kind]:
            out[YStr(element)] = principals[kind]
            out.key_lines[element] = block.line
    if conditions:
        out[YStr("Condition")] = conditions
        out.key_lines["Condition"] = block.line
    return out


def policy_from_value(value):
    """An assume_role_policy value -> (policy YMap, source) or (Unresolved, source)."""
    if isinstance(value, Unresolved):
        if value.pieces is not None:
            return _json_with_interpolations(value), "heredoc" if getattr(value, "heredoc", False) else "string"
        return value, "expression"
    if isinstance(value, YMap):
        return value, "jsonencode"
    if isinstance(value, str):
        source = ("file(" + value.source_file + ")" if getattr(value, "source_file", None)
                  else "heredoc" if getattr(value, "heredoc", False) else "string")
        offset = (value.line - 1) if (value.line and not getattr(value, "source_file", None)) else 0
        try:
            return load_json(str(value), offset), source
        except JsonRejected as exc:
            return Unresolved(f"the policy text is not valid JSON: {exc.reason}", value.line), source
    return Unresolved("assume_role_policy is not a policy document", None), "expression"


def _json_with_interpolations(unresolved):
    """JSON text with ${...} pieces: parse with markers; every string holding a marker becomes
    Unresolved (it names the interpolation)."""
    exprs = []
    text = []
    for kind, part in unresolved.pieces:
        if kind == "lit":
            text.append(part)
        else:
            text.append(MARKER.format(len(exprs)))
            exprs.append(part)
    offset = (unresolved.line - 1) if unresolved.line else 0
    try:
        doc = load_json("".join(text), offset)
    except JsonRejected as exc:
        return Unresolved(f"the policy text with interpolations is not valid JSON ({exc.reason})",
                          unresolved.line)

    def restore(value):
        if isinstance(value, YMap):
            for key in list(value.keys()):
                if MARKER_RE.search(key):
                    raise ValueError("interpolation in a JSON key")
                value[key] = restore(value[key])
            return value
        if isinstance(value, YSeq):
            for i, item in enumerate(value):
                value[i] = restore(item)
            return value
        if isinstance(value, str) and MARKER_RE.search(value):
            pieces = []
            pos = 0
            for m in MARKER_RE.finditer(value):
                if m.start() > pos:
                    pieces.append(("lit", value[pos:m.start()]))
                pieces.append(("expr", exprs[int(m.group(1))]))
                pos = m.end()
            if pos < len(value):
                pieces.append(("lit", value[pos:]))
            out = Unresolved("interpolation", getattr(value, "line", None), pieces)
            out.reason = f"interpolation in a value: {out.text}"
            return out
        return value

    try:
        return restore(doc)
    except ValueError as exc:
        return Unresolved(str(exc), unresolved.line)


# --------------------------------------------------------------------------- modules (folders)

def read_module(files, root):
    """Read the .tf files of ONE folder (a Terraform module) together.

    `files` is a list of (path, display, text). Returns {display: result} where result is
    {"status", "reason", "line", "items": [...], "modules_not_followed": [...]}.
    """
    parsed, results, documents = {}, {}, {}
    for path, display, text in files:
        try:
            blocks, _ = parse_file(text)
        except TfRejected as exc:
            results[display] = {"status": "REJECTED", "reason": exc.reason, "line": exc.line,
                                "items": [], "modules_not_followed": []}
            continue
        parsed[display] = (path, blocks)
        for block in blocks:
            if block.kind == "data" and block.labels[:1] == ["aws_iam_policy_document"]:
                name = block.labels[1] if len(block.labels) > 1 else ""
                documents[name] = "DUPLICATE" if name in documents else (block, display)
    directory = Path(files[0][0]).parent if files else Path(".")
    shared_refs = set()
    for display, (path, blocks) in parsed.items():
        ctx = Context(root, directory, documents)
        items = []
        modules = []
        for block in blocks:
            if block.kind == "module":
                modules.append({"name": block.labels[0] if block.labels else "", "line": block.line})
            if block.kind == "resource" and block.labels[:1] == ["aws_iam_role"]:
                items.append(_role_item(block, ctx))
        shared_refs |= ctx.referenced
        results[display] = {"status": "ANALYSED", "reason": None, "line": None, "items": items,
                            "modules_not_followed": modules}
    # Policy documents not used by any role in this folder are analysed on their own.
    for name, found in documents.items():
        if found == "DUPLICATE" or name in shared_refs:
            continue
        block, display = found
        ctx = Context(root, directory, documents)
        doc = document_from_block(block, ctx)
        results[display]["items"].append({
            "role": {"address": f"data.aws_iam_policy_document.{name}", "name": None,
                     "line": block.line},
            "source": f"data.aws_iam_policy_document.{name}", "line": block.line,
            "value": doc, "notes": ["policy document not used by an aws_iam_role in this folder"]})
    for display, result in results.items():
        if result["status"] == "ANALYSED" and not result["items"]:
            result["status"] = "NOT_A_POLICY"
            result["reason"] = "no aws_iam_role and no aws_iam_policy_document in this file"
        result["items"].sort(key=lambda item: item["line"] or 0)
    return results


def _role_item(block, ctx):
    label = block.labels[1] if len(block.labels) > 1 else ""
    role = {"address": f"aws_iam_role.{label}", "name": None, "line": block.line}
    notes = []
    if "name" in block.attrs:
        name = evaluate(block.attrs["name"][0], ctx)
        if isinstance(name, str):
            role["name"] = str(name)
        else:
            role["name_raw"] = name.text if isinstance(name, Unresolved) and name.text else None
    elif "name_prefix" in block.attrs:
        notes.append("the role uses name_prefix; its full name is chosen by Terraform")
    for meta in ("count", "for_each"):
        if meta in block.attrs:
            notes.append(f"the role uses {meta}: several roles share this trust policy")
    if "assume_role_policy" not in block.attrs:
        value, source, line = Unresolved("aws_iam_role without assume_role_policy", block.line), \
            "missing", block.line
    else:
        expr, line = block.attrs["assume_role_policy"]
        refs_before = set(ctx.referenced)
        raw = evaluate(expr, ctx)
        value, source = policy_from_value(raw)
        new_refs = ctx.referenced - refs_before
        if new_refs:
            source = f"data.aws_iam_policy_document.{sorted(new_refs)[0]}"
    return {"role": role, "source": source, "line": line, "value": value, "notes": notes}
