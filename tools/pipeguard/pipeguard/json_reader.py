"""Strict JSON reading for untrusted trust policies, with line numbers (Phase 2, DECISIONS D7).

1. The text is first parsed with Python's `json` module in strict mode: a duplicate key is
   rejected (Datadog Security Labs reported a duplicate `StringEquals` key that silently dropped
   the `sub` check), NaN/Infinity are rejected, and a too-deep document is rejected (no crash).
2. The same text is then read by `pipeguard.safe_yaml` (JSON is valid YAML 1.2; compose only, with
   the same limits) only to obtain line numbers. If that second reading fails, the JSON value is
   used without line numbers. The content always comes from the strict JSON parse.
"""

import json

from pipeguard import config
from pipeguard.safe_yaml import YamlRejected, YMap, YSeq, YStr, load


class JsonRejected(Exception):
    """The text is not analysed. `reason` is a short English sentence."""

    def __init__(self, reason, line=None):
        super().__init__(reason)
        self.reason = reason
        self.line = line


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise JsonRejected(f"duplicate key '{key}' in a JSON object; a duplicate can hide a value")
        out[key] = value
    return out


def _no_constants(name):
    raise JsonRejected(f"JSON constant {name} is not allowed")


def _plain_to_lined(value):
    """Turn plain JSON values into YMap / YSeq / YStr (without lines)."""
    if isinstance(value, dict):
        out = YMap()
        for key, item in value.items():
            out[YStr(key)] = _plain_to_lined(item)
            out.key_lines[key] = None
        return out
    if isinstance(value, list):
        out = YSeq()
        for item in value:
            out.append(_plain_to_lined(item))
            out.item_lines.append(None)
        return out
    if value is None:
        return None
    if isinstance(value, bool):
        return YStr("true" if value else "false")
    return YStr(value)


def _shift(value, offset):
    """Add `offset` to every recorded line (JSON embedded in a Terraform heredoc)."""
    if not offset:
        return value
    if isinstance(value, YMap):
        value.line = value.line + offset if value.line else value.line
        for key in list(value.key_lines):
            if value.key_lines[key]:
                value.key_lines[key] += offset
        for item in value.values():
            _shift(item, offset)
    elif isinstance(value, YSeq):
        value.line = value.line + offset if value.line else value.line
        value.item_lines = [ln + offset if ln else ln for ln in value.item_lines]
        for item in value:
            _shift(item, offset)
    elif isinstance(value, YStr) and value.line:
        value.line += offset
    return value


def load_json(text, line_offset=0):
    """Parse `text` strictly; return the value as YMap/YSeq/YStr/None with line numbers when
    available. Raise JsonRejected for anything that is not plain, strict JSON."""
    try:
        plain = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except JsonRejected:
        raise
    except RecursionError:
        raise JsonRejected("JSON nesting too deep") from None
    except ValueError as exc:
        line = getattr(exc, "lineno", None)
        raise JsonRejected(f"not valid JSON ({getattr(exc, 'msg', 'parse error')})", line) from None
    if _depth(plain) > config.MAX_YAML_DEPTH:
        # Python's json accepts nesting up to its recursion limit; our recursive helpers would not
        # (security review 2026-11-26). Checked iteratively, before any recursive code runs.
        raise JsonRejected(f"JSON nesting deeper than {config.MAX_YAML_DEPTH} levels")
    try:
        lined = load(text)
    except (YamlRejected, RecursionError):
        lined = None
    if lined is None or not _same(lined, plain):
        lined = _plain_to_lined(plain)
    return _shift(lined, line_offset)


def _depth(value):
    """Maximum nesting depth of a JSON value, computed without recursion."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, (dict, list)):
            deepest = max(deepest, level)
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, level + 1) for child in children)
    return deepest


def _same(lined, plain):
    """True when the YAML reading has the same structure and text as the strict JSON reading."""
    if isinstance(plain, dict):
        return (isinstance(lined, YMap) and list(lined.keys()) == list(plain.keys())
                and all(_same(lined[k], plain[k]) for k in plain))
    if isinstance(plain, list):
        return (isinstance(lined, YSeq) and len(lined) == len(plain)
                and all(_same(a, b) for a, b in zip(lined, plain)))
    if plain is None:
        return lined is None
    if isinstance(plain, bool):
        return lined == ("true" if plain else "false")
    if isinstance(plain, str):
        return isinstance(lined, str) and str(lined) == plain
    return isinstance(lined, str)  # numbers: only used as text
