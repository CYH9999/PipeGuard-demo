"""Safe YAML reading for untrusted workflow files: parse, never construct (DECISIONS D5).

How it works, and why:
- ruamel.yaml in SAFE mode is asked only to *compose* the document: it returns a tree of nodes
  (mapping / sequence / scalar) with line numbers. It never builds Python objects from tags, so a
  tag like `!!python/object/apply:...` is just a label on a node; nothing is imported or run.
- We then walk that tree ourselves and build plain data:
  * every scalar becomes text (`YStr`, a str that remembers its line); `null` becomes None.
    Keys are taken as their literal text, so the key `on` stays "on" even if a `%YAML 1.1`
    directive would make a YAML 1.1 resolver read it as the boolean True.
  * mappings become `YMap` (a dict with `.line` and `.key_lines`), sequences `YSeq`.
- While walking we enforce the limits: a duplicate key, a merge key (`<<`), a recursive alias,
  too many nodes (alias bomb) or too deep nesting raises YamlRejected. The analyzer reports that
  as PG-W00 UNKNOWN: never a crash, never a silently dropped value.
"""

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode

from pipeguard import config

NULL_TAG = "tag:yaml.org,2002:null"
MERGE_TAG = "tag:yaml.org,2002:merge"


class YamlRejected(Exception):
    """The file is not analysed. `reason` is a short English sentence; `line` is 1-based or None."""

    def __init__(self, reason, line=None):
        super().__init__(reason)
        self.reason = reason
        self.line = line


class YStr(str):
    """A scalar's text plus where it is in the file (1-based line; end column is 0-based)."""

    line = None
    end_line = None
    end_col = None


class YMap(dict):
    """A mapping plus its own line and the line of every key."""

    line = None

    def __init__(self):
        super().__init__()
        self.key_lines = {}


class YSeq(list):
    """A sequence plus its own line and the line of every item."""

    line = None

    def __init__(self):
        super().__init__()
        self.item_lines = []


def _line(node):
    return node.start_mark.line + 1


class _Walker:
    def __init__(self, max_nodes, max_depth):
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.count = 0
        self.active = set()  # ids of the nodes on the current path (to find recursive aliases)

    def build(self, node, depth):
        self.count += 1
        if self.count > self.max_nodes:
            raise YamlRejected(
                f"YAML node limit exceeded (more than {self.max_nodes} nodes after following "
                "aliases; possible alias bomb)", _line(node))
        if depth > self.max_depth:
            raise YamlRejected(f"YAML nesting depth limit exceeded ({self.max_depth})", _line(node))
        if isinstance(node, ScalarNode):
            return self._scalar(node)
        if id(node) in self.active:
            raise YamlRejected("recursive YAML alias (a node contains itself)", _line(node))
        self.active.add(id(node))
        try:
            if isinstance(node, MappingNode):
                return self._mapping(node, depth)
            if isinstance(node, SequenceNode):
                return self._sequence(node, depth)
        finally:
            self.active.discard(id(node))
        raise YamlRejected("unsupported YAML node", _line(node))

    @staticmethod
    def _scalar(node):
        if node.tag == NULL_TAG:
            return None
        value = YStr(node.value)
        value.line = _line(node)
        value.end_line = node.end_mark.line + 1
        value.end_col = node.end_mark.column
        return value

    def _mapping(self, node, depth):
        out = YMap()
        out.line = _line(node)
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                raise YamlRejected("a mapping key is not a plain value", _line(key_node))
            if key_node.tag == MERGE_TAG:
                raise YamlRejected(
                    "YAML merge key (<<) is not resolved by PipeGuard", _line(key_node))
            key = YStr(key_node.value)  # literal text, whatever tag a resolver gave it
            key.line = _line(key_node)
            if key in out:
                raise YamlRejected(
                    f"duplicate key '{key}' (first at line {out.key_lines[key]}); "
                    "a duplicate can hide a value", key.line)
            self.count += 1
            out[key] = self.build(value_node, depth + 1)
            out.key_lines[key] = key.line
        return out

    def _sequence(self, node, depth):
        out = YSeq()
        out.line = _line(node)
        for item in node.value:
            out.append(self.build(item, depth + 1))
            out.item_lines.append(_line(item))
        return out


def load(text, max_nodes=None, max_depth=None):
    """Parse one YAML document from `text` into plain data with line numbers, or raise YamlRejected.

    Returns None for an empty document (only comments or nothing).
    """
    max_nodes = config.MAX_YAML_NODES if max_nodes is None else max_nodes
    max_depth = config.MAX_YAML_DEPTH if max_depth is None else max_depth
    yaml = YAML(typ="safe", pure=True)  # a new parser per file: no state shared between files
    try:
        root = yaml.compose(text)
    except RecursionError:
        raise YamlRejected("YAML nesting too deep for the parser") from None
    except YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line = mark.line + 1 if mark is not None else None
        problem = getattr(exc, "problem", None) or "invalid YAML"
        raise YamlRejected(f"YAML syntax error: {problem}", line) from None
    if root is None:
        return None
    return _Walker(max_nodes, max_depth).build(root, 0)
