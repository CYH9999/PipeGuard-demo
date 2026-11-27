"""Output sanitization: scanned text is made harmless before printing (security guidance rule 5).

Every control character (C0 0x00-0x1f including newline and tab, DEL 0x7f, C1 0x80-0x9f) and every
Unicode bidirectional-override character in a scanned value is replaced by a visible escape such as
`\\x1b` or `\\u202e`. So an ANSI sequence (ESC [ 2 J) prints as the harmless text `\\x1b[2J`, and a
scanned value cannot start a fake output line. Stricter than "strip": nothing disappears unseen.
"""

_BIDI = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}


def _escape(ch):
    code = ord(ch)
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return f"\\x{code:02x}"
    if code in _BIDI:
        return f"\\u{code:04x}"
    return ch


def clean(text):
    """Return `text` with every control / bidi character replaced by a visible escape."""
    text = str(text)
    if all(0x20 <= ord(c) < 0x7F for c in text):  # fast path: plain printable ASCII
        return text
    return "".join(_escape(c) for c in text)


def clean_tree(value):
    """Clean every string (keys too) inside dicts and lists; other values are returned as is."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        return {clean(k): clean_tree(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_tree(v) for v in value]
    return value
