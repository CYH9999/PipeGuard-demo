"""Configuration: loads GITHUB_TOKEN from the environment or the repo's .env, never echoing it."""

import os
from pathlib import Path

from dotenv import dotenv_values

TOKEN_VAR = "GITHUB_TOKEN"

# The repository root (the folder above pipeguard/), so the path works on Windows and Linux
# no matter which folder the command is started from.
REPO_ROOT = Path(__file__).resolve().parent.parent
DOTENV_PATH = REPO_ROOT / ".env"


# --- Resource limits for reading untrusted files (security guidance rule 2, DECISIONS D5) ---
# Over a limit the file is reported as PG-W00 UNKNOWN ("not analysed"), never skipped silently.
MAX_FILE_BYTES = 1024 * 1024  # 1 MiB; real workflow files are a few KiB
MAX_WORKFLOW_FILES = 200  # per scan
MAX_TRUST_FILES = 500  # JSON + Terraform files per trust scan (repositories hold many JSON files)
MAX_YAML_NODES = 100_000  # nodes visited while expanding aliases (stops "billion laughs")
MAX_YAML_DEPTH = 64  # nesting depth of mappings/sequences
MAX_MAPPING_ENTRIES = 500  # roles in one .pipeguard.yml (Phase 3, DECISIONS D10)
MAX_MAPPING_PATH = 512  # characters of one mapped path
MAX_MAPPING_SEGMENTS = 32  # folders in one mapped path
# The linker tries (probes x policy values) matches; beyond these sizes one link could take minutes
# (measured: 300 values, 14.4 s). Over a limit the link is UNKNOWN (PG-L00), never computed partly.
MAX_LINK_SUB_VALUES = 50  # sub values in the GitHub statements of one trust policy
MAX_LINK_NEEDED = 50  # needed sub values (and patterns) of one role


class MissingTokenError(RuntimeError):
    """GITHUB_TOKEN is not set in the environment nor in .env."""


class InvalidTokenError(RuntimeError):
    """GITHUB_TOKEN is set but contains spaces or control characters (the value is never shown)."""


def _has_bad_characters(value):
    # A real token is one word of printable ASCII. A space, newline or control character
    # inside it would break the HTTP header or hint at a copy-paste mistake.
    return any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ord(ch) > 0x7E for ch in value)


def load_github_token(environ=None, dotenv_path=DOTENV_PATH):
    """Return the token. The environment wins; .env is read only if the variable is unset or empty.

    The .env file is read with dotenv_values(), which does NOT copy anything into os.environ,
    so the token is not inherited by child processes. Error messages never contain the value.
    """
    environ = os.environ if environ is None else environ
    value = (environ.get(TOKEN_VAR) or "").strip()
    if not value:
        path = Path(dotenv_path)
        if path.is_file():
            value = (dotenv_values(path).get(TOKEN_VAR) or "").strip()
    if not value:
        raise MissingTokenError(
            f"{TOKEN_VAR} is not set. Create a file named .env in the repository root with one "
            f"line: {TOKEN_VAR}=<your fine-grained, read-only token>. "
            "The token is never printed by PipeGuard."
        )
    if _has_bad_characters(value):
        raise InvalidTokenError(
            f"{TOKEN_VAR} contains a space or a control character. Re-create the .env line; "
            "the value is not shown here on purpose."
        )
    return value
