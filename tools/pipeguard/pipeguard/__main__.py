"""Command line:
    python -m pipeguard scan-workflows PATH [--repo OWNER/REPO] [--json]   (Phase 1)
    python -m pipeguard scan-trust PATH [--json]                          (Phase 2)
    python -m pipeguard scan PATH --repo OWNER/REPO [--json]              (Phase 3, linker)
    python -m pipeguard fix PATH --repo OWNER/REPO --out DIR [--owner-id N --repo-id N]
                            [--resolve-pins] [--force]                    (Phase 4, fixer)
    python -m pipeguard gate PATH --repo OWNER/REPO [--fail-on critical|high|medium|low]
                             [--allow-unknown] [--format text|json|github] (Phase 4, gate)

scan-workflows / scan-trust / scan: exit 0 whatever is found; 2 for a usage error.
fix: 0 files written; 2 usage error or refusal (output folder, existing files, token); 3 internal error.
gate: 0 pass; 1 a finding at or above --fail-on; 2 UNKNOWN without --allow-unknown; 3 usage or
internal error (DECISIONS D12). A crash never exits 0.
"""

import argparse
import json
import sys
from pathlib import Path

from pipeguard import config, fixer, gate, linker, trust_analyzer, workflow_analyzer
from pipeguard.output import clean, clean_tree


def _parser():
    parser = argparse.ArgumentParser(prog="python -m pipeguard",
                                     description="PipeGuard: static GitHub Actions -> AWS audit.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan-workflows", help="analyse GitHub Actions workflow files")
    scan.add_argument("path", help="a workflow file, a repository folder or a workflows folder")
    scan.add_argument("--repo", help="OWNER/REPO used in expected sub claims (default OWNER/REPO)")
    scan.add_argument("--json", action="store_true", help="machine-readable JSON output")
    trust = commands.add_parser("scan-trust", help="analyse IAM trust policies (JSON, Terraform)")
    trust.add_argument("path", help="a JSON / .tf file or a folder (searched recursively)")
    trust.add_argument("--json", action="store_true", help="machine-readable JSON output")
    both = commands.add_parser("scan", help="link the workflows and trust policies of one repository")
    both.add_argument("path", help="the repository folder")
    both.add_argument("--repo", required=True, help="OWNER/REPO used in expected sub claims")
    both.add_argument("--json", action="store_true", help="machine-readable JSON output")
    fix = commands.add_parser("fix", help="write a narrowed trust policy and workflow patches to DIR")
    fix.add_argument("path", help="the repository folder (never modified)")
    fix.add_argument("--repo", required=True, help="OWNER/REPO used in the sub claims")
    fix.add_argument("--out", required=True, help="output folder (must not overlap PATH)")
    fix.add_argument("--owner-id", help="numeric GitHub owner ID (immutable sub format; with --repo-id)")
    fix.add_argument("--repo-id", help="numeric GitHub repository ID (immutable sub format)")
    fix.add_argument("--resolve-pins", action="store_true",
                     help="resolve tag/branch refs to commit SHAs through api.github.com (network)")
    fix.add_argument("--force", action="store_true", help="overwrite existing files in DIR")
    g = commands.add_parser("gate", help="CI gate: exit non-zero on findings at or above a threshold")
    g.add_argument("path", help="the repository folder")
    g.add_argument("--repo", required=True, help="OWNER/REPO used in expected sub claims")
    g.add_argument("--fail-on", choices=gate.LEVELS, default="high",
                   help="lowest severity that fails the gate (default: high)")
    g.add_argument("--allow-unknown", action="store_true",
                   help="report UNKNOWN (cannot verify) as a warning instead of failing (exit 2)")
    g.add_argument("--format", choices=sorted(gate.FORMATS), default="text",
                   help="text (default), json, or github (workflow-command annotations)")
    return parser


def _safe_stdout():
    # A redirected stdout on Windows may use a code page that cannot encode every character.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        # The gate must never confuse a usage error with "findings" (1) or "unknown" (2): exit 3.
        if argv[:1] == ["gate"] and exc.code not in (0, None):
            return gate.EXIT_ERROR
        raise
    _safe_stdout()
    if args.command == "gate":
        try:
            return _gate(args)
        except Exception as exc:  # fail closed: a crash never exits 0 (no traceback text printed)
            print(f"error: internal error in gate ({type(exc).__name__}); exit 3", file=sys.stderr)
            return gate.EXIT_ERROR
    if args.command == "scan-trust":
        return _scan_trust(args)
    if args.command == "scan":
        return _scan(args)
    if args.command == "fix":
        try:
            return _fix(args)
        except Exception as exc:  # never exit 0 on a crash; no traceback text (it may hold paths)
            print(f"error: internal error in fix ({type(exc).__name__}); nothing more was written",
                  file=sys.stderr)
            return 3
    try:
        repo = workflow_analyzer.check_repo(args.repo)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path = Path(args.path)
    if not path.exists() and not path.is_symlink():
        print(f"error: path not found: {clean(args.path)}", file=sys.stderr)
        return 2
    result = workflow_analyzer.scan(path, repo=None if args.repo is None else repo)
    if args.json:
        print(json.dumps(clean_tree(result), indent=2, ensure_ascii=True))
    else:
        print(workflow_analyzer.format_text(result))
    return 0


def _scan_trust(args):
    path = Path(args.path)
    if not path.exists() and not path.is_symlink():
        print(f"error: path not found: {clean(args.path)}", file=sys.stderr)
        return 2
    result = trust_analyzer.scan(path)
    if args.json:
        print(json.dumps(clean_tree(result), indent=2, ensure_ascii=True))
    else:
        print(trust_analyzer.format_text(result))
    return 0


def _scan(args):
    try:
        repo = workflow_analyzer.check_repo(args.repo)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path = Path(args.path)
    if not path.is_dir():
        print(f"error: PATH must be a repository folder: {clean(args.path)}", file=sys.stderr)
        return 2
    result = linker.scan(path, repo)
    if args.json:
        print(json.dumps(clean_tree(result), indent=2, ensure_ascii=True))
    else:
        print(linker.format_text(result))
    return 0


def _gate(args):
    try:
        repo = workflow_analyzer.check_repo(args.repo)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return gate.EXIT_ERROR
    path = Path(args.path)
    if not path.is_dir():
        print(f"error: PATH must be a repository folder: {clean(args.path)}", file=sys.stderr)
        return gate.EXIT_ERROR
    code, text = gate.run(path, repo, args.fail_on, args.allow_unknown, args.format)
    print(text)
    return code


def _fix(args):
    try:
        plan = fixer.plan(Path(args.path), args.repo, owner_id=args.owner_id, repo_id=args.repo_id,
                          resolve_pins=args.resolve_pins)
    except ValueError as exc:
        print(f"error: {clean(str(exc))}", file=sys.stderr)
        return 2
    except (config.MissingTokenError, config.InvalidTokenError) as exc:
        print(f"error: --resolve-pins needs GITHUB_TOKEN: {exc}", file=sys.stderr)
        return 2
    try:
        written = fixer.write(plan, Path(args.path), Path(args.out), force=args.force)
    except fixer.FixRefused as exc:
        print(f"error: {clean(str(exc))}; nothing was written", file=sys.stderr)
        return 2
    print(f"PipeGuard fix: {len(written)} file(s) written to {clean(args.out)} (the scanned folder was "
          "not modified; nothing was applied):")
    for name in written:
        print(f"  {clean(name)}")
    print(plan["files"]["SUMMARY.txt"].rstrip().splitlines()[-1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
