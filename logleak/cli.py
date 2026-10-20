"""CLI entry point for logleak."""
import argparse
import json
import sys
from pathlib import Path

try:
    from .scanner import scan
except ImportError:  # running as a plain script
    from scanner import scan


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="logleak",
        description="Find log/print statements that may leak secrets or PII.",
    )
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--exit-code", action="store_true",
                    help="Exit with status 1 when findings exist.")
    args = ap.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 2

    findings = scan(root)
    # make paths relative for readability
    for fd in findings:
        try:
            fd["file"] = str(Path(fd["file"]).relative_to(root))
        except ValueError:
            pass

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("No potential secret/PII leaks in log statements found.")
        else:
            print(f"Found {len(findings)} potential leak(s):")
            for fd in findings:
                print(f"  {fd['file']}:{fd['line']}  ({fd['secret_term']})  {fd['snippet']}")

    if args.exit_code and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())