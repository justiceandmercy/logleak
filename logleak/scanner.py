"""Core scanning logic for logleak."""
import os
import re
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next",
             "out", "vendor", "target", "__pycache__", ".venv", "venv"}
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
               ".php", ".cs", ".kt", ".rs", ".swift"}

SENSITIVE = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "api-key", "access_key", "private_key", "credential", "credentials",
    "ssn", "social_security", "credit_card", "card_number", "cvv",
    "auth_token", "session_id", "cookie", "bearer", "jwt", "refresh_token",
    "client_secret", "db_password", "database_password",
]

# Patterns that indicate a logging/print call on a line.
LOG_PATTERNS = [
    re.compile(r"\bconsole\.(log|debug|info|warn|error|trace)\b", re.I),
    re.compile(r"\blogger\.\w+\b", re.I),
    re.compile(r"\blogging\.\w+\b", re.I),
    re.compile(r"\blog\.\w+\b", re.I),
    re.compile(r"\bprint\s*\(", re.I),
    re.compile(r"\bputs\s*\(", re.I),
    re.compile(r"\bfmt\.Print", re.I),
    re.compile(r"\bprintln!\s*\(", re.I),
    re.compile(r"\btracing::\w+", re.I),
    re.compile(r"\bSystem\.out\.print", re.I),
]

SENSITIVE_RE = re.compile(
    r"\b(" + "|".join(re.escape(s) for s in SENSITIVE) + r")\b", re.I
)


def collect_files(root):
    out = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if Path(fn).suffix in SOURCE_EXTS:
                out.append(Path(dirpath) / fn)
    return out


def scan_file(path):
    findings = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return findings
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        if not any(p.search(line) for p in LOG_PATTERNS):
            continue
        m = SENSITIVE_RE.search(line)
        if not m:
            continue
        # avoid flagging the sensitive word only inside a string that is a key name in a safe context? keep simple
        findings.append({
            "file": str(path),
            "line": i,
            "secret_term": m.group(1),
            "snippet": line.strip()[:200],
        })
    return findings


def scan(root):
    results = []
    for f in collect_files(root):
        results.extend(scan_file(f))
    return results