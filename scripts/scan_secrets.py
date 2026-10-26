"""Fail a change when an added line looks like a committed secret.

The scanner is intentionally conservative: it looks at added diff lines only,
ignores obvious documentation placeholders, and reports a redacted preview.
It is a safety net, not a replacement for a managed secret store or a
full-history scanner such as gitleaks.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

PLACEHOLDERS = (
    "example",
    "placeholder",
    "changeme",
    "change-me",
    "your-",
    "your_",
    "replace-me",
    "dummy",
    "local-demo",
    "not-for-production",
    "redacted",
    "***",
    "<",
    ">",
    "${",
    "${{",
)

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("supabase-secret", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b")),
    (
        "postgres-url-password",
        re.compile(r"postgres(?:ql)?(?:\+psycopg)?://[^:\s]+:([^@\s]{8,})@"),
    ),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|passwd|token|"
            r"client[_-]?secret|private[_-]?key)\b\s*[:=]\s*"
            r"['\"]?([^\s'\"#]{12,})"
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    kind: str
    preview: str


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDERS):
        return True
    if lowered in {"none", "null", "true", "false", "optional", "required"}:
        return True
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def scan_line(path: str, number: int, line: str) -> list[Finding]:
    findings: list[Finding] = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(line):
            if kind == "credential-assignment":
                value = match.group(2)
            elif match.lastindex:
                value = match.group(1)
            else:
                value = match.group(0)
            if kind == "credential-assignment" and _is_placeholder(value):
                continue
            if kind == "postgres-url-password" and _is_placeholder(value):
                continue
            findings.append(
                Finding(
                    file=path,
                    line=number,
                    kind=kind,
                    preview=_redact(value),
                )
            )
    return findings


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(path, number, line))
    return findings


def _added_lines(diff: str):
    path = ""
    number = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                number = int(match.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield path, number, line[1:]
            number += 1
        elif line.startswith(" "):
            number += 1


def scan_diff(diff: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, number, line in _added_lines(diff):
        findings.extend(scan_line(path, number, line))
    return findings


def _git_diff(args: list[str]) -> str:
    result = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    return result.stdout


def _scan_files(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for value in paths:
        path = Path(value)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(value, text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="scan staged changes")
    parser.add_argument("--range", dest="revision_range", help="git revision range")
    parser.add_argument("--files", nargs="*", help="scan whole files instead of a diff")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.files:
        findings = _scan_files(args.files)
    elif args.revision_range:
        findings = scan_diff(_git_diff([args.revision_range]))
    else:
        findings = scan_diff(_git_diff(["--cached"]))

    payload = {"ok": not findings, "findings": [asdict(item) for item in findings]}
    if args.json:
        print(json.dumps(payload, indent=2))
    elif findings:
        for item in findings:
            print(f"{item.file}:{item.line}: {item.kind}: {item.preview}")
    else:
        print("No added-line secrets detected.")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
