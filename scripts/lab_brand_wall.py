#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lab-only keep-out wall (stdlib only; no ripgrep).

Fails if commercial or bank brand tokens, SKU language, or those source
paths appear in the checkout, file paths, current branch name, or commit
subjects on this branch. Author and committer emails on that same commit
range fail when the mailbox domain is a keep-out suffix. The keep-out list
is packed so this tree stays Lab-branded. Plugin4Shell-class threat-pattern
wording is not a keep-out.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Packed keep-out list. Do not decode into comments or docs.
_WORD = (
    "QUVHSVM=",
    "Q2FwU2NvcGU=",
    "QUdG",
    "Q3lnbmV0UXVhbnQ=",
    "U2lnbmV0",
    "U2lnbmV0UXVhbnQ=",
    "RXhjYWxpVkFS",
    "QUlQVEg=",
    "dGhpbmttb25leQ==",
    "RmFsY29u",
    "UElQRUxJTkU=",
    "Q1E=",
)
_PHRASE = (
    "Q3lnbmV0IFF1YW50",
    "U2lnbmV0IFF1YW50",
    "VGhpbmsgTW9uZXk=",
    "SVAtdHJhbnNmZXI=",
    "YWNxdWlyZWQtZnJvbQ==",
)
_PATH_PART = (
    "Y3lnbmV0cXVhbnQ=",
    "dGhpbmttb25leQ==",
)
# Packed keep-out mailbox domains. Suffix-matched; do not decode into comments.
_EMAIL_DOMAIN = ("dGhpbmttb25leS5jby51aw==",)

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".eggs",
        "dist",
        "build",
        "htmlcov",
        ".mypy_cache",
    }
)


def _decode(packed: tuple[str, ...]) -> list[str]:
    return [base64.b64decode(item).decode("ascii") for item in packed]


def _search(root: Path, pattern: str, *, word: bool) -> list[str]:
    needle = (
        re.compile(rf"(?i)\b{re.escape(pattern)}\b")
        if word
        else re.compile(re.escape(pattern), re.I)
    )
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIR_NAMES and not name.endswith(".egg-info")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            rel = path.resolve().relative_to(root.resolve())
            for lineno, line in enumerate(text.splitlines(), start=1):
                if needle.search(line):
                    hits.append(f"{rel.as_posix()}:{lineno}:{line}")
    return hits


def _path_hits(root: Path) -> list[str]:
    parts = [item.lower() for item in _decode(_PATH_PART)]
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIR_NAMES and not name.endswith(".egg-info")
        ]
        rel_dir = Path(dirpath).resolve().relative_to(root.resolve())
        chunks = [p.lower() for p in rel_dir.parts]
        for name in filenames:
            rel = rel_dir / name if rel_dir != Path(".") else Path(name)
            segs = chunks + [name.lower()]
            lowered = str(rel).replace("\\", "/").lower()
            if any(part in segs or part in lowered for part in parts):
                hits.append(f"path:{rel.as_posix()}")
    return hits


def _text_hits(label: str, text: str) -> list[str]:
    hits: list[str] = []
    if not text:
        return hits
    for token in _decode(_WORD):
        if re.search(rf"(?i)\b{re.escape(token)}\b", text):
            hits.append(f"{label}: word-token")
            break
    for phrase in _decode(_PHRASE):
        if phrase.lower() in text.lower():
            hits.append(f"{label}: phrase-token")
            break
    return hits


def _git_output(root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _rev_ok(root: Path, rev: str) -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", rev],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _range_nonempty(root: Path, spec: str) -> bool:
    raw = _git_output(root, ["rev-list", "--count", spec]).strip()
    return raw.isdigit() and int(raw) > 0


def _push_before_spec(root: Path) -> str | None:
    """Actions ``before..HEAD`` when a direct main push leaves the PR range empty."""
    if os.environ.get("GITHUB_EVENT_NAME") != "push":
        return None
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    before = payload.get("before")
    if not isinstance(before, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", before):
        return None
    if set(before) == {"0"}:
        return None
    if not _rev_ok(root, before):
        return None
    return f"{before}..HEAD"


def _git_log_revs(root: Path) -> list[str]:
    """Revision args for the PR range, the push range, or the main tip.

    Prefer ``origin/main..HEAD`` (then ``main..HEAD``) when that range is
    non-empty. A direct push to main checks out with HEAD already equal to
    main, so that range is empty: use the Actions push range when ``before``
    is in the clone, otherwise the last commit (the subject-scan fallback).
    """
    for base in ("origin/main", "main"):
        if _rev_ok(root, base):
            spec = f"{base}..HEAD"
            if _range_nonempty(root, spec):
                return [spec]
            break
    pushed = _push_before_spec(root)
    if pushed and _range_nonempty(root, pushed):
        return [pushed]
    return ["-1"]


def _host_is_keepout(host: str, domains: list[str]) -> bool:
    host = host.lower().strip().rstrip(".")
    if not host:
        return False
    for domain in domains:
        needle = domain.lower().strip().rstrip(".")
        if not needle:
            continue
        if host == needle or host.endswith("." + needle):
            return True
    return False


def _address_is_keepout(address: str, domains: list[str]) -> bool:
    text = address.strip().lower()
    if "@" not in text:
        return False
    host = text.rsplit("@", 1)[1].strip().rstrip(">")
    return _host_is_keepout(host, domains)


def _git_ref_hits(root: Path) -> list[str]:
    hits: list[str] = []
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or ""
    if not branch:
        branch = _git_output(root, ["branch", "--show-current"]).strip()
    hits.extend(_text_hits("branch", branch))
    subjects = _git_output(root, ["log", *_git_log_revs(root), "--format=%s%n%b"])
    hits.extend(_text_hits("commit", subjects))
    return hits


def _git_email_hits(root: Path) -> list[str]:
    domains = _decode(_EMAIL_DOMAIN)
    raw = _git_output(root, ["log", *_git_log_revs(root), "--format=%ae%n%ce"])
    for line in raw.splitlines():
        if _address_is_keepout(line, domains):
            return ["email: domain-token"]
    return []


def scan(root: Path, *, include_git: bool = True) -> list[str]:
    hits: list[str] = []
    for token in _decode(_WORD):
        hits.extend(_search(root, token, word=True))
    for phrase in _decode(_PHRASE):
        hits.extend(_search(root, phrase, word=False))
    hits.extend(_path_hits(root))
    if include_git:
        hits.extend(_git_ref_hits(root))
        hits.extend(_git_email_hits(root))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lab-only brand wall")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--skip-git", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        hits = scan(root, include_git=not args.skip_git)
    except RuntimeError as exc:
        print(f"LAB BRAND WALL ERROR: {exc}", file=sys.stderr)
        return 2
    if hits:
        print("LAB BRAND WALL: commercial/bank keep-out hit. Lab-only artefacts only.")
        for line in hits:
            print(line)
        return 1
    print("LAB BRAND WALL: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
