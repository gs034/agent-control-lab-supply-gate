# SPDX-License-Identifier: Apache-2.0
"""Lab-only brand wall: tree stays clean; planted keep-out tokens fail."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_brand_wall.py"
WRAPPER = ROOT / "scripts" / "check_lab_only.sh"


def _run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd or ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _path_without_rg() -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = "/usr/bin:/bin"
    return env


def test_current_tree_is_lab_only() -> None:
    proc = _run(env=_path_without_rg())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout


def test_plugin4shell_class_wording_is_allowed(tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("Plugin4Shell-class threat pattern\n", encoding="utf-8")
    proc = _run("--root", str(tmp_path), "--skip-git", env=_path_without_rg())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout


def test_planted_word_token_fails(tmp_path: Path) -> None:
    token = base64.b64decode("QUVHSVM=").decode("ascii")
    (tmp_path / "planted.txt").write_text(f"noise {token} noise\n", encoding="utf-8")
    proc = _run("--root", str(tmp_path), "--skip-git", env=_path_without_rg())
    assert proc.returncode == 1
    assert "keep-out" in proc.stdout


def test_planted_path_segment_fails(tmp_path: Path) -> None:
    segment = base64.b64decode("dGhpbmttb25leQ==").decode("ascii")
    nested = tmp_path / segment
    nested.mkdir()
    (nested / "readme.txt").write_text("lab\n", encoding="utf-8")
    proc = _run("--root", str(tmp_path), "--skip-git", env=_path_without_rg())
    assert proc.returncode == 1
    assert "path:" in proc.stdout


_EMAIL_DOMAIN_B64 = "dGhpbmttb25leS5jby51aw=="


def _keepout_domain() -> str:
    return base64.b64decode(_EMAIL_DOMAIN_B64).decode("ascii")


def _git(
    cwd: Path,
    *args: str,
    author: str = "lab@example.com",
    committer: str | None = None,
) -> str:
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_AUTHOR_NAME"] = "Lab"
    env["GIT_COMMITTER_NAME"] = "Lab"
    env["GIT_AUTHOR_EMAIL"] = author
    env["GIT_COMMITTER_EMAIL"] = committer or author
    proc = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        raise AssertionError(f"git {args[0]} failed: {proc.stderr}")
    return proc.stdout.strip()


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-b", "main")
    (path / "note.txt").write_text("lab\n", encoding="utf-8")
    _git(path, "add", "note.txt")
    _git(path, "commit", "-m", "lab note")
    _git(path, "update-ref", "refs/remotes/origin/main", "HEAD")


def test_keepout_email_domain_stays_packed() -> None:
    domain = _keepout_domain()
    script = SCRIPT.read_text(encoding="utf-8")
    assert domain not in script
    assert _EMAIL_DOMAIN_B64 in script
    assert domain not in Path(__file__).read_text(encoding="utf-8")


def test_author_email_domain_on_pr_range_fails(tmp_path: Path) -> None:
    domain = _keepout_domain()
    repo = tmp_path / "repo"
    _init_repo(repo)
    _git(repo, "checkout", "-b", "topic")
    (repo / "more.txt").write_text("lab\n", encoding="utf-8")
    _git(repo, "add", "more.txt")
    _git(repo, "commit", "-m", "lab follow-up", author=f"Person@{domain.upper()}")
    proc = _run("--root", str(repo), env=_path_without_rg())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "email:" in proc.stdout
    assert domain not in proc.stdout
    assert domain not in proc.stderr
    skipped = _run("--root", str(repo), "--skip-git", env=_path_without_rg())
    assert skipped.returncode == 0, skipped.stdout + skipped.stderr


def test_committer_email_subdomain_fails(tmp_path: Path) -> None:
    domain = _keepout_domain()
    repo = tmp_path / "repo"
    _init_repo(repo)
    _git(repo, "checkout", "-b", "topic")
    (repo / "more.txt").write_text("lab\n", encoding="utf-8")
    _git(repo, "add", "more.txt")
    _git(
        repo,
        "commit",
        "-m",
        "lab follow-up",
        author="lab@example.com",
        committer=f"ops@mail.{domain}",
    )
    proc = _run("--root", str(repo), env=_path_without_rg())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "email:" in proc.stdout


def test_lookalike_and_local_part_emails_pass(tmp_path: Path) -> None:
    domain = _keepout_domain()
    word = base64.b64decode("QUVHSVM=").decode("ascii")
    repo = tmp_path / "repo"
    _init_repo(repo)
    _git(repo, "checkout", "-b", "topic")
    for name, author in (
        ("a.txt", f"user@{domain}.example.net"),
        ("b.txt", f"user@not{domain}"),
        ("c.txt", f"{domain}@example.com"),
        ("d.txt", f"{word}@example.com"),
    ):
        (repo / name).write_text("lab\n", encoding="utf-8")
        _git(repo, "add", name)
        _git(repo, "commit", "-m", "lab follow-up", author=author)
    proc = _run("--root", str(repo), env=_path_without_rg())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout


def test_push_to_main_scans_before_range_not_unrelated_history(tmp_path: Path) -> None:
    domain = _keepout_domain()
    repo = tmp_path / "repo"
    _init_repo(repo)
    root = _git(repo, "rev-parse", "HEAD")
    (repo / "mid.txt").write_text("lab\n", encoding="utf-8")
    _git(repo, "add", "mid.txt")
    _git(repo, "commit", "-m", "lab follow-up", author=f"person@{domain}")
    (repo / "tip.txt").write_text("lab\n", encoding="utf-8")
    _git(repo, "add", "tip.txt")
    _git(repo, "commit", "-m", "lab tip")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    tip_only = _run("--root", str(repo), env=_path_without_rg())
    assert tip_only.returncode == 0, tip_only.stdout + tip_only.stderr

    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": root}), encoding="utf-8")
    env = _path_without_rg()
    env["GITHUB_EVENT_NAME"] = "push"
    env["GITHUB_EVENT_PATH"] = str(event)
    pushed = _run("--root", str(repo), env=env)
    assert pushed.returncode == 1, pushed.stdout + pushed.stderr
    assert "email:" in pushed.stdout

    side = tmp_path / "side"
    _init_repo(side)
    _git(side, "checkout", "-b", "other")
    (side / "other.txt").write_text("lab\n", encoding="utf-8")
    _git(side, "add", "other.txt")
    _git(side, "commit", "-m", "lab follow-up", author=f"person@{domain}")
    _git(side, "checkout", "main")
    untouched = _run("--root", str(side), env=_path_without_rg())
    assert untouched.returncode == 0, untouched.stdout + untouched.stderr


def test_main_tip_fallback_catches_keepout_email(tmp_path: Path) -> None:
    domain = _keepout_domain()
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "tip.txt").write_text("lab\n", encoding="utf-8")
    _git(repo, "add", "tip.txt")
    _git(repo, "commit", "-m", "lab tip", committer=f"person@{domain}")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    proc = _run("--root", str(repo), env=_path_without_rg())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "email:" in proc.stdout


def test_wrapper_is_stdlib_python_without_rg() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'which("rg")' not in source
    assert "command -v rg" not in source
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert "lab_brand_wall.py" in wrapper
    assert "command -v rg" not in wrapper
    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=_path_without_rg(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout
