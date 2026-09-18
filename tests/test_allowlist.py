# SPDX-License-Identifier: Apache-2.0
"""Allowlist config module: fail-closed load from explicit set, mapping, file, env."""

from __future__ import annotations

from pathlib import Path

import pytest

from supply_gate.allowlist import AllowlistError, load_allowlist
from supply_gate.origins import DEFAULT_ALLOWED_ORIGINS

ORIGIN_OK = "https://git.example.invalid/marketplace/community-plugins.git"
ORIGIN_SKILL = "https://git.example.invalid/agent-control-lab/skills.git"


def test_builtin_fallback_matches_stub_defaults() -> None:
    loaded = load_allowlist(use_env=False)
    assert loaded.source == "builtin"
    assert loaded.origins == DEFAULT_ALLOWED_ORIGINS
    assert loaded.contains(ORIGIN_OK)


def test_explicit_origins() -> None:
    loaded = load_allowlist(origins={ORIGIN_SKILL})
    assert loaded.source == "explicit"
    assert loaded.origins == frozenset({ORIGIN_SKILL})
    assert not loaded.contains(ORIGIN_OK)


def test_mapping_origins() -> None:
    loaded = load_allowlist(raw={"origins": [ORIGIN_OK, ORIGIN_SKILL]})
    assert loaded.source == "mapping"
    assert loaded.contains(ORIGIN_OK)
    assert loaded.contains(ORIGIN_SKILL)


def test_empty_origins_fail_closed() -> None:
    with pytest.raises(AllowlistError, match="empty"):
        load_allowlist(origins=[])


def test_whitespace_origin_fail_closed() -> None:
    with pytest.raises(AllowlistError, match="whitespace"):
        load_allowlist(origins=["https://git.example.invalid/ok.git and extra"])


def test_json_file_load(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(
        '{"origins": ["https://git.example.invalid/agent-control-lab/skills.git"]}\n',
        encoding="utf-8",
    )
    loaded = load_allowlist(path=path, use_env=False)
    assert loaded.source == "file"
    assert loaded.origins == frozenset({ORIGIN_SKILL})


def test_text_file_load_skips_comments(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.txt"
    path.write_text(
        "# comment\n\nhttps://git.example.invalid/agent-control-lab/skills.git\n",
        encoding="utf-8",
    )
    loaded = load_allowlist(path=path, use_env=False)
    assert loaded.origins == frozenset({ORIGIN_SKILL})


def test_missing_file_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError, match="unreadable"):
        load_allowlist(path=tmp_path / "missing.json", use_env=False)


def test_ill_formed_json_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(AllowlistError, match="ill-formed"):
        load_allowlist(path=path, use_env=False)


def test_env_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "from-env.json"
    path.write_text(
        '{"origins": ["https://git.example.invalid/agent-control-lab/skills.git"]}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(path))
    loaded = load_allowlist()
    assert loaded.source == "env"
    assert loaded.origins == frozenset({ORIGIN_SKILL})


def test_no_fallback_without_config_fail_closed() -> None:
    with pytest.raises(AllowlistError, match="no allowlist"):
        load_allowlist(use_env=False, fallback_builtin=False)
