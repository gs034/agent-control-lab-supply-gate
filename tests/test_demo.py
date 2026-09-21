# SPDX-License-Identifier: Apache-2.0
"""CLI demo: Plugin4Shell-class DENY."""

from __future__ import annotations

from pathlib import Path

import pytest

from supply_gate.demo import main


def test_demo_main_exits_deny(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([])
    captured = capsys.readouterr()
    assert code == 1
    assert '"decision": "DENY"' in captured.out
    assert "head_mismatch" in captured.out
    assert "prose_rejected_as_policy" in captured.out
    assert "Agent Control Lab" in captured.out


def test_demo_fixture_ignores_ambient_host_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allowlist = tmp_path / "exclude-fixture-origin.json"
    allowlist.write_text(
        '{"origins": ["https://git.example.invalid/agent-control-lab/skills.git"]}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(allowlist))
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    code = main([])
    captured = capsys.readouterr()
    assert code == 1
    assert '"decision": "DENY"' in captured.out
    assert "origin_not_allowlisted" not in captured.out
    assert '"kill_active": false' in captured.out
    assert "head_mismatch" in captured.out
    assert "prose_rejected_as_policy" in captured.out
