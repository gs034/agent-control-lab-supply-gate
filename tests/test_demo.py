# SPDX-License-Identifier: Apache-2.0
"""CLI demo: Plugin4Shell-class DENY."""

from __future__ import annotations

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
