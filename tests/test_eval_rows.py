# SPDX-License-Identifier: Apache-2.0
"""v0.3 existence-proof DENY rows on the host adapter path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from supply_gate.adapters import LocalWorktreeAdapter, gated_install_or_update
from supply_gate.reasons import DenyReason, Verdict

ROOT = Path(__file__).resolve().parents[1]
M1B_ROWS = (
    "omitted_adapter_head",
    "unreadable_allowlist",
    "trust_ref_rejected",
    "auto_latest_rejected",
)


def _run_row(name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    base = ROOT / "eval" / name
    envelope = json.loads((base / "envelope.json").read_text(encoding="utf-8"))
    observed = json.loads((base / "observed_head.json").read_text(encoding="utf-8")).get(
        "observed_head"
    )
    if observed is not None and not isinstance(observed, str):
        observed = None
    kwargs: dict[str, Any] = {}
    policy_path = base / "update_policy.json"
    allowlist_path = base / "allowlist.json"
    if policy_path.is_file():
        kwargs["update_policy_path"] = policy_path
    if allowlist_path.is_file():
        kwargs["allowlist_path"] = allowlist_path
    decision = gated_install_or_update(
        envelope,
        LocalWorktreeAdapter(observed),
        **kwargs,
    )
    expected = json.loads(
        (base / "expected_deny_receipt.example.json").read_text(encoding="utf-8")
    )
    return decision.receipt, expected


def test_m1b_rows_are_deterministic_deny() -> None:
    for name in M1B_ROWS:
        receipt, expected = _run_row(name)
        assert receipt == expected, name
        assert receipt["decision"] == Verdict.DENY.value
        assert receipt["brand"] == "Agent Control Lab"
        assert receipt["prose_used_as_policy"] is False


def test_omitted_adapter_head_reason() -> None:
    receipt, _ = _run_row("omitted_adapter_head")
    assert receipt["reasons"] == [DenyReason.VERIFY_MISSING.value]
    assert receipt["verify_performed"] is False


def test_unreadable_allowlist_reason() -> None:
    receipt, _ = _run_row("unreadable_allowlist")
    assert DenyReason.ALLOWLIST_INVALID.value in receipt["reasons"]
    assert receipt["verify_performed"] is True


def test_trust_ref_rejected_reason() -> None:
    receipt, _ = _run_row("trust_ref_rejected")
    assert receipt["reasons"] == [DenyReason.UPDATE_POLICY_REJECTED.value]
    assert receipt["verify_performed"] is True


def test_auto_latest_rejected_reason() -> None:
    receipt, _ = _run_row("auto_latest_rejected")
    assert receipt["reasons"] == [DenyReason.UPDATE_POLICY_REJECTED.value]
    assert receipt["verify_performed"] is True
