# SPDX-License-Identifier: Apache-2.0
"""v0.3.1 M1b corpus rows on the host adapter path."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from supply_gate.adapters import LocalWorktreeAdapter, gated_install_or_update
from supply_gate.allowlist import load_allowlist
from supply_gate.reasons import DenyReason, Verdict
from supply_gate.update_policy import UpdatePolicy

ROOT = Path(__file__).resolve().parents[1]
DENY_ROWS = (
    "omitted_adapter_head",
    "unreadable_allowlist",
    "trust_ref_rejected",
    "auto_latest_rejected",
    "prose_waive_attempt",
)
ALLOW_ROWS = ("allow_pin_and_verify",)
# Host env that must not leak into recorded fixture receipts.
AMBIENT_HOST_ENV = (
    "ACL_SUPPLY_GATE_ALLOWLIST",
    "ACL_SUPPLY_GATE_KILL",
    "ACL_SUPPLY_GATE_UPDATE_POLICY",
)


def _row_kwargs(base: Path) -> dict[str, Any]:
    """Explicit fixture inputs. Never fall through to ambient host env."""
    kwargs: dict[str, Any] = {
        "kill_active": False,
        "use_env": False,
    }
    policy_path = base / "update_policy.json"
    allowlist_path = base / "allowlist.json"
    prose_path = base / "malicious_prose.txt"
    if policy_path.is_file():
        kwargs["update_policy_path"] = policy_path
    else:
        kwargs["update_policy"] = UpdatePolicy.fail_closed_default()
    if allowlist_path.is_file():
        kwargs["allowlist_path"] = allowlist_path
    else:
        kwargs["allowlist"] = load_allowlist(use_env=False)
    if prose_path.is_file():
        kwargs["untrusted_prose"] = prose_path.read_text(encoding="utf-8")
    return kwargs


def _load_envelope_and_head(name: str) -> tuple[Path, dict[str, Any], str | None]:
    base = ROOT / "eval" / name
    envelope = json.loads((base / "envelope.json").read_text(encoding="utf-8"))
    observed = json.loads((base / "observed_head.json").read_text(encoding="utf-8")).get(
        "observed_head"
    )
    if observed is not None and not isinstance(observed, str):
        observed = None
    return base, envelope, observed


def _run_row(name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    base, envelope, observed = _load_envelope_and_head(name)
    decision = gated_install_or_update(
        envelope,
        LocalWorktreeAdapter(observed),
        **_row_kwargs(base),
    )
    expected_path = base / "expected_allow_receipt.example.json"
    if not expected_path.is_file():
        expected_path = base / "expected_deny_receipt.example.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    return decision.receipt, expected


def test_m1b_deny_rows_are_deterministic_deny() -> None:
    for name in DENY_ROWS:
        receipt, expected = _run_row(name)
        assert receipt == expected, name
        assert receipt["decision"] == Verdict.DENY.value
        assert receipt["brand"] == "Agent Control Lab"
        assert receipt["prose_used_as_policy"] is False


def test_m1b_allow_rows_are_deterministic_allow() -> None:
    for name in ALLOW_ROWS:
        receipt, expected = _run_row(name)
        assert receipt == expected, name
        assert receipt["decision"] == Verdict.ALLOW.value
        assert receipt["brand"] == "Agent Control Lab"
        assert receipt["prose_used_as_policy"] is False
        assert receipt["verify_performed"] is True
        assert receipt["skip_verify_attempt"] is False


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


def test_prose_waive_attempt_reason() -> None:
    receipt, _ = _run_row("prose_waive_attempt")
    assert receipt["reasons"] == [DenyReason.PROSE_REJECTED_AS_POLICY.value]
    assert receipt["verify_performed"] is True
    assert receipt["skip_verify_attempt"] is True
    assert receipt["untrusted_prose_present"] is True


def test_allow_row_cannot_skip_head_verify() -> None:
    """ALLOW fixture still DENY if adapter omits HEAD or a structured waive appears."""
    base, envelope, observed = _load_envelope_and_head("allow_pin_and_verify")
    kwargs = _row_kwargs(base)

    omitted = gated_install_or_update(
        envelope,
        LocalWorktreeAdapter(None),
        **kwargs,
    )
    assert omitted.verdict is Verdict.DENY
    assert omitted.reasons == (DenyReason.VERIFY_MISSING,)
    assert omitted.receipt["verify_performed"] is False
    assert omitted.receipt["prose_used_as_policy"] is False

    waived = dict(envelope)
    waived["skip_verify"] = True
    waived_decision = gated_install_or_update(
        waived,
        LocalWorktreeAdapter(observed),
        **kwargs,
    )
    assert waived_decision.verdict is Verdict.DENY
    assert waived_decision.reasons == (DenyReason.PROSE_REJECTED_AS_POLICY,)
    assert waived_decision.receipt["verify_performed"] is True
    assert waived_decision.receipt["skip_verify_attempt"] is True
    assert waived_decision.receipt["prose_used_as_policy"] is False


def test_corpus_rows_ignore_ambient_host_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Conflicting ACL_SUPPLY_GATE_* must not change recorded DENY/ALLOW receipts."""
    allowlist = tmp_path / "conflicting-allowlist.json"
    allowlist.write_text(
        '{"origins": ["https://git.example.invalid/agent-control-lab/skills.git"]}\n',
        encoding="utf-8",
    )
    policy = tmp_path / "conflicting-update-policy.json"
    policy.write_text('{"mode": "trust_ref"}\n', encoding="utf-8")
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(allowlist))
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    monkeypatch.setenv("ACL_SUPPLY_GATE_UPDATE_POLICY", str(policy))
    for name in AMBIENT_HOST_ENV:
        assert os.environ.get(name)

    receipt, expected = _run_row("prose_waive_attempt")
    assert receipt == expected
    assert receipt["reasons"] == [DenyReason.PROSE_REJECTED_AS_POLICY.value]
    assert DenyReason.ORIGIN_NOT_ALLOWLISTED.value not in receipt["reasons"]
    assert DenyReason.KILL_ACTIVE.value not in receipt["reasons"]

    receipt, expected = _run_row("allow_pin_and_verify")
    assert receipt == expected
    assert receipt["decision"] == Verdict.ALLOW.value
    assert receipt["kill_active"] is False

    for name in DENY_ROWS:
        receipt, expected = _run_row(name)
        assert receipt == expected, name
