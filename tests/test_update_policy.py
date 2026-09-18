# SPDX-License-Identifier: Apache-2.0
"""Fail-closed update policy: only pin_and_verify is accepted."""

from __future__ import annotations

from pathlib import Path

import pytest

from supply_gate.reasons import DenyReason
from supply_gate.update_policy import (
    PIN_AND_VERIFY,
    UpdatePolicy,
    UpdatePolicyError,
    evaluate_update_policy,
    infer_operation,
    load_update_policy,
    parse_update_policy,
)


def test_default_policy_is_pin_and_verify() -> None:
    policy = UpdatePolicy.fail_closed_default()
    assert policy.mode == PIN_AND_VERIFY
    assert policy.accepted()
    assert evaluate_update_policy(policy, required=True) == ()


def test_missing_policy_required_is_deny() -> None:
    assert evaluate_update_policy(None, required=True) == (
        DenyReason.UPDATE_POLICY_REJECTED,
    )


def test_missing_policy_optional_is_silent() -> None:
    assert evaluate_update_policy(None, required=False) == ()


@pytest.mark.parametrize(
    "mode",
    ["trust_ref", "auto_latest", "marketplace_pin_only", "trust_pin_only"],
)
def test_weak_mode_rejected(mode: str) -> None:
    policy, weak = parse_update_policy({"mode": mode})
    assert weak is True
    assert policy is not None
    assert not policy.accepted()
    assert evaluate_update_policy(policy, weak_attempt=weak, required=True) == (
        DenyReason.UPDATE_POLICY_REJECTED,
    )


def test_waive_flag_rejected_even_when_mode_is_pin_and_verify() -> None:
    policy, weak = parse_update_policy(
        {"mode": PIN_AND_VERIFY, "auto_update": True}
    )
    assert policy is not None
    assert policy.accepted()
    assert weak is True
    assert evaluate_update_policy(policy, weak_attempt=weak, required=True) == (
        DenyReason.UPDATE_POLICY_REJECTED,
    )


def test_ill_typed_mode_rejected() -> None:
    policy, weak = parse_update_policy({"mode": 1})
    assert policy is None
    assert weak is True


def test_infer_operation_from_capability_language() -> None:
    assert infer_operation({"capability": "plugin.install_or_update"}, None) == "update"
    assert infer_operation({"capability": "skill.fetch"}, None) == "install"
    assert infer_operation({"operation": "install", "capability": "plugin.install_or_update"}, None) == "install"


def test_load_from_example_file() -> None:
    root = Path(__file__).resolve().parents[1]
    policy, weak = load_update_policy(
        path=root / "config" / "update_policy.example.json",
        use_env=False,
        fallback_default=False,
    )
    assert weak is False
    assert policy is not None
    assert policy.accepted()


def test_missing_file_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(UpdatePolicyError):
        load_update_policy(path=tmp_path / "missing.json", use_env=False)
