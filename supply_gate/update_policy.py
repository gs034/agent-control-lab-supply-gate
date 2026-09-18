# SPDX-License-Identifier: Apache-2.0
"""Fail-closed update policy. Weak or missing update rules cannot proceed."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from supply_gate.reasons import DenyReason

PIN_AND_VERIFY = "pin_and_verify"
UPDATE_POLICY_ENV = "ACL_SUPPLY_GATE_UPDATE_POLICY"

# Recognized weak modes. Never honoured as policy.
_WEAK_MODES = frozenset(
    {
        "trust_ref",
        "auto_latest",
        "marketplace_pin_only",
        "trust_pin_only",
        "skip_verify",
    }
)

_WEAK_FLAGS = frozenset(
    {
        "auto_update",
        "trust_marketplace_pin",
        "allow_mutable_ref_without_verify",
        "skip_verify_on_update",
    }
)

_UPDATE_CAPABILITY_MARK = "install_or_update"


class UpdatePolicyError(ValueError):
    """Update policy could not be loaded. Callers must DENY."""


@dataclass(frozen=True)
class UpdatePolicy:
    mode: str = PIN_AND_VERIFY
    source: str = "default"

    @classmethod
    def fail_closed_default(cls) -> UpdatePolicy:
        return cls(mode=PIN_AND_VERIFY, source="default")

    def accepted(self) -> bool:
        return self.mode == PIN_AND_VERIFY


def load_update_policy(
    *,
    path: str | Path | None = None,
    mode: str | None = None,
    raw: Mapping[str, Any] | None = None,
    use_env: bool = True,
    fallback_default: bool = True,
) -> tuple[UpdatePolicy | None, bool]:
    """Load an update policy the same way origins load.

    Precedence: explicit ``mode``, then ``raw``, then ``path``, then
    ``ACL_SUPPLY_GATE_UPDATE_POLICY``, then the fail-closed default.

    Returns ``(policy_or_none, weak_attempt)``.
    ``weak_attempt`` is True when the mapping names a weak mode or waive flag.

    An empty or ill-formed file raises ``UpdatePolicyError``. A provided
    mapping with no mode is empty (callers must DENY). There is no
    implicit allow-all or weak-mode fallback.
    """
    if mode is not None:
        return parse_update_policy({"mode": mode}, source="explicit")
    if raw is not None:
        return parse_update_policy(raw, source="mapping")
    resolved = Path(path) if path is not None else None
    source = "file"
    if resolved is None and use_env:
        env_path = os.environ.get(UPDATE_POLICY_ENV, "").strip()
        if env_path:
            resolved = Path(env_path)
            source = "env"
    if resolved is not None:
        return parse_update_policy(_mapping_from_file(resolved), source=source)
    if fallback_default:
        return UpdatePolicy.fail_closed_default(), False
    return None, False


def parse_update_policy(
    raw: Mapping[str, Any] | None,
    *,
    source: str = "mapping",
) -> tuple[UpdatePolicy | None, bool]:
    """Parse a mapping into an update policy.

    Returns ``(policy_or_none, weak_attempt)``. A provided mapping with no
    mode is empty and fail-closed (not an implicit ``pin_and_verify``).
    """
    if raw is None:
        return None, False
    weak = _weak_flags(raw)
    mode = raw.get("mode")
    if mode is None:
        return None, True
    if not isinstance(mode, str) or not mode.strip():
        return None, True
    normalised = mode.strip()
    if normalised in _WEAK_MODES or normalised != PIN_AND_VERIFY:
        return UpdatePolicy(mode=normalised, source=source), True
    return UpdatePolicy(mode=PIN_AND_VERIFY, source=source), weak


def _mapping_from_file(path: Path) -> Mapping[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UpdatePolicyError(f"update policy file unreadable: {path}") from exc
    if not text.strip():
        raise UpdatePolicyError("update policy file is empty")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UpdatePolicyError("update policy JSON is ill-formed") from exc
    if not isinstance(parsed, Mapping):
        raise UpdatePolicyError("update policy JSON must be an object")
    if "mode" not in parsed and not _weak_flags(parsed):
        raise UpdatePolicyError("update policy is empty")
    return parsed


def infer_operation(envelope: Mapping[str, Any] | None, capability: str | None) -> str:
    """Infer install vs update from envelope operation or capability language."""
    if envelope is not None:
        operation = envelope.get("operation")
        if isinstance(operation, str) and operation.strip():
            return operation.strip()
        if capability is None:
            listed = envelope.get("capability")
            capability = listed if isinstance(listed, str) else None
    if isinstance(capability, str) and _UPDATE_CAPABILITY_MARK in capability:
        return "update"
    return "install"


def evaluate_update_policy(
    policy: UpdatePolicy | None,
    *,
    weak_attempt: bool = False,
    required: bool = False,
) -> tuple[DenyReason, ...]:
    """Fail-closed policy check. Missing/weak policy is DENY when required."""
    if required and policy is None:
        return (DenyReason.UPDATE_POLICY_REJECTED,)
    if policy is None:
        return ()
    if weak_attempt or not policy.accepted():
        return (DenyReason.UPDATE_POLICY_REJECTED,)
    return ()


def _weak_flags(raw: Mapping[str, Any]) -> bool:
    return any(bool(raw.get(key)) for key in _WEAK_FLAGS)
