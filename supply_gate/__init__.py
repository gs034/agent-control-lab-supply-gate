# SPDX-License-Identifier: Apache-2.0
"""Agent Control Lab host-side agent-supply integrity gate (fail-closed stub)."""

from supply_gate.adapters import (
    InstallerAdapter,
    MaterialiseRequest,
    MaterialiseResult,
    RecordingStubAdapter,
    gated_install_or_update,
)
from supply_gate.allowlist import AllowlistConfig, AllowlistError, load_allowlist
from supply_gate.envelope import SupplyEnvelope
from supply_gate.gate import Decision, evaluate, safe_evaluate
from supply_gate.reasons import DenyReason, Verdict
from supply_gate.update_policy import UpdatePolicy, UpdatePolicyError, load_update_policy

__all__ = [
    "AllowlistConfig",
    "AllowlistError",
    "Decision",
    "DenyReason",
    "InstallerAdapter",
    "MaterialiseRequest",
    "MaterialiseResult",
    "RecordingStubAdapter",
    "SupplyEnvelope",
    "UpdatePolicy",
    "UpdatePolicyError",
    "Verdict",
    "evaluate",
    "gated_install_or_update",
    "load_allowlist",
    "load_update_policy",
    "safe_evaluate",
]
