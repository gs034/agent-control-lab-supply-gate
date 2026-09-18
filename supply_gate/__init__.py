# SPDX-License-Identifier: Apache-2.0
"""Agent Control Lab host-side agent-supply integrity gate (fail-closed stub)."""

from supply_gate.envelope import SupplyEnvelope
from supply_gate.gate import Decision, evaluate, safe_evaluate
from supply_gate.reasons import DenyReason, Verdict

__all__ = [
    "Decision",
    "DenyReason",
    "SupplyEnvelope",
    "Verdict",
    "evaluate",
    "safe_evaluate",
]
