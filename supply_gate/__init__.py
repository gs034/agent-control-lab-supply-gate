# SPDX-License-Identifier: Apache-2.0
"""Agent Control Lab host-side agent-supply integrity gate (fail-closed stub)."""

from supply_gate.adapters import (
    InstallerAdapter,
    LocalWorktreeAdapter,
    MaterialiseRequest,
    MaterialiseResult,
    RecordingStubAdapter,
    caller_supplied_head,
    gated_install_or_update,
)
from supply_gate.allowlist import AllowlistConfig, AllowlistError, load_allowlist
from supply_gate.envelope import SupplyEnvelope
from supply_gate.gate import Decision, evaluate, safe_evaluate
from supply_gate.manifest import ManifestError, PinnedSource, SupplyManifest
from supply_gate.reasons import DenyReason, Verdict
from supply_gate.update_policy import UpdatePolicy, UpdatePolicyError, load_update_policy

__all__ = [
    "AllowlistConfig",
    "AllowlistError",
    "Decision",
    "DenyReason",
    "InstallerAdapter",
    "LocalWorktreeAdapter",
    "ManifestError",
    "MaterialiseRequest",
    "MaterialiseResult",
    "PinnedSource",
    "RecordingStubAdapter",
    "SupplyEnvelope",
    "SupplyManifest",
    "UpdatePolicy",
    "UpdatePolicyError",
    "Verdict",
    "caller_supplied_head",
    "evaluate",
    "gated_install_or_update",
    "load_allowlist",
    "load_update_policy",
    "safe_evaluate",
]
