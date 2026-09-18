# SPDX-License-Identifier: Apache-2.0
"""Deterministic host-side receipts. No model judge; JSON only."""

from __future__ import annotations

import json
from typing import Any

from supply_gate.reasons import DenyReason, Verdict

BRAND = "Agent Control Lab"
GATE_ID = "supply-integrity"
SCHEMA_VERSION = "1"


def build_receipt(
    *,
    verdict: Verdict,
    reasons: tuple[DenyReason, ...],
    origin: str | None,
    expected_sha: str | None,
    observed_head: str | None,
    ref: str | None,
    caller: str | None,
    capability: str | None,
    verify_performed: bool,
    kill_active: bool,
    untrusted_prose_present: bool,
    skip_verify_attempt: bool,
) -> dict[str, Any]:
    return {
        "brand": BRAND,
        "caller": caller,
        "capability": capability,
        "decision": verdict.value,
        "expected_sha": expected_sha,
        "gate": GATE_ID,
        "kill_active": kill_active,
        "observed_head": observed_head,
        "origin": origin,
        "prose_used_as_policy": False,
        "reasons": [reason.value for reason in reasons],
        "ref": ref,
        "schema_version": SCHEMA_VERSION,
        "skip_verify_attempt": skip_verify_attempt,
        "untrusted_prose_present": untrusted_prose_present,
        "verify_performed": verify_performed,
    }


def dumps_receipt(receipt: dict[str, Any]) -> str:
    return json.dumps(receipt, sort_keys=True, indent=2) + "\n"
