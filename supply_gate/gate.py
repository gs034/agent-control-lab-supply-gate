# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evaluate(): pin + allowlisted origin + post-checkout HEAD verify."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from supply_gate.allowlist import AllowlistError, load_allowlist
from supply_gate.envelope import SupplyEnvelope, envelope_digest_ok
from supply_gate.origins import origin_allowlisted
from supply_gate.reasons import REASON_ORDER, DenyReason, Verdict
from supply_gate.receipt import build_receipt

KILL_ENV = "ACL_SUPPLY_GATE_KILL"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: tuple[DenyReason, ...]
    receipt: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


def evaluate(
    envelope: SupplyEnvelope | Mapping[str, Any],
    observed_head: str | None,
    *,
    allowed_origins: frozenset[str] | None = None,
    kill_active: bool | None = None,
    untrusted_prose: str | None = None,
    extra_reasons: tuple[DenyReason, ...] = (),
) -> Decision:
    """Host-side gate. Marketplace/agent prose is untrusted data and cannot skip verify.

    ALLOW only when the envelope parses, origin is allowlisted, kill is off,
    observed HEAD is present, and that HEAD exactly matches the pinned digest.
    Host extra reasons (update policy, broken allowlist) are folded into the
    receipt. Any other outcome is DENY with a receipt.
    """
    skip_attempt = False
    parsed: SupplyEnvelope | None
    if isinstance(envelope, SupplyEnvelope):
        parsed = envelope
        skip_attempt = envelope.skip_verify_attempt
    elif isinstance(envelope, Mapping):
        parsed, skip_attempt = SupplyEnvelope.from_mapping(envelope)
    else:
        parsed = None

    kill = _kill_active(kill_active)
    prose_present = bool(untrusted_prose and untrusted_prose.strip())
    observed = _normalize_head(observed_head)
    verify_performed = observed is not None

    reasons: list[DenyReason] = []
    if parsed is None:
        reasons.append(DenyReason.ENVELOPE_INVALID)
    if kill:
        reasons.append(DenyReason.KILL_ACTIVE)
    if skip_attempt:
        # Untrusted structured waive is rejected. Prose text is never a skip;
        # post-checkout HEAD verify still runs below.
        reasons.append(DenyReason.PROSE_REJECTED_AS_POLICY)

    origin = parsed.origin if parsed else _mapping_str(envelope, "origin")
    expected_sha = parsed.expected_sha if parsed else _mapping_str(envelope, "expected_sha")
    caller = parsed.caller if parsed else _mapping_str(envelope, "caller")
    ref = parsed.ref if parsed else _mapping_str(envelope, "ref")
    capability = parsed.capability if parsed else _mapping_str(envelope, "capability")

    if extra_reasons:
        reasons.extend(extra_reasons)

    if parsed is not None:
        allowed, allowlist_ok = _resolve_allowed_origins(allowed_origins)
        if not allowlist_ok:
            reasons.append(DenyReason.ALLOWLIST_INVALID)
        if not origin_allowlisted(parsed.origin, allowed):
            reasons.append(DenyReason.ORIGIN_NOT_ALLOWLISTED)

    if not verify_performed:
        reasons.append(DenyReason.VERIFY_MISSING)
    elif parsed is not None and observed != parsed.expected_sha:
        reasons.append(DenyReason.HEAD_MISMATCH)

    unique = tuple(reason for reason in REASON_ORDER if reason in reasons)
    verdict = Verdict.ALLOW if not unique else Verdict.DENY
    receipt = build_receipt(
        verdict=verdict,
        reasons=unique,
        origin=origin,
        expected_sha=expected_sha.lower() if isinstance(expected_sha, str) else expected_sha,
        observed_head=observed,
        ref=ref,
        caller=caller,
        capability=capability,
        verify_performed=verify_performed,
        kill_active=kill,
        untrusted_prose_present=prose_present,
        skip_verify_attempt=skip_attempt,
    )
    return Decision(verdict=verdict, reasons=unique, receipt=receipt)


def safe_evaluate(
    envelope: SupplyEnvelope | Mapping[str, Any],
    observed_head: str | None,
    **kwargs: Any,
) -> Decision:
    """Fail-closed wrapper: unexpected gate faults become DENY (kill_active)."""
    try:
        return evaluate(envelope, observed_head, **kwargs)
    except Exception:
        kill = True
        observed = _normalize_head(observed_head)
        receipt = build_receipt(
            verdict=Verdict.DENY,
            reasons=(DenyReason.KILL_ACTIVE,),
            origin=None,
            expected_sha=None,
            observed_head=observed,
            ref=None,
            caller=None,
            capability=None,
            verify_performed=observed is not None,
            kill_active=kill,
            untrusted_prose_present=False,
            skip_verify_attempt=False,
        )
        return Decision(verdict=Verdict.DENY, reasons=(DenyReason.KILL_ACTIVE,), receipt=receipt)


def _resolve_allowed_origins(
    allowed_origins: frozenset[str] | None,
) -> tuple[frozenset[str], bool]:
    if allowed_origins is not None:
        return allowed_origins, True
    try:
        return load_allowlist().origins, True
    except AllowlistError:
        return frozenset(), False


def _kill_active(explicit: bool | None) -> bool:
    if explicit is True:
        return True
    if explicit is False:
        return False
    flag = os.environ.get(KILL_ENV, "")
    return flag.strip() in {"1", "true", "TRUE", "yes", "YES"}


def _normalize_head(observed_head: str | None) -> str | None:
    if observed_head is None:
        return None
    if not isinstance(observed_head, str):
        return None
    value = observed_head.strip().lower()
    if not value:
        return None
    if not envelope_digest_ok(value):
        return None
    return value


def _mapping_str(envelope: object, key: str) -> str | None:
    if isinstance(envelope, Mapping):
        value = envelope.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
