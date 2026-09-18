# SPDX-License-Identifier: Apache-2.0
"""Thin installer adapter stub interfaces. No live marketplace or git host."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from supply_gate.allowlist import AllowlistConfig, AllowlistError, load_allowlist
from supply_gate.gate import Decision, evaluate, safe_evaluate
from supply_gate.reasons import DenyReason
from supply_gate.update_policy import (
    UpdatePolicy,
    UpdatePolicyError,
    evaluate_update_policy,
    infer_operation,
    load_update_policy,
)


@dataclass(frozen=True)
class MaterialiseRequest:
    origin: str
    expected_sha: str
    capability: str
    operation: str
    ref: str | None = None


@dataclass(frozen=True)
class MaterialiseResult:
    origin: str
    observed_head: str | None
    notes: str = "stub"


class InstallerAdapter(Protocol):
    """Host materialise step. Implementations must return post-checkout HEAD."""

    def materialise(self, request: MaterialiseRequest) -> MaterialiseResult:
        """Materialise locally and resolve HEAD. Must not skip verify."""
        ...


class RecordingStubAdapter:
    """In-memory stub. Caller injects observed HEAD. No network."""

    def __init__(self, observed_head: str | None) -> None:
        self._observed_head = observed_head

    def materialise(self, request: MaterialiseRequest) -> MaterialiseResult:
        return MaterialiseResult(origin=request.origin, observed_head=self._observed_head)


def gated_install_or_update(
    envelope: Mapping[str, Any],
    adapter: InstallerAdapter,
    *,
    update_policy: UpdatePolicy | None = None,
    update_policy_raw: Mapping[str, Any] | None = None,
    allowlist: AllowlistConfig | None = None,
    untrusted_prose: str | None = None,
    kill_active: bool | None = None,
) -> Decision:
    """Host path: fail-closed update policy → materialise → evaluate.

    Update policy is required on this path. The default is ``pin_and_verify``.
    Weak modes DENY. The adapter is a stub interface; it does not open a
    marketplace.
    """
    extra: list[DenyReason] = []
    weak_attempt = False
    policy = update_policy
    if policy is None:
        try:
            policy, weak_attempt = load_update_policy(
                raw=update_policy_raw,
                fallback_default=True,
            )
        except UpdatePolicyError:
            extra.append(DenyReason.UPDATE_POLICY_REJECTED)
            policy = None
            weak_attempt = True
    extra.extend(
        evaluate_update_policy(policy, weak_attempt=weak_attempt, required=True)
    )

    capability = _mapping_str(envelope, "capability") or ""
    operation = infer_operation(envelope, capability)
    request = MaterialiseRequest(
        origin=_mapping_str(envelope, "origin") or "",
        expected_sha=_mapping_str(envelope, "expected_sha") or "",
        capability=capability,
        operation=operation,
        ref=_mapping_str(envelope, "ref"),
    )
    try:
        result = adapter.materialise(request)
    except Exception:
        return safe_evaluate(envelope, None, kill_active=True)

    origins: frozenset[str] | None
    if allowlist is not None:
        origins = allowlist.origins
    else:
        try:
            origins = load_allowlist().origins
        except AllowlistError:
            extra.append(DenyReason.ALLOWLIST_INVALID)
            origins = frozenset()

    return evaluate(
        envelope,
        result.observed_head,
        allowed_origins=origins,
        kill_active=kill_active,
        untrusted_prose=untrusted_prose,
        extra_reasons=tuple(extra),
    )


def _mapping_str(envelope: Mapping[str, Any], key: str) -> str | None:
    value = envelope.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
