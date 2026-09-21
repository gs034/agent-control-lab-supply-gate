# SPDX-License-Identifier: Apache-2.0
"""Thin installer adapter stub interfaces. No live marketplace or git host."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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

# Caller-supplied worktree paths that look like remotes are refused. This
# helper never fetches; a remote-shaped path is treated as omitted HEAD.
_REMOTE_PREFIXES = ("http://", "https://", "git://", "ssh://", "git@")


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


def caller_supplied_head(
    observed_head: str | None,
    *,
    worktree: str | Path | None = None,
) -> str | None:
    """Return the caller-supplied digest only.

    Never fetches, never runs git, never reads ``HEAD`` from the tree.
    If ``worktree`` is given it must be a local directory; a missing or
    remote-shaped path fails closed (returns ``None`` → ``verify_missing``).
    """
    if worktree is not None:
        raw = str(worktree).strip()
        if not raw:
            return None
        lowered = raw.lower()
        if lowered.startswith(_REMOTE_PREFIXES):
            return None
        path = Path(worktree)
        if not path.exists() or not path.is_dir():
            return None
    if observed_head is None:
        return None
    if not isinstance(observed_head, str) or not observed_head.strip():
        return None
    return observed_head.strip()


class LocalWorktreeAdapter:
    """Optional local-worktree helper. Digest is caller-supplied. No network."""

    def __init__(
        self,
        observed_head: str | None,
        *,
        worktree: str | Path | None = None,
    ) -> None:
        self._observed_head = observed_head
        self._worktree = worktree

    def materialise(self, request: MaterialiseRequest) -> MaterialiseResult:
        head = caller_supplied_head(self._observed_head, worktree=self._worktree)
        return MaterialiseResult(
            origin=request.origin,
            observed_head=head,
            notes="local-worktree",
        )


def gated_install_or_update(
    envelope: Mapping[str, Any],
    adapter: InstallerAdapter,
    *,
    update_policy: UpdatePolicy | None = None,
    update_policy_raw: Mapping[str, Any] | None = None,
    update_policy_path: str | Path | None = None,
    allowlist: AllowlistConfig | None = None,
    allowlist_path: str | Path | None = None,
    untrusted_prose: str | None = None,
    kill_active: bool | None = None,
    use_env: bool = True,
) -> Decision:
    """Host path: load host config → fail-closed update policy → materialise → evaluate.

    Allowlist and update policy load from file/env the same way. Empty or
    broken host config is DENY. Update policy is required on this path; the
    no-config fallback is ``pin_and_verify``. Weak modes DENY. The adapter
    is a stub interface; it does not open a marketplace.

    ``use_env=False`` skips ``ACL_SUPPLY_GATE_*`` lookups so corpus/eval
    fixture runs stay independent of ambient host config. Pass fixture
    files or explicit objects instead. When ``use_env`` is False and
    ``kill_active`` is omitted, kill is off.
    """
    extra: list[DenyReason] = []
    weak_attempt = False
    policy = update_policy
    if policy is None:
        try:
            policy, weak_attempt = load_update_policy(
                path=update_policy_path,
                raw=update_policy_raw,
                use_env=use_env,
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
            origins = load_allowlist(path=allowlist_path, use_env=use_env).origins
        except AllowlistError:
            extra.append(DenyReason.ALLOWLIST_INVALID)
            origins = frozenset()

    kill = False if kill_active is None and not use_env else kill_active
    return evaluate(
        envelope,
        result.observed_head,
        allowed_origins=origins,
        kill_active=kill,
        untrusted_prose=untrusted_prose,
        extra_reasons=tuple(extra),
    )


def _mapping_str(envelope: Mapping[str, Any], key: str) -> str | None:
    value = envelope.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
