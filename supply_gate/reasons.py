# SPDX-License-Identifier: Apache-2.0
"""Stable deny reasons and verdicts for the supply integrity gate."""

from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DenyReason(str, Enum):
    """Canonical deny reasons. Order is receipt-stable."""

    ENVELOPE_INVALID = "envelope_invalid"
    KILL_ACTIVE = "kill_active"
    PROSE_REJECTED_AS_POLICY = "prose_rejected_as_policy"
    ORIGIN_NOT_ALLOWLISTED = "origin_not_allowlisted"
    ALLOWLIST_INVALID = "allowlist_invalid"
    UPDATE_POLICY_REJECTED = "update_policy_rejected"
    VERIFY_MISSING = "verify_missing"
    HEAD_MISMATCH = "head_mismatch"
    MCP_SERVER_UNPINNED = "mcp_server_unpinned"
    SKILL_SHELL_PREAPPROVED = "skill_shell_preapproved"
    HOOK_UPDATE_UNVERIFIED = "hook_update_unverified"


REASON_ORDER: tuple[DenyReason, ...] = tuple(DenyReason)
