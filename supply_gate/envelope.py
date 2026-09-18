# SPDX-License-Identifier: Apache-2.0
"""Structured SupplyEnvelope: pin + origin + caller. Untrusted prose is data only."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

_FULL_DIGEST = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")

# Structured fields that attempt to waive host verify. Never honoured as policy.
_BYPASS_KEYS = frozenset({"skip_verify", "waive_verify", "trust_pin_only", "bypass"})


@dataclass(frozen=True)
class SupplyEnvelope:
    origin: str
    expected_sha: str
    caller: str
    ref: str | None = None
    capability: str | None = None
    skip_verify_attempt: bool = False

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> tuple[SupplyEnvelope | None, bool]:
        """Parse a mapping.

        Returns (envelope_or_none, skip_verify_attempt).
        envelope_or_none is None when required fields are missing or ill-typed.
        skip_verify_attempt is True when untrusted structured data tries to waive verify.
        """
        skip_attempt = _skip_verify_attempt(raw)
        origin = raw.get("origin")
        expected_sha = raw.get("expected_sha")
        caller = raw.get("caller")
        ref = raw.get("ref")
        capability = raw.get("capability")

        if not isinstance(origin, str) or not origin.strip():
            return None, skip_attempt
        if not isinstance(expected_sha, str) or not expected_sha.strip():
            return None, skip_attempt
        if not isinstance(caller, str) or not caller.strip():
            return None, skip_attempt
        if ref is not None and not isinstance(ref, str):
            return None, skip_attempt
        if capability is not None and not isinstance(capability, str):
            return None, skip_attempt

        origin_n = origin.strip()
        sha_n = expected_sha.strip().lower()
        caller_n = caller.strip()
        ref_n = ref.strip() if isinstance(ref, str) and ref.strip() else None
        cap_n = capability.strip() if isinstance(capability, str) and capability.strip() else None

        if not _FULL_DIGEST.fullmatch(sha_n):
            return None, skip_attempt
        if any(ch.isspace() for ch in origin_n):
            return None, skip_attempt

        return (
            cls(
                origin=origin_n,
                expected_sha=sha_n,
                caller=caller_n,
                ref=ref_n,
                capability=cap_n,
                skip_verify_attempt=skip_attempt,
            ),
            skip_attempt,
        )


def envelope_digest_ok(value: str) -> bool:
    return bool(_FULL_DIGEST.fullmatch(value))


def _skip_verify_attempt(raw: Mapping[str, Any]) -> bool:
    if _truthy_bypass(raw):
        return True
    nested = raw.get("untrusted")
    if isinstance(nested, Mapping) and _truthy_bypass(nested):
        return True
    return False


def _truthy_bypass(mapping: Mapping[str, Any]) -> bool:
    for key in _BYPASS_KEYS:
        if bool(mapping.get(key)):
            return True
    return False
