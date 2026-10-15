# SPDX-License-Identifier: Apache-2.0
"""Structured SupplyEnvelope: pin + origin + caller. Untrusted prose is data only."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from supply_gate.digest import digest_ok
from supply_gate.manifest import ManifestError, SupplyManifest, parse_manifest

# Structured fields that attempt to waive host verify. Never honoured as policy.
_BYPASS_KEYS = frozenset({"skip_verify", "waive_verify", "trust_pin_only", "bypass"})
# Top-level keys the gate understands. Any other key, or a key that is not a
# string, is envelope_invalid: a shape this gate does not understand is not trusted.
_ENVELOPE_KEYS = frozenset(
    {
        "origin",
        "expected_sha",
        "caller",
        "ref",
        "capability",
        "manifest",
        "untrusted",
    }
) | _BYPASS_KEYS
# Documented UTF-8 byte caps for the string fields. ``ref`` is 4 KiB.
# A value over its cap is envelope_invalid.
FIELD_MAX_BYTES: dict[str, int] = {
    "origin": 2048,
    "expected_sha": 128,
    "caller": 256,
    "ref": 4096,
    "capability": 256,
}


@dataclass(frozen=True)
class SupplyEnvelope:
    origin: str
    expected_sha: str
    caller: str
    ref: str | None = None
    capability: str | None = None
    skip_verify_attempt: bool = False
    manifest: SupplyManifest | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> tuple[SupplyEnvelope | None, bool]:
        """Parse a mapping.

        Returns (envelope_or_none, skip_verify_attempt).
        envelope_or_none is None when required fields are missing or ill-typed.
        skip_verify_attempt is True when untrusted structured data tries to waive verify.
        """
        skip_attempt = _skip_verify_attempt(raw)
        if _unknown_or_non_string_key(raw):
            return None, skip_attempt
        origin = raw.get("origin")
        expected_sha = raw.get("expected_sha")
        caller = raw.get("caller")
        ref = raw.get("ref")
        capability = raw.get("capability")
        try:
            manifest = parse_manifest(raw.get("manifest"))
        except ManifestError:
            return None, skip_attempt

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
        if any(
            isinstance(value, str) and not _text_within_cap(key, value)
            for key, value in (
                ("origin", origin),
                ("expected_sha", expected_sha),
                ("caller", caller),
                ("ref", ref),
                ("capability", capability),
            )
        ):
            return None, skip_attempt

        origin_n = origin.strip()
        sha_n = expected_sha.strip().lower()
        caller_n = caller.strip()
        ref_n = ref.strip() if isinstance(ref, str) and ref.strip() else None
        cap_n = capability.strip() if isinstance(capability, str) and capability.strip() else None

        if not digest_ok(sha_n):
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
                manifest=manifest,
            ),
            skip_attempt,
        )



def _unknown_or_non_string_key(raw: Mapping[str, Any]) -> bool:
    return any(not isinstance(key, str) or key not in _ENVELOPE_KEYS for key in raw)


def _text_within_cap(field: str, value: str) -> bool:
    """False when ``value`` contains a control, a surrogate, or exceeds its byte cap."""
    for char in value:
        category = unicodedata.category(char)
        if category == "Cc" or category == "Cs":
            return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return size <= FIELD_MAX_BYTES[field]


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
