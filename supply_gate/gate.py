# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evaluate(): pin + allowlisted origin + post-checkout HEAD verify."""

from __future__ import annotations

import json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from supply_gate.allowlist import AllowlistError, load_allowlist
from supply_gate.digest import digest_ok
from supply_gate.envelope import SupplyEnvelope
from supply_gate.manifest import SupplyManifest
from supply_gate.origins import origin_allowlisted
from supply_gate.reasons import REASON_ORDER, DenyReason, Verdict
from supply_gate.receipt import build_receipt

logger = logging.getLogger(__name__)
# Logged field values are cut here so a DENY line cannot carry a secret in full.
_LOG_VALUE_MAX = 64
# Logged when an origin cannot be reduced to scheme://host[:port] or an scp host.
_UNPARSEABLE_ORIGIN = "<unparseable-origin>"
# scp-style ``user[:token]@host:path`` or ``host:path``, with no ``://``.
_SCP_ORIGIN = re.compile(r"^(?:[^@\s]+@)?(?P<host>[^:@/\s]+):\S+$")

KILL_ENV = "ACL_SUPPLY_GATE_KILL"
# Kill switch spellings, compared after strip() and lower(). A non-empty value
# in neither set is treated as killed (fail closed); see kill_value_active.
KILL_TRUE_VALUES = frozenset({"1", "true", "t", "yes", "y", "on"})
KILL_FALSE_VALUES = frozenset({"", "0", "false", "f", "no", "n", "off"})


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
    kill_active: bool | str | None = None,
    untrusted_prose: str | None = None,
    extra_reasons: tuple[DenyReason, ...] = (),
    observed_hooks: Mapping[str, str] | None = None,
    observed_mcp_servers: Mapping[str, str] | None = None,
) -> Decision:
    """Host-side gate. Marketplace/agent prose is untrusted data and cannot skip verify.

    A declared ``manifest`` (MCP servers, permissions, lifecycle hooks) is read
    only to deny: MCP servers and hooks without a pin or without a matching
    observed digest (``observed_mcp_servers`` / ``observed_hooks``), remote
    MCP servers, and shell pre-approval a manifest grants itself are DENY.

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

    if parsed is not None and parsed.manifest is not None:
        if isinstance(parsed.manifest, SupplyManifest):
            reasons.extend(parsed.manifest.deny_reasons(observed_hooks, observed_mcp_servers))
        else:
            # A manifest object the gate did not parse is not trusted.
            reasons.append(DenyReason.ENVELOPE_INVALID)

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
    if verdict is Verdict.DENY:
        _log_deny(receipt)
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
        _log_deny(receipt)
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


def kill_value_active(value: object) -> bool:
    """Read a kill switch value, failing closed.

    ``True`` / ``False`` and ``None`` (unset) mean what they say. A string is
    trimmed and compared case-insensitively: ``KILL_TRUE_VALUES`` is killed,
    ``KILL_FALSE_VALUES`` (including empty, which is how an unset variable
    reads) is not. Any other value, such as a typo (``ture``), a word this
    gate does not know (``enabled``), or a number other than 0 and 1, is
    treated as killed. A kill switch exists to stop installs; an operator who
    sets it with an unexpected spelling meant to turn it on, so ignoring the
    value would fail open.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        flag = value.strip().lower()
        # KILL_TRUE_VALUES and any unrecognised value are both killed.
        return flag in KILL_TRUE_VALUES or flag not in KILL_FALSE_VALUES
    return True


def _kill_active(explicit: object) -> bool:
    if explicit is not None:
        return kill_value_active(explicit)
    return kill_value_active(os.environ.get(KILL_ENV))


def _normalize_head(observed_head: str | None) -> str | None:
    if observed_head is None:
        return None
    if not isinstance(observed_head, str):
        return None
    value = observed_head.strip().lower()
    if not value:
        return None
    if not digest_ok(value):
        return None
    return value


def _log_deny(receipt: Mapping[str, Any]) -> None:
    """One DENY line: reason codes and quoted, truncated field values.

    No receipt body and no secrets. The logged origin is ``scheme://host[:port]``
    or the host of an scp-style origin. Userinfo, path, query and fragment are
    dropped. An origin that cannot be reduced that way is logged as
    ``<unparseable-origin>`` and does not replace the deny reason. Each value
    is a JSON string, so a space inside it cannot forge another field.
    """
    reasons = ",".join(str(reason) for reason in receipt.get("reasons") or ())
    fields = " ".join(
        f"{name}={_log_value(_log_field(name, receipt.get(name)))}"
        for name in ("origin", "expected_sha", "ref", "caller", "capability")
    )
    logger.warning("DENY reasons=%s %s", reasons, fields)


def _log_field(name: str, value: object) -> object:
    if name == "origin" and isinstance(value, str):
        return _strip_origin_userinfo(value)
    return value


def _strip_origin_userinfo(origin: str) -> str:
    """Reduce an origin to ``scheme://host[:port]``, or the host of an scp-style origin.

    Userinfo, path, query and fragment are dropped. An out-of-range port, a bad
    IPv6 host, an empty host, or any other origin that cannot be reduced this
    way is ``<unparseable-origin>``. A parse error is caught here so logging
    cannot turn the original DENY into ``kill_active``.
    """
    try:
        return _origin_log_target(origin)
    except ValueError:
        return _UNPARSEABLE_ORIGIN


def _origin_log_target(origin: str) -> str:
    if "://" in origin:
        parts = urlsplit(origin)
        host = parts.hostname
        port = parts.port
        if not parts.scheme or not host:
            return _UNPARSEABLE_ORIGIN
        if ":" in host:
            host = f"[{host}]"
        authority = f"{host}:{port}" if port is not None else host
        return f"{parts.scheme}://{authority}"
    matched = _SCP_ORIGIN.fullmatch(origin)
    if matched is None:
        return _UNPARSEABLE_ORIGIN
    return matched.group("host")


def _log_value(value: object) -> str:
    """Quote a logged value. Missing values stay a single dash.

    Control characters and lone surrogates become spaces. The result is a JSON
    string with non-ASCII escaped, so U+2028, U+2029, bidi overrides
    (U+202A-U+202E) and bidi isolates (U+2066-U+2069) cannot sit raw in the
    line, and a space or quote inside the value cannot forge a field such as
    ``reason=ok``.
    """
    if not isinstance(value, str) or value == "":
        return "-"
    cleaned: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        if category == "Cc" or category == "Cs":
            cleaned.append(" ")
        else:
            cleaned.append(char)
    text = "".join(cleaned)
    if len(text) > _LOG_VALUE_MAX:
        text = text[:_LOG_VALUE_MAX] + "..."
    return json.dumps(text, ensure_ascii=True)


def _mapping_str(envelope: object, key: str) -> str | None:
    if isinstance(envelope, Mapping):
        value = envelope.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
