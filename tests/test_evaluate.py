# SPDX-License-Identifier: Apache-2.0
"""Tests for fail-closed supply integrity evaluate()."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

import supply_gate.gate as gatemod
from supply_gate.allowlist import load_allowlist
from supply_gate.demo import run_plugin4shell_class
from supply_gate.envelope import (
    FIELD_MAX_BYTES,
    REF_FORBIDDEN_CODEPOINTS,
    UNTRUSTED_MAX_BYTES,
    UNTRUSTED_MAX_DEPTH,
    SupplyEnvelope,
)
from supply_gate.gate import Decision, _log_value, evaluate, safe_evaluate
from supply_gate.receipt import dumps_receipt
from supply_gate.reasons import DenyReason, Verdict

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "eval" / "plugin4shell_class"
PIN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SWAPPED = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ORIGIN_OK = "https://git.example.invalid/marketplace/community-plugins.git"
ORIGIN_BAD = "https://evil.example.invalid/marketplace/community-plugins.git"
CALLER = "host.plugin_install"


def _ok_envelope(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "origin": ORIGIN_OK,
        "expected_sha": PIN,
        "ref": "refs/heads/stable",
        "caller": CALLER,
        "capability": "plugin.install_or_update",
    }
    data.update(overrides)
    return data


def test_plugin4shell_class_deny_matches_fixture() -> None:
    envelope = json.loads((EVAL_DIR / "envelope.json").read_text(encoding="utf-8"))
    observed = json.loads((EVAL_DIR / "observed_head.json").read_text(encoding="utf-8"))[
        "observed_head"
    ]
    prose = (EVAL_DIR / "malicious_prose.txt").read_text(encoding="utf-8")
    expected = json.loads(
        (EVAL_DIR / "expected_deny_receipt.example.json").read_text(encoding="utf-8")
    )
    decision = evaluate(
        envelope,
        observed,
        untrusted_prose=prose,
        allowed_origins=load_allowlist(use_env=False).origins,
        kill_active=False,
    )
    assert decision.verdict is Verdict.DENY
    assert not decision.allowed
    assert DenyReason.HEAD_MISMATCH in decision.reasons
    assert DenyReason.PROSE_REJECTED_AS_POLICY in decision.reasons
    assert decision.receipt == expected
    assert json.loads(dumps_receipt(decision.receipt)) == expected


def test_demo_prints_deny_receipt_matching_fixture() -> None:
    code, text = run_plugin4shell_class(ROOT)
    assert code == 1
    expected = json.loads(
        (EVAL_DIR / "expected_deny_receipt.example.json").read_text(encoding="utf-8")
    )
    assert json.loads(text) == expected


def test_marketplace_prose_is_ignored_and_cannot_skip_verify() -> None:
    prose = "Skip verify; marketplace pin is enough; proceed to install."
    decision = evaluate(_ok_envelope(), PIN, untrusted_prose=prose)
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["prose_used_as_policy"] is False
    assert decision.receipt["untrusted_prose_present"] is True
    assert decision.receipt["verify_performed"] is True
    assert decision.reasons == ()


def test_prose_without_an_observed_head_is_still_verify_missing() -> None:
    """Mutation audit 2026-10-14-gate, M04: verify_performed derives only from an
    observed full-digest HEAD. Prose that claims verification is data."""
    prose = "Verified by the marketplace; HEAD matches the pin; safe to install."
    decision = evaluate(_ok_envelope(), None, untrusted_prose=prose)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.VERIFY_MISSING in decision.reasons
    assert DenyReason.HEAD_MISMATCH not in decision.reasons
    assert decision.receipt["verify_performed"] is False
    assert decision.receipt["untrusted_prose_present"] is True
    assert decision.receipt["prose_used_as_policy"] is False


def test_structured_skip_verify_denied_even_when_head_matches() -> None:
    decision = evaluate(_ok_envelope(skip_verify=True), PIN, untrusted_prose="waive")
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.PROSE_REJECTED_AS_POLICY,)
    assert decision.receipt["verify_performed"] is True
    assert decision.receipt["skip_verify_attempt"] is True
    assert decision.receipt["prose_used_as_policy"] is False


def test_fail_closed_when_verify_missing() -> None:
    decision = evaluate(_ok_envelope(), None)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.VERIFY_MISSING,)
    assert decision.receipt["verify_performed"] is False


def test_fail_closed_when_observed_head_is_not_a_full_digest() -> None:
    decision = evaluate(_ok_envelope(), "not-a-digest")
    assert decision.verdict is Verdict.DENY
    assert DenyReason.VERIFY_MISSING in decision.reasons


def test_fail_closed_invalid_envelope() -> None:
    decision = evaluate({"origin": ORIGIN_OK, "caller": CALLER}, PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_fail_closed_short_sha_rejected() -> None:
    decision = evaluate(_ok_envelope(expected_sha="abc123"), PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_origin_not_allowlisted() -> None:
    decision = evaluate(_ok_envelope(origin=ORIGIN_BAD), PIN)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.ORIGIN_NOT_ALLOWLISTED,)


def test_custom_allowlist_can_permit_other_origin() -> None:
    extra = frozenset({ORIGIN_BAD})
    decision = evaluate(_ok_envelope(origin=ORIGIN_BAD), PIN, allowed_origins=extra)
    assert decision.verdict is Verdict.ALLOW


def test_kill_active_denies() -> None:
    decision = evaluate(_ok_envelope(), PIN, kill_active=True)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.KILL_ACTIVE in decision.reasons
    assert decision.receipt["kill_active"] is True


def test_kill_env_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    decision = evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.KILL_ACTIVE in decision.reasons


def test_allow_when_pin_origin_and_head_agree() -> None:
    parsed, skip = SupplyEnvelope.from_mapping(_ok_envelope())
    assert parsed is not None
    assert skip is False
    decision = evaluate(parsed, PIN)
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["verify_performed"] is True
    assert decision.receipt["reasons"] == []


def test_safe_evaluate_fail_closed_on_unexpected_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> Decision:
        raise RuntimeError("gate fault")

    monkeypatch.setattr(gatemod, "evaluate", boom)
    decision = safe_evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)


def test_naive_pin_alone_is_not_sufficient() -> None:
    """Origin allowlisted + well-formed pin still DENY if checkout HEAD differs."""
    envelope = _ok_envelope()
    naive_fields_ok = (
        envelope["origin"] == ORIGIN_OK
        and isinstance(envelope["expected_sha"], str)
        and len(envelope["expected_sha"]) == 40
    )
    assert naive_fields_ok
    decision = evaluate(envelope, SWAPPED)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.HEAD_MISMATCH in decision.reasons


@pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "t", "yes", "YES", "y", "Y", "on", "ON", " 1 ", "\tyes\n"])
def test_kill_env_truthy_spellings_deny(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """S-5: the kill env is trimmed and compared case-insensitively."""
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", value)
    decision = evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)
    assert decision.receipt["kill_active"] is True


@pytest.mark.parametrize("value", ["ture", "enabled", "2", "kill", "-1", "yes please"])
def test_kill_env_unrecognised_value_fails_closed(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """S-5: an unrecognised non-empty kill value is treated as killed, not ignored."""
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", value)
    decision = evaluate(_ok_envelope(), PIN)
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)


@pytest.mark.parametrize("value", ["", "   ", "0", "false", "False", "f", "no", "NO", "n", "off", " Off "])
def test_kill_env_falsy_spellings_leave_kill_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", value)
    decision = evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["kill_active"] is False


@pytest.mark.parametrize("value", ["True", "on", "y", "YES", " 1 ", "enabled", 1, 2])
def test_kill_active_config_value_truthy_or_unrecognised_denies(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    """S-5: an explicit kill_active config value is read the same way as the env."""
    monkeypatch.delenv("ACL_SUPPLY_GATE_KILL", raising=False)
    decision = evaluate(_ok_envelope(), PIN, kill_active=value)  # type: ignore[arg-type]
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)
    assert decision.receipt["kill_active"] is True


@pytest.mark.parametrize("value", ["off", "false", "0", 0, False])
def test_kill_active_config_value_falsy_overrides_env(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    decision = evaluate(_ok_envelope(), PIN, kill_active=value)  # type: ignore[arg-type]
    assert decision.verdict is Verdict.ALLOW


def test_documented_field_caps() -> None:
    """Each string field has a documented byte cap. ref is 4 KiB."""
    assert FIELD_MAX_BYTES == {
        "origin": 2048,
        "expected_sha": 128,
        "caller": 256,
        "ref": 4096,
        "capability": 256,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("origin", 12),
        ("expected_sha", 12),
        ("caller", 12),
        ("ref", ["refs/heads/stable"]),
        ("capability", {"name": "plugin.install_or_update"}),
    ],
)
def test_non_string_envelope_field_is_invalid(field: str, value: object) -> None:
    decision = evaluate(_ok_envelope(**{field: value}), PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_unknown_top_level_key_is_invalid() -> None:
    decision = evaluate(_ok_envelope(note="hello"), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_operation_is_accepted_and_an_unknown_key_is_still_refused() -> None:
    """update_policy reads operation, so a valid operation is a known envelope key."""
    accepted = evaluate(_ok_envelope(operation="install"), PIN)
    assert accepted.verdict is Verdict.ALLOW
    assert DenyReason.ENVELOPE_INVALID not in accepted.reasons
    refused = evaluate(_ok_envelope(note="hello"), PIN)
    assert refused.verdict is Verdict.DENY
    assert DenyReason.ENVELOPE_INVALID in refused.reasons


def test_non_string_top_level_key_is_invalid() -> None:
    raw = _ok_envelope()
    raw[1] = "x"  # type: ignore[index]
    decision = evaluate(raw, PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


@pytest.mark.parametrize("field", ["origin", "expected_sha", "caller", "ref", "capability"])
def test_field_over_its_byte_cap_is_invalid(field: str) -> None:
    decision = evaluate(_ok_envelope(**{field: "a" * (FIELD_MAX_BYTES[field] + 1)}), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_ref_at_four_kib_is_accepted_and_one_more_byte_is_not() -> None:
    at_cap = "é" * 2048
    assert len(at_cap.encode("utf-8")) == FIELD_MAX_BYTES["ref"] == 4096
    assert evaluate(_ok_envelope(ref=at_cap), PIN).verdict is Verdict.ALLOW
    over = "é" * 2049
    assert len(over.encode("utf-8")) == 4098
    assert DenyReason.ENVELOPE_INVALID in evaluate(_ok_envelope(ref=over), PIN).reasons


@pytest.mark.parametrize("field", ["caller", "ref", "capability", "origin"])
@pytest.mark.parametrize("mark", ["\n", "\x00", "\x7f", "\ud800"])
def test_control_or_lone_surrogate_in_a_string_field_is_invalid(field: str, mark: str) -> None:
    current = _ok_envelope()[field]
    assert isinstance(current, str)
    decision = evaluate(_ok_envelope(**{field: current + mark}), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_deny_logs_one_line_with_reasons_and_truncated_values(caplog: pytest.LogCaptureFixture) -> None:
    """A DENY writes one line in addition to the receipt. Values are truncated; secrets are not copied out."""
    secret = "token-" + ("s" * 200)
    prose = "super-secret-prose-should-not-be-logged"
    envelope = _ok_envelope(ref=secret, origin=ORIGIN_BAD)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(envelope, None, untrusted_prose=prose)
    assert decision.verdict is Verdict.DENY
    assert decision.receipt["ref"] == secret
    assert DenyReason.ORIGIN_NOT_ALLOWLISTED in decision.reasons
    assert DenyReason.VERIFY_MISSING in decision.reasons
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert "\n" not in line
    assert "origin_not_allowlisted" in line
    assert "verify_missing" in line
    assert secret not in line
    assert prose not in line
    assert secret[:64] in line
    assert line.endswith("...") or "ref=" in line


def test_allow_does_not_log_a_deny_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.ALLOW
    assert [record for record in caplog.records if record.getMessage().startswith("DENY ")] == []


def test_safe_evaluate_logs_one_deny_line_without_the_fault_text(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> Decision:
        raise RuntimeError("secret-fault-detail")

    monkeypatch.setattr(gatemod, "evaluate", boom)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = safe_evaluate(_ok_envelope(), PIN)
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    assert "kill_active" in lines[0]
    assert "secret-fault-detail" not in lines[0]


def _compact_untrusted(value: object) -> bytes:
    """The UTF-8 compact form named by ``UNTRUSTED_MAX_BYTES``."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _outside_json_strings(line: str) -> str:
    """Drop JSON string literals so a forged field inside a value is not visible."""
    return re.sub(r'"(?:\\.|[^"\\])*"', "", line)


def test_untrusted_json_object_is_accepted() -> None:
    decision = evaluate(_ok_envelope(untrusted={"note": "hello", "n": 1, "ok": True, "items": [None]}), PIN)
    assert decision.verdict is Verdict.ALLOW
    assert DenyReason.ENVELOPE_INVALID not in decision.reasons


def test_untrusted_bypass_is_still_recorded_when_the_object_is_valid() -> None:
    decision = evaluate(_ok_envelope(untrusted={"skip_verify": True}), PIN)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.PROSE_REJECTED_AS_POLICY,)
    assert decision.receipt["skip_verify_attempt"] is True


@pytest.mark.parametrize("value", ["hello", 1, 1.5, True, False, None, [], ["a"], (1, 2), b"x", {1: "a"}])
def test_untrusted_must_be_a_json_object(value: object) -> None:
    decision = evaluate(_ok_envelope(untrusted=value), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_untrusted_rejects_nan_and_infinity_anywhere(bad: float) -> None:
    for nested in ({"n": bad}, {"a": {"b": [1, bad]}}, {"a": [bad]}):
        decision = evaluate(_ok_envelope(untrusted=nested), PIN)
        assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_untrusted_nan_still_records_a_bypass_attempt() -> None:
    decision = evaluate(_ok_envelope(untrusted={"skip_verify": True, "n": float("nan")}), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons
    assert DenyReason.PROSE_REJECTED_AS_POLICY in decision.reasons


def test_untrusted_depth_cap_counts_objects_and_arrays() -> None:
    """The root object is depth 1. Depth 32 is accepted and depth 33 is not."""
    object_tree: object = {"v": 1}
    for _ in range(UNTRUSTED_MAX_DEPTH - 1):
        object_tree = {"n": object_tree}
    assert evaluate(_ok_envelope(untrusted=object_tree), PIN).verdict is Verdict.ALLOW
    object_tree = {"n": object_tree}
    assert DenyReason.ENVELOPE_INVALID in evaluate(_ok_envelope(untrusted=object_tree), PIN).reasons

    array_tree: object = 1
    for _ in range(UNTRUSTED_MAX_DEPTH - 1):
        array_tree = [array_tree]
    assert evaluate(_ok_envelope(untrusted={"a": array_tree}), PIN).verdict is Verdict.ALLOW
    array_tree = [array_tree]
    assert DenyReason.ENVELOPE_INVALID in evaluate(_ok_envelope(untrusted={"a": array_tree}), PIN).reasons


def test_untrusted_serialized_size_cap_is_utf8_bytes() -> None:
    overhead = len(_compact_untrusted({"p": ""}))
    at_cap = {"p": "a" * (UNTRUSTED_MAX_BYTES - overhead)}
    assert len(_compact_untrusted(at_cap)) == UNTRUSTED_MAX_BYTES
    assert evaluate(_ok_envelope(untrusted=at_cap), PIN).verdict is Verdict.ALLOW
    over = {"p": "a" * (UNTRUSTED_MAX_BYTES - overhead + 1)}
    assert len(_compact_untrusted(over)) == UNTRUSTED_MAX_BYTES + 1
    assert DenyReason.ENVELOPE_INVALID in evaluate(_ok_envelope(untrusted=over), PIN).reasons

    # A character cap would accept this: the compact text is MAX characters,
    # while its UTF-8 encoding is larger than MAX bytes.
    wide = {"p": "é" * (UNTRUSTED_MAX_BYTES - overhead)}
    text = _compact_untrusted(wide).decode("utf-8")
    assert len(text) == UNTRUSTED_MAX_BYTES
    assert len(text.encode("utf-8")) > UNTRUSTED_MAX_BYTES
    assert DenyReason.ENVELOPE_INVALID in evaluate(_ok_envelope(untrusted=wide), PIN).reasons


@pytest.mark.parametrize("mark", [chr(code) for code in sorted(REF_FORBIDDEN_CODEPOINTS)])
def test_ref_rejects_line_separators_and_bidi_marks(mark: str) -> None:
    decision = evaluate(_ok_envelope(ref=f"refs/heads/stable{mark}x"), PIN)
    assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_line_separator_in_caller_does_not_invalidate_the_envelope() -> None:
    decision = evaluate(_ok_envelope(caller="host\u2028"), PIN)
    assert decision.verdict is Verdict.ALLOW


def test_log_value_quotes_a_forged_reason_injection() -> None:
    """The exact injection `` reason=ok`` is quoted, so it is not a new field."""
    quoted = _log_value(" reason=ok")
    assert quoted == json.dumps(" reason=ok")
    assert "reason=ok" not in _outside_json_strings(f"ref={quoted}")


def test_deny_log_quotes_values_against_forged_reason_field(caplog: pytest.LogCaptureFixture) -> None:
    """A value containing `` reason=ok`` stays inside quotes and is not a new field.

    The forged text is an internal space plus ``reason=ok``. A leading space on
    the whole field would be stripped before the receipt is built.
    """
    forged = "x reason=ok"
    envelope = _ok_envelope(ref=forged, origin=ORIGIN_BAD)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(envelope, None)
    assert decision.receipt["ref"] == forged
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert " reason=ok" in forged
    assert 'ref="x reason=ok"' in line
    assert "reason=ok" not in _outside_json_strings(line)
    for name in ("origin", "expected_sha", "ref", "caller", "capability"):
        assert f'{name}="' in line


def test_deny_log_quotes_a_value_that_tries_to_close_the_string(caplog: pytest.LogCaptureFixture) -> None:
    forged = 'x" reason=ok'
    envelope = _ok_envelope(ref=forged, origin=ORIGIN_BAD)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        evaluate(envelope, None)
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert json.dumps(forged) in line
    assert "reason=ok" not in _outside_json_strings(line)


@pytest.mark.parametrize(
    ("origin", "kept"),
    [
        (
            "https://username:password@evil.example.invalid/repo.git",
            "https://evil.example.invalid",
        ),
        (
            "https://username@evil.example.invalid/repo.git",
            "https://evil.example.invalid",
        ),
        (
            "https://username:password@evil.example.invalid:8443/repo.git",
            "https://evil.example.invalid:8443",
        ),
        (
            "https://username:password@[2001:db8::1]/repo.git",
            "https://[2001:db8::1]",
        ),
        (
            "https://username:password@[2001:db8::1]:8443/repo.git?token=SECRET#frag",
            "https://[2001:db8::1]:8443",
        ),
    ],
)
def test_deny_log_strips_origin_userinfo(caplog: pytest.LogCaptureFixture, origin: str, kept: str) -> None:
    envelope = _ok_envelope(origin=origin)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(envelope, None)
    assert decision.receipt["origin"] == origin
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert "username" not in line
    assert "password" not in line
    assert "repo.git" not in line
    assert "SECRET" not in line
    assert json.dumps(kept) in line


@pytest.mark.parametrize(
    ("origin", "kept", "hidden"),
    [
        (
            "https://evil.example.invalid/username:password@file?token=SECRET#frag",
            "https://evil.example.invalid",
            ("password", "SECRET", "frag", "file"),
        ),
        (
            "https://evil.example.invalid/repo?access_token=SECRET#fragment-token",
            "https://evil.example.invalid",
            ("SECRET", "fragment-token", "repo"),
        ),
        (
            "user:TOKEN@git.example.invalid:owner/repo",
            "git.example.invalid",
            ("TOKEN", "owner/repo", "user:TOKEN"),
        ),
        (
            "git@git.example.invalid:owner/repo.git",
            "git.example.invalid",
            ("owner/repo.git",),
        ),
    ],
)
def test_deny_log_origin_keeps_only_scheme_host_or_scp_host(
    caplog: pytest.LogCaptureFixture, origin: str, kept: str, hidden: tuple[str, ...]
) -> None:
    """Path, query, fragment and an scp-style token are not written to the DENY line."""
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(_ok_envelope(origin=origin), PIN)
    assert decision.receipt["origin"] == origin
    assert decision.reasons == (DenyReason.ORIGIN_NOT_ALLOWLISTED,)
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert json.dumps(kept) in line
    assert origin not in line
    for secret in hidden:
        assert secret not in line


@pytest.mark.parametrize(
    "origin",
    [
        "https://user:TOKEN@/owner/repo?access=SECRET",
        "https:///owner/SECRET",
        "http://:8443/SECRET",
        "https://user:TOKEN@evil.example.invalid:99999/repo.git?access=SECRET",
        "https://user:TOKEN@[::gggg]/repo.git?access=SECRET",
        "https://[::gggg]/SECRET",
    ],
)
def test_unparseable_origin_logs_placeholder_and_keeps_the_deny_reason(
    caplog: pytest.LogCaptureFixture, origin: str
) -> None:
    """A bad port, bad IPv6 host, or empty host does not become kill_active."""
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = safe_evaluate(_ok_envelope(origin=origin), PIN)
    assert decision.reasons == (DenyReason.ORIGIN_NOT_ALLOWLISTED,)
    assert DenyReason.KILL_ACTIVE not in decision.reasons
    assert decision.receipt["origin"] == origin
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    assert "origin_not_allowlisted" in line
    assert "kill_active" not in line
    assert json.dumps("<unparseable-origin>") in line
    assert origin not in line
    assert "TOKEN" not in line
    assert "SECRET" not in line


def test_deny_log_escapes_line_separators_and_bidi_marks(caplog: pytest.LogCaptureFixture) -> None:
    marks = "".join(chr(code) for code in sorted(REF_FORBIDDEN_CODEPOINTS))
    envelope = _ok_envelope(caller="host" + marks, origin=ORIGIN_BAD)
    with caplog.at_level(logging.WARNING, logger="supply_gate.gate"):
        decision = evaluate(envelope, PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ENVELOPE_INVALID not in decision.reasons
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("DENY ")]
    assert len(lines) == 1
    line = lines[0]
    for code in REF_FORBIDDEN_CODEPOINTS:
        assert chr(code) not in line
        assert f"\\u{code:04x}" in line
