# SPDX-License-Identifier: Apache-2.0
"""Tests for fail-closed supply integrity evaluate()."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

import supply_gate.gate as gatemod
from supply_gate.allowlist import load_allowlist
from supply_gate.demo import run_plugin4shell_class
from supply_gate.envelope import FIELD_MAX_BYTES, SupplyEnvelope
from supply_gate.gate import Decision, evaluate, safe_evaluate
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
