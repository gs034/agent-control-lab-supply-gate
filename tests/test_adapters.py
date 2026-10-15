# SPDX-License-Identifier: Apache-2.0
"""Thin installer adapter stubs: policy then materialise then evaluate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supply_gate.adapters import (
    LocalWorktreeAdapter,
    RecordingStubAdapter,
    caller_supplied_head,
    gated_install_or_update,
)
from supply_gate.allowlist import load_allowlist
from supply_gate.demo import load_plugin4shell_class_inputs
from supply_gate.gate import evaluate
from supply_gate.reasons import DenyReason, Verdict
from supply_gate.update_policy import UpdatePolicy

ROOT = Path(__file__).resolve().parents[1]
PIN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SWAPPED = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ORIGIN_OK = "https://git.example.invalid/marketplace/community-plugins.git"
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


def test_adapter_allow_when_pin_head_and_policy_agree() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["verify_performed"] is True


def test_weak_update_policy_denies_even_when_head_matches() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_raw={"mode": "trust_ref"},
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.UPDATE_POLICY_REJECTED in decision.reasons
    assert decision.receipt["verify_performed"] is True


def test_auto_latest_update_denied() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_raw={"mode": "auto_latest"},
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.UPDATE_POLICY_REJECTED in decision.reasons


def test_adapter_omitted_head_is_verify_missing() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(None),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.VERIFY_MISSING in decision.reasons


def test_adapter_swapped_head_is_head_mismatch() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(SWAPPED),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.HEAD_MISMATCH in decision.reasons


def test_plugin4shell_class_via_adapter_still_deny() -> None:
    envelope, observed, prose = load_plugin4shell_class_inputs(ROOT)
    decision = gated_install_or_update(
        envelope,
        RecordingStubAdapter(observed),
        update_policy=UpdatePolicy.fail_closed_default(),
        untrusted_prose=prose,
        use_env=False,
        kill_active=False,
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.HEAD_MISMATCH in decision.reasons
    assert DenyReason.PROSE_REJECTED_AS_POLICY in decision.reasons
    assert DenyReason.UPDATE_POLICY_REJECTED not in decision.reasons


def test_broken_allowlist_on_evaluate_is_deny(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "empty.json"
    path.write_text('{"origins": []}\n', encoding="utf-8")
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(path))
    decision = evaluate(_ok_envelope(), PIN)
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ALLOWLIST_INVALID in decision.reasons


def test_example_allowlist_file_loads() -> None:
    loaded = load_allowlist(path=ROOT / "config" / "allowlist.example.json", use_env=False)
    assert ORIGIN_OK in loaded.origins


def test_update_policy_loaded_from_host_file() -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_path=ROOT / "config" / "update_policy.example.json",
    )
    assert decision.verdict is Verdict.ALLOW


def test_broken_update_policy_file_denies(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not-json\n", encoding="utf-8")
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_path=path,
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.UPDATE_POLICY_REJECTED in decision.reasons


def test_empty_update_policy_file_denies(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("\n", encoding="utf-8")
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_path=path,
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.UPDATE_POLICY_REJECTED in decision.reasons


def test_unreadable_allowlist_path_denies(tmp_path: Path) -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        allowlist_path=tmp_path / "missing.json",
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ALLOWLIST_INVALID in decision.reasons


def test_local_worktree_uses_caller_digest_only(tmp_path: Path) -> None:
    worktree = tmp_path / "tree"
    worktree.mkdir()
    (worktree / "HEAD").write_text("should-not-be-read\n", encoding="utf-8")
    decision = gated_install_or_update(
        _ok_envelope(),
        LocalWorktreeAdapter(PIN, worktree=worktree),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["observed_head"] == PIN


def test_local_worktree_missing_tree_is_verify_missing(tmp_path: Path) -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        LocalWorktreeAdapter(PIN, worktree=tmp_path / "absent"),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.VERIFY_MISSING in decision.reasons


def test_local_worktree_remote_shaped_path_is_verify_missing() -> None:
    assert caller_supplied_head(PIN, worktree="https://git.example.invalid/tree") is None
    decision = gated_install_or_update(
        _ok_envelope(),
        LocalWorktreeAdapter(PIN, worktree="https://git.example.invalid/tree"),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.VERIFY_MISSING in decision.reasons


def test_adapter_does_not_change_official_evaluate_receipt() -> None:
    """Adapter path is extra; official evaluate fixture stays the demo contract."""
    envelope = json.loads(
        (ROOT / "eval" / "plugin4shell_class" / "envelope.json").read_text(encoding="utf-8")
    )
    observed = json.loads(
        (ROOT / "eval" / "plugin4shell_class" / "observed_head.json").read_text(
            encoding="utf-8"
        )
    )["observed_head"]
    prose = (ROOT / "eval" / "plugin4shell_class" / "malicious_prose.txt").read_text(
        encoding="utf-8"
    )
    expected = json.loads(
        (ROOT / "eval" / "plugin4shell_class" / "expected_deny_receipt.example.json").read_text(
            encoding="utf-8"
        )
    )
    decision = evaluate(
        envelope,
        observed,
        untrusted_prose=prose,
        allowed_origins=load_allowlist(use_env=False).origins,
        kill_active=False,
    )
    assert decision.receipt == expected


def test_gated_path_use_env_false_ignores_ambient_host_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    allowlist = tmp_path / "exclude-fixture-origin.json"
    allowlist.write_text(
        '{"origins": ["https://git.example.invalid/agent-control-lab/skills.git"]}\n',
        encoding="utf-8",
    )
    policy = tmp_path / "weak.json"
    policy.write_text('{"mode": "trust_ref"}\n', encoding="utf-8")
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(allowlist))
    monkeypatch.setenv("ACL_SUPPLY_GATE_UPDATE_POLICY", str(policy))
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        use_env=False,
    )
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["kill_active"] is False
    assert DenyReason.ORIGIN_NOT_ALLOWLISTED not in decision.reasons
    assert DenyReason.UPDATE_POLICY_REJECTED not in decision.reasons
    assert DenyReason.KILL_ACTIVE not in decision.reasons


def test_gated_path_kill_env_still_denies_when_use_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", "1")
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.KILL_ACTIVE in decision.reasons


@pytest.mark.parametrize("value", ["on", "True", " y ", "enabled"])
def test_gated_path_kill_config_value_spellings_deny(value: str) -> None:
    """S-5: a kill_active config value on the adapter path is read fail closed."""
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
        kill_active=value,  # type: ignore[arg-type]
        use_env=False,
    )
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)


def test_gated_path_kill_env_truthy_spelling_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_KILL", " On ")
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert decision.reasons == (DenyReason.KILL_ACTIVE,)


def _write(tmp_path: Path, name: str, data: bytes | str) -> Path:
    path = tmp_path / name
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


_NOT_UTF8 = b"\xff\xfe{\x00"
_TOO_DEEP = '{"origins": ' + "[" * 100000 + "]" * 100000 + "}"


@pytest.mark.parametrize("data", [_NOT_UTF8, _TOO_DEEP], ids=["not_utf8", "too_deep"])
def test_malformed_allowlist_file_is_deny_not_raise(tmp_path: Path, data: bytes | str) -> None:
    """S-6: a malformed allowlist on the adapter path is allowlist_invalid, never an exception."""
    path = _write(tmp_path, "allowlist.json", data)
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
        allowlist_path=path,
        use_env=False,
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ALLOWLIST_INVALID in decision.reasons


@pytest.mark.parametrize("allowlist", [{"origins": [ORIGIN_OK]}, [ORIGIN_OK], "nope"])
def test_allowlist_object_of_the_wrong_type_is_deny_not_raise(allowlist: object) -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
        allowlist=allowlist,  # type: ignore[arg-type]
        use_env=False,
    )
    assert decision.verdict is Verdict.DENY
    assert DenyReason.ALLOWLIST_INVALID in decision.reasons


def test_malformed_allowlist_env_is_deny_not_raise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_SUPPLY_GATE_ALLOWLIST", str(_write(tmp_path, "allowlist.json", _NOT_UTF8)))
    monkeypatch.delenv("ACL_SUPPLY_GATE_KILL", raising=False)
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy=UpdatePolicy.fail_closed_default(),
    )
    assert DenyReason.ALLOWLIST_INVALID in decision.reasons
    # evaluate() reads the same env allowlist and also returns a DENY, not an exception.
    direct = evaluate(_ok_envelope(), PIN, kill_active=False)
    assert direct.verdict is Verdict.DENY
    assert DenyReason.ALLOWLIST_INVALID in direct.reasons


@pytest.mark.parametrize("data", [_NOT_UTF8, '{"mode": ' + "[" * 100000 + "]" * 100000 + "}"], ids=["not_utf8", "too_deep"])
def test_malformed_update_policy_file_is_deny_not_raise(tmp_path: Path, data: bytes | str) -> None:
    """S-6: a malformed update policy file is update_policy_rejected, never an exception."""
    path = _write(tmp_path, "policy.json", data)
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        update_policy_path=path,
        use_env=False,
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.UPDATE_POLICY_REJECTED,)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"update_policy_raw": ["pin_and_verify"]},
        {"update_policy_raw": "pin_and_verify"},
        {"update_policy": {"mode": "pin_and_verify"}},
        {"update_policy": "pin_and_verify"},
    ],
)
def test_update_policy_of_the_wrong_type_is_deny_not_raise(kwargs: dict[str, object]) -> None:
    decision = gated_install_or_update(
        _ok_envelope(),
        RecordingStubAdapter(PIN),
        use_env=False,
        **kwargs,  # type: ignore[arg-type]
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.UPDATE_POLICY_REJECTED,)


@pytest.mark.parametrize("envelope", [None, [1, 2], "envelope", 7, b"{}"])
def test_non_object_envelope_is_deny_not_raise(envelope: object) -> None:
    """S-6: a non-object envelope is envelope_invalid; the adapter is not asked to materialise."""

    class _Refuse:
        def materialise(self, request: object) -> object:
            raise AssertionError("adapter must not run for a non-object envelope")

    decision = gated_install_or_update(
        envelope,  # type: ignore[arg-type]
        _Refuse(),  # type: ignore[arg-type]
        update_policy=UpdatePolicy.fail_closed_default(),
        use_env=False,
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.ENVELOPE_INVALID, DenyReason.VERIFY_MISSING)
    assert decision.receipt["decision"] == "DENY"


def test_adapter_returning_a_non_result_is_deny_not_raise() -> None:
    class _Broken:
        def materialise(self, request: object) -> object:
            return None

    decision = gated_install_or_update(
        _ok_envelope(),
        _Broken(),  # type: ignore[arg-type]
        update_policy=UpdatePolicy.fail_closed_default(),
        use_env=False,
    )
    # Same outcome as an adapter that raises: the fault is DENY (kill_active), no HEAD.
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.KILL_ACTIVE, DenyReason.VERIFY_MISSING)
