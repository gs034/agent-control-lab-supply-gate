# SPDX-License-Identifier: Apache-2.0
"""v0.4 manifest classes: unpinned MCP server, shell pre-approval, unverified hook update."""

from __future__ import annotations

from supply_gate.adapters import RecordingStubAdapter, gated_install_or_update
from supply_gate.allowlist import load_allowlist
from supply_gate.gate import evaluate
from supply_gate.reasons import DenyReason, Verdict
from supply_gate.update_policy import UpdatePolicy

PIN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HOOK_PIN = "cccccccccccccccccccccccccccccccccccccccc"
ORIGIN = "https://git.example.invalid/marketplace/community-plugins.git"
ALLOWED = load_allowlist(use_env=False).origins


def _envelope(manifest: dict[str, object]) -> dict[str, object]:
    return {
        "origin": ORIGIN,
        "expected_sha": PIN,
        "caller": "host.plugin_install",
        "capability": "plugin.install_or_update",
        "manifest": manifest,
    }


def _evaluate(manifest: dict[str, object], **kwargs: object):
    return evaluate(_envelope(manifest), PIN, allowed_origins=ALLOWED, kill_active=False, **kwargs)


def test_pinned_manifest_with_verified_hooks_still_allows() -> None:
    manifest = {
        "mcp_servers": [{"name": "files", "source": "https://mcp.example.invalid/files", "pin": PIN}],
        "permissions": ["Read", "Edit"],
        "hooks": [{"name": "post-install", "source": "hooks/post_install.py", "pin": HOOK_PIN}],
    }
    decision = _evaluate(manifest, observed_hooks={"hooks/post_install.py": HOOK_PIN})
    assert decision.verdict is Verdict.ALLOW
    assert decision.receipt["verify_performed"] is True


def test_unpinned_mcp_server_is_deny() -> None:
    manifest = {"mcp_servers": [{"name": "files", "source": "https://mcp.example.invalid/files"}]}
    decision = _evaluate(manifest)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.MCP_SERVER_UNPINNED,)
    short = {"mcp_servers": [{"name": "files", "source": "x", "pin": "abc123"}]}
    assert _evaluate(short).reasons == (DenyReason.MCP_SERVER_UNPINNED,)
    camel = {"mcpServers": [{"source": "https://mcp.example.invalid/files"}]}
    assert _evaluate(camel).reasons == (DenyReason.MCP_SERVER_UNPINNED,)


def test_shell_preapproval_in_manifest_is_deny() -> None:
    for token in ("Bash", "Bash(*)", "Bash*", "Tool:Bash", "shell:exec", "powershell", "*", "all", "Ba\u200bsh", "\uff42ash"):
        decision = _evaluate({"allowed_tools": ["Read", token]})
        assert decision.verdict is Verdict.DENY, token
        assert decision.reasons == (DenyReason.SKILL_SHELL_PREAPPROVED,), token
    assert _evaluate({"permissions": ["Read", "WebFetch", "Publish"]}).verdict is Verdict.ALLOW
    assert _evaluate({"allowedTools": ["Bash"]}).reasons == (DenyReason.SKILL_SHELL_PREAPPROVED,)


def test_hook_without_pin_or_observed_digest_is_deny() -> None:
    unpinned = {"hooks": [{"name": "h", "source": "hooks/h.py"}]}
    assert _evaluate(unpinned, observed_hooks={"hooks/h.py": HOOK_PIN}).reasons == (
        DenyReason.HOOK_UPDATE_UNVERIFIED,
    )
    pinned = {"hooks": [{"name": "h", "source": "hooks/h.py", "pin": HOOK_PIN}]}
    assert _evaluate(pinned).reasons == (DenyReason.HOOK_UPDATE_UNVERIFIED,)
    swapped = {"hooks/h.py": PIN}
    assert _evaluate(pinned, observed_hooks=swapped).reasons == (
        DenyReason.HOOK_UPDATE_UNVERIFIED,
    )


def test_manifest_reasons_stack_after_head_verify_and_never_skip_it() -> None:
    manifest = {
        "mcp_servers": [{"name": "files", "source": "https://mcp.example.invalid/files"}],
        "allowed_tools": ["Bash"],
        "hooks": [{"name": "h", "source": "hooks/h.py"}],
    }
    decision = evaluate(_envelope(manifest), None, allowed_origins=ALLOWED, kill_active=False)
    assert decision.reasons == (
        DenyReason.VERIFY_MISSING,
        DenyReason.MCP_SERVER_UNPINNED,
        DenyReason.SKILL_SHELL_PREAPPROVED,
        DenyReason.HOOK_UPDATE_UNVERIFIED,
    )
    assert decision.receipt["verify_performed"] is False


def test_ill_formed_manifest_is_envelope_invalid() -> None:
    for bad in (
        {"mcp_servers": "files"},
        {"hooks": [{"pin": PIN}]},
        {"permissions": "Bash"},
        {"tools": ["Bash"]},
        {"plugin": {"mcp_servers": []}},
        "manifest",
    ):
        decision = _evaluate(bad) if isinstance(bad, dict) else evaluate(
            {**_envelope({}), "manifest": bad}, PIN, allowed_origins=ALLOWED, kill_active=False
        )
        assert decision.verdict is Verdict.DENY
        assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_non_mapping_observed_hooks_is_deny_not_error() -> None:
    pinned = {"hooks": [{"source": "hooks/h.py", "pin": HOOK_PIN}]}
    for bad in ([("hooks/h.py", HOOK_PIN)], "hooks/h.py", 7):
        decision = _evaluate(pinned, observed_hooks=bad)
        assert decision.reasons == (DenyReason.HOOK_UPDATE_UNVERIFIED,)


def test_manifest_reasons_flow_through_adapter_path() -> None:
    manifest = {"hooks": [{"name": "h", "source": "hooks/h.py", "pin": HOOK_PIN}]}
    kwargs = {
        "update_policy": UpdatePolicy.fail_closed_default(),
        "allowlist": load_allowlist(use_env=False),
        "kill_active": False,
        "use_env": False,
    }
    verified = gated_install_or_update(
        _envelope(manifest),
        RecordingStubAdapter(PIN, observed_hooks={"hooks/h.py": HOOK_PIN}),
        **kwargs,
    )
    assert verified.verdict is Verdict.ALLOW
    unverified = gated_install_or_update(_envelope(manifest), RecordingStubAdapter(PIN), **kwargs)
    assert unverified.reasons == (DenyReason.HOOK_UPDATE_UNVERIFIED,)


def test_manifest_absent_leaves_receipt_shape_unchanged() -> None:
    decision = evaluate(
        {k: v for k, v in _envelope({}).items() if k != "manifest"},
        PIN,
        allowed_origins=ALLOWED,
        kill_active=False,
    )
    assert decision.verdict is Verdict.ALLOW
    assert "manifest" not in decision.receipt
