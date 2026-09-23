# SPDX-License-Identifier: Apache-2.0
"""v0.4 manifest classes and real-shape loader: MCP, permissions, hooks."""

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
    for benign in ("Read", "WebFetch", "Publish", "shift", "hash", "cmdline", "execution_log",
                   "Read(*.sh)", "Edit(scripts/**/*.sh)", "Skill(exec-plan)", "Write(cmd.txt)"):
        assert _evaluate({"permissions": [benign]}).verdict is Verdict.ALLOW, benign
    assert _evaluate({"permissions": ["mcp__shell__run"]}).reasons == (DenyReason.SKILL_SHELL_PREAPPROVED,)
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
        {"permissions": {"allow": ["Read"], "defaultMode": "bypass"}},
        {"permissions": 1},
        {"tools": ["Bash"]},
        {"plugin": {"mcp_servers": []}},
        {"hooks": [{"source": "h", "pin": PIN, "bogus": 1}]},
        "manifest",
    ):
        decision = _evaluate(bad) if isinstance(bad, dict) else evaluate(
            {**_envelope({}), "manifest": bad}, PIN, allowed_origins=ALLOWED, kill_active=False
        )
        assert decision.verdict is Verdict.DENY
        assert DenyReason.ENVELOPE_INVALID in decision.reasons


def test_unparsed_manifest_object_on_envelope_is_envelope_invalid() -> None:
    from supply_gate.envelope import SupplyEnvelope

    direct = SupplyEnvelope(
        origin=ORIGIN,
        expected_sha=PIN,
        caller="host.plugin_install",
        capability="plugin.install_or_update",
        manifest={"mcp_servers": [{"source": "s"}]},  # type: ignore[arg-type]
    )
    decision = evaluate(direct, PIN, allowed_origins=ALLOWED, kill_active=False)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == (DenyReason.ENVELOPE_INVALID,)


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


HOOK_B = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
SHA256 = "ab" * 32


def _real_shape_manifest(**overrides: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "mcpServers": {
            "files": {
                "type": "stdio",
                "command": "npx",
                "args": ["-y", "mcp-files"],
                "env": {"EXAMPLE_ROOT": "/tmp/example"},
                "cwd": "/tmp/example",
                "pin": PIN,
            },
            "browser": {
                "type": "http",
                "url": "https://mcp.example.invalid/browser",
                "headers": {"X-Example": "1"},
                "pin": SHA256,
            },
        },
        "permissions": {
            "allow": ["Read", "Grep", "Edit(src/**)"],
            "deny": ["Bash"],
            "ask": ["WebFetch"],
        },
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": "Write|Edit",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "hooks/format.py",
                            "timeout": 30,
                            "pin": HOOK_PIN,
                        }
                    ],
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "http",
                            "url": "https://hooks.example.invalid/session",
                            "pin": HOOK_B,
                        }
                    ]
                }
            ],
        },
    }
    manifest.update(overrides)
    return manifest


_REAL_HOOKS = {
    "hooks/format.py": HOOK_PIN,
    "https://hooks.example.invalid/session": HOOK_B,
}


def test_real_shape_manifest_allows_when_pinned_and_head_matches() -> None:
    decision = _evaluate(_real_shape_manifest(), observed_hooks=_REAL_HOOKS)
    assert decision.verdict is Verdict.ALLOW
    assert decision.reasons == ()
    assert decision.receipt["verify_performed"] is True
    assert decision.receipt["observed_head"] == PIN


def test_real_shape_manifest_still_fails_closed_on_head_verify() -> None:
    """Client-config shapes do not skip pin or post-checkout HEAD verify."""
    missing = evaluate(
        _envelope(_real_shape_manifest()),
        None,
        allowed_origins=ALLOWED,
        kill_active=False,
        observed_hooks=_REAL_HOOKS,
    )
    assert missing.verdict is Verdict.DENY
    assert missing.reasons == (DenyReason.VERIFY_MISSING,)
    assert missing.receipt["verify_performed"] is False

    swapped = evaluate(
        _envelope(_real_shape_manifest()),
        "b" * 40,
        allowed_origins=ALLOWED,
        kill_active=False,
        observed_hooks=_REAL_HOOKS,
    )
    assert swapped.reasons == (DenyReason.HEAD_MISMATCH,)
    assert swapped.receipt["verify_performed"] is True


def test_real_shape_mcp_transport_without_digest_is_unpinned() -> None:
    command = {
        "mcpServers": {
            "files": {
                "command": "npx",
                "args": ["-y", "mcp-files"],
                "env": {"EXAMPLE_ROOT": "/tmp/example"},
            }
        }
    }
    assert _evaluate(command).reasons == (DenyReason.MCP_SERVER_UNPINNED,)
    remote = {
        "mcpServers": {
            "browser": {"type": "streamable-http", "url": "https://mcp.example.invalid/browser"}
        }
    }
    assert _evaluate(remote).reasons == (DenyReason.MCP_SERVER_UNPINNED,)
    tagged = {"mcp_servers": {"files": {"command": "npx", "args": ["-y", "mcp-files"], "pin": "latest"}}}
    assert _evaluate(tagged).reasons == (DenyReason.MCP_SERVER_UNPINNED,)


def test_real_shape_permission_object_and_string_grants() -> None:
    granted = {"permissions": {"allow": ["Read", "Bash(git status)"], "deny": ["WebFetch"], "ask": ["Edit"]}}
    assert _evaluate(granted).reasons == (DenyReason.SKILL_SHELL_PREAPPROVED,)
    not_a_grant = {"permissions": {"deny": ["Bash"], "ask": ["shell"]}}
    assert _evaluate(not_a_grant).verdict is Verdict.ALLOW
    assert _evaluate({"allowed-tools": "Bash(git:*) Read"}).reasons == (DenyReason.SKILL_SHELL_PREAPPROVED,)
    assert _evaluate({"allowed-tools": "Read, Grep"}).verdict is Verdict.ALLOW
    assert _evaluate({"permissions": "Read Grep"}).verdict is Verdict.ALLOW


def test_real_shape_hook_map_needs_pin_and_observed_digest() -> None:
    unpinned = {
        "hooks": {
            "PostToolUse": [
                {"matcher": "Write|Edit", "hooks": [{"type": "command", "command": "hooks/format.py"}]}
            ]
        }
    }
    assert _evaluate(unpinned, observed_hooks=_REAL_HOOKS).reasons == (DenyReason.HOOK_UPDATE_UNVERIFIED,)
    pinned = {
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": "Write|Edit",
                    "hooks": [{"type": "command", "command": "hooks/format.py", "pin": HOOK_PIN}],
                }
            ]
        }
    }
    swapped = {"hooks/format.py": PIN}
    assert _evaluate(pinned, observed_hooks=swapped).reasons == (DenyReason.HOOK_UPDATE_UNVERIFIED,)
    prompt = {
        "hooks": {
            "Stop": [{"hooks": [{"type": "prompt", "prompt": "Review the diff.", "pin": HOOK_PIN}]}]
        }
    }
    assert _evaluate(prompt, observed_hooks={"Review the diff.": HOOK_PIN}).verdict is Verdict.ALLOW


def test_real_shape_reasons_stack_without_skipping_verify() -> None:
    manifest = {
        "mcpServers": {"files": {"command": "npx", "args": ["-y", "mcp-files"]}},
        "permissions": {"allow": ["Bash"]},
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "hooks/session_start.py"}]}]},
    }
    decision = evaluate(
        _envelope(manifest),
        None,
        allowed_origins=ALLOWED,
        kill_active=False,
    )
    assert decision.reasons == (
        DenyReason.VERIFY_MISSING,
        DenyReason.MCP_SERVER_UNPINNED,
        DenyReason.SKILL_SHELL_PREAPPROVED,
        DenyReason.HOOK_UPDATE_UNVERIFIED,
    )
    assert decision.receipt["verify_performed"] is False


def test_real_shape_ill_formed_values_are_envelope_invalid() -> None:
    for bad in (
        {"mcpServers": {"files": "npx"}},
        {"mcpServers": {"": {"command": "npx"}}},
        {"mcpServers": {"files": {"command": "npx", "args": [1]}}},
        {"mcpServers": {"files": {"command": "npx", "env": {"X": 1}}}},
        {"mcpServers": {"files": {"type": "http", "command": "npx"}}},
        {"mcpServers": {"files": {"type": "plugin", "command": "npx"}}},
        {"mcpServers": {"files": {"command": "npx", "token": "x"}}},
        {"hooks": {"PostToolUse": [{"type": "command", "command": "hooks/format.py"}]}},
        {"hooks": {"PostToolUse": {"hooks": []}}},
        {"hooks": {"": []}},
        {"hooks": {"Stop": [{"hooks": [{"type": "plugin", "command": "hooks/x.py"}]}]}},
        {"hooks": {"Stop": [{"hooks": [{"type": "command"}]}]}},
        {"permissions": {"allow": ["Read"], "additionalDirectories": ["/tmp"]}},
        {"allowed-tools": ["Read", 1]},
    ):
        decision = _evaluate(bad)
        assert decision.verdict is Verdict.DENY, bad
        assert DenyReason.ENVELOPE_INVALID in decision.reasons, bad


def test_manifest_absent_leaves_receipt_shape_unchanged() -> None:
    decision = evaluate(
        {k: v for k, v in _envelope({}).items() if k != "manifest"},
        PIN,
        allowed_origins=ALLOWED,
        kill_active=False,
    )
    assert decision.verdict is Verdict.ALLOW
    assert "manifest" not in decision.receipt
