# SPDX-License-Identifier: Apache-2.0
"""Declared artefact manifest: MCP servers, permissions, lifecycle hooks.

The manifest is untrusted structured data supplied with the artefact listing.
The gate reads it only to deny. A manifest cannot grant itself anything, and
a manifest shaped in a way this gate does not understand is invalid.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from supply_gate.digest import digest_ok
from supply_gate.reasons import DenyReason

# Accepted top-level keys, with the camelCase spellings client configs use.
_KEY_ALIASES = {
    "mcp_servers": "mcp_servers",
    "mcpServers": "mcp_servers",
    "hooks": "hooks",
    "permissions": "permissions",
    "allowed_tools": "permissions",
    "allowedTools": "permissions",
}
# Fixed shell-class vocabulary. A bare wildcard grants shell too.
_SHELL_WORDS = re.compile(
    r"(?:^|[^a-z0-9_])(?:bash|sh|shell|exec|execute|cmd|powershell|zsh|terminal|run_command)(?:[^a-z0-9_]|$)"
)
_WILDCARDS = frozenset({"*", "all"})
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


class ManifestError(ValueError):
    """Manifest present but ill-formed or not understood. Callers must treat the envelope as invalid."""


@dataclass(frozen=True)
class PinnedSource:
    source: str
    pin: str | None

    @property
    def pinned(self) -> bool:
        return self.pin is not None and digest_ok(self.pin)


@dataclass(frozen=True)
class SupplyManifest:
    mcp_servers: tuple[PinnedSource, ...] = ()
    hooks: tuple[PinnedSource, ...] = ()
    shell_preapproved: bool = False

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> SupplyManifest:
        fields: dict[str, list[Any]] = {"mcp_servers": [], "hooks": [], "permissions": []}
        for key, value in raw.items():
            target = _KEY_ALIASES.get(key)
            if target is None:
                raise ManifestError(f"unknown manifest key: {key!r}")
            fields[target].append(value)
        return cls(
            mcp_servers=_pinned_sources(fields["mcp_servers"], "mcp_servers"),
            hooks=_pinned_sources(fields["hooks"], "hooks"),
            shell_preapproved=_shell_preapproved(fields["permissions"]),
        )

    def deny_reasons(self, observed_hooks: Any) -> tuple[DenyReason, ...]:
        reasons: list[DenyReason] = []
        if any(not server.pinned for server in self.mcp_servers):
            reasons.append(DenyReason.MCP_SERVER_UNPINNED)
        if self.shell_preapproved:
            reasons.append(DenyReason.SKILL_SHELL_PREAPPROVED)
        if self.hooks and not _hooks_verified(self.hooks, observed_hooks):
            reasons.append(DenyReason.HOOK_UPDATE_UNVERIFIED)
        return tuple(reasons)


def parse_manifest(raw: Any) -> SupplyManifest | None:
    """Return the manifest, None when absent. Raise ManifestError when ill-formed."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ManifestError("manifest must be an object")
    return SupplyManifest.from_mapping(raw)


def _pinned_sources(values: list[Any], label: str) -> tuple[PinnedSource, ...]:
    out: list[PinnedSource] = []
    for raw in values:
        if not isinstance(raw, list):
            raise ManifestError(f"{label} must be a list")
        for entry in raw:
            if not isinstance(entry, Mapping):
                raise ManifestError(f"{label} entries must be objects")
            source = entry.get("source")
            if not isinstance(source, str) or not source.strip():
                raise ManifestError(f"{label} entry needs a source")
            pin = entry.get("pin")
            if pin is not None and not isinstance(pin, str):
                raise ManifestError(f"{label} pin must be a string")
            out.append(
                PinnedSource(
                    source=source.strip(),
                    pin=pin.strip().lower() if isinstance(pin, str) and pin.strip() else None,
                )
            )
    return tuple(out)


def _shell_preapproved(values: list[Any]) -> bool:
    for raw in values:
        if not isinstance(raw, list):
            raise ManifestError("permissions must be a list")
        for item in raw:
            if not isinstance(item, str):
                raise ManifestError("permissions entries must be strings")
            if _is_shell_grant(item):
                return True
    return False


def _is_shell_grant(item: str) -> bool:
    norm = unicodedata.normalize("NFKC", item).translate(_ZERO_WIDTH).strip().lower()
    return norm in _WILDCARDS or bool(_SHELL_WORDS.search(norm))


def _hooks_verified(hooks: tuple[PinnedSource, ...], observed: Any) -> bool:
    if not isinstance(observed, Mapping):
        return False
    for hook in hooks:
        if not hook.pinned:
            return False
        seen = observed.get(hook.source)
        if not isinstance(seen, str):
            return False
        seen_n = seen.strip().lower()
        if not digest_ok(seen_n) or seen_n != hook.pin:
            return False
    return True
