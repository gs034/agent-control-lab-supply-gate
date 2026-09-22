# SPDX-License-Identifier: Apache-2.0
"""Declared artefact manifest: MCP servers, permissions, lifecycle hooks.

The manifest is untrusted structured data supplied with the artefact listing.
The gate reads it only to deny. A manifest cannot grant itself anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from supply_gate.envelope import envelope_digest_ok
from supply_gate.reasons import DenyReason

_PERMISSION_KEYS = ("permissions", "allowed_tools")
_SHELL_TOKENS = frozenset({"bash", "sh", "shell", "exec", "cmd", "powershell", "zsh"})


class ManifestError(ValueError):
    """Manifest present but ill-formed. Callers must treat the envelope as invalid."""


@dataclass(frozen=True)
class PinnedSource:
    name: str
    source: str
    pin: str | None

    @property
    def pinned(self) -> bool:
        return self.pin is not None and envelope_digest_ok(self.pin)


@dataclass(frozen=True)
class SupplyManifest:
    mcp_servers: tuple[PinnedSource, ...] = ()
    hooks: tuple[PinnedSource, ...] = ()
    shell_preapproved: bool = False

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> SupplyManifest:
        return cls(
            mcp_servers=_pinned_sources(raw.get("mcp_servers"), "mcp_servers"),
            hooks=_pinned_sources(raw.get("hooks"), "hooks"),
            shell_preapproved=_shell_preapproved(raw),
        )

    def deny_reasons(self, observed_hooks: Mapping[str, str] | None) -> tuple[DenyReason, ...]:
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


def _pinned_sources(raw: Any, label: str) -> tuple[PinnedSource, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ManifestError(f"{label} must be a list")
    out: list[PinnedSource] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise ManifestError(f"{label} entries must be objects")
        source = entry.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ManifestError(f"{label} entry needs a source")
        name = entry.get("name", source)
        if not isinstance(name, str) or not name.strip():
            raise ManifestError(f"{label} entry name must be a string")
        pin = entry.get("pin")
        if pin is not None and not isinstance(pin, str):
            raise ManifestError(f"{label} pin must be a string")
        out.append(
            PinnedSource(
                name=name.strip(),
                source=source.strip(),
                pin=pin.strip().lower() if isinstance(pin, str) and pin.strip() else None,
            )
        )
    return tuple(out)


def _shell_preapproved(raw: Mapping[str, Any]) -> bool:
    for key in _PERMISSION_KEYS:
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            raise ManifestError(f"{key} must be a list")
        for item in value:
            if not isinstance(item, str):
                raise ManifestError(f"{key} entries must be strings")
            if _is_shell_token(item):
                return True
    return False


def _is_shell_token(item: str) -> bool:
    head = item.strip().lower().split("(", 1)[0].split(":", 1)[0].strip()
    return head in _SHELL_TOKENS


def _hooks_verified(hooks: tuple[PinnedSource, ...], observed: Mapping[str, str] | None) -> bool:
    if observed is None:
        return False
    for hook in hooks:
        if not hook.pinned:
            return False
        seen = observed.get(hook.source)
        if not isinstance(seen, str):
            return False
        seen_n = seen.strip().lower()
        if not envelope_digest_ok(seen_n) or seen_n != hook.pin:
            return False
    return True
