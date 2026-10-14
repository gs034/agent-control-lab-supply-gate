# SPDX-License-Identifier: Apache-2.0
"""Declared artefact manifest: MCP servers, permissions, lifecycle hooks.

The manifest is untrusted structured data supplied with the artefact listing.
The gate reads it only to deny. A manifest cannot grant itself anything, and
a manifest shaped in a way this gate does not understand is invalid.

Stub lists (``source`` / ``pin`` / ``name``) stay valid. Client-config shapes
for the same three classes also parse: a name-keyed MCP transport, a
permissions object or string, and a lifecycle-event hook map.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from supply_gate.digest import digest_ok
from supply_gate.reasons import DenyReason

# Accepted top-level keys, with the camelCase and skill-frontmatter spellings
# client configs use.
_KEY_ALIASES = {
    "mcp_servers": "mcp_servers",
    "mcpServers": "mcp_servers",
    "hooks": "hooks",
    "permissions": "permissions",
    "allowed_tools": "permissions",
    "allowedTools": "permissions",
    "allowed-tools": "permissions",
}
# Fixed shell-class vocabulary, matched as whole words in the permission head
# (the part before any "(" argument). Underscores separate words so an MCP tool
# named like mcp__shell__run is caught, and digits do not end a word, so a
# versioned name like bash2 or pwsh7 is caught too. The list names shells and
# shell-launch verbs only. Interpreters (python, node, ruby, perl) are not
# shells here; a host that treats them as shell-equivalent needs its own rule.
# Whole-word matching also denies a namespace segment that is a shell word
# (mcp__ash__x, a.sh); that is the fail-closed side of the trade.
_SHELL_WORDS = re.compile(
    r"(?:^|[^a-z])(?:"
    r"bash|sh|shell|exec|execute|cmd|powershell|pwsh|zsh|terminal|run_command|run-command"
    r"|ash|dash|fish|ksh|csh|tcsh|busybox"
    r")(?:[^a-z]|$)"
)
# A bare wildcard head grants everything. A glob character anywhere in a head
# (``Ba*``, ``B?sh``, ``*ash``) may match a shell-class tool on the host that
# expands it, so it is treated as a possible shell grant and denied.
_WILDCARDS = frozenset({"*", "all"})
_GLOB_CHARACTERS = frozenset({"*", "?"})
# Invisible characters outside Unicode category Cf that a host may drop or split on.
_INVISIBLE = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0})
# A rule head is a plain tool name: letters, digits and the punctuation tool names use.
_RULE_HEAD = re.compile(r"[a-z0-9_.:*?@/-]+")
_MCP_ENTRY_KEYS = frozenset(
    {"source", "pin", "name", "command", "args", "env", "cwd", "type", "url", "headers"}
)
_MCP_TYPES = frozenset({"stdio", "sse", "http", "streamable-http"})
_MCP_REMOTE_TYPES = frozenset({"sse", "http", "streamable-http"})
_HOOK_STUB_KEYS = frozenset({"source", "pin", "name"})
_HOOK_GROUP_KEYS = frozenset({"matcher", "hooks"})
_HOOK_COMMAND_KEYS = frozenset(
    {"type", "command", "url", "prompt", "source", "pin", "name", "timeout"}
)
_HOOK_TYPES = frozenset({"command", "prompt", "http", "agent"})
_PERM_OBJECT_KEYS = frozenset({"allow", "deny", "ask"})
# Only ``allow`` pre-approves a tool. ``deny`` and ``ask`` still involve the operator.
_PERM_GRANT_KEYS = frozenset({"allow"})


class ManifestError(ValueError):
    """Manifest present but ill-formed or not understood. Callers must treat the envelope as invalid."""


@dataclass(frozen=True)
class PinnedSource:
    source: str
    pin: str | None
    # A remote MCP server (http / sse / streamable-http) is fetched live on
    # every connection, so no digest of it can be pinned.
    remote: bool = False
    # What actually launches, as the adapter must key its observation: the
    # source for a plain source entry, otherwise a canonical record of the
    # command, args, env and cwd (or the url / prompt). An author-chosen
    # ``source`` label alone never selects the observation for a command.
    launch: str = ""

    @property
    def launch_key(self) -> str:
        return self.launch or self.source

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
        # Aliases of one field are merged, not rejected: the union can only
        # add deny inputs.
        for key, value in raw.items():
            target = _KEY_ALIASES.get(key)
            if target is None:
                raise ManifestError(f"unknown manifest key: {key!r}")
            fields[target].append(value)
        return cls(
            mcp_servers=_mcp_servers(fields["mcp_servers"]),
            hooks=_hooks(fields["hooks"]),
            shell_preapproved=_shell_preapproved(fields["permissions"]),
        )

    def deny_reasons(
        self,
        observed_hooks: Any,
        observed_mcp_servers: Any = None,
    ) -> tuple[DenyReason, ...]:
        """Deny reasons from the manifest alone.

        A pin is a claim by the artefact's author. An MCP server or hook is
        accepted only when the adapter observed a digest of what will run and
        that digest equals the pin; a remote MCP server can never be pinned.
        """
        reasons: list[DenyReason] = []
        if self.mcp_servers and (
            any(server.remote for server in self.mcp_servers)
            or _duplicate_keys(self.mcp_servers)
            or not _observed_matches_pins(self.mcp_servers, observed_mcp_servers)
        ):
            reasons.append(DenyReason.MCP_SERVER_UNPINNED)
        if self.shell_preapproved:
            reasons.append(DenyReason.SKILL_SHELL_PREAPPROVED)
        if self.hooks and (_duplicate_keys(self.hooks) or not _observed_matches_pins(self.hooks, observed_hooks)):
            reasons.append(DenyReason.HOOK_UPDATE_UNVERIFIED)
        return tuple(reasons)


def parse_manifest(raw: Any) -> SupplyManifest | None:
    """Return the manifest, None when absent. Raise ManifestError when ill-formed."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ManifestError("manifest must be an object")
    return SupplyManifest.from_mapping(raw)


def _mcp_servers(values: list[Any]) -> tuple[PinnedSource, ...]:
    out: list[PinnedSource] = []
    for raw in values:
        if isinstance(raw, list):
            for entry in raw:
                out.append(_mcp_entry(entry))
        elif isinstance(raw, Mapping):
            for name, entry in raw.items():
                if not isinstance(name, str) or not name.strip():
                    raise ManifestError("mcp_servers names must be non-empty strings")
                out.append(_mcp_entry(entry))
        else:
            raise ManifestError("mcp_servers must be a list or object")
    return tuple(out)


def _mcp_entry(entry: Any) -> PinnedSource:
    if not isinstance(entry, Mapping):
        raise ManifestError("mcp_servers entries must be objects")
    _reject_unknown(entry, _MCP_ENTRY_KEYS, "mcp_servers entry")
    _optional_str(entry, "name")
    source = _optional_str(entry, "source")
    command = _optional_str(entry, "command")
    url = _optional_str(entry, "url")
    transport = _optional_str(entry, "type")
    if transport is not None:
        transport = transport.lower()
        if transport not in _MCP_TYPES:
            raise ManifestError(f"mcp_servers type is not understood: {transport!r}")
    if "args" in entry and entry["args"] is not None:
        _require_string_list(entry["args"], "mcp_servers args")
    if "env" in entry and entry["env"] is not None:
        _require_string_map(entry["env"], "mcp_servers env")
    if "headers" in entry and entry["headers"] is not None:
        _require_string_map(entry["headers"], "mcp_servers headers")
    if "cwd" in entry and entry["cwd"] is not None and _optional_str(entry, "cwd") is None:
        raise ManifestError("mcp_servers cwd must be a string")
    if transport in _MCP_REMOTE_TYPES and url is None:
        raise ManifestError("remote mcp server needs a url")
    if transport == "stdio" and command is None and source is None:
        raise ManifestError("stdio mcp server needs a command")
    if source is None:
        source = url or command
    if source is None:
        raise ManifestError("mcp_servers entry needs a source")
    remote = transport in _MCP_REMOTE_TYPES or (url is not None and command is None)
    launch = ""
    if command is not None:
        launch = _launch_record(
            "command",
            command=command,
            args=list(entry.get("args") or []),
            env=dict(entry.get("env") or {}),
            cwd=entry.get("cwd"),
        )
    return PinnedSource(source=source, pin=_pin_value(entry), remote=remote, launch=launch)


def _hooks(values: list[Any]) -> tuple[PinnedSource, ...]:
    out: list[PinnedSource] = []
    for raw in values:
        if isinstance(raw, list):
            for entry in raw:
                out.extend(_hook_list_item(entry))
        elif isinstance(raw, Mapping):
            for event, groups in raw.items():
                if not isinstance(event, str) or not event.strip():
                    raise ManifestError("hook events must be non-empty strings")
                if not isinstance(groups, list):
                    raise ManifestError("hook event must be a list")
                for group in groups:
                    out.extend(_hook_group(group))
        else:
            raise ManifestError("hooks must be a list or object")
    return tuple(out)


def _hook_list_item(entry: Any) -> list[PinnedSource]:
    if not isinstance(entry, Mapping):
        raise ManifestError("hooks entries must be objects")
    keys = set(entry)
    if "hooks" in keys:
        return _hook_group(entry)
    if keys <= _HOOK_STUB_KEYS:
        return [_hook_stub(entry)]
    if keys <= _HOOK_COMMAND_KEYS:
        return [_hook_command(entry)]
    raise ManifestError(f"hooks entry has unknown keys: {sorted(keys - _HOOK_COMMAND_KEYS)}")


def _hook_stub(entry: Mapping[str, Any]) -> PinnedSource:
    _reject_unknown(entry, _HOOK_STUB_KEYS, "hooks entry")
    _optional_str(entry, "name")
    source = _optional_str(entry, "source")
    if source is None:
        raise ManifestError("hooks entry needs a source")
    return PinnedSource(source=source, pin=_pin_value(entry))


def _hook_group(entry: Any) -> list[PinnedSource]:
    if not isinstance(entry, Mapping):
        raise ManifestError("hook group must be an object")
    _reject_unknown(entry, _HOOK_GROUP_KEYS, "hook group")
    if "matcher" in entry and entry["matcher"] is not None and not isinstance(entry["matcher"], str):
        raise ManifestError("hook matcher must be a string")
    nested = entry.get("hooks")
    if not isinstance(nested, list):
        raise ManifestError("hook group needs a hooks list")
    out: list[PinnedSource] = []
    for item in nested:
        if not isinstance(item, Mapping):
            raise ManifestError("hook command must be an object")
        _reject_unknown(item, _HOOK_COMMAND_KEYS, "hook command")
        out.append(_hook_command(item))
    return out


def _hook_command(entry: Mapping[str, Any]) -> PinnedSource:
    _optional_str(entry, "name")
    hook_type = _optional_str(entry, "type")
    if hook_type is not None:
        hook_type = hook_type.lower()
        if hook_type not in _HOOK_TYPES:
            raise ManifestError(f"hook type is not understood: {hook_type!r}")
    command = _optional_str(entry, "command")
    url = _optional_str(entry, "url")
    prompt = _optional_str(entry, "prompt")
    if hook_type == "command" and command is None:
        raise ManifestError("command hook needs a command")
    if hook_type == "http" and url is None:
        raise ManifestError("http hook needs a url")
    if hook_type in {"prompt", "agent"} and prompt is None:
        raise ManifestError("prompt hook needs a prompt")
    if "timeout" in entry and entry["timeout"] is not None:
        timeout = entry["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ManifestError("hook timeout must be a number")
    source = _optional_str(entry, "source")
    if source is None:
        source = command or url or prompt
    if source is None:
        raise ManifestError("hooks entry needs a source")
    # A hook runs its command, url or prompt; that string is the observation key.
    launch = command or url or prompt or ""
    return PinnedSource(source=source, pin=_pin_value(entry), launch=launch)


def _shell_preapproved(values: list[Any]) -> bool:
    for raw in values:
        if _permission_grants_shell(raw):
            return True
    return False


def _permission_grants_shell(raw: Any) -> bool:
    if isinstance(raw, list):
        return _tokens_grant_shell(_token_list(raw, "permissions"))
    if isinstance(raw, str):
        return _is_shell_grant(raw)
    if isinstance(raw, Mapping):
        _reject_unknown(raw, _PERM_OBJECT_KEYS, "permissions")
        granted = False
        for key in ("allow", "deny", "ask"):
            if key not in raw:
                continue
            tokens = _token_list(raw[key], f"permissions {key}")
            if key in _PERM_GRANT_KEYS and _tokens_grant_shell(tokens):
                granted = True
        return granted
    raise ManifestError("permissions must be a list, string, or object")


def _token_list(raw: Any, label: str) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        if not all(isinstance(item, str) for item in raw):
            raise ManifestError(f"{label} entries must be strings")
        return list(raw)
    raise ManifestError(f"{label} must be a list or string")


def _tokens_grant_shell(tokens: list[str]) -> bool:
    return any(_is_shell_grant(item) for item in tokens)


def _is_shell_grant(item: str) -> bool:
    """True when any rule in ``item`` grants a shell-class tool or a bare wildcard.

    A string may carry several rules (``Read(src/**) Bash(*)``). Each rule is
    judged on its own head, so a benign parenthesised rule cannot hide the next.
    An invisible format character may be dropped by one host and read as a
    separator by another, so both readings are judged and either one denies.
    """
    norm = unicodedata.normalize("NFKC", item).lower()
    invalid: ManifestError | None = None
    # Fixed order, every reading judged: a shell grant in any reading wins over
    # an ill-formed one, so the deny reason does not depend on evaluation order.
    for reading in (_strip_invisible(norm, " "), _strip_invisible(norm, "")):
        try:
            if _reading_grants_shell(reading):
                return True
        except ManifestError as exc:
            invalid = invalid or exc
    if invalid is not None:
        raise invalid
    return False


def _reading_grants_shell(reading: str) -> bool:
    for rule in _split_rules(reading):
        head = rule.split("(", 1)[0].strip()
        if not _RULE_HEAD.fullmatch(head):
            raise ManifestError("permissions rule name is not a plain tool name")
        if head in _WILDCARDS or _GLOB_CHARACTERS & set(head) or _SHELL_WORDS.search(head):
            return True
    return False


def _strip_invisible(text: str, replacement: str) -> str:
    return "".join(
        replacement if (unicodedata.category(char) == "Cf" or ord(char) in _INVISIBLE) else char
        for char in text
    )


def _split_rules(text: str) -> list[str]:
    """Split a permission string into ``Tool`` / ``Tool(pattern)`` rules.

    Whitespace and commas separate rules outside parentheses. Unbalanced
    parentheses, or text glued to a closing ``)``, are ill-formed: the gate
    cannot tell where a rule ends.
    """
    rules: list[str] = []
    current: list[str] = []
    depth = 0
    closed = False
    for char in text:
        separator = depth == 0 and (char == "," or char.isspace())
        if closed and not separator:
            raise ManifestError("permissions rule has text after its closing ')'")
        closed = False
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                raise ManifestError("permissions rule has an unbalanced ')'")
            depth -= 1
            closed = depth == 0
        elif separator:
            if current:
                rules.append("".join(current))
                current = []
            continue
        current.append(char)
    if depth != 0:
        raise ManifestError("permissions rule has an unbalanced '('")
    if current:
        rules.append("".join(current))
    return rules


def _launch_record(kind: str, **fields: Any) -> str:
    """Canonical text naming what launches; the key an adapter reports its digest under."""
    return json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def mcp_observation_key(entry: Mapping[str, Any]) -> str:
    """The key an adapter must report a local MCP server's digest under.

    For a server with a ``command`` it is a canonical record of command, args,
    env and cwd, so the digest is bound to what launches and not to an
    author-chosen ``source`` label. A plain ``source`` entry keys by source.
    """
    return _mcp_entry(entry).launch_key


def _duplicate_keys(entries: tuple[PinnedSource, ...]) -> bool:
    """Two entries sharing a source label or a launch record cannot each be checked by one observation."""
    sources = [entry.source for entry in entries]
    launches = [entry.launch_key for entry in entries]
    return len(set(sources)) != len(sources) or len(set(launches)) != len(launches)


def _observed_matches_pins(entries: tuple[PinnedSource, ...], observed: Any) -> bool:
    """Every entry is pinned and the adapter observed exactly that digest for what it launches."""
    if not isinstance(observed, Mapping):
        return False
    for entry in entries:
        if not entry.pinned:
            return False
        seen = observed.get(entry.launch_key)
        if not isinstance(seen, str):
            return False
        seen_n = seen.strip().lower()
        if not digest_ok(seen_n) or seen_n != entry.pin:
            return False
    return True


def _pin_value(entry: Mapping[str, Any]) -> str | None:
    if "pin" not in entry or entry["pin"] is None:
        return None
    pin = entry["pin"]
    if not isinstance(pin, str):
        raise ManifestError("pin must be a string")
    stripped = pin.strip().lower()
    return stripped or None


def _optional_str(entry: Mapping[str, Any], key: str) -> str | None:
    if key not in entry or entry[key] is None:
        return None
    value = entry[key]
    if not isinstance(value, str):
        raise ManifestError(f"{key} must be a string")
    stripped = value.strip()
    return stripped or None


def _require_string_list(value: Any, label: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{label} must be a list of strings")


def _require_string_map(value: Any, label: str) -> None:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ManifestError(f"{label} must be an object of strings")


def _reject_unknown(entry: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(entry) - allowed
    if unknown:
        raise ManifestError(f"{label} has unknown keys: {sorted(unknown)}")
