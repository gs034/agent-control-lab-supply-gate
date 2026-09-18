# SPDX-License-Identifier: Apache-2.0
"""Host allowlist configuration. Fail-closed on missing, empty, or ill-formed input."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from supply_gate.origins import DEFAULT_ALLOWED_ORIGINS

ALLOWLIST_ENV = "ACL_SUPPLY_GATE_ALLOWLIST"


class AllowlistError(ValueError):
    """Allowlist could not be loaded. Callers must DENY."""


@dataclass(frozen=True)
class AllowlistConfig:
    origins: frozenset[str]
    source: str

    def contains(self, origin: str) -> bool:
        return origin in self.origins


def load_allowlist(
    *,
    path: str | Path | None = None,
    origins: Iterable[str] | None = None,
    raw: Mapping[str, Any] | None = None,
    use_env: bool = True,
    fallback_builtin: bool = True,
) -> AllowlistConfig:
    """Load an origin allowlist.

    Precedence: explicit ``origins``, then ``raw``, then ``path``, then
    ``ACL_SUPPLY_GATE_ALLOWLIST``, then the builtin stub set.

    An empty set, whitespace origin, or parse error raises ``AllowlistError``.
    There is no implicit allow-all.
    """
    if origins is not None:
        return AllowlistConfig(origins=_validate_origins(origins), source="explicit")
    if raw is not None:
        return AllowlistConfig(origins=_origins_from_mapping(raw), source="mapping")
    resolved = Path(path) if path is not None else None
    if resolved is None and use_env:
        env_path = os.environ.get(ALLOWLIST_ENV, "").strip()
        if env_path:
            resolved = Path(env_path)
            return AllowlistConfig(origins=_origins_from_file(resolved), source="env")
    if resolved is not None:
        return AllowlistConfig(origins=_origins_from_file(resolved), source="file")
    if fallback_builtin:
        return AllowlistConfig(origins=frozenset(DEFAULT_ALLOWED_ORIGINS), source="builtin")
    raise AllowlistError("no allowlist configured")


def _validate_origins(origins: Iterable[str]) -> frozenset[str]:
    cleaned: list[str] = []
    for item in origins:
        if not isinstance(item, str):
            raise AllowlistError("origin is not a string")
        value = item.strip()
        if not value:
            raise AllowlistError("origin is empty")
        if any(ch.isspace() for ch in value):
            raise AllowlistError("origin contains whitespace")
        cleaned.append(value)
    unique = frozenset(cleaned)
    if not unique:
        raise AllowlistError("allowlist is empty")
    return unique


def _origins_from_mapping(raw: Mapping[str, Any]) -> frozenset[str]:
    listed = raw.get("origins")
    if not isinstance(listed, list):
        raise AllowlistError("origins must be a list")
    return _validate_origins(listed)


def _origins_from_file(path: Path) -> frozenset[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AllowlistError(f"allowlist file unreadable: {path}") from exc
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AllowlistError("allowlist JSON is ill-formed") from exc
        if not isinstance(parsed, Mapping):
            raise AllowlistError("allowlist JSON must be an object")
        return _origins_from_mapping(parsed)
    lines: list[str] = []
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        lines.append(item)
    return _validate_origins(lines)
