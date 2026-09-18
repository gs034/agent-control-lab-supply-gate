# SPDX-License-Identifier: Apache-2.0
"""Allowlisted artefact origins. Exact string match; fail-closed on anything else."""

from __future__ import annotations

# Example.invalid hosts only. This stub is not a production registry.
DEFAULT_ALLOWED_ORIGINS: frozenset[str] = frozenset(
    {
        "https://git.example.invalid/marketplace/community-plugins.git",
        "https://git.example.invalid/agent-control-lab/skills.git",
    }
)


def origin_allowlisted(origin: str, allowed: frozenset[str] | None = None) -> bool:
    allowed_origins = DEFAULT_ALLOWED_ORIGINS if allowed is None else allowed
    return origin in allowed_origins
