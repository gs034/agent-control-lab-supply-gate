# SPDX-License-Identifier: Apache-2.0
"""Full-digest check shared by the envelope and the manifest."""

from __future__ import annotations

import re

_FULL_DIGEST = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def digest_ok(value: str) -> bool:
    return bool(_FULL_DIGEST.fullmatch(value))
