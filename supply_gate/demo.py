# SPDX-License-Identifier: Apache-2.0
"""CLI existence-proof: Plugin4Shell-class row DENY (fail-closed)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from supply_gate.gate import evaluate, safe_evaluate
from supply_gate.receipt import dumps_receipt
from supply_gate.reasons import Verdict

EVAL_REL = Path("eval") / "plugin4shell_class"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def eval_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / EVAL_REL


def load_plugin4shell_class_inputs(root: Path | None = None) -> tuple[dict[str, Any], str | None, str]:
    base = eval_dir(root)
    envelope = json.loads((base / "envelope.json").read_text(encoding="utf-8"))
    observed_raw = json.loads((base / "observed_head.json").read_text(encoding="utf-8"))
    observed = observed_raw.get("observed_head")
    prose = (base / "malicious_prose.txt").read_text(encoding="utf-8")
    if not isinstance(observed, str):
        observed = None
    return envelope, observed, prose


def run_plugin4shell_class(root: Path | None = None) -> tuple[int, str]:
    envelope, observed, prose = load_plugin4shell_class_inputs(root)
    decision = evaluate(envelope, observed, untrusted_prose=prose)
    text = dumps_receipt(decision.receipt)
    code = 0 if decision.verdict is Verdict.ALLOW else 1
    return code, text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Agent Control Lab supply integrity gate demo. "
            "Exercises the Plugin4Shell-class fail-closed DENY row. "
            "Agent/marketplace prose cannot skip verify."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root containing eval/ (default: package parent).",
    )
    args = parser.parse_args(argv)
    try:
        code, text = run_plugin4shell_class(args.root)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        # Fail-closed: fixture/IO faults still DENY, never proceed to install.
        decision = safe_evaluate({}, None, kill_active=True)
        text = dumps_receipt(decision.receipt)
        sys.stderr.write(f"gate unavailable: {exc}\n")
        sys.stdout.write(text)
        return 1
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
