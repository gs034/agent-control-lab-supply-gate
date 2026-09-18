# Contributing

**Agent Control Lab** only. Apache-2.0. See `LICENSE`.

This repository accepts **Lab-only** artefacts: the host-side agent-supply integrity gate stub, its public threat model, and the Plugin4Shell-class existence-proof row.

## Rejected

- Commercial SKUs, bank product paths, and vendor / bank brand strings.
- Copies of commercial or bank source trees, adapters, or UI.
- Marketplace integrations, live git-host clients, production UI, or attack-success-rate claims.
- Weakening fail-closed `evaluate()` / `safe_evaluate()`.

Brand tokens are enforced by `scripts/check_lab_only.sh` (ripgrep over the checkout, path names, branch name, and commit subjects/bodies). A hit **fails CI**. The script reconstructs the token list at runtime so the tree does not store those brands as literals.

The threat-pattern name **Plugin4Shell-class** (already used under `eval/plugin4shell_class/`) is allowed. It is not a vendor product.

## Required

- Brand: **Agent Control Lab** only.
- Licence stays Apache-2.0. Do not relicense.
- Branch names and commit subjects must pass the same Lab-only check as the tree.
- Read `docs/threat-model.md`, `SECURITY.md`, and the architecture / **Non-goals** sections in `README.md` before changing behaviour.

## Checks

```bash
bash scripts/check_lab_only.sh
python -m pytest
python -m supply_gate.demo
```

Vulnerability reports: `SECURITY.md` (GitHub Security Advisories only).
