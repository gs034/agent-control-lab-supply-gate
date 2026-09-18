# Contributing

**Agent Control Lab** only. Apache-2.0. See `LICENSE`.

This repository accepts **Lab-only** artefacts: the host-side agent-supply integrity gate stub, its public threat model, and the Plugin4Shell-class existence-proof row.

## Keep-out

Accept Lab artefacts only. Reject:

- Commercial SKUs, bank product trees, and vendor / bank brand strings (including spaced or concatenated forms and SKU wording).
- Commercial or bank directory prefixes and copies of those source trees.
- Provenance / assignment language that marks the tree as a commercial successor or imported product line.
- Marketplace integrations, live git-host clients, production UI, or attack-success-rate claims.
- Weakening fail-closed `evaluate()` / `safe_evaluate()`.

The brand-wall is `scripts/check_lab_only.sh` via `.github/workflows/lab-brand-wall.yml` (also `.github/workflows/lab-only.yml`). It runs `rg -n -i` with `-w` on short / ambiguous tokens, over checkout contents, path names, branch name, and commit subjects/bodies. A hit **fails CI**. Tokens are reconstructed at runtime so the tree does not store those brands as literals.

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
