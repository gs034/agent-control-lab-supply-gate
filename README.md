# Agent Control Lab — supply integrity gate

**BLUF:** Host-side, fail-closed gate for agent/plugin/skill **install or update**. Pin an expected SHA (optional ref), allowlist the origin, then **verify post-checkout HEAD** against the pin. Mismatch, missing verify, non-allowlisted origin, parse error, or kill → **DENY** with a deterministic receipt. Marketplace/agent prose is untrusted data and **cannot skip verify**.

Philanthropic public goods / Navigators artefact. **Not** a commercial SKU. Brand: **Agent Control Lab** only.

Apache-2.0. See `LICENSE`. SPDX-License-Identifier: Apache-2.0 in source.

## What this is (and is not)

This is a **greenfield stub** that demonstrates a diligence-hard control:

1. **Pin** — envelope carries `expected_sha` and optional `ref`.
2. **Allowlisted origin** — exact match to a host allowlist (git remote / package source).
3. **Post-checkout HEAD verify** — after materialise/checkout, resolve actual HEAD (artefact digest) and compare to the pin.
4. **Fail-closed** — never proceed to install/use on deny.
5. **No model judge** — receipts are host JSON. Untrusted prose is not policy.

This is **not**:

- a production marketplace integration
- a commercial product
- “trust the marketplace pin alone”
- an LLM monitor or judge
- an attack-success-rate (ASR) scoreboard

## Fail-closed check (Plugin4Shell-class)

**Plugin4Shell-class** is a *threat pattern* name, not a vendor product: a marketplace/plugin install that would satisfy a **naive SHA pin** on a mutable ref / swapped tree, but **fails post-checkout HEAD verify** (or tries to waive verify with marketplace prose).

Existence-proof DENY only — no ASR % claims.

```bash
python -m pytest
python -m supply_gate.demo
```

The demo prints a **DENY** receipt. Compare shape/semantics to:

`eval/plugin4shell_class/expected_deny_receipt.example.json`

Agent/marketplace prose (`eval/plugin4shell_class/malicious_prose.txt`) is loaded as data only and cannot skip verify.

## Install (optional)

Python 3.11+. Stdlib gate; pytest for tests.

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Envelope

Structured `SupplyEnvelope`: `origin`, `expected_sha`, optional `ref`, `caller` / `capability`. Optional untrusted fields such as `skip_verify` are **not** policy; a truthy skip is `prose_rejected_as_policy` and verify still runs.

`evaluate(envelope, observed_head) -> Decision` with `ALLOW` or `DENY`.

Deny reasons: `origin_not_allowlisted`, `head_mismatch`, `verify_missing`, `envelope_invalid`, `kill_active`, `prose_rejected_as_policy`.

Kill: pass `kill_active=True` or set `ACL_SUPPLY_GATE_KILL=1`. Gate faults via `safe_evaluate` also DENY.

## Host path (not a model)

Callers materialise/checkout, resolve HEAD or artefact digest, then call `evaluate`. If that verify step is skipped (`observed_head` missing), the gate returns **DENY** / `verify_missing`. There is no path where listing prose installs without verify.
