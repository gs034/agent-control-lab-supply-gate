# Agent Control Lab — supply integrity gate

Host-side, fail-closed gate for agent/plugin/skill **install or update**. Pin an expected SHA (optional ref), allowlist the origin, then **verify post-checkout HEAD** against the pin. Mismatch, missing verify, non-allowlisted origin, parse error, or kill → **DENY** with a deterministic receipt. Marketplace/agent prose is untrusted data and **cannot skip verify**.

Philanthropic public goods / Navigators artefact. **Not** a commercial SKU. Brand: **Agent Control Lab** only.

Apache-2.0. See `LICENSE`. SPDX-License-Identifier: Apache-2.0 in source.

Architecture: `docs/adr/ADR-0001-lab-supply-gate-architecture.md`. Roadmap (stub → v0.2 → v1, EOI M1b): `docs/ROADMAP.md`. Threat model: `docs/threat-model.md`. Reporting: `SECURITY.md`. Lab-only rules: `CONTRIBUTING.md`.

## Architecture

The host is the policy point. A caller that is about to exercise an **install or update** capability builds a structured `SupplyEnvelope` (allowlisted origin, expected SHA pin, optional ref, capability), materialises the artefact, resolves post-checkout HEAD (or artefact digest), and calls `evaluate`. The v0.2 adapter path (`gated_install_or_update`) applies a fail-closed update policy first, then asks a thin installer adapter stub for HEAD, then evaluates. The gate ALLOW only when the envelope is well-formed, the origin is on the host allowlist, kill is off, update policy is accepted where required, observed HEAD is a full digest, and that HEAD equals the pin. Marketplace or agent prose is untrusted data: it cannot skip verify, and a structured waive is recorded as `prose_rejected_as_policy` while verify still runs. The trust domain is this host check; it does not inherit trust from a model, a monitor, an MCP server, or a marketplace host.

## What this is

v0.2 foundation that demonstrates a diligence-hard control:

1. **Pin** — envelope carries `expected_sha` and optional `ref`.
2. **Allowlisted origin** — exact match to a host allowlist (git remote / package source).
3. **Post-checkout HEAD verify** — after materialise/checkout, resolve actual HEAD (artefact digest) and compare to the pin.
4. **Fail-closed** — never proceed to install/use on deny. Update policy must be `pin_and_verify`; weak modes DENY.
5. **No model judge** — receipts are host JSON. Untrusted prose is not policy.
6. **Thin installer adapter stubs** — interfaces only; no live marketplace.

## Non-goals

- Not an LLM, chain-of-thought, or transcript judge.
- Not a production marketplace integration, live git-host adapter, or production UI.
- Not a commercial product and not “trust the marketplace pin alone.”
- Existence-proof gate. Plugin4Shell-class is a threat-pattern DENY row, not an attack-success-rate claim.
- Not a monorepo with the Lab host/runtime PEP plane.

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

Deny reasons: `origin_not_allowlisted`, `allowlist_invalid`, `update_policy_rejected`, `head_mismatch`, `verify_missing`, `envelope_invalid`, `kill_active`, `prose_rejected_as_policy`.

Host allowlist config: explicit set, JSON/text file, or `ACL_SUPPLY_GATE_ALLOWLIST`. Example: `config/allowlist.example.json`. Update policy example: `config/update_policy.example.json` (mode `pin_and_verify` only).

Kill: pass `kill_active=True` or set `ACL_SUPPLY_GATE_KILL=1`. Gate faults via `safe_evaluate` also DENY.

## Host path (not a model)

Callers materialise/checkout, resolve HEAD or artefact digest, then call `evaluate`. The v0.2 helper `gated_install_or_update` does the same after a fail-closed update-policy check and a thin installer adapter stub (in-memory HEAD only; no live marketplace). If that verify step is skipped (`observed_head` missing), the gate returns **DENY** / `verify_missing`. There is no path where listing prose installs without verify.
