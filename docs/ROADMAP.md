# Roadmap

Agent Control Lab **agent-supply integrity** plane. Brand: Agent Control Lab
only. Apache-2.0. Separate repository from the Lab host/runtime PEP plane.

This map is capability language only: what the host can prove about the
**install or update** capability. It is not a product roadmap and not a
calendar.

EOI **M1b** is the public-goods milestone this plane must evidence: a
fail-closed host gate that pins an artefact, allowlists its origin, verifies
post-checkout HEAD, and DENY a Plugin4Shell-class swapped tree / prose-waive
row. Later Lab cuts stay inside that same capability.

| Lab cut | What the host can prove | EOI M1b mapping |
| --- | --- | --- |
| **stub (v0.1)** | `evaluate()` ALLOW only on pin + allowlisted origin + HEAD match. Plugin4Shell-class eval row is a deterministic DENY. Marketplace prose cannot skip verify. | M1b existence-proof: a host DENY receipt for the published threat pattern. |
| **v0.2 foundation** (this cut) | Architecture pinned in `docs/adr/ADR-0001-lab-supply-gate-architecture.md`. Allowlist is a loadable host config (fail-closed on empty/broken). Update policy is fail-closed `pin_and_verify`. Thin installer adapter **stub interfaces** exist; no live marketplace. Demo DENY row unchanged. | M1b architecture and host policy surfaces named. The install/update capability is specified, not only demonstrated. |
| **v1** | Adapter path is the documented host call: local materialise → HEAD → `evaluate`, with policy file load and additional DENY rows (broken allowlist, rejected update mode, omitted HEAD from the adapter). Still no live marketplace requirement. | M1b complete for this plane: pin, origin allowlist, HEAD verify, and fail-closed update are one host capability with recorded receipts. |

## Stub (v0.1) — done on `main`

- Structured `SupplyEnvelope`: origin, `expected_sha`, optional `ref`, caller,
  capability.
- Exact-match builtin allowlist (`*.example.invalid`).
- Post-checkout HEAD verify inside `evaluate` / `safe_evaluate`.
- Plugin4Shell-class fixtures under `eval/plugin4shell_class/`.
- `python -m supply_gate.demo` exits 1 with the DENY receipt.

## v0.2 foundation — this cut

- ADR-0001: pin, allowlisted origins, HEAD verify, fail-closed update policy,
  Plugin4Shell-class, capability language.
- Allowlist config module (`supply_gate.allowlist`): explicit set, JSON/text
  file, or `ACL_SUPPLY_GATE_ALLOWLIST`. Empty or ill-formed → DENY.
- Update policy (`supply_gate.update_policy`): only `pin_and_verify` is
  accepted. Weak modes and waive flags → `update_policy_rejected`.
- Thin installer adapter stubs (`supply_gate.adapters`): `InstallerAdapter`
  protocol, in-memory recording stub, `gated_install_or_update` host path.
- README points at the ADR and this map. Demo and official eval row stay
  fail-closed DENY.

## v1 — next Lab cut (not this PR)

- Keep the same capability. Do not add a live marketplace or git-host client
  as a requirement.
- Load update policy from host config the same way origins load.
- More existence-proof rows: omitted adapter HEAD, unreadable allowlist,
  `trust_ref` / `auto_latest` rejected on update.
- Optional local-worktree HEAD helper that still takes the observed digest
  from the caller — not a network install.

## Out of scope for every cut on this map

- LLM / transcript judge.
- Production UI.
- Attack-success-rate claims.
- Monorepo merge with the Lab PEP repository.
- Commercial SKU branding.

Threat model: `docs/threat-model.md`. Reporting: `SECURITY.md`.
