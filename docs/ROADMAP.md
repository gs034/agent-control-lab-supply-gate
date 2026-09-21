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
| **v0.2 foundation** | Architecture pinned in `docs/adr/ADR-0001-lab-supply-gate-architecture.md`. Allowlist is a loadable host config (fail-closed on empty/broken). Update policy is fail-closed `pin_and_verify`. Thin installer adapter **stub interfaces** exist; no live marketplace. Demo DENY row unchanged. | M1b architecture and host policy surfaces named. The install/update capability is specified, not only demonstrated. |
| **v0.3 / v1** | Adapter path is the documented host call: load allowlist and update policy from host config (file/env; empty/broken → DENY) → local materialise → HEAD → `evaluate`. Additional DENY rows: omitted adapter HEAD, unreadable allowlist, `trust_ref` / `auto_latest` rejected. Optional local-worktree helper takes a caller-supplied digest only. Still no live marketplace. Demo DENY row unchanged. | M1b host capability: pin, origin allowlist, HEAD verify, and fail-closed update are one host path with recorded DENY receipts. |
| **v0.3.1 corpus** (this cut) | Recorded ALLOW row that still cannot skip HEAD verify. Dedicated prose-waive DENY row. Existing host-path DENY rows remain. Official demo DENY unchanged. | M1b corpus: DENY existence-proofs plus one ALLOW receipt that still ran verify. |

## Stub (v0.1) — done on `main`

- Structured `SupplyEnvelope`: origin, `expected_sha`, optional `ref`, caller,
  capability.
- Exact-match builtin allowlist (`*.example.invalid`).
- Post-checkout HEAD verify inside `evaluate` / `safe_evaluate`.
- Plugin4Shell-class fixtures under `eval/plugin4shell_class/`.
- `python -m supply_gate.demo` exits 1 with the DENY receipt.

## v0.2 foundation — done on `main`

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

## v0.3 / v1 — done on `main`

- Update policy loads from host config the same way origins load: explicit
  mode, mapping, JSON file, or `ACL_SUPPLY_GATE_UPDATE_POLICY`. Empty or
  broken config → DENY. No-config fallback remains fail-closed
  `pin_and_verify`.
- `gated_install_or_update` accepts `update_policy_path` and `allowlist_path`.
- Existence-proof DENY rows under `eval/`: `omitted_adapter_head`,
  `unreadable_allowlist`, `trust_ref_rejected`, `auto_latest_rejected`.
- Optional `LocalWorktreeAdapter` / `caller_supplied_head`: caller supplies
  the digest. The helper does not fetch, run git, or read HEAD from the tree.
- Official Plugin4Shell-class demo path is unchanged DENY. Adapter stubs stay
  non-live.

## v0.3.1 corpus — this cut (M1b corpus on this plane)

- Dedicated `eval/prose_waive_attempt/`: structured waive plus listing prose
  is DENY (`prose_rejected_as_policy`) even when HEAD matches the pin.
  Verify still ran.
- Recorded `eval/allow_pin_and_verify/`: ALLOW only when pin, allowlisted
  origin, `pin_and_verify`, and matching HEAD agree. The same envelope DENY
  if the adapter omits HEAD or a structured waive appears. ALLOW cannot skip
  HEAD verify.
- Existing host-path DENY rows and the official Plugin4Shell-class demo stay
  fail-closed DENY. Still no live marketplace.

## Out of scope for every cut on this map

- LLM / transcript judge.
- Production UI.
- Attack-success-rate claims.
- Monorepo merge with the Lab PEP repository.
- Commercial SKU branding.
- Live marketplace or network install.

Threat model: `docs/threat-model.md`. Reporting: `SECURITY.md`.
