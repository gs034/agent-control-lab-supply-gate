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
| **v0.3.1 corpus** | Recorded ALLOW row that still cannot skip HEAD verify. Dedicated prose-waive DENY row. Existing host-path DENY rows remain. Official demo DENY unchanged. | M1b corpus: DENY existence-proofs plus one ALLOW receipt that still ran verify. |
| **v0.4 manifest classes** | The declared artefact manifest is read only to deny. Three DENY rows where pin and HEAD match but the manifest fails: unpinned MCP server, shell pre-approval a manifest grants itself, lifecycle hook without a pin or with a non-matching observed digest. Receipt schema v1 unchanged; three reason codes appended. | M1b corpus extended to the MCP, skill-permission and hook-update surfaces named in the harness-defect literature. Threat-pattern DENY rows only; not an ecosystem remediation claim. |
| **v0.4.1 real-shape loader** (this cut) | Same three manifest DENY classes. The loader also accepts client-config shapes: name-keyed MCP transports, a permissions object or string, and a lifecycle-event hook map. Unknown keys stay `envelope_invalid`. No new deny reasons. Pin and post-checkout HEAD verify unchanged. | M1b corpus: the same threat-pattern DENY rows on realistic manifest shapes. Not a new control and not a coverage taxonomy. |

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

## v0.3.1 corpus, done on `main` (M1b corpus on this plane)

- Dedicated `eval/prose_waive_attempt/`: structured waive plus listing prose
  is DENY (`prose_rejected_as_policy`) even when HEAD matches the pin.
  Verify still ran.
- Recorded `eval/allow_pin_and_verify/`: ALLOW only when pin, allowlisted
  origin, `pin_and_verify`, and matching HEAD agree. The same envelope DENY
  if the adapter omits HEAD or a structured waive appears. ALLOW cannot skip
  HEAD verify.
- Existing host-path DENY rows and the official Plugin4Shell-class demo stay
  fail-closed DENY. Still no live marketplace.

## v0.4 manifest classes

- `SupplyEnvelope.manifest` (optional): `mcp_servers` (or `mcpServers`),
  `permissions` / `allowed_tools` (or `allowedTools`), `hooks`. Any other
  top-level key, or an ill-formed value, is `envelope_invalid`: a manifest
  shape this gate does not understand is not trusted.
- `mcp_server_unpinned`: any declared MCP server without a full-digest pin.
- `skill_shell_preapproved`: any shell-class token in the manifest's own
  permission list. The host operator grants capabilities; a manifest does not.
- `hook_update_unverified`: any declared hook without a full-digest pin, or
  whose adapter-observed digest (`observed_hooks`) is missing or differs.
- Rows: `eval/mcp_server_unpinned/`, `eval/skill_shell_preapproved/`,
  `eval/hook_update_unverified/`. In every row the artefact pin and HEAD
  match; the manifest is the only deny. `verify_performed` stays true.
- Receipt schema stays v1 (no new keys). Existing recorded receipts are
  byte-identical. Official Plugin4Shell-class demo unchanged DENY.

Still open on the v0.4 classes: observed hook digests are caller-supplied like HEAD
(no live materialisation); permission tokens are matched by a fixed
shell-class word list plus bare wildcards (`*`, `all`) after Unicode
normalisation, not by a harness-specific grammar; a manifest that omits
its hooks or servers entirely is not detected here (that is the plane's
alternate-path residual, stated in the threat model).

## v0.4.1 real-shape loader (this cut)

Parent tip `938769656e7cb311d1953dee9df22b79275e6c09`.

The v0.4 classes stay. The loader also accepts the client-config shapes
those classes already name. Stub lists still parse. Any other key is
`envelope_invalid`. No new deny reasons. Pin and post-checkout HEAD
verify are unchanged: missing or unequal HEAD is still DENY.

- `mcpServers` / `mcp_servers` may be a name-keyed object. Each value may
  carry `command`, `args`, `env`, `cwd`, or `type` (`stdio`, `sse`,
  `http`, `streamable-http`) plus `url` and `headers`, and an optional
  full-digest `pin`. A transport without a full-digest pin is
  `mcp_server_unpinned`.
- `permissions` / `allowed_tools` / `allowedTools` / `allowed-tools` may
  be a string or an object with `allow`, `deny`, and `ask`. Only `allow`
  (and a bare list or string) is a grant. A shell-class grant is
  `skill_shell_preapproved`.
- `hooks` may be a lifecycle-event object. Each event lists groups
  (`matcher`, `hooks`). A hook command, url, or prompt needs a full-digest
  `pin` and a matching `observed_hooks` entry keyed by that command, url,
  prompt, or explicit `source`. Otherwise `hook_update_unverified`.

Rows: `eval/mcp_server_real_shape/`, `eval/skill_shell_real_shape/`,
`eval/hook_real_shape/`. In every row the artefact pin and HEAD match;
the manifest is the only deny. `verify_performed` stays true.

## Out of scope for every cut on this map

- LLM / transcript judge.
- Production UI.
- Attack-success-rate claims.
- Monorepo merge with the Lab PEP repository.
- Commercial SKU branding.
- Live marketplace or network install.

Threat model: `docs/threat-model.md`. Reporting: `SECURITY.md`.
