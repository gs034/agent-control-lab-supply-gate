# Agent-supply integrity threat model

Public, short model for the **agent-supply integrity** plane in Agent Control Lab.
This repository is a host-side, fail-closed **existence-proof gate** (v0.3.1 / M1b corpus). Brand: Agent Control Lab only.

Apache-2.0. See `LICENSE`.

## Plane and assets

The plane is the host decision that runs **before** an agent, plugin, or skill is installed or updated.

Assets:

- the materialised tree (post-checkout working copy / artefact)
- the pin binding (`expected_sha`, optional `ref`)
- the origin allowlist (exact string match; host config)
- the fail-closed update policy (`pin_and_verify` only)
- the host-resolved post-checkout HEAD (artefact digest)

A listing, marketplace host, model, monitor, or MCP server does not sit inside this trust domain.

## Trust domain

**In scope (policy):**

1. **Pin** — envelope carries a full-digest `expected_sha` (40-hex SHA-1 or 64-hex SHA-256). Optional `ref` is metadata, not a substitute for HEAD.
2. **Allowlisted origin** — exact match to a host allowlist (git remote / package source). Unknown origin is DENY.
3. **Post-checkout HEAD verify** — after materialise/checkout, the caller resolves actual HEAD and the gate compares it to the pin.

**Out of trust (data only):**

- marketplace or agent prose
- structured waive flags (`skip_verify`, `waive_verify`, `trust_pin_only`, `bypass`)
- model output, chain-of-thought, or transcript text
- monitor scores
- MCP server claims
- marketplace-host attestations that are not the host-resolved HEAD

Untrusted text cannot skip verify. A truthy structured waive is recorded as `prose_rejected_as_policy`; verify still runs.

## Attack class (Plugin4Shell-class)

**Plugin4Shell-class** is a *threat pattern* name, not a vendor product.

A marketplace or plugin install that would satisfy a **naive SHA pin** (well-formed pin + allowlisted origin on a mutable ref / swapped tree), but:

- **fails post-checkout HEAD verify** (materialised HEAD ≠ pin), and/or
- **tries to skip verify** via marketplace/agent prose or structured waive flags.

Existence-proof DENY only. This document does not claim an attack-success-rate.

## Attack class (manifest classes, v0.4)

Three further *threat patterns*, named by control shape and not by any vendor:

- **Unpinned MCP server:** the artefact's manifest declares an MCP server dependency by tag, branch or promise instead of a full digest. A pinned artefact that pulls unpinned dependencies is not pinned.
- **Skill shell pre-approval:** the manifest pre-approves shell-class tools for itself so the operator is never asked. A manifest is untrusted data; only the host operator grants capabilities.
- **Hook update unverified:** a lifecycle hook changes without a pin, or its materialised digest is missing or differs from the declared pin. A hook update is an install/update on this plane and gets the same verify.

In all three rows the artefact pin and post-checkout HEAD match; the manifest is the only deny. The gate reads the manifest to deny, never to grant. The same three reasons apply when the manifest uses a client-config shape (name-keyed MCP transport, permissions object or string, lifecycle-event hook map) as well as the stub list. A shape this gate does not understand is `envelope_invalid`. No further deny class is introduced for those shapes. A manifest that omits its servers or hooks entirely is outside what this gate can see; that is the plane's alternate-path residual. Existence-proof DENY only; no attack-success-rate claim.

## Control taxonomy

| Control | Rule | Fail-closed outcome |
| --- | --- | --- |
| Pin | `expected_sha` must be a full digest; short / missing / ill-typed pin is invalid | `envelope_invalid` → DENY |
| Optional ref | `ref` may be present; it is not policy | never substitutes for HEAD |
| Origin allowlist | exact string match only; empty/broken config is not allow-all | `origin_not_allowlisted` or `allowlist_invalid` → DENY |
| Update policy | host config (file/env) must load; adapter path requires `pin_and_verify`; weak modes (`trust_ref`, `auto_latest`) rejected | `update_policy_rejected` → DENY |
| Post-checkout HEAD verify | observed HEAD present, well-formed, and equal to the pin | `verify_missing` or `head_mismatch` → DENY |
| Prose is data | listing/agent text is never policy | structured waive → `prose_rejected_as_policy`; verify still runs |
| Declared MCP servers | every `manifest.mcp_servers` entry carries a full-digest pin; tags and promises are not pins | `mcp_server_unpinned` → DENY |
| Declared permissions | a manifest cannot pre-approve shell-class tools or a bare wildcard for itself; only the host operator grants capabilities | `skill_shell_preapproved` → DENY |
| Declared hooks | every `manifest.hooks` entry carries a full-digest pin and the adapter-observed hook digest equals it | `hook_update_unverified` → DENY |
| Kill | host kill switch (`kill_active` or `ACL_SUPPLY_GATE_KILL`) | `kill_active` → DENY |
| Fault wrapper | unexpected gate exception | `safe_evaluate` → DENY (`kill_active`) |

ALLOW only when the envelope parses, origin is allowlisted, kill is off, update policy is accepted where required, observed HEAD is present, and that HEAD exactly matches the pin. Any other outcome is DENY with a deterministic host JSON receipt.

## Fail-closed

There is no path where untrusted prose installs without verify. If the caller omits `observed_head`, the gate returns DENY / `verify_missing`. If checkout HEAD has moved, the gate returns DENY / `head_mismatch` even when the advertised pin looks well-formed.

## Non-goals

- Not an LLM, chain-of-thought, or transcript judge.
- Not a production marketplace integration, live git-host adapter, or production UI.
- Not a monitor, MCP policy engine, or model-trust layer.
- Not an attack-success-rate scoreboard.
- Existence-proof gate. Default allowlist hosts are `*.example.invalid`.
- Thin installer adapters are stub interfaces only. The optional local-worktree helper takes a caller-supplied digest; it is not a network install.

See `docs/adr/ADR-0001-lab-supply-gate-architecture.md`, `docs/ROADMAP.md`,
`SECURITY.md`, and `README.md` for the host call shape.
