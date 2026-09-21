# ADR-0001 — Lab supply-gate architecture

- Status: Accepted
- Date: 2026-09-18
- Updated: 2026-09-21 (v0.3.1 / M1b corpus: recorded ALLOW + prose-waive DENY)
- Brand: Agent Control Lab
- Licence: Apache-2.0
- Plane: agent-supply integrity (host decision before install or update)

This note pins the host architecture for the Agent Control Lab supply integrity
gate. It is written in Lab voice and **capability language only**: the host
either grants or withholds a named install/update capability. It does not name
vendor products, commercial SKUs, or other programmes.

## Why this exists

An agent, plugin, or skill must not become runnable on the host merely because
a listing advertised a SHA, a mutable ref looked current, or marketplace prose
said “already checked.” The host is the policy point. This plane answers one
question:

> May this host exercise the **install or update** capability for this origin
> and this pin, given the HEAD that was actually materialised?

Anything else — listing text, model output, a monitor score, an MCP claim — is
untrusted data.

## Host capability

The only capability this plane grants is:

| Capability | Meaning |
| --- | --- |
| `plugin.install_or_update` | Materialise a plugin tree and make it eligible for use |
| `skill.install_or_update` | Materialise a skill tree and make it eligible for use |
| `agent.install_or_update` | Materialise an agent artefact and make it eligible for use |

The gate does not interpret product names. Callers put a capability string on
the envelope. The host ALLOW that capability only when every control below
passes. There is no “trust the advertised pin” capability and no “skip verify”
capability.

## Decision

1. **Pin** — the envelope carries a full-digest `expected_sha` (40-hex SHA-1 or
   64-hex SHA-256). Optional `ref` is metadata. A ref is never a substitute
   for HEAD.
2. **Allowlisted origin** — exact string match to a host-loaded allowlist
   (git remote or package source). Unknown, empty, or unreadable allowlist is
   DENY. Default stub hosts are `*.example.invalid` only.
3. **Post-checkout HEAD verify** — after materialise/checkout, the caller (or
   a thin installer adapter) resolves the actual HEAD or artefact digest. The
   gate compares that value to the pin. Missing, ill-formed, or unequal HEAD
   is DENY (`verify_missing` / `head_mismatch`).
4. **Fail-closed update policy** — an update (and any `*.install_or_update`
   capability exercised through the adapter path) must present mode
   `pin_and_verify`. Weak modes (`trust_ref`, `auto_latest`,
   `marketplace_pin_only`, structured waive flags) are DENY
   (`update_policy_rejected`). A missing policy on the adapter path is DENY.
   There is no auto-update on a mutable ref.
5. **Untrusted prose is data** — marketplace or agent text cannot skip verify.
   A structured waive (`skip_verify`, `waive_verify`, `trust_pin_only`,
   `bypass`) is recorded as `prose_rejected_as_policy`; verify still runs.

ALLOW only when the envelope parses, the origin is allowlisted, kill is off,
update policy is accepted where required, observed HEAD is a full digest, and
that HEAD equals the pin. Any other outcome is DENY with a deterministic host
JSON receipt.

## Plugin4Shell-class threat

**Plugin4Shell-class** is a threat-pattern name, not a vendor product. It is
the existence-proof row for this plane.

A listing may satisfy a **naive SHA pin** (well-formed pin + allowlisted
origin on a mutable ref / swapped tree) while:

- the materialised HEAD is not the pin, and/or
- listing or agent prose tries to waive post-checkout verify.

The Lab response is DENY. This ADR does not claim an attack-success-rate.

The official demo fixture is `eval/plugin4shell_class/`.
`python -m supply_gate.demo` must print that DENY receipt and exit 1.

Additional recorded rows under `eval/` (adapter path) include omitted HEAD,
unreadable allowlist, rejected weak update modes (`trust_ref`,
`auto_latest`), a dedicated prose-waive attempt, and one ALLOW receipt that
still cannot skip HEAD verify (`eval/allow_pin_and_verify/`).

## Allowlist configuration

Origins are host configuration, not envelope policy. The allowlist config
module loads an explicit set, a JSON/text file, or `ACL_SUPPLY_GATE_ALLOWLIST`.
If none of those are provided, the stub falls back to the builtin
`*.example.invalid` set. Parse errors, empty sets, and origins that contain
whitespace fail closed: the host cannot ALLOW an origin it cannot name.

Exact string match only. No glob, no suffix, no “same host, different path.”

## Update policy configuration

Update policy is host configuration, loaded the same way as origins: an
explicit mode, a JSON mapping, a JSON file, or
`ACL_SUPPLY_GATE_UPDATE_POLICY`. If none of those are provided, the stub
falls back to fail-closed `pin_and_verify`. An empty file, empty mapping,
missing mode, unreadable path, or ill-formed JSON is DENY
(`update_policy_rejected`). Weak modes (`trust_ref`, `auto_latest`,
`marketplace_pin_only`) are never honoured.

## Installer adapters (stub interfaces)

The host path is:

1. Build a structured envelope (origin, pin, optional ref, caller, capability).
2. Load allowlist and update policy from host config (file/env). Empty or
   broken config is DENY.
3. Apply fail-closed update policy.
4. Ask a thin **installer adapter** to materialise the artefact and return
   post-checkout HEAD.
5. Call `evaluate`. If the adapter omitted HEAD, the gate returns
   `verify_missing`.

v0.3 ships the same stub interfaces plus an optional **local-worktree**
helper (`LocalWorktreeAdapter` / `caller_supplied_head`). The helper takes a
caller-supplied digest only. It does not fetch, run git, or read HEAD from
the tree. A missing or remote-shaped worktree path is omitted HEAD
(`verify_missing`). No live marketplace, no live git-host client, and no
production UI are required or implied.

## Fail-closed

There is no path where untrusted prose installs without verify. There is no
path where an update proceeds on a mutable ref without pin-and-verify. If the
allowlist cannot be loaded, if update policy is missing or weak, if checkout
HEAD has moved, or if the gate itself faults (`safe_evaluate`), the outcome
is DENY.

Kill: `kill_active=True` or `ACL_SUPPLY_GATE_KILL=1`.

## What this is not

- Not an LLM, chain-of-thought, or transcript judge.
- Not a production marketplace integration or live git-host adapter.
- Not a commercial SKU.
- Not a measured attack-success-rate scoreboard.
- Not a monorepo with the Lab host/runtime PEP plane. This repository stays
  a separate supply-integrity artefact.

## Consequences

- Callers must resolve HEAD after checkout. Skipping that step is DENY.
- Hosts must maintain an origin allowlist. An empty or broken allowlist
  cannot be treated as “allow all.”
- Updates share the same pin + HEAD verify as first install, plus an explicit
  `pin_and_verify` policy. Weak update modes are rejected in code, not
  documented as future work-arounds.
- Receipts stay host JSON. Brand: Agent Control Lab only.

See `docs/threat-model.md` for the control taxonomy, `docs/ROADMAP.md` for
stub → v0.2 → v0.3 / v1 → v0.3.1 corpus against EOI M1b, and `README.md`
for the call shape.
