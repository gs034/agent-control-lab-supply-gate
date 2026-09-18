# Security

Agent Control Lab host-side **agent-supply integrity** gate. Fail-closed stub. Apache-2.0.

## Fail-closed

The gate DENY when any required check is missing or fails: invalid envelope, origin not allowlisted, broken/empty allowlist, rejected update policy, missing or ill-formed post-checkout HEAD, HEAD ≠ pin, host kill, structured skip-verify attempt, or unexpected gate fault (`safe_evaluate`). Marketplace or agent prose is untrusted data and **cannot skip verify**.

There is no “trust the advertised pin alone” path.

## Trust domain

Policy is host-side only: pin (`expected_sha`, optional `ref`), exact-match origin allowlist, fail-closed update policy (`pin_and_verify`), and post-checkout HEAD verify.

This trust domain is **independent** of:

- a language model or chain-of-thought
- a monitor or transcript judge
- an MCP server
- a marketplace host or listing

Those surfaces are not policy authorities for install or update.

Threat pattern and control taxonomy: `docs/threat-model.md`. Plugin4Shell-class is a published threat-pattern name in `eval/plugin4shell_class/`, not a vendor product.

## Reporting a vulnerability

Use **GitHub Security Advisories** on this repository:

https://github.com/gs034/agent-control-lab-supply-gate/security/advisories

There is no separate security inbox. Do not invent or use a mail alias. Do not open a public issue that includes a working bypass of the gate.

Public discussion of the documented Plugin4Shell-class pattern (naive pin that fails HEAD verify, or prose that tries to waive verify) is already in-tree and does not need a private report.

Please include: gate version / commit, envelope shape (redact secrets), observed HEAD vs pin, and whether verify was omitted or bypassed.

## Supported versions

This is an existence-proof gate on `main`. Security reports should target current `main`.
