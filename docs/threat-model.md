# Agent-supply integrity threat model

Public, short model for the **agent-supply integrity** plane in Agent Control Lab.
This repository is a host-side, fail-closed **existence-proof gate** (v0.4.1: M1b corpus plus the v0.4 manifest deny classes). Brand: Agent Control Lab only.

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

In all three rows the artefact pin and post-checkout HEAD match; the manifest is the only deny. The gate reads the manifest to deny, never to grant. The same three reasons apply when the manifest uses a client-config shape (name-keyed MCP transport, permissions object or string, lifecycle-event hook map) as well as the stub list. A shape this gate does not understand is `envelope_invalid`. No further deny class is introduced for those shapes. A manifest that omits its servers or hooks entirely is outside what this gate can see; that is the plane's alternate-path residual. Existence-proof DENY only; no attack-success-rate claim. Adapter contract: observed MCP digests are keyed by `mcp_observation_key` (command, args, env, cwd; a plain source entry keys by that source) and hook digests by the command, url or prompt that runs, a free-text source label does not select the observation for a command, and duplicate source labels are denied.

## Control taxonomy

Each row carries a status as of 14 October 2026. **mitigated**: a test or an `eval/` row shows the rule holds at this tip. **accepted residual**: a known gap, written down, accepted for this existence-proof gate. **unmitigated**: a gap the roadmap still owes work on. Work item codes (L3.1 host-side state binding, L3.6 tamper-evident host log, L3.8 persistent single-use grants, L3.10 kill reach into a running tool, L4.1 provider-executed tools, L4.2 alternate-path fixtures and counts, L4.5 a materialiser so HEAD and hook digests are not caller-supplied, L4.6 omission detection, L5 measured efficacy, L6 tagged release) name items in the owner's route-to-production plan, which is not in this repository; the code is the pointer, the phrase is the meaning.  A status is a statement about this tree, not an attack-success claim.

| Control | Rule | Fail-closed outcome | Status (15 Oct 2026) |
| --- | --- | --- | --- |
| Pin | `expected_sha` must be a string and a full digest, at most 128 bytes; short / missing / ill-typed / over-cap pin is invalid. Top-level envelope keys must be strings and known. String fields are capped (`origin` 2048 bytes, `caller` 256 bytes, `ref` 4096 bytes, `capability` 256 bytes). A lone surrogate or a control character in a string field is invalid. Optional `untrusted`, when present, must be a JSON object: no NaN or Infinity anywhere, nesting at most 32 (the root object counts as 1), and a compact UTF-8 JSON serialization (`sort_keys`, separators `,` and `:`, `ensure_ascii` off) of at most 64 KiB (`UNTRUSTED_MAX_DEPTH`, `UNTRUSTED_MAX_BYTES`). Any other `untrusted` value is invalid | `envelope_invalid` → DENY | mitigated, including unknown keys, length caps, lone surrogates, control characters, and the untrusted object limits |
| Optional ref | `ref` may be present and is capped at 4 KiB (4096 bytes); it is not policy. A non-string ref, a longer ref, a ref with a lone surrogate or a control character, or a ref containing U+2028, U+2029, a bidi override (U+202A-U+202E), or a bidi isolate (U+2066-U+2069) is invalid | never substitutes for HEAD | mitigated: a ref never substitutes for HEAD, including line separators and bidi marks |
| Origin allowlist | exact string match only; empty/broken config is not allow-all | `origin_not_allowlisted` or `allowlist_invalid` → DENY | mitigated |
| Update policy | host config (file/env) must load; adapter path requires `pin_and_verify`; weak modes (`trust_ref`, `auto_latest`) rejected | `update_policy_rejected` → DENY | mitigated |
| Post-checkout HEAD verify | observed HEAD present, well-formed, and equal to the pin | `verify_missing` or `head_mismatch` → DENY | mitigated for the comparison; **unmitigated** for the input, HEAD is caller-supplied until a materialiser exists (L4.5) |
| Prose is data | listing/agent text is never policy | structured waive → `prose_rejected_as_policy`; verify still runs | mitigated |
| Declared MCP servers | every `manifest.mcp_servers` entry carries a full-digest pin and the adapter observed that digest for what will launch (`observed_mcp_servers`); tags, promises and remote servers (a remote `type`, a `url` with no `command`, or a `source` spelled as a URL) are not pins. An entry with no `command` that carries `args`, `env` or `cwd` would change what runs without changing the observation key, and an entry with both `url` and `command` but no `type` is ambiguous; both are ill-formed (`envelope_invalid`) | `mcp_server_unpinned` → DENY | mitigated for the comparison, including launch fields on a source entry and URL-shaped sources (S-7); the observed MCP digest is caller-supplied like HEAD (**unmitigated**, L4.5); a manifest that omits its servers is **unmitigated** (omission detection, L4.6) |
| Declared permissions | a manifest cannot pre-approve shell-class tools for itself. Head matching covers shells and shell-launch verbs (`bash`, `sh`, `shell`, `exec`, `execute`, `cmd`, `powershell`, `pwsh`, `zsh`, `terminal`, `run_command`, `run-command`, `ash`, `dash`, `fish`, `ksh`, `csh`, `tcsh`, `busybox`), a bare wildcard, and a rule head carrying `*` or `?` (`Ba*`, `B?sh`). Other non-tool-name characters in a head fail as ill-formed (`envelope_invalid`). Matching is whole-word, digits included (`bash2`), so a namespace segment that is a shell word (`mcp__ash__x`) is also refused. camelCase and PascalCase names are split into parts, for heads and for argument tokens, and a part is a grant only when that whole part is a real launcher (`execShell` is `exec` and `shell`, `HTTPShell` is `http` and `shell`, and adjacent parts that form `run_command` make `runCommand` a grant). `cmd`, `ksh` and `fish` are grants when they are the last camelCase segment, compared case-insensitively, so `runCmd`, `runCMD`, `mcp__x__runCmd`, `startKsh` and `openFish` are grants. `CmdLine`, `KshConfig` and `fishFinder` are not grants, because those words are not the last segment. `evalCode` and `sudoRun` read as `eval_code` and `sudo_run` and are not grants, because `_` stays inside those names. Names such as `readBashHistory` and `terminalWidth` are refused because `bash` and `terminal` are whole camel parts that are real launchers, a fail-safe side effect of that split. A glob or the marks `/`, `=`, `^`, `~`, `%` and `+` glued onto a leading shell word (`Bash*`, `Bash?`, `Bash/*`, `Bash=*`, `bash^`, `bash~`, `bash%`, `bash+x`), a shell word that is only a trailing dot (`bash.`), and a leading hyphen on a whole shell word (`-bash`, `-su`, `--eval`) are the same deny. A hyphen inside a path (`docs/-su`) is not that bare token. `/usr/bin/doas` is a grant because its last segment is the launch word. Argument text is cut on whitespace, commas, parentheses, `;`, `|`, quotes, backticks, `&`, `>`, `<`, braces, brackets, `!`, `#`, `=`, `+`, `%`, `~`, `^`, `*`, `?` and backslash. On a path those marks are cut only in the last segment, so an ordinary glob stays allowed (`Read(src/*.py)`, `Read(tests/eval/*)`, `Read(notes/bash/*)`), while `Read(a%bash)`, `a~bash`, `a^bash`, `a*bash` and `a?bash` are grants. A bare name, a `.exe`, `.cmd`, `.bat`, `.ps1` or `.com` spelling whose stem is exactly a shell word, after repeated and trailing dots are collapsed (`bash.cmd`, `sh.bat`, `bash.ps1`, `sh.com`, `xargs.exe`, `bash..exe`, `bash.exe.`; not `Read(scripts/run.cmd)` or `build.bat`), a hyphen suffix and a colon suffix (`Bash:*`, `Bash:ls`) are judged with the head list, as is the last path segment, including after a trailing slash (`Read(/bin/sh)`, `Read(./sh)`, `Read(a, /bin/sh/)`). `eval`, `su`, `env`, `sudo`, `doas`, `xargs` and `nohup` are denied as heads and inside arguments when the whole token, or the whole last path segment, is that word, after a `:` suffix is removed (`eval:*`, `sudo:*`, `Read(su:*)`). `_` and `-` stay inside the name, so `eval_runner`, `run_eval`, `mcp__lab__eval` and `su-docs` are not grants. A longer file name, a middle path segment, or a directory token whose launch word is not the last segment is not a grant (`Read(.env)`, `src/env/config.py`, `docs/su/x`, `eval.py`, `eval/`, `src/env/`, `src/eval/`), while `eval`, `Read(a, su)`, `doas` and `nohup` are. NUL and any other non-whitespace control character in rule text is ill-formed (`envelope_invalid`); the same character is also read as a space, so a shell word beside it is still a grant. An MCP server-wide rule, `mcp__<server>` with no `__<tool>` segment (`mcp__desktop-commander`), is a shell grant in a head or an argument (S-8). A tool name inside an argument is read by one linear pass, including `.exe`, `.cmd`, `.bat`, `.ps1` and `.com` suffixes. An argument piece longer than 256 characters is not read as a tool name, and any shell word inside it denies (S-9). Interpreter heads (`python`, `node`) are not treated as shells; that is a host policy question, open | `skill_shell_preapproved` → DENY | 15 October 2026: mitigated for the head list, camelCase launcher parts, a case-insensitive last camel segment of `cmd`, `ksh` or `fish`, glued marks, argument separators, path tails, `.cmd`, `.bat`, `.ps1` and `.com` launchers, collapsed dots, `%` `~` `^` `*` `?` separators, control characters in rule text, leading hyphens, colon suffixes, `eval`, `su`, `env`, `sudo`, `doas`, `xargs` and `nohup` as whole tokens or whole last path segments, MCP server-wide grants (S-8), and a linear tool-name scan (S-9); interpreter heads remain an open host-policy question, pinned as not shell-class by `tests/test_manifest.py::test_interpreter_heads_are_not_shell_class_here`, owner decision pending |
| Declared hooks | every `manifest.hooks` entry carries a full-digest pin and the adapter-observed hook digest equals it. A hook carrying more than one distinct command, url or prompt cannot be keyed by what runs and is ill-formed (`envelope_invalid`) | `hook_update_unverified` → DENY | mitigated for the comparison; the observed hook digest is caller-supplied like HEAD (**unmitigated**, L4.5); a manifest that omits its hooks is **unmitigated** (L4.6) |
| Kill | host kill switch (`kill_active` or `ACL_SUPPLY_GATE_KILL`), trimmed and case-insensitive: `1`, `true`, `t`, `yes`, `y`, `on` are on; empty, `0`, `false`, `f`, `no`, `n`, `off` are off; any other non-empty value is on (fail closed) | `kill_active` → DENY | mitigated, including truthy spellings and unrecognised values (S-5) |
| Fault wrapper | unexpected gate exception. Every DENY, including this one, also logs one line with its reason codes and truncated field values. Each value is quoted so it cannot forge another field. The logged origin is `scheme://host[:port]`, or the host alone for an scp-style origin. Userinfo, path, query and fragment are dropped. An origin that cannot be reduced that way (out-of-range port, bad IPv6 host, empty host, or other parse failure) is logged as `<unparseable-origin>` and the original deny reason is kept. U+2028, U+2029, bidi overrides and bidi isolates are escaped (no secrets, no receipt body) | `safe_evaluate` → DENY (`kill_active`) | mitigated |
| Adapter boundary | `gated_install_or_update` never raises: a malformed or unreadable allowlist (bad JSON, non-UTF-8, nesting too deep, wrong object type), a malformed update policy (file, mapping or object), or an envelope that is not an object comes back as a decision | `allowlist_invalid`, `update_policy_rejected` or `envelope_invalid` → DENY; an adapter fault or other unexpected fault → DENY (`kill_active`) | mitigated (S-6) |

ALLOW only when the envelope parses, origin is allowlisted, kill is off, update policy is accepted where required, observed HEAD is present, and that HEAD exactly matches the pin. Any other outcome is DENY with a deterministic host JSON receipt. Each DENY also writes one log line with the reason codes and truncated field values. Each value is quoted and escaped so a space inside it cannot forge another field. The logged origin is `scheme://host[:port]`, or the host alone for an scp-style origin. Userinfo, path, query and fragment are dropped. An origin that cannot be reduced that way is logged as `<unparseable-origin>`, and that failure does not replace the deny reason. U+2028, U+2029, bidi overrides (U+202A-U+202E) and bidi isolates (U+2066-U+2069) are escaped. That line does not include secrets or the receipt body.

## Fail-closed

There is no path where untrusted prose installs without verify. If the caller omits `observed_head`, the gate returns DENY / `verify_missing`. If checkout HEAD has moved, the gate returns DENY / `head_mismatch` even when the advertised pin looks well-formed.

## Non-goals

Each bullet is an accepted residual for this existence-proof gate. The bullet marked *Proposed wording* awaits the owner's decision.

- Not an LLM, chain-of-thought, or transcript judge.
- Not a production marketplace integration, live git-host adapter, or production UI.
- Not a monitor, MCP policy engine, or model-trust layer.
- Not an attack-success-rate scoreboard.
- Not a judge of upstream content. A pin bump to a commit that already carries a malicious contribution (for example, one an agent landed upstream through fake identities and a reviewed PR) passes every check here once the operator accepts that pin. Origin, digest and HEAD verify prove which bytes were pinned, not that those bytes are benign. Agent-driven upstream poisoning of this kind is documented in arXiv:2609.38415v1 (UK AISI, simulated environments). Proposed wording, for owner review.
- Existence-proof gate. Default allowlist hosts are `*.example.invalid`.
- Thin installer adapters are stub interfaces only. The optional local-worktree helper takes a caller-supplied digest; it is not a network install.

See `docs/adr/ADR-0001-lab-supply-gate-architecture.md`, `docs/ROADMAP.md`,
`SECURITY.md`, and `README.md` for the host call shape.
