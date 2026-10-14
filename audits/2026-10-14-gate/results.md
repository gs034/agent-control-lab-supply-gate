# Mutation audit 2026-10-14-gate

- PEP commit: `a8de8e41bd7b2cc04a28e4b93a1346e6ce3be389`
- Python: 3.13.16
- Mutants specified by: same-family
- Timeout per run: 300.0 s

The kill rate is reported as measured. There is no pass threshold.

## Kill rate

- Timeouts counted as killed: 9 of 12 (75%)
- Timeouts not counted as killed: 9 of 12 (75%)

Outcomes: killed 9, survived-never-activated 0, survived-oracle-masked 3, timeout 0, invalid 0, harness-fault 0. Invalid patches (0) and harness faults (0) are outside the denominator.

## Mutants

| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `supply_gate/gate.py` | `152` | safe_evaluate returns ALLOW instead of DENY when evaluate() raises an unexpected exception. | an unexpected gate fault must fail closed as DENY (kill_active); the fault wrapper may never produce an ALLOW decision. | killed | `tests/test_evaluate.py::test_safe_evaluate_fail_closed_on_unexpected_fault` | 2.81 |
| M02 | `supply_gate/gate.py` | `73` | the kill switch only adds KILL_ACTIVE when the envelope is already invalid, so a valid envelope ignores kill. | an active kill switch (explicit or ACL_SUPPLY_GATE_KILL) must DENY every evaluation, whatever the envelope contains. | killed | `tests/test_adapters.py::test_gated_path_kill_env_still_denies_when_use_env`<br>`tests/test_evaluate.py::test_kill_active_denies`<br>`tests/test_evaluate.py::test_kill_env_denies` | 3.0 |
| M03 | `supply_gate/gate.py` | `98` | when the envelope carries a ref, the observed HEAD is no longer compared to the pinned digest (trust the ref). | the post-checkout HEAD must exactly equal expected_sha; a mutable ref is never a substitute for the pin and a mismatch is DENY (head_mismatch). | killed | `tests/test_adapters.py::test_adapter_swapped_head_is_head_mismatch`<br>`tests/test_adapters.py::test_plugin4shell_class_via_adapter_still_deny`<br>`tests/test_adapters.py::test_adapter_does_not_change_official_evaluate_receipt`<br>`tests/test_demo.py::test_demo_main_exits_deny`<br>`tests/test_demo.py::test_demo_fixture_ignores_ambient_host_env` | 3.12 |
| M04 | `supply_gate/gate.py` | `68` | the presence of untrusted prose counts as a performed verify, so no observed HEAD plus prose drops verify_missing and records verify_performed=true. | verify_performed and verify_missing derive only from an observed full-digest HEAD; marketplace or agent prose is data and cannot stand in for verification. | survived-oracle-masked | - | 2.8 |
| M05 | `supply_gate/gate.py` | `93` | an empty allowed-origins set skips the origin check, turning an empty allowlist into allow-all. | an origin not in the allowlist is DENY (origin_not_allowlisted); an empty allowlist admits no origin and there is no implicit allow-all. | killed | `tests/test_eval_rows.py::test_m1b_deny_rows_are_deterministic_deny`<br>`tests/test_eval_rows.py::test_corpus_rows_ignore_ambient_host_env` | 2.96 |
| M06 | `supply_gate/manifest.py` | `87` | PinnedSource.pinned accepts any non-empty pin string, so a short or malformed pin counts as pinned. | an MCP server or hook pin must be a full 40/64-hex digest; a short or malformed pin is unpinned and DENY (mcp_server_unpinned / hook_update_unverified). | survived-oracle-masked | - | 2.96 |
| M07 | `supply_gate/manifest.py` | `125` | a remote (never-pinnable) MCP server triggers MCP_SERVER_UNPINNED only when every declared server is remote, so one remote server is masked by pinned local ones. | a single remote MCP server (http / sse / streamable-http) in the manifest is DENY (mcp_server_unpinned) regardless of how the other servers are pinned and observed. | survived-oracle-masked | - | 2.93 |
| M08 | `supply_gate/manifest.py` | `348` | drop the glob-character check on a permission head, so Ba*, B?sh and *ash are no longer treated as a shell grant. | a permission head containing a glob character may expand to a shell-class tool on the host and must be DENY (skill_shell_preapproved). | killed | `tests/test_manifest.py::test_glob_in_a_rule_head_is_a_possible_shell_grant[Ba*]`<br>`tests/test_manifest.py::test_glob_in_a_rule_head_is_a_possible_shell_grant[Ba*(*)]`<br>`tests/test_manifest.py::test_glob_in_a_rule_head_is_a_possible_shell_grant[B*(*)]`<br>`tests/test_manifest.py::test_glob_in_a_rule_head_is_a_possible_shell_grant[Read(src/**) Ba*(x)]`<br>`tests/test_manifest.py::test_glob_in_a_rule_head_is_a_possible_shell_grant[Read(*.sh), Ba*]` | 3.0 |
| M09 | `supply_gate/manifest.py` | `402` | an entry without a full-digest pin is skipped during observed-digest matching instead of failing it, so an unpinned hook (or MCP server) is accepted. | every declared hook and MCP server must carry a full-digest pin equal to the adapter-observed digest; an unpinned entry is DENY (hook_update_unverified / mcp_server_unpinned). | killed | `tests/test_manifest.py::test_hook_without_pin_or_observed_digest_is_deny`<br>`tests/test_manifest.py::test_real_shape_hook_map_needs_pin_and_observed_digest` | 3.28 |
| M10 | `supply_gate/manifest.py` | `328` | NFKC normalisation of permission strings is disabled, so a compatibility-form spelling of a shell word is no longer folded to ASCII before shell matching. | a fullwidth or compatibility spelling of a shell word (e.g. U+FF22 U+FF41 U+FF53 U+FF48) must be classified as a shell grant (skill_shell_preapproved), not merely as an unparseable rule. | killed | `tests/test_manifest.py::test_shell_preapproval_in_manifest_is_deny` | 3.25 |
| M11 | `supply_gate/update_policy.py` | `115` | a weak or unknown update mode is silently normalised to pin_and_verify with weak_attempt=False instead of being reported. | a weak update mode (trust_ref, auto_latest, skip_verify, ...) must be returned as a weak attempt and DENY (update_policy_rejected); it is never honoured as pin_and_verify. | killed | `tests/test_adapters.py::test_weak_update_policy_denies_even_when_head_matches`<br>`tests/test_adapters.py::test_auto_latest_update_denied`<br>`tests/test_eval_rows.py::test_m1b_deny_rows_are_deterministic_deny`<br>`tests/test_eval_rows.py::test_trust_ref_rejected_reason`<br>`tests/test_eval_rows.py::test_auto_latest_rejected_reason` | 3.08 |
| M12 | `supply_gate/update_policy.py` | `162` | evaluate_update_policy ignores weak_attempt, so a pin_and_verify policy carrying a waive flag (auto_update, skip_verify_on_update) passes. | a waive flag in the update policy is DENY (update_policy_rejected) even when the mode itself is pin_and_verify. | killed | `tests/test_update_policy.py::test_waive_flag_rejected_even_when_mode_is_pin_and_verify` | 3.03 |

## Survivors

Each survivor that touches a fail-closed path is filed as a defect.

- M04 (survived-oracle-masked): verify_performed and verify_missing derive only from an observed full-digest HEAD; marketplace or agent prose is data and cannot stand in for verification.
- M06 (survived-oracle-masked): an MCP server or hook pin must be a full 40/64-hex digest; a short or malformed pin is unpinned and DENY (mcp_server_unpinned / hook_update_unverified).
- M07 (survived-oracle-masked): a single remote MCP server (http / sse / streamable-http) in the manifest is DENY (mcp_server_unpinned) regardless of how the other servers are pinned and observed.
