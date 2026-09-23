# Hook update unverified, client-config shape

Existence-proof DENY only. Not an attack-success-rate claim.

The artefact pin and post-checkout HEAD match. The manifest uses a
lifecycle-event hook map. `PostToolUse` is pinned to one digest and the
observed command digest differs. `SessionStart` matches its pin.
`observed_hooks` is keyed by the command string. One mismatch is
`hook_update_unverified`; `verify_performed` stays true. Same deny class
as `eval/hook_update_unverified/`. No new deny reason.
