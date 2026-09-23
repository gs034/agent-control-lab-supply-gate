# Skill shell pre-approval, client-config shape

Existence-proof DENY only. Not an attack-success-rate claim.

The skill pin and post-checkout HEAD match. The manifest uses a
permissions object (`allow`, `deny`, `ask`) rather than a flat token
list. `allow` contains `Bash(git status)`, so the manifest grants
itself shell. `deny` and `ask` are not grants. The host path DENY with
`skill_shell_preapproved`; `verify_performed` stays true. Same deny
class as `eval/skill_shell_preapproved/`. No new deny reason.
