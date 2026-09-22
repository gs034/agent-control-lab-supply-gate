# Skill shell pre-approval

Existence-proof DENY only. Not an attack-success-rate claim.

The skill pin and post-checkout HEAD match, but the declared manifest
grants itself shell pre-approval (`Bash(*)` in `allowed_tools`). A
manifest is untrusted data; only the host operator issues capabilities.
The host path DENY with `skill_shell_preapproved`; `verify_performed`
stays true. Threat pattern: skill shell pre-approval in agent harness
setups (harness-scan class).
