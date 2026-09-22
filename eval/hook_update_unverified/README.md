# Hook update unverified

Existence-proof DENY only. Not an attack-success-rate claim.

The artefact pin and post-checkout HEAD match, but the declared
lifecycle hook is pinned to one digest and the materialised hook has
another. A hook update is an install/update on the supply plane and
gets the same pin plus observed-digest verify. The host path DENY with
`hook_update_unverified`; `verify_performed` stays true. Threat
pattern: lifecycle-hook update path as a supply surface (hook-update
class).
