# ALLOW pin-and-verify (HEAD still required)

Recorded ALLOW only when pin, allowlisted origin, `pin_and_verify`, and
post-checkout HEAD all agree. Marketplace or agent prose is not policy.

This row cannot skip HEAD verify. The same envelope is DENY if the
adapter omits HEAD (`verify_missing`) or if a structured waive is
present (`prose_rejected_as_policy`). `verify_performed` is true on the
ALLOW receipt.
