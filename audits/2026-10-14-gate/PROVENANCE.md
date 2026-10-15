# Provenance note

The results in this folder cannot be re-verified. The seal names commit `a8de8e41bd7b2cc04a28e4b93a1346e6ce3be389`, which is absent from this repository and from origin, and its sealed test and `pyproject.toml` hashes match the pre-rebase commit `2941253`, not the merged history. The harness that ran it lacked the P-1, P-2, P-6 and P-7 fixes (S-15 to S-17). A re-run under a new audit id with the fixed harness is planned. See "Audit 2026-10-14-gate cannot be re-verified" in `audits/README.md`.

This note is not read by the harness. The seal, mutants and results here are unchanged.
