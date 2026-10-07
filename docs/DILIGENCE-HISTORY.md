# Diligence history — residual historical PR refs

**Date:** 2026-10-07
**Repo:** Agent Control Lab supply-gate (`agent-control-lab-supply-gate`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The current `main` tip is Lab-clean for brand-wall / tip purposes. Residual keep-out material is employer-domain author/committer emails. Exact strings are recorded in the Lab chinese-wall vault and the Support pack, and are not spelled in this tree. Leftover dirt is GitHub-owned `refs/pull/*` only. It is not on the current `main` tip tree.

Collaborators cannot delete `refs/pull/*` (GitHub returns HTTP 422, read-only). **Support/GC is the only path to purge `refs/pull/*`.**

This note is a diligence disclosure. Demo ≠ eng clear ≠ funding unlock. It is not a claim about attack success rates or product readiness. No history rewrite, no force-push, and no repository recreate were performed.

## Verified refs (2026-10-07, Europe/London)

SHAs below were checked against the live GitHub refs. Findings name the ref and SHA only.

| Ref | SHA | Residual location |
| --- | --- | --- |
| `main` | `676213b8345d609f2ef3ae5965ec96e8acdbf3c6` | None in the tip tree |
| `refs/pull/8/head` | `477af75f560ffbc3e6b2dda00bf370bee43faac9` | Employer-domain author/committer emails on that historical PR head (commit author/committer identity). Not tip tree content |

The exact strings themselves stay in the Lab chinese-wall vault and the Support pack under `agent-control-lab/contam-support/` (Ticket B). They are not in this tree.

## Purge path

Do not attempt to delete `refs/pull/*` with a collaborator credential. GitHub treats those refs as read-only (HTTP 422). Support/GC is the only path to purge `refs/pull/*`. The Support pack already exists under `agent-control-lab/contam-support/` (Ticket B).

## Reading guide

- Tip and release trees: treat as Lab-clean.
- Full-history or PR-ref scanners: expect residual employer-domain author/committer emails on the historical SHA above. They are not on current `main`.
- Do not copy those strings into tip files, commit subjects, or branch names.
