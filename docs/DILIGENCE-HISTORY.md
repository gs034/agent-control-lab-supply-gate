# Diligence history — residual historical refs

**Date:** 2026-10-07
**Repo:** Agent Control Lab supply-gate (`agent-control-lab-supply-gate`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The current `main` tip is `676213b8345d609f2ef3ae5965ec96e8acdbf3c6`. That tip tree is Lab-clean for brand-wall / tip purposes, and it stays clean. None of the 24 commits reachable from `main` carry keep-out author/committer identity. Residual keep-out material is author/committer identity on historical commits that sit off `main`. Exact strings are recorded in the Lab chinese-wall vault and the Support pack, and are not spelled in this tree.

Residual locations are `refs/pull/8/head`, two first-parent ancestors of that head that are off `main`, the branch tip that matches `refs/pull/8/head`, plus `refs/pull/9/head` and the branch tip at the same SHA. `refs/pull/9/head` is a descendant of `477af75`; its own tip identity is clean and its ancestry is not. Those commits are off the current `main` tip tree.

Collaborators cannot delete `refs/pull/*` (GitHub returns HTTP 422, read-only). **Support/GC is still required to purge `refs/pull/8/head` and `refs/pull/9/head`.** Deleting branch refs does not delete those pull refs.

This note is a diligence disclosure. Demo ≠ eng clear ≠ funding unlock. It is not a claim about attack success rates or product readiness. No history rewrite, no force-push, and no repository recreate were performed.

## Verified refs (2026-10-07, Europe/London)

SHAs below were checked against the live GitHub refs. Findings name the ref and SHA only. Keep-out on the three historical commits is author/committer identity only. Commit messages and patches on those commits do not spell keep-out tokens.

| Ref | SHA | Residual location |
| --- | --- | --- |
| `main` | `676213b8345d609f2ef3ae5965ec96e8acdbf3c6` | None in the tip tree. Brand-wall clean. None of the 24 commits reachable from this tip carry keep-out author/committer identity. |
| `refs/pull/8/head` | `477af75f560ffbc3e6b2dda00bf370bee43faac9` | Author and committer identity on this commit are keep-out. Off `main`. |
| First-parent ancestor of `477af75`, off `main` | `6f89599d7af03c09686dd9267067153461e88d17` | Author and committer identity are keep-out. Off `main`. |
| First-parent ancestor of `477af75`, off `main` | `76ab9a5867e55aed04a01a2d64d34105b04a2f8d` | Author and committer identity are keep-out. Off `main`. |
| `refs/heads/claude/festive-johnson-ut9x2r` | `477af75f560ffbc3e6b2dda00bf370bee43faac9` | Same tip as `refs/pull/8/head`. The three commits above are reachable from this branch. |
| `refs/pull/9/head` | `96ebb40fd6bdeef49d9ff326d2fb0bbf26928564` | Descendant of `477af75` (ahead 2, behind 0). Tip author/committer identity is clean; ancestry is not. |
| `refs/heads/cursor/supply-gate-real-shape-loader-7c02` | `96ebb40fd6bdeef49d9ff326d2fb0bbf26928564` | Same tip as `refs/pull/9/head`. Tip author/committer identity is clean; ancestry is not. |

The exact strings themselves stay in the Lab chinese-wall vault and the Support pack under `agent-control-lab/contam-support/` (Ticket B). They are not in this tree.

## Purge path

Do not attempt to delete `refs/pull/*` with a collaborator credential. GitHub treats those refs as read-only (HTTP 422). Support/GC is still required to purge `refs/pull/8/head` and `refs/pull/9/head`. Deleting `refs/heads/claude/festive-johnson-ut9x2r` or `refs/heads/cursor/supply-gate-real-shape-loader-7c02` does not delete those pull refs. The Support pack already exists under `agent-control-lab/contam-support/` (Ticket B).

## Reading guide

- Tip and release trees: current `main` (`676213b8345d609f2ef3ae5965ec96e8acdbf3c6`) is Lab-clean. This repo has no tags and no releases; treat this bullet as guidance if a later release is cut from that tip.
- Full-history, branch-ref, or PR-ref scanners: expect residual author/committer identity on `477af75f560ffbc3e6b2dda00bf370bee43faac9`, `6f89599d7af03c09686dd9267067153461e88d17`, and `76ab9a5867e55aed04a01a2d64d34105b04a2f8d`. Those three commits are reachable from `refs/pull/8/head`, `refs/heads/claude/festive-johnson-ut9x2r`, `refs/pull/9/head`, and `refs/heads/cursor/supply-gate-real-shape-loader-7c02`. They are off current `main`. The pull/9 tip `96ebb40fd6bdeef49d9ff326d2fb0bbf26928564` is clean on its own author/committer identity and dirty in ancestry.
- Do not copy those strings into tip files, commit subjects, or branch names.
