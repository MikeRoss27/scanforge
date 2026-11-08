---
name: git-cross-env-divergence
description: Diagnose and resolve git pull/rebase failures caused by uncommitted local work that overlaps or duplicates work already pushed from another environment (e.g. WSL2 vs Windows clones of the same repo).
source: auto-skill
extracted_at: '2026-08-17T21:42:19.793Z'
---

# Git cross-environment divergence (WSL2 ↔ Windows)

Use this when `git pull --rebase` (or VS Code's Sync) fails with
`cannot pull with rebase: You have unstaged changes`, and the user suspects a
dual-environment (e.g. WSL2 Ubuntu + Windows) repo split.

## Symptom signature

- `git pull --tags -r origin main` → `error: cannot pull with rebase: You have unstaged changes.`
- Root cause is almost always: the *other* environment pushed N commits to
  `origin` while *this* clone has uncommitted work on the same files.

## Diagnose before acting (don't stash blindly)

1. `git status` — look for the two-part signature: branch is **behind
   `origin/main` by N commits** *and* has uncommitted changes. Both together =
   the classic dual-environment divergence.
2. `git rev-parse --show-toplevel` — confirm which working tree you're in
   (`D:/...` = Windows, `/mnt/d/...` or `~/...` = WSL2 clone).
3. Detect overlap between local work and the incoming commits:
   - `git log --oneline <local-head>..origin/main -- <modified-files...>`
   - If those commits touch the **same files** as the local uncommitted work,
     expect real conflicts, not a clean fast-forward.

## Detect a *divergent/duplicate* implementation (the non-obvious step)

When local changes and incoming commits both touch the same feature, ask
whether the local work is a parallel re-implementation of something already
merged upstream. Two cheap probes:

- `git ls-tree origin/main <untracked-file>` — empty output means the file does
  NOT exist on the remote; it is local-only.
- `git log --oneline --all --diff-filter=AD -- <file>` — empty across **all**
  refs means the file was **never committed anywhere**. A feature-named commit
  that touches *related* files in the incoming range, but a local file that
  appears nowhere in history, means the same feature was implemented
  differently (e.g. inline in `events.go` instead of a separate `findings.go`).

This determines the resolution: **merge** (independent work) vs **discard one
side** (superseded duplicate).

## Resolution

1. `git stash push -u -m "wip: <description>"` — the `-u` is mandatory to
   capture **untracked** files too.
2. `git pull --rebase --tags origin main` — when the branch is strictly behind
   ("behind by N commits, can be fast-forwarded"), this **fast-forwards** with
   no real rebase and no conflicts (there are no local commits to replay). The
   "rebase" wording in the error is misleading in this case.
3. `git stash pop` — conflicts (if any) surface here, on files changed in both.
   Safety: a `stash pop` that hits conflicts **keeps the stash entry** in
   `git stash list`, so nothing is lost yet.
4. Decide keep vs discard based on step "detect divergent implementation":
   - **Discard** (superseded work):
     `git restore --source=HEAD --staged --worktree -- <files>`, delete the
     untracked file (`del /f /q <path>` on Windows), then `git stash drop`.
   - **Keep**: resolve each conflict marker normally (`<<<<<<< Updated upstream`
     vs `>>>>>>> Stashed changes`) and reconcile both sides.

## Verify

- `git status` → `working tree clean`, `up to date with 'origin/main'`.
- No `<<<<<<<`/`=======`/`>>>>>>>` markers remain.
- `git rev-parse HEAD` equals `git rev-parse origin/main`.
- `go build ./...` passes (for Go repos).

## Prevention

Working across two clones of the same repo (WSL2 + Windows): always `git
status` + `git pull` in the environment you're about to edit, or use a
dedicated branch per environment, so uncommitted work doesn't silently drift
out of sync with what the other side already pushed.

## Why

Local uncommitted work and already-pushed work are frequently the *same
feature written twice* — a fact invisible from `git status` alone but exposed
by `git log --all --diff-filter=AD -- <file>` returning empty. Classifying the
divergence (duplicate vs independent) *before* resolving conflicts avoids a
broken hybrid or wasted merge effort.