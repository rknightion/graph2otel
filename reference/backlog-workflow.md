# Backlog tracker rules for this repo

Read before creating, editing or finalising a Backlog task, doc or decision here. The tracker is
Backlog.md in `backlog/`, committed to git, and it is the record of intent and progress rather
than `AGENTS.md`.

## CLI traps

A guard hook in the agent config denies most of these calls outright, because each failure mode is
silent and unrepairable.

- **Never use `--notes` or `--plan` bare.** They *silently replace* the whole section, destroying
  another session's writes with no warning and exit 0. Use `--append-notes` and `--append-plan`.
  This is an open upstream bug, not a misunderstanding.
- **Hand-editing tracker markdown is unrepairable, not merely discouraged.** Section boundaries
  are HTML-comment markers; break one and the section is *silently dropped* at exit 0. The data
  stays in the file but is invisible to the CLI until the next write destroys it for real. There
  is no repair command, and `backlog doctor` only fixes duplicate task IDs. `backlog/config.yml` is the one exception and is edited by hand, because
  list-valued keys cannot be set through `backlog config set`.
- **Finalize in one call**, so an interrupted session cannot leave finished work looking
  unfinished: `backlog task edit GTO-0007 --check-ac 1 --check-ac 2 -s Done`.
- **Never let two agents edit the same task.** The edit funnel is safe; reorder, draft saves, the
  TUI path, `doc update` and decision updates are not.
- **Do not build a workflow on decisions.** They are half-built upstream: no `decision
  edit`/`view`/`update`, no supersede mechanism, no status validation. Durable reference goes in
  docs; tasks are the unit.

## Content rules

- Before designing a wave, read this repo's own fan-out protocol doc and its wave operating model
  doc; `backlog doc list --plain` lists both.

- **Statuses are `To Do`, `In Progress`, `Parked`, `Done`.** `Parked` means attempted and
  blocked, with a **concrete resume boundary** in the notes: the specific next probe or decision,
  never "needs investigation".
- When a later note reverses an earlier claim, correct the earlier one the same day. If a task's
  description contradicts its notes, the newest note wins; fix the description before moving on.
- Any **"do not X yet"** must name its unblock condition, so a later reader can check whether it
  has fired.
- Every do-not-redo or verified-fact entry carries its **evidence class**:
  `live-measured (date, task)` / `docs-only` / `n=1`. Docs-only and n=1 are cheap to re-open; do
  not give them the armour of a measured fact.

## Identifiers

`backlog/` is committed, so keep new account identifiers and personal data out of tasks, docs and
decisions: no UPNs, device names, serials, tenant or object GUIDs, IP addresses. Write the shape,
not the instance ("the tenant's second service account", `<container>/<blob>`). Aggregate counts,
timings and structural findings are fine. The project's own vocabulary (`m7kni`, `camden`, the
storage account) is not covered; it is already in hundreds of tracked files and in `README.md`,
so tokenising it would protect nothing. Sweep before committing:

```sh
rg -ni 'DESKTOP-|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|@[a-z0-9.-]+\.(io|com|net)|\b(?:\d{1,3}\.){3}\d{1,3}\b' backlog/
```

**Do not write that sweep with `rg -E`.** `-E` is ripgrep's `--encoding` flag, not "extended
regex": it swallows the pattern as an encoding name, matches nothing, and exits like a clean run.

## Legacy issue numbers

New work is `GTO-NNNN`. A bare `#NNN` in code comments or task notes refers to a pre-Backlog
GitHub issue; those were deleted and now resolve only in `archive/github-issues-2026-08-14.json`,
indexed by the *Closed GitHub issues* doc in `backlog doc list --plain`.
