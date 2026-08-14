---
id: doc-0002
title: Wave operating model
type: guide
created_date: '2026-08-14 16:28'
updated_date: '2026-08-14 16:28'
---
> **This document carries only what is true of graph2otel.** The campaign model itself — run
> contract and run modes, the routing contract, authority and the thread pool, the append-only
> registry contention case in general, the child lane brief, external-contract freezing, the
> structural failure patterns, the unattended blocker contract, the goal-file template and the
> pre-flight checklist — is the *Agent fan-out protocol (canonical)* doc, imported verbatim.
> Read that first. Nothing here restates it; if something in here could be pasted into another
> project unchanged, it is in the wrong document.

## Run artefacts do not live in `codex/` here

The protocol prescribes a gitignored `codex/` at the repo root. graph2otel uses **`docs/superpowers/`**
for goals, plans, specs and research, and **`.superpowers/`** for per-lane reports and review diffs.
Both are gitignored, both are mirrored between machines by `codex-sync.sh` (it matches `codex/` *and*
`docs/superpowers/`), so the syncing property the protocol's naming rule protects is intact.

`.superpowers/` was **committed once by accident, in `099ba59`, by a `git add -A`**. Published history
is not rewritten, so the `.gitignore` line is the only thing stopping a recurrence. In a wave, stage
explicit pathspecs — never `git add -A`, never `git commit -a`.

## Exclusive resources — three, and two of them are not files

**1. The live tenant, probed only as `graph2otel-poller`.** Two Graph app identities exist and they
are not interchangeable: `homelab-agentic-mgmt` *grants* scopes, and `graph2otel-poller` is the only
identity whose answer says anything about what graph2otel itself can see. A lane that probes as the
management identity proves nothing and will report a capability the shipped binary does not have.
Use `g2o-probe`.

**Live-tenant mutations stay on the main thread** — app registrations, scope grants, diagnostic
settings, anything that changes tenant state. Not merely convention: a subagent inherits auto mode
and *cannot* clear a soft block, because clearing one requires the user's own message naming the
action and a lane's transcript contains no user message. A lane blocked on a tenant mutation is stuck
with nothing able to unblock it, and re-dispatching it reads as bad faith. Same for camden deploys
and destructive git.

**2. camden — the single production instance.** graph2otel is single-instance with no
leader-election, so there is one place the code actually runs. Deploy and verification are a
main-thread action.

**3. `golangci-lint` holds a GLOBAL lock, across repositories.** Two lanes running `make check`,
`make lint` or a commit that fires the pre-commit hook will collide with
`Error: parallel golangci-lint is running` — and so will an unrelated session working in a *different
repo on the same machine*. Measured during this migration on 2026-08-14: a `golangci-lint` run
belonging to `genai-otel-bridge` failed graph2otel's pre-commit hook twice, and killing the lint of a
timed-out run left the lock held by a process `pgrep` no longer showed. **The gate is not a
parallelisable step.** Give it to one lane, or serialise it at the wiring checkpoint. Retry rather
than concluding the tree is broken.

## The append-only registries in this repo

The protocol says split these before fan-out. These are the ones to split:

- **`internal/collectors` — seven registration paths**: `Deps`/`All`, `WindowDeps`/`WindowAll`,
  `BlobDeps`/`RegisterBlob`, `O365Deps`/`O365All`, `MDCADeps`/`RegisterMDCA`, `EXODeps`/`RegisterEXO`,
  `HuntDeps`/`RegisterHunt`/`HuntAll`.
- **`internal/collectordoc` — `Rows`**, which takes one slice per path
  (`snapshot, window, blob, o365, mdca, exo, hunt`). **An eighth path means changing that signature in
  the same commit.** That is not bookkeeping — the signature *is* the mechanism that keeps the
  coverage gate honest, because a gate that cannot see a collector reports coverage it does not have.
  A lane adding a registration path owns the `Rows` change and **may not defer it to the wiring
  pass**; deferring it is exactly how the gate stayed green over a missing collector (#139/#100).
- **`internal/semconv/additive.go`** — a new unit must be classified or CI fails.
- **`internal/wirecheck`** — a collector that assumes a value set declares it here, with the `Enum`
  *derived from the map the collector already keys on*, never restated.
- **`spec/graph-beta-surface.json`** — gated both ways; a beta-consuming package must be listed.

## Recurring defects in this codebase

Each of these has bitten more than once. They are the things to write into a lane's brief.

**A green gate is not evidence the gate can see your work.** The collector-doc gates have gone green
over an invisible collector **twice, for two different reasons**. Check both blindness modes; never
treat a green `make check` as proof a collector is documented.

**A guard that asserts one layer above the bug finds nothing.** Three instances in one week —
`telemetrytest`'s join, `SetStrs`' empty-filter, and a key-set-versus-value swap. Identify the layer
the bug actually lives on and assert *there*. Sabotage the implementation and watch the test fail for
the right reason; that is the only thing that finds this class.

**`make check | tail` in a background shell notifies exit 0 over a FAILED gate.** The pipe's exit
status is `tail`'s. Redirect to a file and echo `$?`. Also beware the persistent-cwd and buffered-tail
traps in the same shape.

**An absent field is not a sentinel.** Graph omits optional numerics as well as sentinelling them, so
a bare `float64` publishes a fabricated `0` that looks like a real measurement. Use pointers — and
read the emitted *values* after deploy, not just that the series exists.

**Fixtures carry date time bombs.** An absolute date in a horizon- or watermark-gated collector's
fixture fails on a **calendar date**, not on a code change; one turned `main` red on 2026-07-28.
Before debugging your own diff, check whether the failure is date-triggered.

**Vary the probe shape before parking anything as blocked.** Three false "blocked on data" verdicts
in one week all came from malformed probes, not from missing data. The beta `$metadata` EDM is the
cheap oracle. A wrongly-parked task costs a whole run.

**Find the denial LAYER before asking for a scope.** Five refusals, none of which came from Graph
auth. An HTML body on a 403 means an edge refused the request and no scope grant will ever help.

**A green tick is not evidence of data.** Empty-collection success is the steady state for several
collectors — risk signals on a healthy tenant, `m365.activity` on a small one — so a mapping bug is
invisible while the list stays empty. Mappers are written against live samples, never docs and never
hand-written fixtures.

**Wire over docs.** Microsoft's documentation has been wrong on essentially every load-bearing detail
on this project's path. A lane may not assert API behaviour from docs alone; it measures, then
records with a `live-measured` tag.

## Lane conventions

Lanes build in **worktree isolation**; the main thread probes, reviews and merges. One trap belongs to
that arrangement here. `scripts/regen-generated.sh` discovers signal-capture packages with
`rg --files internal -g 'signalgate_test.go'`, and **`rg --files` obeys ignore rules**. A package
underneath any gitignored path is therefore invisible to it — and `.claude/worktrees/` is gitignored,
so a worktree created *inside the repo* gets a regen that reports success having regenerated nothing
for that lane. Put lane worktrees outside the repo, and diff the generated artifacts rather than
trusting regen's exit code. (Ordinary untracked files are not affected: ripgrep skips *ignored*
paths, not merely-uncommitted ones.)

## Ownership and the escape hatch

One file, one owner, with the registries above owned by each lane *for its own entry only*. The escape
hatch when a lane needs a file it does not own: **stop and return the question — do not edit it, and
do not invent an answer the brief does not cover.** A boundary with no escape hatch is a stop
condition wearing a safety label.

The blanket exception, for the auto-mode reason given above: **tenant mutations, camden deploys and
destructive git are main-thread work regardless of who owns the file.**

## Run-end against this tracker

The queue is `backlog task list --plain -s "To Do"`. Landed work is `Done` with the resulting SHA in
its final summary and the `make check` evidence cited, not asserted. Blocked work is `Parked` with a
concrete resume boundary — the specific next probe or decision, not "needs investigation". Work
discovered mid-run becomes a new task labelled `needs-triage`.

**Cite pre-2026-08-14 work as `#NNN` and new work as `gto-NNNN`.** The GitHub issues were deleted on
2026-08-14; `#NNN` resolves to `archive/github-issues-2026-08-14.json`, indexed by the *Closed GitHub
issues* doc. Two ID spaces exist over this project's history and only one of them is still growing.
