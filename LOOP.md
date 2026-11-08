# Loop: graph2otel
tier: guarded
gate: just check
ci-required: ci-success
grafana-stack: none
tracker: github
landing: pr

Issues are public: no tenant id, hostname, address or email in any issue, pull request or doc.
The tracker working model is `~/repos/agent-docs/docs/github-tracker.md` (maintainers only).

Runs in production against a live tenant. `just check` covers all four Go modules plus the
generated-asset drift gates; `just ci` adds the container smoke leg. Run `just` with stdin from
`/dev/null`; a `[confirm]` recipe writes a live Grafana stack, so never pass `--yes` or
`JUST_YES=1`.

## Queue

- The queue is `just tracker queue`: open issues at Project Status Ready on the rknightion Project.
- A charter selects work by labels (`type:task`, `type:bug`, `type:feature`, `needs-owner`,
  `needs-triage`) and Project fields (Status, Priority, Effort, Lane). Never queue a `needs-owner` or
  `needs-triage` issue.
- Only the root writes issues and the Project, through `just tracker`. A lane returns the status and
  the AC ticks it wants.
- A queue row names the issue as `#N`. A legacy board id (`GTO-0001`) resolves with `just issue <ID>`;
  `.github/tracker/id-map.json` is the map.

## Credentials

- Probe the live tenant only as `graph2otel-poller` with `g2o-probe`. `homelab-agentic-mgmt` grants
  scopes and proves nothing about what the shipped binary can see. Tenant mutations (app
  registrations, scope grants, diagnostic settings), camden deploys and destructive git stay with
  the root.

## Traps

- A green `just check` does not prove the collector-doc gates can see your work: they have gone
  green over an invisible collector twice, for two different reasons. Check both blindness modes.
- A guard asserting one layer above the bug finds nothing. Sabotage the implementation and watch
  the test fail for the right reason.
- A gate piped through `tail` reports the pipe's exit status over a failed gate: redirect to a file
  and echo `$?`.
- Graph omits optional numerics as well as sentinelling them: a bare `float64` publishes a
  fabricated `0`. Use pointers, and read the emitted values after deploy.
- Fixtures with an absolute date in a horizon- or watermark-gated collector fail on a calendar
  date, not on a code change: check for a date trigger before debugging your own diff.
- Vary the probe shape before parking a task as blocked on data; malformed probes caused repeated
  false verdicts, and the beta `$metadata` EDM is the cheap oracle. An HTML body on a 403 means an
  edge refused the request and no scope grant helps.
- `scripts/regen-generated.sh` finds signal-capture packages with `rg --files`, which obeys ignore
  rules: a lane worktree inside the repo (under gitignored `.claude/worktrees/`) regenerates
  nothing and exits 0. Keep lane worktrees outside the repo and diff the generated artifacts.
- Mappers are written against live samples, never docs or hand-written fixtures; record API
  behaviour with a `live-measured` tag.
- Cite work as `#N`. A `#N` of 426 or lower is an early issue GitHub no longer has
  (`archive/README.md` holds it); a legacy board id (`GTO-0001`) resolves with `just issue <ID>`.

## Mutexes

- camden is the single production instance with no leader election: deploy and verification are
  root actions.
- `golangci-lint` holds a global lock across repositories: `just check`, `just lint` or a commit
  firing the pre-commit hook collides with `parallel golangci-lint is running`, including with
  another session in a different repo. Give the gate to one lane, and retry rather than concluding
  the tree is broken.
- Append-only registries, each lane owning its own entry only: the seven registration paths in
  `internal/collectors` (`Deps`/`All`, `WindowDeps`/`WindowAll`, `BlobDeps`/`RegisterBlob`,
  `O365Deps`/`O365All`, `MDCADeps`/`RegisterMDCA`, `EXODeps`/`RegisterEXO`,
  `HuntDeps`/`RegisterHunt`/`HuntAll`), `internal/semconv/additive.go` (a new unit must be
  classified), `internal/wirecheck` (the `Enum` derived from the map the collector keys on) and
  `spec/graph-beta-surface.json` (a beta-consuming package must be listed).
- `internal/collectordoc` `Rows` takes one slice per registration path. A lane adding an eighth
  path changes that signature in the same commit and never defers it: the signature is what keeps
  the coverage gate honest.

## Lane brief

A file outside your ownership stops you: return the question, never invent an answer the brief
does not cover. Do not weaken a drift gate to make it pass.
