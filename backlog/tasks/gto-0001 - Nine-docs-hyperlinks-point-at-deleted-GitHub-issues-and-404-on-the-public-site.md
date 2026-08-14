---
id: GTO-0001
title: Nine docs hyperlinks point at deleted GitHub issues and 404 on the public site
status: To Do
assignee: []
created_date: '2026-08-14 16:35'
labels:
  - needs-triage
  - docs
dependencies: []
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The GitHub issues were archived and deleted on 2026-08-14, so every hyperlink to `github.com/rknightion/graph2otel/issues/<N>` now 404s. Nine of them are live links on the published docs site, which is a reader-facing break rather than an internal shorthand problem.

docs/runbooks.md:373 (#419), :405 (#401), :420 (#297), :455 (#419), :464 (#268)
docs/collectors.md:10 (#139), :21 (#140)
docs/deploying-observability.md:309 (#297)
docs/permissions.md:167 (#11)

The ~402 bare `#NNN` mentions elsewhere in docs/ are NOT in scope and should be left alone: they are shorthand, AGENTS.md says where they resolve, and rewriting them would be churn over the whole doc set.

The trap here is docs/collectors.md, which is GENERATED. Its two links live in the generator, so editing the file makes the fix vanish on the next `make regen` and fails the drift gate. Fix the source and prove it with a regen.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No file under docs/ contains a hyperlink to github.com/rknightion/graph2otel/issues/<N>
- [ ] #2 The two docs/collectors.md links are fixed at their generator source, and `make regen` reproduces the fixed output with no drift
- [ ] #3 Each replacement resolves for a reader: either the bare #NNN text with no link, or a pointer to the Closed GitHub issues doc and archive/
- [ ] #4 Bare #NNN shorthand elsewhere in docs/ is unchanged
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->
