---
id: GTO-0002
title: >-
  About 90 prose references still point readers at CLAUDE.md, now a 6-line
  import stub
status: To Do
assignee: []
created_date: '2026-08-14 16:47'
labels:
  - needs-triage
  - docs
dependencies: []
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since the 2026-08-14 tracker migration AGENTS.md carries the instructions and CLAUDE.md is a six-line `@AGENTS.md` import. Around 90 references across ~76 files still say 'see CLAUDE.md' — Go doc comments citing the cardinality rule and the wire-over-docs rule, docs/ pages, CONTRIBUTING.md, and the Helm chart.

Not a break: CLAUDE.md still exists and imports AGENTS.md, so a reader who follows the pointer arrives somewhere useful. It is an accuracy defect, which is why it is a task rather than part of the migration commit.

Two traps make this less mechanical than a global sed looks:

1. Some of the targets are GENERATED. docs/collectors.md comes from internal/collectordoc; charts/graph2otel/README.md comes from README.md.gotmpl via helm-docs. Editing the generated file loses the change on the next regen and fails the drift gate — fix the source and prove it with `make regen` / `make helm-docs`.
2. cmd/graph2otel/documentation_contract_test.go and internal/collectordoc/agentsmd_test.go deliberately name AGENTS.md as the watched file. Do not let a sweep rename those back, and do not point either gate at CLAUDE.md — it would then measure the import stub and pass forever.

Deliberately out of scope: CHANGELOG.md and archive/, which are historical records, and third_party/, which is vendored.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No tracked file outside CHANGELOG.md, archive/ and third_party/ directs a reader to CLAUDE.md for guidance that now lives in AGENTS.md
- [ ] #2 Generated targets (docs/collectors.md, charts/graph2otel/README.md) are fixed at their source and regeneration reproduces the fix with no drift
- [ ] #3 The two documentation-gate tests still watch AGENTS.md, and the size tripwire still fails when AGENTS.md is padded past its limit
- [ ] #4 make check is green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->
