---
id: GTO-0003
title: 'CI red since 2026-08-10: chart README drifted from its template in cede7dd'
status: In Progress
assignee:
  - '@codex'
created_date: '2026-08-14 17:20'
updated_date: '2026-08-16 10:22'
labels:
  - needs-triage
  - ci
dependencies: []
modified_files:
  - Makefile
  - charts/graph2otel/README.md
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The baseline CI required by Renovate automerge has been red since cede7dd (2026-08-10). The Helm job exposes two related defects introduced when the chart homepage moved to the documentation site:

- `charts/graph2otel/README.md` still contains the old GitHub homepage.
- `make helm-docs` passes the chart directory itself as `--chart-search-root`; helm-docs searches children of that root, discovers no charts, exits successfully, and therefore cannot regenerate the stale README. This silent no-op is why the generated output was missed and why the documented repair command did not repair it.

The fix must point helm-docs at the parent `charts` directory and regenerate the README from `README.md.gotmpl` plus `Chart.yaml`. Do not edit the generated README alone.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 make helm-docs produces no diff on a clean tree
- [ ] #2 The 'helm lint + template' job passes on main
- [x] #3 The fix is the regenerated output, not a hand-edit of charts/graph2otel/README.md
- [x] #4 The make helm-docs target discovers the graph2otel chart instead of exiting successfully without generating anything
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Regenerate the Helm chart README from its template. 2. Verify the generated file is stable and run the full repository gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Reproduced 2026-08-16: the existing make target exited 0 without a Found Chart message and left the stale homepage unchanged. Directly using --chart-search-root charts found graph2otel and produced the expected one-line README update. This corrects the earlier task claim that make helm-docs already generated the diff. Evidence class: locally measured (2026-08-16, GTO-0003).

Validation 2026-08-16: make helm-docs logged Found Chart directories [graph2otel] and a second run preserved the README SHA-256 exactly. The CI-only acceptance criterion remains unchecked until the branch runs on GitHub.
<!-- SECTION:NOTES:END -->
