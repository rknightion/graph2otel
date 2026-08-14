---
id: GTO-0003
title: 'CI red since 2026-08-10: chart README drifted from its template in cede7dd'
status: To Do
assignee: []
created_date: '2026-08-14 17:20'
labels:
  - needs-triage
  - ci
dependencies: []
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The 'helm lint + template' job's 'helm-docs README up to date' step has failed on every CI run since cede7dd (2026-08-10), which is why ci-success has been red on main for four days. It is NOT caused by the 2026-08-14 tracker migration — the run on a0797e6 (2026-08-11) fails the same job.

Diagnosed, one line. cede7dd pointed the chart's home at the docs site but did not regenerate the generated README:

    -**Homepage:** <https://github.com/rknightion/graph2otel>
    +**Homepage:** <https://m7kni.io/graph2otel/>

`make helm-docs` produces exactly that diff and nothing else — verified locally 2026-08-14, exit 0, one file, one line. The regeneration was deliberately NOT committed as part of the tracker migration, to keep an unrelated chart change out of that history.

Trap: charts/graph2otel/README.md is GENERATED from README.md.gotmpl. Editing the README by hand fixes CI once and drifts again on the next chart change — run the generator.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 make helm-docs produces no diff on a clean tree
- [ ] #2 The 'helm lint + template' job passes on main
- [ ] #3 The fix is the regenerated output, not a hand-edit of charts/graph2otel/README.md
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->
