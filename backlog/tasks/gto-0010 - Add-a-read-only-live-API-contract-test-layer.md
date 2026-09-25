---
id: GTO-0010
title: Add a read-only live API contract test layer
status: To Do
assignee: []
created_date: '2026-09-25 08:05'
labels:
  - testing
dependencies: []
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The 2026-09-25 test audit found no integration, e2e or live build tags in this repo (0 files); all coverage is unit tests over recorded fixtures, so upstream API shape drift is caught only if a fixture happens to match reality. Add a `//go:build live` read-only contract suite modelled on tailscale2otel's internal/tsapi/contract/live/live_test.go: it hits the real API, distinguishes misconfiguration from absent resources, and runs in CI with credentials minted through OpenBao (never a PAT).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A //go:build live suite exercises the endpoints the collectors depend on, read-only
- [ ] #2 CI runs it on a schedule with OpenBao-issued credentials and skips cleanly when they are absent
- [ ] #3 A deliberately broken fixture/shape assumption makes the live test fail for the right reason
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check is green — fmt-check, lint, tidy-check, tools-check, forks-check, test, audit, gen-check, helm-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 just gen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, signal catalog, dashboards, alert rules, chart README, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->
