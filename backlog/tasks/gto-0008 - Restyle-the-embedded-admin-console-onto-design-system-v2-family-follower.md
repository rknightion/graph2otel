---
id: GTO-0008
title: Restyle the embedded admin console onto design system v2 (family follower)
status: To Do
assignee: []
created_date: '2026-08-31 12:12'
labels:
  - design-system
dependencies: []
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The v2 design is committed at design/console-v2/: this repo's Console v2 canvas, graph2otel-implementation-spec.md, implementation-spec.md (THE FAMILY SPEC from tailscale2otel - its section 1 is the shared token block, byte-identical across tailscale2otel, opnsense2otel, graph2otel and codexlb2otel; copy it, never edit it per repo), and internal/admin/ holding a draft restyled page.html.tmpl - treat the draft as reference, not finished code. Read both specs in full before any code change.

Scope: Go html/template + inline CSS/vanilla JS + go:embed stays; no framework, no build step, no CDN, no external network request. Fonts self-hosted per the family spec. Light default honouring prefers-color-scheme with the existing data-theme toggle kept and winning. The family standards apply (underline tabs, word+shape health badge, dense-table standard); this repo's differentiator is the sparkline/trend small-chart standard (axis, grid, petrol-derived series, both themes), drawn in its canvas and defined in its spec as a reusable family pattern; Config and Cardinality derive from the family patterns. SEQUENCING: tailscale2otel task TSO-0103 lands first; if it extended the shared token block, inherit the extended version.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the console page renders on the family token block, light and dark, light default
- [ ] #2 the shared token block matches the family spec section 1 byte-for-byte (as landed by the standard-setter)
- [ ] #3 Overview trend charts match the small-chart standard in both themes
- [ ] #4 no external network requests; AA pairs hold
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check is green — fmt-check, lint, tidy-check, tools-check, forks-check, test, audit, gen-check, helm-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 just gen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, signal catalog, dashboards, alert rules, chart README, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
- [ ] #4 just check green
<!-- DOD:END -->
