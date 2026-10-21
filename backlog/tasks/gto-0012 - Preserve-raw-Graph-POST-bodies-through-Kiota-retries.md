---
id: GTO-0012
title: Preserve raw Graph POST bodies through Kiota retries
status: In Progress
assignee: []
created_date: '2026-10-21T15:50:00Z'
updated_date: '2026-10-21T15:57:00Z'
labels: []
dependencies: []
references:
  - 'https://github.com/rknightion/graph2otel/pull/517'
priority: high
type: bug
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Coverage CI during the Go 1.27.3 security update exposed a real retry failure: an export-job POST was resent with its declared content length and an exhausted body. Kiota 1.5.9 rewinds io.Seeker and builds its default middleware slice from a map, so compression sometimes hides the non-seekable stdlib wrapper and sometimes does not. The existing real-HTTP export throttle regression failed three of thirty repetitions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 RawPost replays the identical nonempty payload when the real Kiota retry handler runs before compression, with a regression observed red before the fix and green afterward
- [ ] #2 The existing export throttle integration test passes thirty repetitions and the final full gate, CodeRabbit review, and exact-head required CI pass before landing
- [ ] #3 RawPost replays the identical nonempty payload when the real Kiota retry handler runs before compression, with a regression observed red before the fix and green afterward
- [ ] #4 The existing export throttle integration test passes thirty repetitions and the final full gate, CodeRabbit review, and exact-head required CI pass before reporting completion
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check is green — fmt-check, lint, tidy-check, tools-check, forks-check, test, audit, gen-check, helm-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 just gen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, signal catalog, dashboards, alert rules, chart README, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Keep the existing Kiota retry and compression pipeline; preserve seekability on RawPost bodies and its replay factory, retain empty-body semantics, prove the regression through the real retry handler, and rerun the existing HTTP integration test thirty times plus the full remote gate. Review the delta with CodeRabbit and require latest-head CI before merging.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Measured 2026-10-21: unchanged-tree remote run20261021T154344Z-graph2otel-52f45996 failed the existing throttle regression3/30. Deterministic TestRawPostReplaysBodyBeforeCompression then failed with an empty second payload before the fix and passed after it. Patched real-HTTP30x run20261021T154815Z-graph2otel-5fab5652 passed. Full gate run20261021T154819Z-graph2otel-684a86c7 passed; final gate after preserving NoBody and documenting the contract is running. CodeRabbit and exact-head CI pending; no generator-driven surface changed.

CodeRabbit delta review completed with findings0; both changed Go files reviewed. Required status on the previous PR head is green but its optional coverage job revealed the real failure, so the corrected candidate must replace it and pass CI before landing.

Final corrected-code full gate PASS: remote run20261021T155018Z-graph2otel-c9b294bf, tree560c38fa26c0176e3aa85b9fec0c9081f4f07f83, 15:50:21–15:54:09UTC. CodeRabbit complete with findings0. Corrected-head GitHub CI still required before landing.

Renovate auto-merged the earlier Go update while the retry fix was being reviewed. Used the explicitly authorized direct-main route for reviewed/gated fix a4aaef5a4400d51b4223ddf71efafa465d087bbb. Acceptance wording corrected from CI before landing to CI before completion to reflect that authorized direct-main workflow; exact-head CI remains mandatory. No generated surface changed.
<!-- SECTION:NOTES:END -->
