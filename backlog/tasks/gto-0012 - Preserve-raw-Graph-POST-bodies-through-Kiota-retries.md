---
id: GTO-0012
title: Preserve raw Graph POST bodies through Kiota retries
status: In Progress
assignee: []
created_date: '2026-10-21T15:50:00Z'
updated_date: '2026-10-21T16:20:00Z'
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
Coverage CI during the Go 1.27.3 security update exposed export-job POST retries with declared content length but exhausted bodies. Kiota1.5.9 seeks io.Seeker and builds middleware order from a map. Preserving Seek fixes exhausted original bodies, but follow-up main CI exposed another cause: RoundTrip can return an early response while the transport still drains the same reader, so seeking before backoff also shares it with the next attempt. Both causes require regression proof; the retry policy stays unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 RawPost replays the identical nonempty payload when the real Kiota retry handler runs before compression, with a regression observed red before the fix and green afterward
- [ ] #2 The existing export throttle integration tests pass thirty repetitions and the final full gate, CodeRabbit review, and exact-head required CI pass before reporting completion
- [ ] #3 A previous request body can still be drained after an early response without consuming the retried request payload
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

Correction: the first Seek-only fix passed30 repetitions but main CI39630305069 failed TestExportHonoursRetryAfterOnThrottledCreateAndPoll with body0. Added TestRawPostRetryDoesNotReuseInFlightBody, using the real complete Kiota pipeline and an HTTP edge that drains the old body during the next attempt: it failed on the Seek-only fix with gzip EOF. Snapshotting at the retry middleware boundary and supplying a fresh request/body per attempt makes both deterministic regressions pass. Final source gate and repeat suite pending.

Independent-reader candidate: both existing real-HTTP throttle integration tests passed30 repetitions each (60 total), remote run20261021T160949Z-graph2otel-be3980ae, tree97b7e07baf68255ffab0667bff22fd8c45627398,16:09:53–16:11:45UTC. The new full-pipeline in-flight-body regression and the original Seek regression passed locally after the isolation fix; both were observed failing before their respective fixes. Full gate and CodeRabbit delta pending.

Independent-reader final full gate PASS: run20261021T160949Z-graph2otel-0c2c62ac on gate-2 slot2, tree97b7e07baf68255ffab0667bff22fd8c45627398,16:10:24–16:14:44UTC. Gaterun retried a transient same-ref setup push conflict before executing the complete passing gate. CodeRabbit delta is still running; no completion claim or merge yet.

CodeRabbit delta completed: all five changed files reviewed, one minor tracker finding, no source findings. Verified and corrected duplicate acceptance criteria through the full-replacement CLI option; retained the independent in-flight-body requirement as distinct criterion3. No code change after the passing final gate. Source candidate ready to commit and require fresh exact-head CI.
<!-- SECTION:NOTES:END -->
