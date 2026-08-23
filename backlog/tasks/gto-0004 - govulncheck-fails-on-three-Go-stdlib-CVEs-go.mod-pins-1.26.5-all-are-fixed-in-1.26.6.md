---
id: GTO-0004
title: Upgrade Go toolchain to 1.27
status: In Progress
assignee:
  - '@codex'
created_date: '2026-08-14 17:20'
updated_date: '2026-08-23 20:21'
labels:
  - needs-triage
  - ci
  - security
dependencies: []
modified_files:
  - go.mod
priority: high
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Adopt Go 1.27 consistently across the application, nested modules, build image, cloud setup automation, and contributor documentation. This supersedes the earlier patch-only 1.26.6 remediation while retaining its standard-library vulnerability fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All active Go module and toolchain pins require Go 1.27
- [x] #2 Build images, setup automation, and current documentation agree with the Go 1.27 requirement
- [x] #3 The full repository gate passes under Go 1.27
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [x] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Raise the pinned Go toolchain to the patched 1.26.6 release. 2. Run the full repository gate, including govulncheck, under the pinned toolchain.

3. Expand the patch-only remediation to Go 1.27.0 across every active toolchain surface. 4. Resolve the Go 1.27 removal of the goroutineleakprofile experiment through GTO-0006. 5. Run the full gate, push main, and confirm hosted CI.

Current plan only: the earlier 1.26.6 patch step is historical and superseded. Require Go 1.27.0 across active toolchain surfaces, resolve the deleted goroutineleakprofile experiment through GTO-0006, run the full gate, push main, and confirm hosted CI.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Updated go.mod to 1.26.6. Full local validation is blocked by the supplied Go installations: the preinstalled go command crashes while selecting 1.26.6, and a downloaded archive reports go1.26.6 while containing a standard library compiled by go1.24.3. CI-only criteria remain unchecked pending GitHub.

Go 1.27.0 full local make check passed: race tests, lint with 0 issues, govulncheck with no reachable vulnerabilities, tidy, nested tools, fork checks, Grafana checks, and build. No registry-driven or generated surface changed, so regeneration was not required. Paid-plan CodeRabbit review completed; its tracker-plan observations were clarified and its workflow mismatch claim was verified false against the root and nested module pins.

The campaign-wide Linux compatibility sweep raised the local/cloud golangci-lint pin from v2.12.2 to current v2.13.1, matching the existing hosted workflow. The cloud setup contract test and shell syntax check passed. A local Linux-target lint attempt remained active for over 10 minutes and was stopped without a result; exact-head hosted CI is the Linux proof.
<!-- SECTION:NOTES:END -->
