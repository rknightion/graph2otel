---
id: GTO-0005
title: Add cloud environment setup script
status: Done
assignee: []
created_date: '2026-08-16 11:25'
updated_date: '2026-08-16 12:56'
labels: []
dependencies: []
references:
  - 'https://learn.chatgpt.com/docs/environments/cloud-environment#manual-setup'
  - 'https://code.claude.com/docs/en/cloud-environments#setup-scripts'
type: chore
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Provide one repository setup script that Codex cloud and Claude Code cloud can run to install the project toolchain, including Backlog.md, so cloud agents can execute the tracked development and validation workflow.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 scripts/cloud-environment-setup.sh begins with a warning that non-cloud local agents must not execute it
- [x] #2 The script installs Backlog.md and all tools required by the repository make check and common CI validation paths
- [x] #3 The script is idempotent and compatible with both Codex cloud and Claude Code cloud setup execution
- [x] #4 Automated checks validate shell syntax and the setup contract
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [x] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Derive required runtimes and pinned validation tools from the repository Makefile and CI.
2. Add a defensive, idempotent Bash setup script with persistent PATH configuration suitable for both cloud products.
3. Add a lightweight contract test, run it failing first, then implement and run the full repository gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented an idempotent Ubuntu provisioning script for both cloud products. It installs Go 1.26.6 (the patched release satisfying the module minimum), Backlog.md 1.50.1, pinned lint/vulnerability/Helm documentation tools, Helm, shellcheck, and base build dependencies; it persists PATH in .bashrc because Codex runs setup in a separate shell.

Validation passed: bash -n scripts/cloud-environment-setup.sh; go test ./scripts -run TestCloudEnvironmentSetupContract -count=1; git diff --check; and make check using Go 1.26.6. The first Go 1.26.5 make check attempt correctly exposed the standard-library vulnerabilities tracked by GTO-0004, which is why the cloud script provisions the patched release.

Implementation commit: 47b4b9c. This checkout has no configured Git remote, so the required push could not be performed here; resume boundary: configure the repository remote, then push commit 47b4b9c (and the tracker finalization commit).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the cross-cloud setup script and its Go contract test. Verified shell syntax, the focused contract test, diff hygiene, and the complete make check gate under the provisioned Go 1.26.6 toolchain.
<!-- SECTION:FINAL_SUMMARY:END -->
