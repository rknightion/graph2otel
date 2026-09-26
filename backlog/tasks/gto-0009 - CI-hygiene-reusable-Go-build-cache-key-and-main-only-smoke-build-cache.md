---
id: GTO-0009
title: 'CI hygiene: reusable Go build cache key and main-only smoke-build cache'
status: Done
assignee: []
created_date: '2026-09-26 15:50'
updated_date: '2026-09-26 17:13'
labels: []
dependencies: []
priority: high
type: chore
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
1. `ci.yml` step 'Restore Go build cache for Docker' (around line 173) keys on `${{ github.sha }}`: unique per commit, never reused (about 2.9 GB of dead entries). Key on `hashFiles('**/go.sum')` (plus Go version) and keep the restore-keys prefix.
2. The no-push smoke build writes `cache-to: type=gha,mode=max,scope=ci-smoke` from every run including PRs. Write the cache only on push to main; PRs use cache-from only.

Context: fleet CI hygiene, tracked centrally as GHC-0006 in rknightion/.github. The container-publish.yml buildx cache move to a GHCR registry cache happens there and arrives here through the normal Renovate bump; orphaned PR and tag caches are deleted by the n8n repo-settings aligner. Neither needs work in this repo.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 docker-go-build cache key is content-hashed and restores exactly on a rerun
- [x] #2 ci-smoke build writes cache only on push to main
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check is green — fmt-check, lint, tidy-check, tools-check, forks-check, test, audit, gen-check, helm-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 just gen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, signal catalog, dashboards, alert rules, chart README, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Content-hashed the docker-go-build cache key (runner.os + resolved Go version + hashFiles(go.sum)) with restore-keys prefixes, and gated ci-smoke's cache-to on github.event_name == 'push' so PR builds only read the trunk cache. just check green locally. Pushed as commit eff811b.
<!-- SECTION:FINAL_SUMMARY:END -->
