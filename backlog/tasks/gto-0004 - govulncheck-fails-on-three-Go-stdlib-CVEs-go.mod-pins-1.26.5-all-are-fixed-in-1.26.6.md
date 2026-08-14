---
id: GTO-0004
title: >-
  govulncheck fails on three Go stdlib CVEs: go.mod pins 1.26.5, all are fixed
  in 1.26.6
status: To Do
assignee: []
created_date: '2026-08-14 17:20'
labels:
  - needs-triage
  - ci
  - security
dependencies: []
priority: high
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The govulncheck job fails on main. All three findings are standard-library, none is a dependency:

- GO-2026-6218 net/url — quadratic complexity in resolvePath, reached via annotations.Client.Publish -> http.Client.Do (internal/annotations/client.go:141)
- GO-2026-6091 html/template — Javascript regexp context tracking, reached via admin.Start -> http.Server.ListenAndServe (internal/admin/admin.go:172)
- GO-2026-6090 crypto/tls — unbounded post-handshake messages

Each says 'Found in: <pkg>@go1.26.5, Fixed in: <pkg>@go1.26.6'. go.mod line 3 says `go 1.26.5` and every CI job uses `go-version-file: go.mod`, so CI builds on the vulnerable toolchain.

This is why a local `make check` can be green while CI is red: a developer machine on go1.26.6 scans a patched stdlib. Confirmed 2026-08-14 — local go1.26.6 passed govulncheck minutes before CI failed on the same commit. Do not chase it as a flake.

Not caused by the tracker migration; it appeared when the advisories were published, after the 2026-08-11 run.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go.mod requires a Go version that carries fixes for GO-2026-6218, GO-2026-6091 and GO-2026-6090
- [ ] #2 govulncheck passes in CI, not only on a maintainer laptop
- [ ] #3 make check is green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->
