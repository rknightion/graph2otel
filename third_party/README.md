# `third_party/` — the two pinned OTLP/HTTP exporter forks

`otlploghttp` and `otlpmetrichttp` are byte-for-byte copies of upstream
OpenTelemetry Go exporter modules at a pinned version, with one small graph2otel
patch. `otel-http-forks.tsv` records the module, version, upstream commit, and
**the exact list of files allowed to differ**; `check-otel-http-forks.sh` proves
the copy differs from upstream in those files and no others.

The root `go.mod` `replace`s both modules to these directories, so this source is
what the shipped binary actually builds — and what `govulncheck ./...` analyses.

## What the patch does

Upstream's exporters give no way to observe retry attempts or the request bytes
the HTTP transport actually reads (including on redirects), which is what
`internal/telemetry` needs to attribute egress volume and cost. The patch adds a
`RequestObserver` seam: `client.go` reports each attempt and wraps the request
body, `config.go` (plus `internal/oconf/options.go` on the metric side) carries
the option, and `request_observer_test.go` is a graph2otel-added test.

One structural change is unrelated to that: upstream's `go.mod` carries `replace`
directives pointing at monorepo-relative paths (`../../../..`). Those cannot
resolve in a standalone vendored copy, so **every `replace` line is stripped**.
That is the whole go.mod patch — everything else in it is ordinary tidy output.

## Re-vendoring onto a new upstream version

Renovate cannot do this. It bumps `go.mod` version strings, which leaves the
vendored `.go` files sitting at the old API — the failure looks like `undefined:
api.KeyValue` in an upstream file nobody edited. **`ignorePaths` in
`renovate.json` deliberately keeps Renovate out of this directory**; these files
are derived artifacts, regenerated here.

Do not hand-copy the patched files. Three-way rebase the patch onto the new
upstream so a conflict is reported rather than silently dropped:

```sh
OLD=$(go env GOMODCACHE)/go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@v0.20.0
NEW=$(go env GOMODCACHE)/go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@v0.21.0
go mod download go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@v0.21.0

mkdir /tmp/rv && cd /tmp/rv && git init -q .
cp -R "$OLD"/. . && chmod -R u+w . && git add -A && git commit -qm base && git branch -f base
git checkout -q -b newup base                  # new upstream
find . -mindepth 1 -not -path './.git*' -delete && cp -R "$NEW"/. . && chmod -R u+w .
git add -A && git commit -qm "upstream new"
git checkout -q -b patched base                # our current copy
find . -mindepth 1 -not -path './.git*' -delete && cp -R <repo>/third_party/otlploghttp/. . && chmod -R u+w .
git add -A && git commit -qm "graph2otel patch"
git rebase --onto newup base patched
```

`client.go`, `config.go` and `internal/oconf/options.go` have merged cleanly so
far. **`go.mod` and `go.sum` always conflict and are not worth merging** — take
the new upstream's, strip every `replace` line, and run `go mod tidy`.

Then, back in the repo:

1. Replace the fork directory with the rebased tree (`git archive patched | tar -x`).
2. Update `otel-http-forks.tsv`: the version, and the upstream **commit** SHA in
   the source URL. Resolve it from the tag — the 0.x submodule tag
   (`exporters/otlp/otlplog/otlploghttp/v0.21.0`) and the core `v1.45.0` tag point
   at the same commit, which is why one SHA covers both rows.
3. Bump the root `go.mod`. The two replaced modules need
   `go mod edit -require=...@<new>` — `go get` will not touch a replaced module,
   and `forks-check` fails if the required version does not match the manifest.
4. `make tidy && make check`.

## Traps this has already produced

**A `replace`d module keeps its stale `require` version silently.** Everything
builds, and only `forks-check` catches it — it compares `go list -m` against the
manifest for exactly this reason.

**An upstream API removal lands in unmodified files.** `otel/log` v0.21.0 removed
`Kind`/`Value`/`KeyValue` in favor of `go.opentelemetry.io/otel/attribute`
(upstream #8490), breaking `internal/transform/log.go` — a file the patch never
touches. The fork is not insulated from upstream churn; it is exposed to all of it.

**A silent behaviour change rode along with it.** In v1.45.0
`otlpmetrichttp.WithEndpointURL` stopped appending the default signal path when
the URL has no path. graph2otel is unaffected because `otlpHTTPURL` already
appends `/v1/metrics` itself, so the URL always has a path — but nothing in the
compiler would have said so. Read the upstream CHANGELOG's Changed and Removed
sections on every bump, not just the compiler output.
