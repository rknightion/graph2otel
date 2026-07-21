// Separate CI-only module so it never affects the main module's `go build ./...`
// or `go test ./...`. It slices the Microsoft Graph *beta* CSDL ($metadata) down
// to the operations graph2otel consumes and diffs that slice against the
// committed snapshot, reporting drift with severity-ranked exit codes.
//
// Deliberately dependency-free (standard library only): the drift canary must
// build and run from a cold cache with no module downloads, and adding the main
// module's msgraph-heavy tree here would make a 10-second job a 3-minute one.
module github.com/rknightion/graph2otel/tools/graphdrift

go 1.26.5
