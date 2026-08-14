# GitHub Issues archive

`github-issues-2026-08-14.json` is the complete contents of this repository's GitHub Issues tracker
as of **2026-08-14**, captured immediately before the issues themselves were deleted. The project
moved to Backlog.md on that date; see the *Closed GitHub issues* doc (`backlog doc list --plain`)
for the browsable index, and this file for the bodies and replies behind it.

**This is the record, not a convenience copy.** The issues it describes no longer exist on GitHub, so
`gh issue view <N>` will 404. Anything in the repository that cites `#NNN` — `AGENTS.md`, the domain
reference docs under `docs/`, commit messages, code comments — resolves here.

## What it contains

403 issues and all 920 comments, verified against the REST API's own per-issue comment counts before
capture: 403 issues on both sides, an exact per-issue comment-count match, zero mismatches. Per
issue: number, title, body, state, state reason, author, labels, milestone, assignees,
created/updated/closed timestamps, URL, and every comment with its author and timestamp.

```sh
jq '.[] | select(.number == 374)' archive/github-issues-2026-08-14.json          # one issue
jq -r '.[] | select(.number == 374) | .comments[].body' archive/…                # its replies
jq -r '.[] | select(.title | test("cardinality"; "i")) | "#\(.number) \(.title)"' archive/…
jq -r '.[] | select(.stateReason == "NOT_PLANNED") | "#\(.number) \(.title)"' archive/…
```

## It is redacted, and the redaction is deliberately narrow

67 distinct values were replaced with stable placeholders before this file was committed: 60 GUIDs
(device, object, correlation and subscription identifiers), 2 user principal names, one public
source IP, one device name, one Exchange target server, one Grafana host and one Grafana stack id.

| Placeholder | Was |
| --- | --- |
| `<guid-N>` | a tenant-scoped GUID — device, object, correlation or subscription id |
| `<upn-N>` | a user principal name |
| `<device-N>` | a device name |
| `<public-ip-N>` | a real public source address |
| `<exchange-server-N>` | an Exchange target server named in a Graph error body |
| `<grafana-host-N>`, `<grafana-stack-id>` | the telemetry backend's host and stack id |

**One distinct real value maps to one placeholder throughout**, so a reader can still tell that two
issues discuss the same device or correlation id without learning which.

**The scope is "not already in tracked source", and that is the whole rule.** Most identifiers these
issues discuss are already committed to this public repository — the collector test fixtures are
built from live wire samples by design (`AGENTS.md`, *A green tick is not evidence of data*), so the
tenant GUID, `rob@m7kni.io`, ten of the eleven `DESKTOP-*` device names, `camden`,
`grafana.m7kni.com` and the storage account name all appear in tracked files and in `README.md`.
Those are already in permanent public git history; tokenising them here would protect nothing and
would leave the archive's vocabulary disagreeing with the codebase it documents. So the redaction
covers exactly the values that appear **only** in the issues — the ones that would otherwise move
from somewhere deletable into permanent public history at the moment of deletion.

Deliberately left intact: documentation placeholders (`alice@contoso.com`, `example@email.com`,
TEST-NET addresses such as `203.0.113.7`), Microsoft's public first-party application ids
(`00000003-0000-0ff1-ce00-000000000000` and friends, which carry no tenant identity), and GitHub
Actions run ids, which are public on a public repository.

## Two traps in verifying this, both of which produced a wrong "clean"

**Sweep the decoded fields, never the serialized JSON.** In `json.dumps` output an escape such as
`\n` leaves a literal `n` immediately before the following word, which breaks a `\b` word boundary
and silently undercounts. Every substitution and every verification pass here walks the parsed
structure.

**A GUID is not `\b`-delimited in practice.** The first pass used `\b…\b` and leaked a correlation
id embedded in a composite identifier — `Sync_9b9e047f-…_4b8c18bd-…` — because the underscore before
it is a word character, so the boundary never matched. It was caught only because the leak sweep ran
over decoded fields against every value the redactor claimed to have replaced. The regex now
delimits on hex-and-dash instead, which matches inside a composite while never partially matching a
longer hex run. **A redactor that is not adversarially swept against its own claimed output will
certify a file clean while it still leaks.**
