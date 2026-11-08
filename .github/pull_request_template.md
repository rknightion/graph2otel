<!--
Thanks for contributing! Please keep PRs focused. See CONTRIBUTING.md.
Do not include secrets, tokens, tenant identifiers, or any Entra ID / Intune record content.
-->

## What & why

<!-- What does this change do, and what problem does it solve? -->

## Checklist

- [ ] `just check` is green (fmt + lint + tests + vuln scan + generated-asset drift + build)
- [ ] Tests added/updated (TDD: failing test first), no live network in tests
- [ ] New `.go` files carry the `SPDX-License-Identifier: AGPL-3.0-only` header
- [ ] Conventional Commit title (`feat:` / `fix:` / `docs:` / … ; `!` for breaking)
- [ ] No tenant-specific / customer-specific values added to core code or defaults (kept configurable)
- [ ] Cardinality impact considered for any new metric labels

## Notes for reviewers

<!-- Anything reviewers should focus on, risks, follow-ups. -->

## Issue

<!-- Closes #<number> on a line of its own for each issue of this repository this change completes (Closes owner/repo#<number> means the same). Refs #<number> when it only relates to one. A change with no issue says "Task: none, <reason>" on a line of its own. -->

## Acceptance evidence

<!-- One row per acceptance criterion of every issue this change closes, copied exactly from the issue's "- [ ] ACn" list. Evidence class is code, live or browser. In Proof, put repository paths in backticks, and write anything else (a command, a read-back, a run) without them. Delete the example row. Leave the table out only when the change closes no issue. -->

| Issue | AC | AC text | Evidence class | Proof |
| --- | --- | --- | --- | --- |
| #N | AC1 | The acceptance criterion, word for word | code | `path/to/the_test.go` TestWhatItProves |
