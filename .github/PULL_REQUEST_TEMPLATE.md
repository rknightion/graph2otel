<!--
Thanks for contributing! Please keep PRs focused. See CONTRIBUTING.md.
Do not include secrets, tokens, tenant identifiers, or any Entra ID / Intune record content.
-->

## What & why

<!-- What does this change do, and what problem does it solve? -->

## Checklist

- [ ] `make check` is green (vet + test + lint + build)
- [ ] Tests added/updated (TDD: failing test first), no live network in tests
- [ ] New `.go` files carry the `SPDX-License-Identifier: AGPL-3.0-only` header
- [ ] Conventional Commit title (`feat:` / `fix:` / `docs:` / … ; `!` for breaking)
- [ ] No tenant-specific / customer-specific values added to core code or defaults (kept configurable)
- [ ] Cardinality impact considered for any new metric labels

## Notes for reviewers

<!-- Anything reviewers should focus on, risks, follow-ups. -->
