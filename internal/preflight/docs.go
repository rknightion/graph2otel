package preflight

import (
	"fmt"
	"sort"
	"strings"
)

// HelpText returns the static help/output text printed by `graph2otel check`
// (both on -h and appended to a normal run): the two least-privilege traps to
// avoid when provisioning the app registration, the admin-consent and
// directory-role caveats this check cannot itself verify, and a
// representative catalog of scopes collectors are expected to need.
func HelpText() string {
	var b strings.Builder

	b.WriteString("Least-privilege notes:\n")
	for scope, why := range ExpectedExceptionScopes {
		fmt.Fprintf(&b, "  - %s is an EXPECTED exception (not over-privilege): %s\n", scope, why)
	}
	for _, scope := range sortedStringKeys(NeverRequestScopes) {
		fmt.Fprintf(&b, "  - do NOT grant %s: %s\n", scope, NeverRequestScopes[scope])
	}

	b.WriteString("\nCaveats this check cannot verify by itself:\n")
	b.WriteString("  - Admin consent: a permission added to the app registration is not active until a tenant\n")
	b.WriteString("    admin separately grants admin consent. This check reads the token's granted-permission\n")
	b.WriteString("    claim, so an un-consented permission is correctly reported as missing here too — but a\n")
	b.WriteString("    permission that IS consented can still 403 at runtime if a directory role is also required\n")
	b.WriteString("    (see below), which this check cannot detect.\n")
	b.WriteString("  - Directory role gating: some Graph surfaces (notably Identity Protection) additionally\n")
	b.WriteString("    require the calling service principal to hold a directory role, not just an API permission\n")
	b.WriteString("    scope. A service principal can pass this check and still 403 at runtime if it lacks the\n")
	b.WriteString("    required role — this check has no way to enumerate directory-role assignments.\n")

	b.WriteString("\nRepresentative required scopes by domain (non-exhaustive; the actual check compares\n")
	b.WriteString("against what enabled collectors declare, not this list):\n")
	for _, domain := range sortedDomainKeys(DocumentedRequiredScopes) {
		fmt.Fprintf(&b, "  %s:\n", domain)
		for _, scope := range DocumentedRequiredScopes[domain] {
			fmt.Fprintf(&b, "    - %s\n", scope)
		}
	}

	return b.String()
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedDomainKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
