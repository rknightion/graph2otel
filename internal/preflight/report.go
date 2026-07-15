package preflight

import (
	"fmt"
	"io"
	"strings"
)

// WriteReport prints a human-readable rendering of one tenant's Report to w:
// per-collector OK/MISSING lines, the expected-exception note (if any), and
// the de-duplicated "grant + admin-consent these" summary.
func WriteReport(w io.Writer, tenantID string, r Report) {
	fmt.Fprintf(w, "tenant %s:\n", tenantID)

	if len(r.Collectors) == 0 {
		fmt.Fprintln(w, "  (no collector permission requirements to check)")
	}
	for _, cr := range r.Collectors {
		if cr.OK {
			fmt.Fprintf(w, "  [OK]      %s (%d permission(s) required, all granted)\n", cr.Name, len(cr.Required))
			continue
		}
		fmt.Fprintf(w, "  [MISSING] %s: missing %s\n", cr.Name, strings.Join(cr.Missing, ", "))
	}

	if len(r.ExpectedExceptions) > 0 {
		fmt.Fprintf(w, "  expected exception(s) (not over-privilege, see -h): %s\n",
			strings.Join(r.ExpectedExceptions, ", "))
	}

	if r.OK {
		fmt.Fprintln(w, "  all enabled collectors satisfied.")
		return
	}
	fmt.Fprintf(w, "  grant and admin-consent these permissions: %s\n", strings.Join(r.MissingAggregate, ", "))
}
