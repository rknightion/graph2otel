package collectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rknightion/graph2otel/internal/collector"
)

// ConflictsWith is implemented by a collector that emits the SAME records as
// another collector over a DIFFERENT transport, so enabling both ships every
// record twice into one stream (#144).
//
// It sits beside Experimental as the second optional interface the composition
// root asserts on, and it is optional for the same reason: only the collector's
// author knows the fact. The registry cannot derive it, and neither can a
// reader of the code — most obviously, it is NOT event-name equality.
// entra.signins.interactive and entra.signins.non_interactive both emit
// "entra.signin" and do NOT conflict: they are disjoint slices of one endpoint,
// and a check built on the event name would refuse to start on the single most
// common sign-in configuration there is. "Same records, different transport" is
// the rule, and it is a claim about the data, not about the strings.
//
// The declaration goes on the SECOND transport (the blob twin, the Management
// Activity API collector) rather than on the original, and it travels with that
// collector rather than living in a central list. A central list is precisely
// what went blind in #139/#100 — it was edited by whoever remembered, and the
// gate over it passed because it could not see the fourth registration path. A
// method on the type cannot be forgotten by a later edit to a different file.
//
// Declared today (measured live on camden, 2026-07-16 — 18/18 and 1375/1375 id
// overlap between the polled and blob copies):
//
//   - entra.signins.non_interactive.blob  -> entra.signins.non_interactive
//   - entra.signins.service_principal.blob -> entra.signins.service_principal
//   - m365.activity                        -> m365.unified_audit
//
// entra.signins.microsoft_service_principal declares NOTHING and must not: its
// records are Microsoft's own first-party service-to-service auth, it has no
// Graph endpoint at all, and live sampling found ZERO id overlap with the
// neighboring polled stream. It is a disjoint dataset that happens to sit in
// the same spec table — the exact shape of mistake a copy-pasted declaration
// would make.
type ConflictsWith interface {
	// ConflictsWith names the stable collector names this collector must not
	// run alongside. Names, not instances: the peer may be registered through a
	// completely different construction path, and a collector must be able to
	// declare a conflict without importing its twin.
	ConflictsWith() []string
}

// CheckConflicts returns an error when a collector declaring a conflict is
// registered alongside a peer it named. It is the enforcement half of
// ConflictsWith, and it is fail-fast by design: the composition root refuses to
// start the process rather than warning and carrying on.
//
// Warn-and-continue would be the wrong shape here. The entire failure mode is
// that the conflicting state LOOKS healthy — every collector reports success,
// every tick is green, and the only symptom is that the backend holds two
// byte-identical copies of every record (#141: there is no provenance
// attribute, so an operator cannot even tell the copies apart, let alone drop
// one lane at query time). A warning in that state is a line in a log nobody
// reads about a system that appears to be working. #117 set the precedent: an
// unwritable checkpoint dir fails the process rather than degrading silently,
// for exactly the same reason.
//
// cs is the tenant's fully registered set — every collector the scheduler will
// actually run. Passing the assembled registry rather than re-walking the
// factory slices is deliberate (#139/#100): collectors.All(), WindowAll(),
// BlobAll() and O365All() all funnel into one collector.Registry, so reading
// that registry sees every construction path by construction, and a fifth path
// cannot make this check blind the way it made collectordoc.Rows blind. The
// call site is what has to be right — after ALL registration, never between two
// paths — and cmd/graph2otel/tenants.go says so at the call.
func CheckConflicts(cs []collector.Collector) error {
	registered := make(map[string]bool, len(cs))
	for _, c := range cs {
		registered[c.Name()] = true
	}

	var problems []string
	reported := map[string]bool{}
	for _, c := range cs {
		d, ok := c.(ConflictsWith)
		if !ok {
			continue
		}
		for _, peer := range d.ConflictsWith() {
			// A self-declaration is always "registered" and would refuse every
			// boot; a peer that is absent is the supported single-transport
			// deployment, which is most of them.
			if peer == c.Name() || !registered[peer] {
				continue
			}
			// Key on the unordered pair so a mutual declaration is one problem,
			// not two phrasings of it.
			key := pairKey(c.Name(), peer)
			if reported[key] {
				continue
			}
			reported[key] = true
			problems = append(problems, fmt.Sprintf(
				"%q and %q are both enabled: they are the same records over different transports, "+
					"so every record ships twice into one stream. Disable exactly one — "+
					"set `collectors.%q.enabled: false` (every tenant) or "+
					"`tenants[].collectors.%q.enabled: false` (this tenant only)",
				c.Name(), peer, c.Name(), c.Name()))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	// Sorted so the message is identical across runs: map iteration order over
	// the registry would otherwise reshuffle a multi-conflict error every boot.
	sort.Strings(problems)
	return fmt.Errorf("conflicting collectors registered:\n  %s", strings.Join(problems, "\n  "))
}

// pairKey identifies an unordered pair of collector names.
func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}
