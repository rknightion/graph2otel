// Package preflight validates, ahead of time, that a graph2otel process holds
// the admin-consented Microsoft Graph application permissions its enabled
// collectors need — so a missing permission is reported once, up front, by
// `graph2otel check`, instead of surfacing later as a runtime 403 that an
// operator has to reverse-engineer back to a missing app-registration scope.
//
// The package is deliberately decoupled from internal/collector: a collector
// declares what it needs by optionally implementing PermissionRequirer, and
// this package's comparison core (Check) works over a plain []CollectorReq
// built from anything — a real collector registry, or a fixture in a test.
package preflight

import "sort"

// PermissionRequirer is optionally implemented by a collector to declare the
// Microsoft Graph application permissions it needs. It is checked via a type
// assertion (see BuildRequirements) so this package never imports
// internal/collector's concrete collector types.
type PermissionRequirer interface {
	// RequiredPermissions returns the Graph application permission scopes
	// (e.g. "AuditLog.Read.All") this collector needs to run.
	RequiredPermissions() []string
}

// CollectorReq is one collector's declared permission requirement, the input
// Check compares against the granted-permission set.
type CollectorReq struct {
	// Name identifies the collector in the report (e.g. "sign_ins").
	Name string
	// Permissions is the set of Graph application permission scopes this
	// collector needs. An empty/nil slice means the collector declared no
	// requirement (or didn't implement PermissionRequirer).
	Permissions []string
}

// CollectorResult is one collector's outcome from Check.
type CollectorResult struct {
	Name string
	// Required is the collector's declared permission set, echoed for the
	// report (so OK entries still show what was checked).
	Required []string
	// Missing is the subset of Required not present in the granted set, in
	// the order Required listed them.
	Missing []string
	// OK is true when Missing is empty.
	OK bool
}

// Report is the outcome of comparing a granted-permission set against a set
// of enabled collectors' declared requirements.
type Report struct {
	// Collectors holds one CollectorResult per input CollectorReq, in input order.
	Collectors []CollectorResult
	// MissingAggregate is the de-duplicated, sorted union of every missing
	// permission across all collectors — the "grant + admin-consent these"
	// list. A permission needed by five collectors appears here once.
	MissingAggregate []string
	// ExpectedExceptions is the de-duplicated, sorted list of required
	// permissions that are known least-privilege exceptions (see
	// ExpectedExceptionScopes) — e.g. a ReadWrite scope needed only to
	// create an export job. These are surfaced as an expected note rather
	// than flagged as unexplained over-privilege, regardless of whether the
	// scope is currently granted or missing.
	ExpectedExceptions []string
	// OK is true when MissingAggregate is empty — every enabled collector's
	// requirements are satisfied.
	OK bool
}

// Check compares the granted application-permission set against reqs (one
// entry per enabled collector) and produces a Report. It is pure: no I/O, no
// Graph calls — callers (the real adapter, or a test fixture) supply granted
// however they obtained it.
func Check(granted []string, reqs []CollectorReq) Report {
	grantedSet := make(map[string]bool, len(granted))
	for _, p := range granted {
		grantedSet[p] = true
	}

	missingSet := make(map[string]bool)
	exceptionSet := make(map[string]bool)
	results := make([]CollectorResult, 0, len(reqs))

	for _, req := range reqs {
		var missing []string
		for _, perm := range req.Permissions {
			if _, known := ExpectedExceptionScopes[perm]; known {
				exceptionSet[perm] = true
			}
			if !grantedSet[perm] {
				missing = append(missing, perm)
				missingSet[perm] = true
			}
		}
		results = append(results, CollectorResult{
			Name:     req.Name,
			Required: req.Permissions,
			Missing:  missing,
			OK:       len(missing) == 0,
		})
	}

	return Report{
		Collectors:         results,
		MissingAggregate:   sortedKeys(missingSet),
		ExpectedExceptions: sortedKeys(exceptionSet),
		OK:                 len(missingSet) == 0,
	}
}

// BuildRequirements turns a map of enabled-collector-name -> collector
// instance into the []CollectorReq Check needs, type-asserting each value
// against PermissionRequirer. A collector that doesn't implement it
// contributes a requirement with no declared permissions rather than being
// dropped, so the report still lists it as checked (trivially OK).
//
// This is the composition root's wiring point: once concrete collectors land
// (#11's M2-M5 dependency), pass the registry's enabled collectors here
// instead of a nil/empty Requirements func.
func BuildRequirements(collectors map[string]any) []CollectorReq {
	names := make([]string, 0, len(collectors))
	for name := range collectors {
		names = append(names, name)
	}
	sort.Strings(names)

	reqs := make([]CollectorReq, 0, len(collectors))
	for _, name := range names {
		var perms []string
		if pr, ok := collectors[name].(PermissionRequirer); ok {
			perms = pr.RequiredPermissions()
		}
		reqs = append(reqs, CollectorReq{Name: name, Permissions: perms})
	}
	return reqs
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
