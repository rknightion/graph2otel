package main

import (
	"fmt"
	"sort"
	"strings"
)

// Severity ranks a change by whether it can break a collector.
type Severity string

const (
	// SeverityBreaking is anything that can make a collector decode less than
	// it did, or reach a different resource: removals, renames (which read as a
	// removal plus an addition), retargeted types, and a path that stops
	// resolving.
	SeverityBreaking Severity = "breaking"
	// SeverityInfo is upstream growth — new properties, new navigation
	// properties, new enum members, new closure types. Microsoft adds these
	// continuously, so they are reported but never fire the canary; a canary
	// that cries wolf daily gets ignored.
	SeverityInfo Severity = "info"
)

// Change is one difference between two snapshots.
type Change struct {
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`
	Kind     string   `json:"kind"`
	Detail   string   `json:"detail"`
}

// Diff compares a committed snapshot against a freshly built one.
func Diff(old, next *Snapshot) []Change {
	var out []Change
	out = append(out, diffOperations(old, next)...)
	out = append(out, diffTypes(old, next)...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity != b.Severity {
			return a.Severity == SeverityBreaking
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	return out
}

// HasActionable reports whether any change warrants firing the canary.
func HasActionable(changes []Change) bool {
	for _, c := range changes {
		if c.Severity == SeverityBreaking {
			return true
		}
	}
	return false
}

func diffOperations(old, next *Snapshot) []Change {
	var out []Change
	oldOps := indexOps(old)
	newOps := indexOps(next)

	for path, o := range oldOps {
		n, ok := newOps[path]
		if !ok {
			// The snapshot no longer covers a path it used to. In the daily run
			// both files come from the same commit, so this means the snapshot
			// is stale against the manifest — regenerate it.
			out = append(out, Change{SeverityBreaking, path, "operation_removed", "no longer in the manifest slice; regenerate the snapshot"})
			continue
		}
		switch {
		case n.Type == "" && o.Type != "":
			out = append(out, Change{SeverityBreaking, path, "operation_unresolved", n.Error})
		case n.Type != o.Type:
			out = append(out, Change{SeverityBreaking, path, "operation_type_changed", fmt.Sprintf("%s -> %s", o.Type, n.Type)})
		case n.Resolution != o.Resolution:
			out = append(out, Change{SeverityInfo, path, "operation_resolution_changed", fmt.Sprintf("%s -> %s", o.Resolution, n.Resolution)})
		}
	}
	for path := range newOps {
		if _, ok := oldOps[path]; !ok {
			out = append(out, Change{SeverityBreaking, path, "operation_added", "in the manifest but not the snapshot; regenerate the snapshot"})
		}
	}
	return out
}

func indexOps(s *Snapshot) map[string]OperationSnapshot {
	out := make(map[string]OperationSnapshot, len(s.Operations))
	for _, op := range s.Operations {
		out[op.Path] = op
	}
	return out
}

func diffTypes(old, next *Snapshot) []Change {
	var out []Change
	for name, o := range old.Types {
		n, ok := next.Types[name]
		if !ok {
			out = append(out, Change{SeverityBreaking, name, "type_removed", "gone from the beta EDM"})
			continue
		}
		if o.Kind != n.Kind {
			out = append(out, Change{SeverityBreaking, name, "kind_changed", fmt.Sprintf("%s -> %s", o.Kind, n.Kind)})
		}
		if o.BaseType != n.BaseType {
			out = append(out, Change{SeverityBreaking, name, "base_type_changed", fmt.Sprintf("%q -> %q", o.BaseType, n.BaseType)})
		}
		out = append(out, diffMembers(name, "property", o.Properties, n.Properties)...)
		out = append(out, diffMembers(name, "navigation", o.NavigationProperties, n.NavigationProperties)...)
		out = append(out, diffEnumMembers(name, o.Members, n.Members)...)
	}
	for name := range next.Types {
		if _, ok := old.Types[name]; !ok {
			out = append(out, Change{SeverityInfo, name, "type_added", "new in the consumed closure"})
		}
	}
	return out
}

// diffMembers compares one type's property or navigation-property map. The
// change kinds are "<what>_removed" / "_added" / "_type_changed".
func diffMembers(subject, what string, old, next map[string]string) []Change {
	var out []Change
	removedKind, addedKind, changedKind := what+"_removed", what+"_added", what+"_type_changed"
	for name, o := range old {
		n, ok := next[name]
		if !ok {
			out = append(out, Change{SeverityBreaking, subject, removedKind, fmt.Sprintf("%s (%s)", name, o)})
			continue
		}
		if n != o {
			out = append(out, Change{SeverityBreaking, subject, changedKind, fmt.Sprintf("%s: %s -> %s", name, o, n)})
		}
	}
	for name, n := range next {
		if _, ok := old[name]; !ok {
			out = append(out, Change{SeverityInfo, subject, addedKind, fmt.Sprintf("%s (%s)", name, n)})
		}
	}
	return out
}

func diffEnumMembers(subject string, old, next []string) []Change {
	var out []Change
	inNext := make(map[string]bool, len(next))
	for _, m := range next {
		inNext[m] = true
	}
	inOld := make(map[string]bool, len(old))
	for _, m := range old {
		inOld[m] = true
	}
	for _, m := range old {
		if !inNext[m] {
			out = append(out, Change{SeverityBreaking, subject, "enum_member_removed", m})
		}
	}
	for _, m := range next {
		if !inOld[m] {
			out = append(out, Change{SeverityInfo, subject, "enum_member_added", m})
		}
	}
	return out
}

// RenderMarkdown renders changes as a Markdown table, for the tracking issue.
func RenderMarkdown(changes []Change) string {
	if len(changes) == 0 {
		return "No drift detected on the consumed Microsoft Graph beta surface.\n"
	}
	var b strings.Builder
	b.WriteString("| Severity | Subject | Kind | Detail |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", c.Severity, c.Subject, c.Kind, c.Detail)
	}
	if !HasActionable(changes) {
		b.WriteString("\nAll changes are additive (`info`) — nothing graph2otel consumes has been removed or retyped.\n")
	}
	return b.String()
}
