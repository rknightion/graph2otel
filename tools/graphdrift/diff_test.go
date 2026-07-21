package main

import (
	"strings"
	"testing"
)

func baseline() *Snapshot {
	return &Snapshot{
		Source: "https://graph.microsoft.com/beta/$metadata",
		Operations: []OperationSnapshot{
			{Path: "/auditLogs/signIns", Type: "microsoft.graph.signIn", Resolution: "model"},
		},
		Types: map[string]*NamedType{
			"microsoft.graph.signIn": {
				Kind:                 "EntityType",
				BaseType:             "microsoft.graph.entity",
				Properties:           map[string]string{"appId": "Edm.String", "status": "microsoft.graph.signInStatus"},
				NavigationProperties: map[string]string{"detail": "microsoft.graph.signInDetail"},
			},
			"microsoft.graph.riskLevel": {Kind: "EnumType", Members: []string{"high", "low"}},
		},
	}
}

// findChange returns the first change with the given kind, or a zero Change.
func findChange(changes []Change, kind string) Change {
	for _, c := range changes {
		if c.Kind == kind {
			return c
		}
	}
	return Change{}
}

func TestDiffCleanSnapshot(t *testing.T) {
	if got := Diff(baseline(), baseline()); len(got) != 0 {
		t.Errorf("Diff of identical snapshots = %v, want none", got)
	}
}

func TestDiffBreakingChanges(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Snapshot)
		kind    string
		subject string
	}{
		{"property removed", func(s *Snapshot) {
			delete(s.Types["microsoft.graph.signIn"].Properties, "appId")
		}, "property_removed", "microsoft.graph.signIn"},
		{"property type changed", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].Properties["appId"] = "Edm.Guid"
		}, "property_type_changed", "microsoft.graph.signIn"},
		{"navigation property removed", func(s *Snapshot) {
			delete(s.Types["microsoft.graph.signIn"].NavigationProperties, "detail")
		}, "navigation_removed", "microsoft.graph.signIn"},
		{"navigation property retargeted", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].NavigationProperties["detail"] = "microsoft.graph.other"
		}, "navigation_type_changed", "microsoft.graph.signIn"},
		{"type removed", func(s *Snapshot) {
			delete(s.Types, "microsoft.graph.riskLevel")
		}, "type_removed", "microsoft.graph.riskLevel"},
		{"base type changed", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].BaseType = "microsoft.graph.thing"
		}, "base_type_changed", "microsoft.graph.signIn"},
		{"kind changed", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].Kind = "ComplexType"
		}, "kind_changed", "microsoft.graph.signIn"},
		{"enum member removed", func(s *Snapshot) {
			s.Types["microsoft.graph.riskLevel"].Members = []string{"low"}
		}, "enum_member_removed", "microsoft.graph.riskLevel"},
		{"operation retargeted", func(s *Snapshot) {
			s.Operations[0].Type = "microsoft.graph.somethingElse"
		}, "operation_type_changed", "/auditLogs/signIns"},
		{"operation stopped resolving", func(s *Snapshot) {
			s.Operations[0].Type = ""
			s.Operations[0].Error = "segment \"signIns\" is neither a navigation property nor a bound operation"
		}, "operation_unresolved", "/auditLogs/signIns"},
		{"operation dropped from the manifest", func(s *Snapshot) {
			s.Operations = nil
		}, "operation_removed", "/auditLogs/signIns"},
		{"operation added to the manifest", func(s *Snapshot) {
			s.Operations = append(s.Operations, OperationSnapshot{Path: "/new", Type: "microsoft.graph.thing", Resolution: "model"})
		}, "operation_added", "/new"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := baseline()
			tc.mutate(next)
			changes := Diff(baseline(), next)
			got := findChange(changes, tc.kind)
			if got.Kind == "" {
				t.Fatalf("no %s change in %v", tc.kind, changes)
			}
			if got.Severity != SeverityBreaking {
				t.Errorf("%s severity = %q, want breaking", tc.kind, got.Severity)
			}
			if got.Subject != tc.subject {
				t.Errorf("%s subject = %q, want %q", tc.kind, got.Subject, tc.subject)
			}
			if !HasActionable(changes) {
				t.Error("HasActionable = false on a breaking change")
			}
		})
	}
}

func TestDiffAdditionsAreInformationalOnly(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		kind   string
	}{
		{"property added", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].Properties["brandNew"] = "Edm.String"
		}, "property_added"},
		{"navigation property added", func(s *Snapshot) {
			s.Types["microsoft.graph.signIn"].NavigationProperties["extra"] = "microsoft.graph.thing"
		}, "navigation_added"},
		{"enum member added", func(s *Snapshot) {
			s.Types["microsoft.graph.riskLevel"].Members = []string{"high", "low", "unknownFutureValue"}
		}, "enum_member_added"},
		{"type added to the closure", func(s *Snapshot) {
			s.Types["microsoft.graph.brandNew"] = &NamedType{Kind: "ComplexType"}
		}, "type_added"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := baseline()
			tc.mutate(next)
			changes := Diff(baseline(), next)
			got := findChange(changes, tc.kind)
			if got.Kind == "" {
				t.Fatalf("no %s change in %v", tc.kind, changes)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("%s severity = %q, want info", tc.kind, got.Severity)
			}
			if HasActionable(changes) {
				t.Errorf("HasActionable = true on additions only — the canary would fire on routine upstream churn: %v", changes)
			}
		})
	}
}

func TestDiffIsSorted(t *testing.T) {
	next := baseline()
	next.Types["microsoft.graph.signIn"].Properties["zzz"] = "Edm.String"
	next.Types["microsoft.graph.signIn"].Properties["aaa"] = "Edm.String"
	delete(next.Types["microsoft.graph.signIn"].Properties, "appId")
	changes := Diff(baseline(), next)
	for i := 1; i < len(changes); i++ {
		prev, cur := changes[i-1], changes[i]
		if prev.Severity == cur.Severity && prev.Subject == cur.Subject && prev.Kind > cur.Kind {
			t.Fatalf("changes are not deterministically ordered: %v", changes)
		}
	}
	// Breaking sorts ahead of info so the report leads with what matters.
	if changes[0].Severity != SeverityBreaking {
		t.Errorf("first change = %+v, want the breaking one first", changes[0])
	}
}

func TestRenderMarkdownCleanRun(t *testing.T) {
	out := RenderMarkdown(nil)
	if !strings.Contains(out, "No drift") {
		t.Errorf("clean render = %q", out)
	}
}

func TestRenderMarkdownTable(t *testing.T) {
	out := RenderMarkdown([]Change{{Severity: SeverityBreaking, Subject: "microsoft.graph.signIn", Kind: "property_removed", Detail: "appId (Edm.String)"}})
	for _, want := range []string{"| Severity |", "breaking", "microsoft.graph.signIn", "property_removed", "appId"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}
