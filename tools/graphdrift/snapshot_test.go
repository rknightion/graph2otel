package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const testManifestJSON = `{
  "metadata_url": "https://graph.microsoft.com/beta/$metadata",
  "packages": [
    {
      "package": "internal/collectors/entra/signins",
      "collectors": ["entra.signins"],
      "operations": [
        {"path": "/auditLogs/signIns"}
      ]
    },
    {
      "package": "internal/collectors/intune/scripts",
      "collectors": ["intune.scripts"],
      "operations": [
        {"path": "/deviceManagement/scripts/{id}/runSummary"},
        {"path": "/deviceManagement/anomalyOverview", "type": "microsoft.graph.summary", "unmodeled": true, "note": "works on the wire, absent from the EDM"}
      ]
    }
  ]
}`

func mustManifest(t *testing.T) *Manifest {
	t.Helper()
	man, err := ParseManifest([]byte(testManifestJSON))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	return man
}

func TestParseManifestRejectsUnknownFields(t *testing.T) {
	_, err := ParseManifest([]byte(`{"metadata_url":"x","packages":[],"surprise":1}`))
	if err == nil {
		t.Fatal("ParseManifest accepted an unknown field; the manifest schema must be strict")
	}
}

func TestParseManifestValidation(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"no packages", `{"metadata_url":"u","packages":[]}`},
		{"package with no operations", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[]}]}`},
		{"duplicate package", `{"metadata_url":"u","packages":[
			{"package":"a","collectors":["c"],"operations":[{"path":"/x"}]},
			{"package":"a","collectors":["c"],"operations":[{"path":"/y"}]}]}`},
		{"unmodeled without a type", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"/x","unmodeled":true,"note":"n"}]}]}`},
		{"unmodeled without a note", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"/x","unmodeled":true,"type":"t"}]}]}`},
		{"resolve_as on an unmodeled op", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"/x","unmodeled":true,"type":"t","note":"n","resolve_as":"/y"}]}]}`},
		{"type declared on a modeled op", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"/x","type":"t"}]}]}`},
		{"path not rooted", `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"x"}]}]}`},
		{"no collectors", `{"metadata_url":"u","packages":[{"package":"a","collectors":[],"operations":[{"path":"/x"}]}]}`},
		{"conflicting duplicate path", `{"metadata_url":"u","packages":[
			{"package":"a","collectors":["c"],"operations":[{"path":"/x"}]},
			{"package":"b","collectors":["c"],"operations":[{"path":"/x","unmodeled":true,"type":"t","note":"n"}]}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(tc.doc)); err == nil {
				t.Error("ParseManifest accepted an invalid manifest")
			}
		})
	}
}

func TestParseManifestAcceptsAnIdenticalDuplicatePathInTwoPackages(t *testing.T) {
	doc := `{"metadata_url":"u","packages":[
		{"package":"a","collectors":["c"],"operations":[{"path":"/x"}]},
		{"package":"b","collectors":["d"],"operations":[{"path":"/x"}]}]}`
	man, err := ParseManifest([]byte(doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got := len(man.Operations()); got != 1 {
		t.Errorf("Operations() = %d, want 1 (deduped)", got)
	}
}

func TestBuildSnapshotResolvesOperations(t *testing.T) {
	m := mustParse(t)
	snap := BuildSnapshot(mustManifest(t), m)

	if snap.Source != "https://graph.microsoft.com/beta/$metadata" {
		t.Errorf("Source = %q", snap.Source)
	}
	byPath := map[string]OperationSnapshot{}
	for _, op := range snap.Operations {
		byPath[op.Path] = op
	}
	if got := byPath["/auditLogs/signIns"]; got.Type != "microsoft.graph.signIn" || got.Resolution != "model" {
		t.Errorf("/auditLogs/signIns = %+v, want microsoft.graph.signIn via model", got)
	}
	if got := byPath["/deviceManagement/scripts/{id}/runSummary"]; got.Type != "microsoft.graph.runSummary" {
		t.Errorf("runSummary op = %+v", got)
	}
	if got := byPath["/deviceManagement/anomalyOverview"]; got.Type != "microsoft.graph.summary" || got.Resolution != "unmodeled" {
		t.Errorf("unmodeled op = %+v, want microsoft.graph.summary via unmodeled", got)
	}
}

func TestBuildSnapshotRecordsResolutionFailureInsteadOfDropping(t *testing.T) {
	doc := `{"metadata_url":"u","packages":[{"package":"a","collectors":["c"],"operations":[{"path":"/auditLogs/gone"}]}]}`
	man, err := ParseManifest([]byte(doc))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	snap := BuildSnapshot(man, mustParse(t))
	if len(snap.Operations) != 1 {
		t.Fatalf("Operations = %d, want 1 — an unresolvable path must stay visible", len(snap.Operations))
	}
	if snap.Operations[0].Type != "" || snap.Operations[0].Error == "" {
		t.Errorf("op = %+v, want empty type and a recorded error", snap.Operations[0])
	}
}

func TestBuildSnapshotSlicesTypeClosure(t *testing.T) {
	snap := BuildSnapshot(mustManifest(t), mustParse(t))

	// The resolved entity, its base chain, and the complex/enum types its own
	// properties reference.
	for _, want := range []string{
		"microsoft.graph.signIn",
		"microsoft.graph.entity",
		"microsoft.graph.signInStatus",
		"microsoft.graph.riskLevel",
		"microsoft.graph.runSummary",
		"microsoft.graph.summary",
	} {
		if _, ok := snap.Types[want]; !ok {
			t.Errorf("type %s missing from the slice", want)
		}
	}
	// Navigation targets are separate operations, not closure members: nothing
	// pulls auditLogRoot in, and the slice must stay small.
	if _, ok := snap.Types["microsoft.graph.auditLogRoot"]; ok {
		t.Error("auditLogRoot is in the slice; the closure must not follow navigation properties")
	}
	if _, ok := snap.Types["microsoft.graph.security.auditLogQuery"]; ok {
		t.Error("an unconsumed type leaked into the slice")
	}
}

func TestSnapshotJSONIsDeterministic(t *testing.T) {
	a, err := MarshalSnapshot(BuildSnapshot(mustManifest(t), mustParse(t)))
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	b, err := MarshalSnapshot(BuildSnapshot(mustManifest(t), mustParse(t)))
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	if string(a) != string(b) {
		t.Error("MarshalSnapshot is not deterministic")
	}
	if !strings.HasSuffix(string(a), "\n") {
		t.Error("snapshot must end with a newline so it is a well-formed text file")
	}
	var round Snapshot
	if err := json.Unmarshal(a, &round); err != nil {
		t.Fatalf("snapshot does not round-trip: %v", err)
	}
}
