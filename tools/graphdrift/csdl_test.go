package main

import (
	"strings"
	"testing"
)

// testCSDL is a miniature of the real beta $metadata: two schemas, one of them
// aliased, a container with a singleton and an entity set, inheritance, a
// complex type, an enum, a derived type used as a cast segment, and a bound
// function. Every shape the resolver has to handle on the live document is
// represented here, so the resolver tests need no network.
const testCSDL = `<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
<edmx:DataServices>
<Schema Namespace="microsoft.graph" Alias="graph" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <EnumType Name="riskLevel"><Member Name="low" Value="0" /><Member Name="high" Value="1" /></EnumType>
  <ComplexType Name="signInStatus"><Property Name="errorCode" Type="Edm.Int32" /></ComplexType>
  <EntityType Name="entity" Abstract="true"><Key><PropertyRef Name="id" /></Key><Property Name="id" Type="Edm.String" /></EntityType>
  <EntityType Name="signIn" BaseType="graph.entity">
    <Property Name="createdDateTime" Type="Edm.DateTimeOffset" />
    <Property Name="status" Type="graph.signInStatus" />
    <Property Name="riskLevelAggregated" Type="graph.riskLevel" />
  </EntityType>
  <EntityType Name="auditLogRoot">
    <NavigationProperty Name="signIns" Type="Collection(graph.signIn)" />
  </EntityType>
  <EntityType Name="script" BaseType="graph.entity">
    <NavigationProperty Name="runSummary" Type="graph.runSummary" />
  </EntityType>
  <EntityType Name="specialScript" BaseType="graph.script">
    <NavigationProperty Name="extras" Type="Collection(graph.entity)" />
  </EntityType>
  <EntityType Name="runSummary" BaseType="graph.entity"><Property Name="successCount" Type="Edm.Int32" /></EntityType>
  <ComplexType Name="summary"><Property Name="total" Type="Edm.Int32" /></ComplexType>
  <EntityType Name="deviceManagement">
    <NavigationProperty Name="scripts" Type="Collection(graph.script)" />
  </EntityType>
  <Function Name="getSummary" IsBound="true">
    <Parameter Name="bindingParameter" Type="Collection(graph.script)" />
    <ReturnType Type="graph.summary" />
  </Function>
  <EntityContainer Name="GraphService">
    <Singleton Name="auditLogs" Type="graph.auditLogRoot" />
    <Singleton Name="deviceManagement" Type="graph.deviceManagement" />
    <EntitySet Name="scripts" EntityType="microsoft.graph.script" />
  </EntityContainer>
</Schema>
<Schema Namespace="microsoft.graph.security" Alias="self" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <EntityType Name="auditLogQuery" BaseType="graph.entity"><Property Name="status" Type="Edm.String" /></EntityType>
</Schema>
</edmx:DataServices>
</edmx:Edmx>`

func mustParse(t *testing.T) *Model {
	t.Helper()
	m, err := ParseCSDL(strings.NewReader(testCSDL))
	if err != nil {
		t.Fatalf("ParseCSDL: %v", err)
	}
	return m
}

func TestParseCSDLIndexesTypesByFullyQualifiedName(t *testing.T) {
	m := mustParse(t)

	nt, ok := m.Lookup("microsoft.graph.signIn")
	if !ok {
		t.Fatalf("microsoft.graph.signIn not indexed; have %d types", len(m.Types))
	}
	if nt.Kind != "EntityType" {
		t.Errorf("Kind = %q, want EntityType", nt.Kind)
	}
	if nt.BaseType != "microsoft.graph.entity" {
		t.Errorf("BaseType = %q, want microsoft.graph.entity (alias must be expanded)", nt.BaseType)
	}
	if got := nt.Properties["status"]; got != "microsoft.graph.signInStatus" {
		t.Errorf("Properties[status] = %q, want microsoft.graph.signInStatus", got)
	}
	if got := nt.Properties["createdDateTime"]; got != "Edm.DateTimeOffset" {
		t.Errorf("Properties[createdDateTime] = %q, want Edm.DateTimeOffset", got)
	}
	if _, ok := m.Lookup("microsoft.graph.security.auditLogQuery"); !ok {
		t.Error("microsoft.graph.security.auditLogQuery not indexed — second schema dropped")
	}
}

func TestParseCSDLKeepsCollectionWrapperOnNavigationProperties(t *testing.T) {
	m := mustParse(t)
	nt, _ := m.Lookup("microsoft.graph.auditLogRoot")
	if got := nt.NavigationProperties["signIns"]; got != "Collection(microsoft.graph.signIn)" {
		t.Errorf("NavigationProperties[signIns] = %q, want Collection(microsoft.graph.signIn)", got)
	}
}

func TestParseCSDLRecordsEnumMembers(t *testing.T) {
	m := mustParse(t)
	nt, ok := m.Lookup("microsoft.graph.riskLevel")
	if !ok {
		t.Fatal("enum microsoft.graph.riskLevel not indexed")
	}
	if nt.Kind != "EnumType" {
		t.Errorf("Kind = %q, want EnumType", nt.Kind)
	}
	want := []string{"high", "low"} // sorted
	if len(nt.Members) != len(want) || nt.Members[0] != want[0] || nt.Members[1] != want[1] {
		t.Errorf("Members = %v, want %v (sorted)", nt.Members, want)
	}
}

func TestResolvePath(t *testing.T) {
	m := mustParse(t)

	tests := []struct {
		name string
		path string
		want string
	}{
		{"singleton navigation", "/auditLogs/signIns", "microsoft.graph.signIn"},
		{"entity set", "/scripts", "microsoft.graph.script"},
		{"key segment is skipped", "/deviceManagement/scripts/{id}/runSummary", "microsoft.graph.runSummary"},
		{"derived-type cast segment", "/scripts/{id}/microsoft.graph.specialScript/extras", "microsoft.graph.entity"},
		{"aliased cast segment", "/scripts/{id}/graph.specialScript/extras", "microsoft.graph.entity"},
		{"bound function", "/deviceManagement/scripts/getSummary", "microsoft.graph.summary"},
		{"inherited navigation property", "/scripts/{id}/runSummary", "microsoft.graph.runSummary"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.ResolvePath(tc.path)
			if err != nil {
				t.Fatalf("ResolvePath(%q): %v", tc.path, err)
			}
			if got != tc.want {
				t.Errorf("ResolvePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestResolvePathErrors(t *testing.T) {
	m := mustParse(t)

	tests := []struct {
		name string
		path string
	}{
		{"unknown container root", "/nope/signIns"},
		{"unknown navigation property", "/auditLogs/nope"},
		{"unknown cast type", "/scripts/{id}/microsoft.graph.nope/extras"},
		{"empty path", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := m.ResolvePath(tc.path); err == nil {
				t.Errorf("ResolvePath(%q) = %q, want error", tc.path, got)
			}
		})
	}
}

func TestResolvePathIgnoresQueryString(t *testing.T) {
	m := mustParse(t)
	got, err := m.ResolvePath("/deviceManagement/scripts?$select=id,displayName")
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	if got != "microsoft.graph.script" {
		t.Errorf("got %q, want microsoft.graph.script", got)
	}
}
