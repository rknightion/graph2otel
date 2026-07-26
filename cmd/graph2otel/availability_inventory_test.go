package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestAvailabilityCandidatesCoverCompleteSevenPathCensus(t *testing.T) {
	first := availabilityCandidates()
	second := availabilityCandidates()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("availabilityCandidates() is not deterministic across calls")
	}
	if !slices.IsSortedFunc(first, compareAvailabilityCandidates) {
		t.Fatal("availabilityCandidates() is not sorted by logical name and family")
	}
	if len(first) != 151 {
		t.Fatalf("availabilityCandidates() count = %d, want 151 registration-path candidates", len(first))
	}

	wantFamilies := map[availabilityFamily]bool{
		availabilityFamilySnapshot: false,
		availabilityFamilyWindow:   false,
		availabilityFamilyBlob:     false,
		availabilityFamilyO365:     false,
		availabilityFamilyMDCA:     false,
		availabilityFamilyEXO:      false,
		availabilityFamilyHunt:     false,
	}
	byName := make(map[string][]availabilityCandidate, len(first))
	for _, candidate := range first {
		if candidate.Name == "" {
			t.Fatal("availability candidate has an empty name")
		}
		if candidate.Transport == "" {
			t.Fatalf("availability candidate %q has an empty transport", candidate.Name)
		}
		if !knownAvailabilityTransport(candidate.Transport) {
			t.Fatalf("availability candidate %q has unbounded transport %q", candidate.Name, candidate.Transport)
		}
		if _, ok := wantFamilies[candidate.Family]; !ok {
			t.Fatalf("availability candidate %q has unbounded family %q", candidate.Name, candidate.Family)
		}
		wantFamilies[candidate.Family] = true
		for _, requirement := range candidate.PartialRequirements {
			if !knownAvailabilityLimitation(requirement.Limitation) {
				t.Fatalf("availability candidate %q has unbounded limitation %q", candidate.Name, requirement.Limitation)
			}
			if !availability.ValidMissingCapability(requirement.MissingCapability) {
				t.Fatalf("availability candidate %q has unbounded partial capability %q", candidate.Name, requirement.MissingCapability)
			}
		}
		for _, peer := range candidate.ConflictsWith {
			if peer == "" || peer == candidate.Name {
				t.Fatalf("availability candidate %q has invalid conflict peer %q", candidate.Name, peer)
			}
		}
		byName[candidate.Name] = append(byName[candidate.Name], candidate)
	}
	for family, seen := range wantFamilies {
		if !seen {
			t.Errorf("seven-path census did not visit family %q", family)
		}
	}
	if len(byName) != 148 {
		t.Fatalf("availability logical-name count = %d, want 148", len(byName))
	}
	for _, candidate := range first {
		for _, peer := range candidate.ConflictsWith {
			if _, ok := byName[peer]; !ok {
				t.Errorf("availability candidate %q declares unknown conflict peer %q", candidate.Name, peer)
			}
		}
	}

	wantDuplicates := map[string]bool{
		"entra.directory_audits": false,
		"entra.provisioning":     false,
		"entra.risk_detections":  false,
	}
	for name, candidates := range byName {
		if len(candidates) == 1 {
			continue
		}
		if len(candidates) != 2 {
			t.Errorf("logical collector %q has %d candidates, want one or one Graph/blob pair", name, len(candidates))
			continue
		}
		if _, ok := wantDuplicates[name]; !ok {
			t.Errorf("unexplained duplicate logical collector %q", name)
			continue
		}
		wantDuplicates[name] = true
		transports := map[telemetry.Transport]bool{}
		for _, candidate := range candidates {
			transports[candidate.Transport] = true
		}
		if len(transports) != 2 || !transports[telemetry.TransportGraph] || !transports[telemetry.TransportBlob] {
			t.Errorf("duplicate %q transports = %v, want graph and blob", name, transports)
		}
	}
	for name, seen := range wantDuplicates {
		if !seen {
			t.Errorf("Graph/blob duplicate %q is missing", name)
		}
	}

	candidateByName := availabilityCandidatesByName(first)
	if got := candidateByName["m365.activity"][0].ConflictsWith; !reflect.DeepEqual(got, []string{"m365.unified_audit"}) {
		t.Errorf("m365.activity conflicts = %v, want [m365.unified_audit]", got)
	}
	if got := candidateByName["m365.unified_audit"][0].ConflictsWith; len(got) != 0 {
		t.Errorf("m365.unified_audit conflicts = %v, want none: declarations are directional", got)
	}
	if got := candidateByName["entra.signins.managed_identity.blob"][0].ConflictsWith; !reflect.DeepEqual(got, []string{"entra.signins.managed_identity"}) {
		t.Errorf("managed-identity blob conflicts = %v, want its polled peer", got)
	}
}

func TestAvailabilityCandidatesMatchCollectorReferenceCensus(t *testing.T) {
	want := make(map[string]bool)
	for _, name := range registeredNames(t) {
		want[name] = true
	}
	got := make(map[string]bool)
	for _, candidate := range availabilityCandidates() {
		got[candidate.Name] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("availability logical census does not match the independent collector-reference census:\n got: %v\nwant: %v", got, want)
	}
}

func TestResolveAvailabilityInventoryIsCompleteBoundedAndDeterministic(t *testing.T) {
	cfg := availabilityTestConfig()
	first := resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true)
	second := resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("resolveAvailabilityInventory() is not deterministic across calls")
	}
	if len(first) != 148 {
		t.Fatalf("inventory count = %d, want 148 logical collectors", len(first))
	}
	if !slices.IsSortedFunc(first, func(a, b availability.Static) int {
		return compareStrings(a.Collector, b.Collector)
	}) {
		t.Fatal("inventory is not sorted by logical collector name")
	}

	seen := make(map[string]bool, len(first))
	for _, static := range first {
		if static.Collector == "" {
			t.Fatal("availability row has an empty collector")
		}
		if seen[static.Collector] {
			t.Errorf("availability row %q appears more than once", static.Collector)
		}
		seen[static.Collector] = true
		if static.Transport == "" {
			t.Errorf("availability row %q has an empty transport", static.Collector)
		}
		if !knownAvailabilityTransport(static.Transport) {
			t.Errorf("availability row %q has unbounded transport %q", static.Collector, static.Transport)
		}
		if !availability.ValidPair(static.State, static.Reason) {
			t.Errorf("availability row %q has unbounded state/reason %q/%q", static.Collector, static.State, static.Reason)
		}
		for _, limitation := range static.Limitations {
			if !knownAvailabilityLimitation(limitation) {
				t.Errorf("availability row %q has unbounded limitation %q", static.Collector, limitation)
			}
		}
		for _, capability := range static.MissingCapabilities {
			if !availability.ValidMissingCapability(capability) {
				t.Errorf("availability row %q has unbounded missing capability %q", static.Collector, capability)
			}
		}
	}

	byName := availabilityStaticsByName(t, first)
	assertAvailabilityStatic(t, byName, "entra.directory_audits", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, byName, "entra.provisioning", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, byName, "entra.risk_detections", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, byName, "m365.activity", telemetry.TransportO365Activity, availability.StateStarting, availability.ReasonNoCompletedRun)

	for _, name := range []string{
		"entra.graph_activity",
		"graph2otel.blob_categories",
		"mdca.discovery_parse",
		"m365.exchange_audit_config",
		"defender.oauth_app",
	} {
		got := byName[name]
		if got.State != availability.StateDisabled || got.Reason != availability.ReasonTransportNotConfigured {
			t.Errorf("%s state/reason = %q/%q, want disabled/transport_not_configured", name, got.State, got.Reason)
		}
	}
}

func TestResolveAvailabilityInventoryAppliesOptInAndExplicitConfigGates(t *testing.T) {
	trueValue := true
	falseValue := false
	cfg := &config.Config{Tenants: []config.TenantConfig{{
		TenantID:       "tenant-a",
		ExchangeOnline: config.ExchangeOnlineConfig{Enabled: true},
		Collectors: map[string]config.CollectorConfig{
			"entra.users": {Enabled: &falseValue},
		},
	}}}
	got := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))

	assertAvailabilityStatic(t, got, "entra.recommendations", telemetry.TransportGraph, availability.StateDisabled, availability.ReasonExperimentalNotEnabled)
	assertAvailabilityStatic(t, got, "m365.message_trace", telemetry.TransportExchangeOnline, availability.StateDisabled, availability.ReasonHighVolumeNotEnabled)
	assertAvailabilityStatic(t, got, "entra.users", telemetry.TransportGraph, availability.StateDisabled, availability.ReasonDisabledByConfig)

	cfg.Tenants[0].Collectors["entra.recommendations"] = config.CollectorConfig{Enabled: &trueValue}
	cfg.Tenants[0].Collectors["m365.message_trace"] = config.CollectorConfig{Enabled: &trueValue}
	got = availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, got, "entra.recommendations", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, got, "m365.message_trace", telemetry.TransportExchangeOnline, availability.StateStarting, availability.ReasonNoCompletedRun)
}

func TestResolveAvailabilityInventoryDistinguishesLicenseAbsenceFromProbeFailure(t *testing.T) {
	cfg := availabilityTestConfig()
	knownMissing := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", license.Capabilities{}, true))
	assertAvailabilityStatic(t, knownMissing, "entra.signins.interactive", telemetry.TransportGraph, availability.StateBlocked, availability.ReasonLicenseUnavailable)
	if got := knownMissing["entra.signins.interactive"].MissingCapabilities; !reflect.DeepEqual(got, []availability.MissingCapability{availability.MissingCapabilityEntraP1}) {
		t.Fatalf("entra.signins.interactive missing capabilities = %v, want [entra_p1]", got)
	}

	unknown := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", nil, false))
	assertAvailabilityStatic(t, unknown, "entra.signins.interactive", telemetry.TransportGraph, availability.StateStartupFailed, availability.ReasonLicenseDetectionFailed)
	assertAvailabilityStatic(t, unknown, "entra.users", telemetry.TransportGraph, availability.StateStartupFailed, availability.ReasonLicenseDetectionFailed)
	assertAvailabilityStatic(t, unknown, "entra.domains", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
}

func TestResolveAvailabilityInventoryReportsTypedPartialLicenseLimitations(t *testing.T) {
	cfg := availabilityTestConfig()
	baseTier := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", license.Capabilities{}, true))
	assertAvailabilityLimitations(t, baseTier, "entra.risk",
		[]availability.Limitation{availability.LimitationRiskyUsers},
		[]availability.MissingCapability{availability.MissingCapabilityEntraP2})
	assertAvailabilityLimitations(t, baseTier, "entra.roles",
		[]availability.Limitation{availability.LimitationPIMAssignments},
		[]availability.MissingCapability{availability.MissingCapabilityEntraP2})
	assertAvailabilityLimitations(t, baseTier, "entra.users",
		[]availability.Limitation{availability.LimitationStaleAccounts},
		[]availability.MissingCapability{availability.MissingCapabilityEntraP1OrP2})

	p1 := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", license.Capabilities{
		license.CapEntraP1: true,
	}, true))
	assertAvailabilityLimitations(t, p1, "entra.risk",
		[]availability.Limitation{availability.LimitationRiskyUsers},
		[]availability.MissingCapability{availability.MissingCapabilityEntraP2})
	assertAvailabilityLimitations(t, p1, "entra.roles",
		[]availability.Limitation{availability.LimitationPIMAssignments},
		[]availability.MissingCapability{availability.MissingCapabilityEntraP2})
	assertAvailabilityLimitations(t, p1, "entra.users", nil, nil)

	p2 := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", license.Capabilities{
		license.CapEntraP2: true,
	}, true))
	assertAvailabilityLimitations(t, p2, "entra.risk", nil, nil)
	assertAvailabilityLimitations(t, p2, "entra.roles", nil, nil)
	assertAvailabilityLimitations(t, p2, "entra.users", nil, nil)
}

func TestResolveAvailabilityInventorySelectsBlobOrBoundedGraphFallback(t *testing.T) {
	cfg := availabilityTestConfig()
	cfg.Collectors = map[string]config.CollectorConfig{
		"entra.directory_audits": {Source: "blob"},
	}
	fallback := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, fallback, "entra.directory_audits", telemetry.TransportGraph, availability.StateStarting, availability.ReasonTransportFallback)

	cfg.Tenants[0].BlobIngest.AccountURL = "https://example.blob.core.windows.net"
	blob := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, blob, "entra.directory_audits", telemetry.TransportBlob, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, blob, "entra.graph_activity", telemetry.TransportBlob, availability.StateStarting, availability.ReasonNoCompletedRun)

	cfg.Collectors["entra.directory_audits"] = config.CollectorConfig{}
	graph := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, graph, "entra.directory_audits", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
}

func TestResolveAvailabilityInventoryMarksInactivePeerCoveredByActiveDeclarer(t *testing.T) {
	cfg := availabilityTestConfig()
	defaults := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, defaults, "m365.activity", telemetry.TransportO365Activity, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, defaults, "m365.unified_audit", telemetry.TransportO365Activity, availability.StateCovered, availability.ReasonCoveredByAlternative)

	falseValue := false
	cfg.Tenants[0].BlobIngest.AccountURL = "https://example.blob.core.windows.net"
	cfg.Tenants[0].Collectors = map[string]config.CollectorConfig{
		"entra.signins.managed_identity": {Enabled: &falseValue},
	}
	blob := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, blob, "entra.signins.managed_identity.blob", telemetry.TransportBlob, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, blob, "entra.signins.managed_identity", telemetry.TransportBlob, availability.StateCovered, availability.ReasonCoveredByAlternative)
}

func TestResolveAvailabilityInventoryKeepsDirectionalInactiveDeclarerUncovered(t *testing.T) {
	trueValue := true
	cfg := availabilityTestConfig()
	cfg.Tenants[0].Collectors = map[string]config.CollectorConfig{
		"entra.signins.managed_identity": {Enabled: &trueValue},
	}
	got := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))
	assertAvailabilityStatic(t, got, "entra.signins.managed_identity", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, got, "entra.signins.managed_identity.blob", telemetry.TransportBlob, availability.StateDisabled, availability.ReasonTransportNotConfigured)
}

func TestResolveAvailabilityInventoryKeepsBothActiveConflictsVisible(t *testing.T) {
	trueValue := true
	cfg := availabilityTestConfig()
	cfg.Tenants[0].BlobIngest.AccountURL = "https://example.blob.core.windows.net"
	cfg.Tenants[0].Collectors = map[string]config.CollectorConfig{
		"m365.unified_audit":             {Enabled: &trueValue},
		"entra.signins.managed_identity": {Enabled: &trueValue},
	}
	got := availabilityStaticsByName(t, resolveAvailabilityInventory(cfg, "tenant-a", allAvailabilityTestCapabilities(), true))

	assertAvailabilityStatic(t, got, "m365.activity", telemetry.TransportO365Activity, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, got, "m365.unified_audit", telemetry.TransportAuditQuery, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, got, "entra.signins.managed_identity.blob", telemetry.TransportBlob, availability.StateStarting, availability.ReasonNoCompletedRun)
	assertAvailabilityStatic(t, got, "entra.signins.managed_identity", telemetry.TransportGraph, availability.StateStarting, availability.ReasonNoCompletedRun)
}

func availabilityTestConfig() *config.Config {
	return &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
}

func allAvailabilityTestCapabilities() license.Capabilities {
	return license.Capabilities{
		license.CapEntraP1:                   true,
		license.CapEntraP2:                   true,
		license.CapWorkloadIdentitiesPremium: true,
		license.CapIntune:                    true,
		license.CapPurviewInfoProtection:     true,
		license.CapPurviewRecordsMgmt:        true,
	}
}

func availabilityStaticsByName(t *testing.T, statics []availability.Static) map[string]availability.Static {
	t.Helper()
	byName := make(map[string]availability.Static, len(statics))
	for _, static := range statics {
		if _, exists := byName[static.Collector]; exists {
			t.Fatalf("duplicate availability row %q", static.Collector)
		}
		byName[static.Collector] = static
	}
	return byName
}

func availabilityCandidatesByName(candidates []availabilityCandidate) map[string][]availabilityCandidate {
	byName := make(map[string][]availabilityCandidate, len(candidates))
	for _, candidate := range candidates {
		byName[candidate.Name] = append(byName[candidate.Name], candidate)
	}
	return byName
}

func assertAvailabilityStatic(
	t *testing.T,
	byName map[string]availability.Static,
	name string,
	transport telemetry.Transport,
	state availability.State,
	reason availability.Reason,
) {
	t.Helper()
	got, ok := byName[name]
	if !ok {
		t.Fatalf("availability inventory missing %q", name)
	}
	if got.Transport != transport || got.State != state || got.Reason != reason {
		t.Errorf("%s transport/state/reason = %q/%q/%q, want %q/%q/%q",
			name, got.Transport, got.State, got.Reason, transport, state, reason)
	}
}

func assertAvailabilityLimitations(
	t *testing.T,
	byName map[string]availability.Static,
	name string,
	wantLimitations []availability.Limitation,
	wantMissing []availability.MissingCapability,
) {
	t.Helper()
	got, ok := byName[name]
	if !ok {
		t.Fatalf("availability inventory missing %q", name)
	}
	if len(wantLimitations) == 0 {
		if got.State != availability.StateStarting || got.Reason != availability.ReasonNoCompletedRun ||
			len(got.Limitations) != 0 || len(got.MissingCapabilities) != 0 {
			t.Errorf("%s state/reason/limitations/missing = %q/%q/%v/%v, want starting/no_completed_run/[]/[]",
				name, got.State, got.Reason, got.Limitations, got.MissingCapabilities)
		}
		return
	}
	if got.State != availability.StateLimited || got.Reason != availability.ReasonPartialLicense ||
		!reflect.DeepEqual(got.Limitations, wantLimitations) ||
		!reflect.DeepEqual(got.MissingCapabilities, wantMissing) {
		t.Errorf("%s state/reason/limitations/missing = %q/%q/%v/%v, want limited/partial_license/%v/%v",
			name, got.State, got.Reason, got.Limitations, got.MissingCapabilities, wantLimitations, wantMissing)
	}
}

func knownAvailabilityLimitation(limitation availability.Limitation) bool {
	switch limitation {
	case availability.LimitationRiskyUsers, availability.LimitationPIMAssignments, availability.LimitationStaleAccounts:
		return true
	default:
		return false
	}
}

func knownAvailabilityTransport(transport telemetry.Transport) bool {
	switch transport {
	case telemetry.TransportGraph,
		telemetry.TransportBlob,
		telemetry.TransportO365Activity,
		telemetry.TransportAuditQuery,
		telemetry.TransportReportExport,
		telemetry.TransportMDCA,
		telemetry.TransportExchangeOnline:
		return true
	default:
		return false
	}
}
