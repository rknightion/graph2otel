// Package availability defines the bounded collector availability contract.
package availability

import (
	"reflect"
	"testing"

	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestDeriveRuntimeOutcomes(t *testing.T) {
	base := Static{Collector: "entra.users", Transport: telemetry.TransportGraph, State: StateStarting, Reason: ReasonNoCompletedRun}
	causes := []recordoutcome.Cause{
		recordoutcome.CausePermissionDenied,
		recordoutcome.CauseSourceError,
		recordoutcome.CauseDecodeError,
		recordoutcome.CauseMappingError,
		recordoutcome.CauseMissingEventTime,
		recordoutcome.CauseAccountingMismatch,
		recordoutcome.CauseTimeout,
		recordoutcome.CausePanic,
	}

	tests := []struct {
		name    string
		summary *recordoutcome.Summary
		state   State
		reason  Reason
	}{
		{name: "no completed run", state: StateStarting, reason: ReasonNoCompletedRun},
		{name: "empty", summary: &recordoutcome.Summary{Result: recordoutcome.ResultEmpty}, state: StateHealthyEmpty, reason: ReasonEmpty},
		{name: "success", summary: &recordoutcome.Summary{Result: recordoutcome.ResultSuccess}, state: StateHealthy, reason: ReasonSuccess},
	}
	for _, cause := range causes {
		tests = append(tests,
			struct {
				name    string
				summary *recordoutcome.Summary
				state   State
				reason  Reason
			}{name: "partial " + string(cause), summary: &recordoutcome.Summary{Result: recordoutcome.ResultPartial, Cause: cause}, state: StateDegraded, reason: Reason(cause)},
		)
		state := StateFailed
		if cause == recordoutcome.CausePermissionDenied {
			state = StateBlocked
		}
		tests = append(tests,
			struct {
				name    string
				summary *recordoutcome.Summary
				state   State
				reason  Reason
			}{name: "failure " + string(cause), summary: &recordoutcome.Summary{Result: recordoutcome.ResultFailure, Cause: cause}, state: state, reason: Reason(cause)},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Derive(base, tt.summary)
			if got.State != tt.state || got.Reason != tt.reason {
				t.Fatalf("Derive() state/reason = %q/%q, want %q/%q", got.State, got.Reason, tt.state, tt.reason)
			}
			if (got.LastOutcome == nil) != (tt.summary == nil) {
				t.Fatalf("Derive() LastOutcome = %v, want summary presence %t", got.LastOutcome, tt.summary != nil)
			}
		})
	}
}

func TestDeriveStaticDecisionsTakePrecedence(t *testing.T) {
	runtime := &recordoutcome.Summary{Result: recordoutcome.ResultFailure, Cause: recordoutcome.CauseSourceError}
	tests := []struct {
		name   string
		static Static
		state  State
		reason Reason
	}{
		{name: "disabled", static: Static{State: StateDisabled, Reason: ReasonDisabledByConfig}, state: StateDisabled, reason: ReasonDisabledByConfig},
		{name: "blocked", static: Static{State: StateBlocked, Reason: ReasonLicenseUnavailable}, state: StateBlocked, reason: ReasonLicenseUnavailable},
		{name: "covered", static: Static{State: StateCovered, Reason: ReasonCoveredByAlternative}, state: StateCovered, reason: ReasonCoveredByAlternative},
		{name: "license detection failed", static: Static{State: StateStartupFailed, Reason: ReasonLicenseDetectionFailed}, state: StateStartupFailed, reason: ReasonLicenseDetectionFailed},
		{name: "transport initialization failed", static: Static{State: StateStartupFailed, Reason: ReasonTransportInitializationFailed}, state: StateStartupFailed, reason: ReasonTransportInitializationFailed},
		{name: "invalid transport configuration", static: Static{State: StateStartupFailed, Reason: ReasonInvalidTransportConfiguration}, state: StateStartupFailed, reason: ReasonInvalidTransportConfiguration},
		{name: "startup failure", static: Static{State: StateStartupFailed, Reason: ReasonGraphClientInitializationFailed}, state: StateStartupFailed, reason: ReasonGraphClientInitializationFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Derive(tt.static, runtime)
			if got.State != tt.state || got.Reason != tt.reason {
				t.Fatalf("Derive() state/reason = %q/%q, want %q/%q", got.State, got.Reason, tt.state, tt.reason)
			}
		})
	}
}

func TestDeriveLimitedYieldsToRuntimeDegradation(t *testing.T) {
	static := Static{State: StateLimited, Reason: ReasonPartialLicense}
	tests := []struct {
		name    string
		summary *recordoutcome.Summary
		state   State
		reason  Reason
	}{
		{name: "no completed run", state: StateLimited, reason: ReasonPartialLicense},
		{name: "empty", summary: &recordoutcome.Summary{Result: recordoutcome.ResultEmpty}, state: StateLimited, reason: ReasonPartialLicense},
		{name: "success", summary: &recordoutcome.Summary{Result: recordoutcome.ResultSuccess}, state: StateLimited, reason: ReasonPartialLicense},
		{name: "partial", summary: &recordoutcome.Summary{Result: recordoutcome.ResultPartial, Cause: recordoutcome.CauseSourceError}, state: StateDegraded, reason: ReasonSourceError},
		{name: "failure", summary: &recordoutcome.Summary{Result: recordoutcome.ResultFailure, Cause: recordoutcome.CauseSourceError}, state: StateFailed, reason: ReasonSourceError},
		{name: "permission failure", summary: &recordoutcome.Summary{Result: recordoutcome.ResultFailure, Cause: recordoutcome.CausePermissionDenied}, state: StateBlocked, reason: ReasonPermissionDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Derive(static, tt.summary)
			if got.State != tt.state || got.Reason != tt.reason {
				t.Fatalf("Derive() state/reason = %q/%q, want %q/%q", got.State, got.Reason, tt.state, tt.reason)
			}
		})
	}
}

func TestDeriveTransportFallbackFollowsCleanRuns(t *testing.T) {
	static := Static{State: StateStarting, Reason: ReasonTransportFallback}
	tests := []struct {
		name    string
		summary *recordoutcome.Summary
		state   State
		reason  Reason
	}{
		{name: "no completed run", state: StateStarting, reason: ReasonTransportFallback},
		{name: "empty", summary: &recordoutcome.Summary{Result: recordoutcome.ResultEmpty}, state: StateHealthyEmpty, reason: ReasonTransportFallback},
		{name: "success", summary: &recordoutcome.Summary{Result: recordoutcome.ResultSuccess}, state: StateHealthy, reason: ReasonTransportFallback},
		{name: "partial", summary: &recordoutcome.Summary{Result: recordoutcome.ResultPartial, Cause: recordoutcome.CauseSourceError}, state: StateDegraded, reason: ReasonSourceError},
		{name: "failure", summary: &recordoutcome.Summary{Result: recordoutcome.ResultFailure, Cause: recordoutcome.CauseSourceError}, state: StateFailed, reason: ReasonSourceError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Derive(static, tt.summary)
			if got.State != tt.state || got.Reason != tt.reason {
				t.Fatalf("Derive() state/reason = %q/%q, want %q/%q", got.State, got.Reason, tt.state, tt.reason)
			}
		})
	}
}

func TestDeriveStartingAndRuntimeStatesYieldToCompletedRun(t *testing.T) {
	summary := &recordoutcome.Summary{Result: recordoutcome.ResultSuccess}
	for _, state := range []State{StateStarting, StateHealthyEmpty, StateHealthy, StateDegraded, StateFailed} {
		t.Run(string(state), func(t *testing.T) {
			got := Derive(Static{State: state}, summary)
			if got.State != StateHealthy || got.Reason != ReasonSuccess {
				t.Fatalf("Derive() state/reason = %q/%q, want %q/%q", got.State, got.Reason, StateHealthy, ReasonSuccess)
			}
		})
	}
}

func TestDeriveCopiesLimitationsAndSummary(t *testing.T) {
	static := Static{
		Collector:           "entra.risk",
		Transport:           telemetry.TransportGraph,
		State:               StateLimited,
		Reason:              ReasonPartialLicense,
		Limitations:         []Limitation{LimitationRiskyUsers},
		MissingCapabilities: []MissingCapability{MissingCapabilityEntraP2},
	}
	summary := &recordoutcome.Summary{Result: recordoutcome.ResultSuccess}
	got := Derive(static, summary)
	static.Limitations[0] = "mutated"
	static.MissingCapabilities[0] = "mutated"
	summary.Result = recordoutcome.ResultFailure
	if !reflect.DeepEqual(got.Limitations, []Limitation{LimitationRiskyUsers}) {
		t.Fatalf("Limitations = %v, want independent copy", got.Limitations)
	}
	if !reflect.DeepEqual(got.MissingCapabilities, []MissingCapability{MissingCapabilityEntraP2}) {
		t.Fatalf("MissingCapabilities = %v, want independent copy", got.MissingCapabilities)
	}
	if got.LastOutcome == nil || got.LastOutcome.Result != recordoutcome.ResultSuccess {
		t.Fatalf("LastOutcome = %+v, want independent success summary", got.LastOutcome)
	}
	got.Limitations[0] = "output mutation"
	got.MissingCapabilities[0] = "output mutation"
	if static.Limitations[0] != "mutated" {
		t.Fatalf("mutating output limitations changed static input: %v", static.Limitations)
	}
	if static.MissingCapabilities[0] != "mutated" {
		t.Fatalf("mutating output missing capabilities changed static input: %v", static.MissingCapabilities)
	}
}

func TestMissingCapabilityContractIsClosed(t *testing.T) {
	want := []MissingCapability{
		MissingCapabilityEntraP1,
		MissingCapabilityEntraP2,
		MissingCapabilityWorkloadIdentitiesPremium,
		MissingCapabilityIntune,
		MissingCapabilityPurviewInformationProtection,
		MissingCapabilityPurviewRecordsManagement,
		MissingCapabilityEntraP1OrP2,
	}
	if got := MissingCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingCapabilities() = %v, want %v", got, want)
	}
	for _, capability := range want {
		if !ValidMissingCapability(capability) {
			t.Errorf("ValidMissingCapability(%q) = false, want true", capability)
		}
	}
	if ValidMissingCapability("arbitrary") {
		t.Fatal("ValidMissingCapability(arbitrary) = true, want false")
	}
	wholeCollector := map[license.Capability]MissingCapability{
		license.CapEntraP1:                   MissingCapabilityEntraP1,
		license.CapEntraP2:                   MissingCapabilityEntraP2,
		license.CapWorkloadIdentitiesPremium: MissingCapabilityWorkloadIdentitiesPremium,
		license.CapIntune:                    MissingCapabilityIntune,
		license.CapPurviewInfoProtection:     MissingCapabilityPurviewInformationProtection,
		license.CapPurviewRecordsMgmt:        MissingCapabilityPurviewRecordsManagement,
	}
	for capability, wantMissing := range wholeCollector {
		got, ok := MissingCapabilityFor(capability)
		if !ok || got != wantMissing {
			t.Errorf("MissingCapabilityFor(%q) = %q/%v, want %q/true", capability, got, ok, wantMissing)
		}
	}
	if got, ok := MissingCapabilityFor("arbitrary"); ok || got != "arbitrary" {
		t.Errorf("MissingCapabilityFor(arbitrary) = %q/%v, want arbitrary/false", got, ok)
	}
}

func TestPartialRequirementsAreCanonicalAndImmutable(t *testing.T) {
	want := []PartialRequirement{{
		Limitation:        LimitationRiskyUsers,
		MissingCapability: MissingCapabilityEntraP2,
	}}
	got := PartialRequirements("entra.risk")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PartialRequirements(entra.risk) = %v, want %v", got, want)
	}
	got[0].Limitation = "mutated"
	if again := PartialRequirements("entra.risk"); !reflect.DeepEqual(again, want) {
		t.Fatalf("mutating returned requirements changed canonical metadata: %v", again)
	}
	if got := PartialRequirements("unknown"); got != nil {
		t.Fatalf("PartialRequirements(unknown) = %v, want nil", got)
	}
}

func TestAvailabilityContract(t *testing.T) {
	wantStates := []State{
		StateDisabled,
		StateBlocked,
		StateCovered,
		StateStarting,
		StateHealthyEmpty,
		StateHealthy,
		StateLimited,
		StateDegraded,
		StateFailed,
		StateStartupFailed,
	}
	if got := States(); !reflect.DeepEqual(got, wantStates) {
		t.Fatalf("States() = %v, want %v", got, wantStates)
	}
	if got := Reasons(); len(got) == 0 {
		t.Fatal("Reasons() = empty, want closed reason set")
	}

	for _, state := range States() {
		for _, reason := range Reasons() {
			if ValidPair(state, reason) != expectedPair(state, reason) {
				t.Errorf("ValidPair(%q, %q) did not match contract", state, reason)
			}
		}
	}
	for _, pair := range [][2]string{{"unknown", string(ReasonSuccess)}, {string(StateHealthy), "unknown"}, {string(StateHealthy), string(ReasonEmpty)}} {
		if ValidPair(State(pair[0]), Reason(pair[1])) {
			t.Errorf("ValidPair(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

func expectedPair(state State, reason Reason) bool {
	switch state {
	case StateDisabled:
		return reason == ReasonTransportNotConfigured || reason == ReasonExperimentalNotEnabled || reason == ReasonHighVolumeNotEnabled || reason == ReasonDisabledByConfig
	case StateBlocked:
		return reason == ReasonPermissionDenied || reason == ReasonLicenseUnavailable
	case StateCovered:
		return reason == ReasonCoveredByAlternative
	case StateStarting:
		return reason == ReasonNoCompletedRun || reason == ReasonTransportFallback
	case StateHealthyEmpty:
		return reason == ReasonEmpty || reason == ReasonTransportFallback
	case StateHealthy:
		return reason == ReasonSuccess || reason == ReasonTransportFallback
	case StateLimited:
		return reason == ReasonPartialLicense
	case StateDegraded:
		return isRuntimeReason(reason)
	case StateFailed:
		return isRuntimeReason(reason) && reason != ReasonPermissionDenied
	case StateStartupFailed:
		return reason == ReasonCredentialInitializationFailed || reason == ReasonGraphClientInitializationFailed || reason == ReasonLicenseDetectionFailed || reason == ReasonTransportInitializationFailed || reason == ReasonInvalidTransportConfiguration
	default:
		return false
	}
}

func isRuntimeReason(reason Reason) bool {
	for _, cause := range []recordoutcome.Cause{
		recordoutcome.CausePermissionDenied,
		recordoutcome.CauseSourceError,
		recordoutcome.CauseDecodeError,
		recordoutcome.CauseMappingError,
		recordoutcome.CauseMissingEventTime,
		recordoutcome.CauseAccountingMismatch,
		recordoutcome.CauseTimeout,
		recordoutcome.CausePanic,
	} {
		if reason == Reason(cause) {
			return true
		}
	}
	return false
}
