// Package availability defines the bounded current availability contract for a
// logical collector. It is shared by the OTLP and admin surfaces so they cannot
// reconstruct different meanings from scrape counters or free-form errors.
package availability

import (
	"slices"

	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// State is the bounded current availability of a logical collector.
type State string

const (
	StateDisabled      State = "disabled"
	StateBlocked       State = "blocked"
	StateCovered       State = "covered"
	StateStarting      State = "starting"
	StateHealthyEmpty  State = "healthy_empty"
	StateHealthy       State = "healthy"
	StateLimited       State = "limited"
	StateDegraded      State = "degraded"
	StateFailed        State = "failed"
	StateStartupFailed State = "startup_failed"
)

// Reason is the bounded explanation for an availability State.
type Reason string

const (
	ReasonTransportNotConfigured          Reason = "transport_not_configured"
	ReasonExperimentalNotEnabled          Reason = "experimental_not_enabled"
	ReasonHighVolumeNotEnabled            Reason = "high_volume_not_enabled"
	ReasonDisabledByConfig                Reason = "disabled_by_config"
	ReasonPermissionDenied                Reason = Reason(recordoutcome.CausePermissionDenied)
	ReasonLicenseUnavailable              Reason = "license_unavailable"
	ReasonCoveredByAlternative            Reason = "covered_by_alternative"
	ReasonNoCompletedRun                  Reason = "no_completed_run"
	ReasonLicenseDetectionFailed          Reason = "license_detection_failed"
	ReasonTransportInitializationFailed   Reason = "transport_initialization_failed"
	ReasonInvalidTransportConfiguration   Reason = "invalid_transport_configuration"
	ReasonTransportFallback               Reason = "transport_fallback"
	ReasonEmpty                           Reason = "empty"
	ReasonSuccess                         Reason = "success"
	ReasonPartialLicense                  Reason = "partial_license"
	ReasonSourceError                     Reason = Reason(recordoutcome.CauseSourceError)
	ReasonDecodeError                     Reason = Reason(recordoutcome.CauseDecodeError)
	ReasonMappingError                    Reason = Reason(recordoutcome.CauseMappingError)
	ReasonMissingEventTime                Reason = Reason(recordoutcome.CauseMissingEventTime)
	ReasonAccountingMismatch              Reason = Reason(recordoutcome.CauseAccountingMismatch)
	ReasonTimeout                         Reason = Reason(recordoutcome.CauseTimeout)
	ReasonPanic                           Reason = Reason(recordoutcome.CausePanic)
	ReasonCredentialInitializationFailed  Reason = "credential_initialization_failed" //nolint:gosec // bounded status code, not a credential
	ReasonGraphClientInitializationFailed Reason = "graph_client_initialization_failed"
)

// Limitation is a bounded capability omitted from an otherwise available
// collector. It is exposed in typed admin and generated-doc data, never metric
// labels.
type Limitation string

const (
	LimitationRiskyUsers     Limitation = "risky_users"
	LimitationPIMAssignments Limitation = "pim_assignments"
	LimitationStaleAccounts  Limitation = "stale_accounts"
)

// MissingCapability is a bounded entitlement that explains why a whole
// collector or one of its sub-signals is unavailable. The single-capability
// values exactly match license.Capability; EntraP1OrP2 is the one supported
// alternative requirement.
type MissingCapability string

const (
	MissingCapabilityEntraP1                      MissingCapability = MissingCapability(license.CapEntraP1)
	MissingCapabilityEntraP2                      MissingCapability = MissingCapability(license.CapEntraP2)
	MissingCapabilityWorkloadIdentitiesPremium    MissingCapability = MissingCapability(license.CapWorkloadIdentitiesPremium)
	MissingCapabilityIntune                       MissingCapability = MissingCapability(license.CapIntune)
	MissingCapabilityPurviewInformationProtection MissingCapability = MissingCapability(license.CapPurviewInfoProtection)
	MissingCapabilityPurviewRecordsManagement     MissingCapability = MissingCapability(license.CapPurviewRecordsMgmt)
	MissingCapabilityEntraP1OrP2                  MissingCapability = "entra_p1_or_p2"
)

// PartialRequirement is canonical metadata for an omitted sub-signal. Both
// inventory resolution and generated collector documentation consume this
// table so the limitation and its entitlement cannot drift apart.
type PartialRequirement struct {
	Limitation        Limitation
	MissingCapability MissingCapability
}

// Static is the immutable availability decision for a configured logical
// collector before its most recent completed run is considered.
type Static struct {
	Collector           string
	Transport           telemetry.Transport
	State               State
	Reason              Reason
	Limitations         []Limitation
	MissingCapabilities []MissingCapability
}

// Point is one current availability value. LastOutcome is nil until the
// collector has completed a run.
type Point struct {
	Collector           string
	Transport           telemetry.Transport
	State               State
	Reason              Reason
	Limitations         []Limitation
	MissingCapabilities []MissingCapability
	LastOutcome         *recordoutcome.Summary
}

var states = []State{
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

var reasons = []Reason{
	ReasonTransportNotConfigured,
	ReasonExperimentalNotEnabled,
	ReasonHighVolumeNotEnabled,
	ReasonDisabledByConfig,
	ReasonPermissionDenied,
	ReasonLicenseUnavailable,
	ReasonCoveredByAlternative,
	ReasonNoCompletedRun,
	ReasonLicenseDetectionFailed,
	ReasonTransportInitializationFailed,
	ReasonInvalidTransportConfiguration,
	ReasonTransportFallback,
	ReasonEmpty,
	ReasonSuccess,
	ReasonPartialLicense,
	ReasonSourceError,
	ReasonDecodeError,
	ReasonMappingError,
	ReasonMissingEventTime,
	ReasonAccountingMismatch,
	ReasonTimeout,
	ReasonPanic,
	ReasonCredentialInitializationFailed,
	ReasonGraphClientInitializationFailed,
}

var missingCapabilities = []MissingCapability{
	MissingCapabilityEntraP1,
	MissingCapabilityEntraP2,
	MissingCapabilityWorkloadIdentitiesPremium,
	MissingCapabilityIntune,
	MissingCapabilityPurviewInformationProtection,
	MissingCapabilityPurviewRecordsManagement,
	MissingCapabilityEntraP1OrP2,
}

var partialRequirements = map[string][]PartialRequirement{
	"entra.risk": {
		{Limitation: LimitationRiskyUsers, MissingCapability: MissingCapabilityEntraP2},
	},
	"entra.roles": {
		{Limitation: LimitationPIMAssignments, MissingCapability: MissingCapabilityEntraP2},
	},
	"entra.users": {
		{Limitation: LimitationStaleAccounts, MissingCapability: MissingCapabilityEntraP1OrP2},
	},
}

type pair struct {
	state  State
	reason Reason
}

var allowedPairs = map[pair]struct{}{
	{StateDisabled, ReasonTransportNotConfigured}:               {},
	{StateDisabled, ReasonExperimentalNotEnabled}:               {},
	{StateDisabled, ReasonHighVolumeNotEnabled}:                 {},
	{StateDisabled, ReasonDisabledByConfig}:                     {},
	{StateBlocked, ReasonPermissionDenied}:                      {},
	{StateBlocked, ReasonLicenseUnavailable}:                    {},
	{StateCovered, ReasonCoveredByAlternative}:                  {},
	{StateStarting, ReasonNoCompletedRun}:                       {},
	{StateStarting, ReasonTransportFallback}:                    {},
	{StateHealthyEmpty, ReasonEmpty}:                            {},
	{StateHealthyEmpty, ReasonTransportFallback}:                {},
	{StateHealthy, ReasonSuccess}:                               {},
	{StateHealthy, ReasonTransportFallback}:                     {},
	{StateLimited, ReasonPartialLicense}:                        {},
	{StateDegraded, ReasonPermissionDenied}:                     {},
	{StateDegraded, ReasonSourceError}:                          {},
	{StateDegraded, ReasonDecodeError}:                          {},
	{StateDegraded, ReasonMappingError}:                         {},
	{StateDegraded, ReasonMissingEventTime}:                     {},
	{StateDegraded, ReasonAccountingMismatch}:                   {},
	{StateDegraded, ReasonTimeout}:                              {},
	{StateDegraded, ReasonPanic}:                                {},
	{StateFailed, ReasonSourceError}:                            {},
	{StateFailed, ReasonDecodeError}:                            {},
	{StateFailed, ReasonMappingError}:                           {},
	{StateFailed, ReasonMissingEventTime}:                       {},
	{StateFailed, ReasonAccountingMismatch}:                     {},
	{StateFailed, ReasonTimeout}:                                {},
	{StateFailed, ReasonPanic}:                                  {},
	{StateStartupFailed, ReasonCredentialInitializationFailed}:  {},
	{StateStartupFailed, ReasonGraphClientInitializationFailed}: {},
	{StateStartupFailed, ReasonLicenseDetectionFailed}:          {},
	{StateStartupFailed, ReasonTransportInitializationFailed}:   {},
	{StateStartupFailed, ReasonInvalidTransportConfiguration}:   {},
}

// States returns a copy of the closed availability state set in display order.
func States() []State {
	return slices.Clone(states)
}

// Reasons returns a copy of the closed availability reason set in display order.
func Reasons() []Reason {
	return slices.Clone(reasons)
}

// MissingCapabilities returns a copy of the closed missing-capability set.
func MissingCapabilities() []MissingCapability {
	return slices.Clone(missingCapabilities)
}

// ValidMissingCapability reports whether capability belongs to the closed set.
func ValidMissingCapability(capability MissingCapability) bool {
	return slices.Contains(missingCapabilities, capability)
}

// MissingCapabilityFor converts a whole-collector license capability into its
// bounded availability code.
func MissingCapabilityFor(capability license.Capability) (MissingCapability, bool) {
	missing := MissingCapability(capability)
	return missing, ValidMissingCapability(missing) && missing != MissingCapabilityEntraP1OrP2
}

// PartialRequirements returns an immutable copy of the canonical sub-signal
// requirements for collector.
func PartialRequirements(collector string) []PartialRequirement {
	return slices.Clone(partialRequirements[collector])
}

// MissingPartialRequirements resolves the canonical sub-signal requirements
// against a tenant's detected capability set.
func MissingPartialRequirements(
	collector string,
	caps license.Capabilities,
) ([]Limitation, []MissingCapability) {
	requirements := partialRequirements[collector]
	limitations := make([]Limitation, 0, len(requirements))
	missing := make([]MissingCapability, 0, len(requirements))
	for _, requirement := range requirements {
		if requirementSatisfied(requirement.MissingCapability, caps) {
			continue
		}
		limitations = append(limitations, requirement.Limitation)
		missing = append(missing, requirement.MissingCapability)
	}
	return limitations, missing
}

func requirementSatisfied(requirement MissingCapability, caps license.Capabilities) bool {
	switch requirement {
	case MissingCapabilityEntraP1OrP2:
		return caps.Has(license.CapEntraP1) || caps.Has(license.CapEntraP2)
	default:
		return caps.Has(license.Capability(requirement))
	}
}

// ValidPair reports whether state and reason are a permitted availability pair.
func ValidPair(state State, reason Reason) bool {
	_, ok := allowedPairs[pair{state: state, reason: reason}]
	return ok
}

// Derive combines a static decision with the most recent immutable run summary.
// Terminal static decisions take precedence over any runtime result. Starting and
// runtime states yield to a completed run; a nil summary means no completed run.
func Derive(static Static, summary *recordoutcome.Summary) Point {
	point := Point{
		Collector:           static.Collector,
		Transport:           static.Transport,
		State:               static.State,
		Reason:              static.Reason,
		Limitations:         slices.Clone(static.Limitations),
		MissingCapabilities: slices.Clone(static.MissingCapabilities),
	}
	if summary != nil {
		outcome := *summary
		point.LastOutcome = &outcome
	}

	if !ValidPair(point.State, point.Reason) {
		point.State = StateStarting
		point.Reason = ReasonNoCompletedRun
	}
	if isTerminalStaticState(point.State) || summary == nil {
		return point
	}
	if point.State == StateLimited && isCleanResult(summary.Result) {
		return point
	}
	if point.State == StateStarting && point.Reason == ReasonTransportFallback {
		switch summary.Result {
		case recordoutcome.ResultEmpty:
			point.State = StateHealthyEmpty
			return point
		case recordoutcome.ResultSuccess:
			point.State = StateHealthy
			return point
		}
	}

	point.State, point.Reason = runtimeState(*summary)
	return point
}

func isTerminalStaticState(state State) bool {
	switch state {
	case StateDisabled, StateBlocked, StateCovered, StateStartupFailed:
		return true
	default:
		return false
	}
}

func isCleanResult(result recordoutcome.Result) bool {
	return result == recordoutcome.ResultEmpty || result == recordoutcome.ResultSuccess
}

func runtimeState(summary recordoutcome.Summary) (State, Reason) {
	switch summary.Result {
	case recordoutcome.ResultEmpty:
		return StateHealthyEmpty, ReasonEmpty
	case recordoutcome.ResultSuccess:
		return StateHealthy, ReasonSuccess
	case recordoutcome.ResultPartial:
		return StateDegraded, runtimeReason(summary.Cause)
	case recordoutcome.ResultFailure:
		reason := runtimeReason(summary.Cause)
		if reason == ReasonPermissionDenied {
			return StateBlocked, reason
		}
		return StateFailed, reason
	default:
		return StateFailed, ReasonAccountingMismatch
	}
}

func runtimeReason(cause recordoutcome.Cause) Reason {
	reason := Reason(cause)
	if ValidPair(StateDegraded, reason) {
		return reason
	}
	return ReasonAccountingMismatch
}
