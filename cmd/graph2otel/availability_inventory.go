package main

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

type availabilityFamily string

const (
	availabilityFamilySnapshot availabilityFamily = "snapshot"
	availabilityFamilyWindow   availabilityFamily = "window"
	availabilityFamilyBlob     availabilityFamily = "blob"
	availabilityFamilyO365     availabilityFamily = "o365"
	availabilityFamilyMDCA     availabilityFamily = "mdca"
	availabilityFamilyEXO      availabilityFamily = "exo"
	availabilityFamilyHunt     availabilityFamily = "hunt"
)

type availabilityCandidate struct {
	Name                string
	Family              availabilityFamily
	Transport           telemetry.Transport
	Experimental        bool
	HighVolume          bool
	Capability          license.Capability
	PartialRequirements []availability.PartialRequirement
	ConflictsWith       []string
}

type availabilityFactoryVisitor struct {
	snapshot []collectors.Factory
	window   []collectors.WindowFactory
	blob     []collectors.BlobFactory
	o365     []collectors.O365Factory
	mdca     []collectors.MDCAFactory
	exo      []collectors.EXOFactory
	hunt     []collectors.HuntFactory
}

func (v *availabilityFactoryVisitor) Snapshot(fs []collectors.Factory)     { v.snapshot = fs }
func (v *availabilityFactoryVisitor) Window(fs []collectors.WindowFactory) { v.window = fs }
func (v *availabilityFactoryVisitor) Blob(fs []collectors.BlobFactory)     { v.blob = fs }
func (v *availabilityFactoryVisitor) O365(fs []collectors.O365Factory)     { v.o365 = fs }
func (v *availabilityFactoryVisitor) MDCA(fs []collectors.MDCAFactory)     { v.mdca = fs }
func (v *availabilityFactoryVisitor) EXO(fs []collectors.EXOFactory)       { v.exo = fs }
func (v *availabilityFactoryVisitor) Hunt(fs []collectors.HuntFactory)     { v.hunt = fs }

var _ collectorFactoryVisitor = (*availabilityFactoryVisitor)(nil)

// availabilityCandidates constructs every registered collector through inert
// dependencies and records only bounded registration metadata. No factory is
// polled and no tenant client, credential, or network is required.
func availabilityCandidates() []availabilityCandidate {
	var paths availabilityFactoryVisitor
	visitRegisteredCollectorFactories(&paths)

	candidates := make([]availabilityCandidate, 0,
		len(paths.snapshot)+len(paths.window)+len(paths.blob)+len(paths.o365)+
			len(paths.mdca)+len(paths.exo)+len(paths.hunt))
	appendCandidate := func(c collector.Collector, family availabilityFamily) {
		if c == nil {
			panic(fmt.Sprintf("availability inventory: %s factory returned a nil collector", family))
		}
		candidates = append(candidates, newAvailabilityCandidate(c, family))
	}

	for _, factory := range paths.snapshot {
		appendCandidate(factory(collectors.Deps{}), availabilityFamilySnapshot)
	}
	windowDeps := snapshotWindowDeps()
	for _, factory := range paths.window {
		rw := factory(windowDeps)
		appendCandidate(rw.Collector, availabilityFamilyWindow)
	}
	for _, factory := range paths.blob {
		appendCandidate(factory(collectors.BlobDeps{}), availabilityFamilyBlob)
	}
	for _, factory := range paths.o365 {
		rw := factory(collectors.O365Deps{})
		appendCandidate(rw.Collector, availabilityFamilyO365)
	}
	for _, factory := range paths.mdca {
		rw := factory(collectors.MDCADeps{})
		appendCandidate(rw.Collector, availabilityFamilyMDCA)
	}
	for _, factory := range paths.exo {
		appendCandidate(factory(collectors.EXODeps{}), availabilityFamilyEXO)
	}
	for _, factory := range paths.hunt {
		appendCandidate(factory(collectors.HuntDeps{}), availabilityFamilyHunt)
	}

	slices.SortFunc(candidates, compareAvailabilityCandidates)
	return candidates
}

func newAvailabilityCandidate(c collector.Collector, family availabilityFamily) availabilityCandidate {
	candidate := availabilityCandidate{
		Name:                c.Name(),
		Family:              family,
		Transport:           collector.TransportOf(c),
		PartialRequirements: availability.PartialRequirements(c.Name()),
	}
	if experimental, ok := c.(collectors.Experimental); ok {
		candidate.Experimental = experimental.Experimental()
	}
	if highVolume, ok := c.(collectors.HighVolume); ok {
		candidate.HighVolume = highVolume.HighVolume()
	}
	if requirer, ok := c.(license.CapabilityRequirer); ok {
		candidate.Capability = requirer.RequiredCapability()
	}
	if declarer, ok := c.(collectors.ConflictsWith); ok {
		candidate.ConflictsWith = slices.Clone(declarer.ConflictsWith())
		slices.Sort(candidate.ConflictsWith)
		candidate.ConflictsWith = slices.Compact(candidate.ConflictsWith)
	}
	return candidate
}

func compareAvailabilityCandidates(a, b availabilityCandidate) int {
	if byName := cmp.Compare(a.Name, b.Name); byName != 0 {
		return byName
	}
	if byFamily := cmp.Compare(a.Family, b.Family); byFamily != 0 {
		return byFamily
	}
	return cmp.Compare(a.Transport, b.Transport)
}

func compareStrings(a, b string) int {
	return cmp.Compare(a, b)
}

// resolveAvailabilityInventory turns the registration-path census into exactly
// one deterministic static row per logical collector for a configured tenant.
// The only same-name alternatives are the three Graph/blob source switches.
func resolveAvailabilityInventory(
	cfg *config.Config,
	tenantID string,
	caps license.Capabilities,
	licenseKnown bool,
) []availability.Static {
	if cfg == nil {
		cfg = &config.Config{}
	}
	candidates := availabilityCandidates()
	blobConfigured := tenantBlobAccountURL(cfg, tenantID) != ""
	statics := make([]availability.Static, 0, 148)
	selectedCandidates := make([]availabilityCandidate, 0, 148)

	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && candidates[end].Name == candidates[start].Name {
			end++
		}
		selected, fallback := selectAvailabilityCandidate(
			cfg, tenantID, candidates[start:end], blobConfigured,
		)
		statics = append(statics, resolveAvailabilityStatic(
			cfg, tenantID, selected, caps, licenseKnown, blobConfigured, fallback,
		))
		selectedCandidates = append(selectedCandidates, selected)
		start = end
	}

	applyAvailabilityCoverage(statics, selectedCandidates)
	slices.SortFunc(statics, func(a, b availability.Static) int {
		return cmp.Compare(a.Collector, b.Collector)
	})
	return statics
}

func selectAvailabilityCandidate(
	cfg *config.Config,
	tenantID string,
	candidates []availabilityCandidate,
	blobConfigured bool,
) (availabilityCandidate, bool) {
	if len(candidates) == 1 {
		return candidates[0], false
	}
	if len(candidates) != 2 || !allowedAvailabilityDuplicate(candidates[0].Name) {
		panic(fmt.Sprintf("availability inventory: unexplained duplicate %q", candidates[0].Name))
	}

	var graphCandidate, blobCandidate *availabilityCandidate
	for i := range candidates {
		switch candidates[i].Transport {
		case telemetry.TransportGraph:
			graphCandidate = &candidates[i]
		case telemetry.TransportBlob:
			blobCandidate = &candidates[i]
		}
	}
	if graphCandidate == nil || blobCandidate == nil {
		panic(fmt.Sprintf("availability inventory: duplicate %q is not a Graph/blob pair", candidates[0].Name))
	}
	if cfg.CollectorSource(tenantID, candidates[0].Name) != "blob" {
		return *graphCandidate, false
	}
	if blobConfigured {
		return *blobCandidate, false
	}
	return *graphCandidate, true
}

func resolveAvailabilityStatic(
	cfg *config.Config,
	tenantID string,
	candidate availabilityCandidate,
	caps license.Capabilities,
	licenseKnown bool,
	blobConfigured bool,
	fallback bool,
) availability.Static {
	static := availability.Static{
		Collector: candidate.Name,
		Transport: candidate.Transport,
	}

	enabled, _ := cfg.CollectorSettings(tenantID, candidate.Name)
	if !enabled {
		static.State = availability.StateDisabled
		static.Reason = availability.ReasonDisabledByConfig
		return static
	}
	if !availabilityTransportConfigured(cfg, tenantID, candidate, blobConfigured) {
		static.State = availability.StateDisabled
		static.Reason = availability.ReasonTransportNotConfigured
		return static
	}
	if candidate.Experimental && !cfg.CollectorExplicitlyEnabled(tenantID, candidate.Name) {
		static.State = availability.StateDisabled
		static.Reason = availability.ReasonExperimentalNotEnabled
		return static
	}
	if candidate.HighVolume && !cfg.CollectorExplicitlyEnabled(tenantID, candidate.Name) {
		static.State = availability.StateDisabled
		static.Reason = availability.ReasonHighVolumeNotEnabled
		return static
	}

	licenseDependent := candidate.Capability != "" || len(candidate.PartialRequirements) > 0
	if licenseDependent && !licenseKnown {
		static.State = availability.StateStartupFailed
		static.Reason = availability.ReasonLicenseDetectionFailed
		return static
	}
	if candidate.Capability != "" && !caps.Has(candidate.Capability) {
		missing, ok := availability.MissingCapabilityFor(candidate.Capability)
		if !ok {
			panic(fmt.Sprintf("availability inventory: unbounded capability %q", candidate.Capability))
		}
		static.State = availability.StateBlocked
		static.Reason = availability.ReasonLicenseUnavailable
		static.MissingCapabilities = []availability.MissingCapability{missing}
		return static
	}
	static.Limitations, static.MissingCapabilities = availability.MissingPartialRequirements(candidate.Name, caps)
	if len(static.Limitations) > 0 {
		static.State = availability.StateLimited
		static.Reason = availability.ReasonPartialLicense
		return static
	}

	static.State = availability.StateStarting
	if fallback {
		static.Reason = availability.ReasonTransportFallback
	} else {
		static.Reason = availability.ReasonNoCompletedRun
	}
	return static
}

// applyAvailabilityCoverage promotes an inactive collector to covered only when
// an active registered collector explicitly declares that it ships the peer's
// records. ConflictsWith is directional: the inactive declarer cannot infer
// coverage from an active peer that declares nothing. When both sides are
// active, both rows remain active so the composition root's fail-fast conflict
// check still sees the invalid double-ship configuration.
func applyAvailabilityCoverage(
	statics []availability.Static,
	candidates []availabilityCandidate,
) {
	if len(statics) != len(candidates) {
		panic("availability inventory: static and candidate census lengths differ")
	}
	index := make(map[string]int, len(statics))
	active := make([]bool, len(statics))
	for i := range statics {
		index[statics[i].Collector] = i
		active[i] = availabilityStaticActive(statics[i])
	}
	for i, candidate := range candidates {
		if !active[i] {
			continue
		}
		for _, peer := range candidate.ConflictsWith {
			peerIndex, ok := index[peer]
			if !ok {
				panic(fmt.Sprintf("availability inventory: %q declares unknown conflict peer %q", candidate.Name, peer))
			}
			if active[peerIndex] {
				continue
			}
			statics[peerIndex].Transport = candidate.Transport
			statics[peerIndex].State = availability.StateCovered
			statics[peerIndex].Reason = availability.ReasonCoveredByAlternative
			statics[peerIndex].Limitations = nil
			statics[peerIndex].MissingCapabilities = nil
		}
	}
}

func availabilityStaticActive(static availability.Static) bool {
	switch static.State {
	case availability.StateStarting, availability.StateLimited:
		return true
	default:
		return false
	}
}

func availabilityTransportConfigured(
	cfg *config.Config,
	tenantID string,
	candidate availabilityCandidate,
	blobConfigured bool,
) bool {
	switch candidate.Family {
	case availabilityFamilyBlob:
		return blobConfigured
	case availabilityFamilyMDCA:
		return tenantMDCAConfig(cfg, tenantID).Configured()
	case availabilityFamilyEXO:
		return tenantEXOConfig(cfg, tenantID).Enabled
	case availabilityFamilyHunt:
		return tenantHuntingConfig(cfg, tenantID).Enabled
	case availabilityFamilyWindow:
		if candidate.Transport == telemetry.TransportExchangeOnline {
			return tenantEXOConfig(cfg, tenantID).Enabled
		}
	case availabilityFamilySnapshot:
		if candidate.Name == "graph2otel.blob_categories" {
			return blobConfigured
		}
	}
	return true
}

func allowedAvailabilityDuplicate(name string) bool {
	switch name {
	case "entra.directory_audits", "entra.provisioning", "entra.risk_detections":
		return true
	default:
		return false
	}
}
