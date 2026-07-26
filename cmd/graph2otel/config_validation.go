package main

import (
	"fmt"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
)

// collectorOverrideFactoryVisitor builds the command's configuration inventory
// from the same seven registration paths runtime wiring visits. known contains
// logical collector names across every transport. polled and blob retain the
// candidate transport sets long enough to derive source-switchable names by
// intersection.
type collectorOverrideFactoryVisitor struct {
	known  map[string]bool
	polled map[string]bool
	blob   map[string]bool
}

func (v *collectorOverrideFactoryVisitor) Snapshot(factories []collectors.Factory) {
	for _, factory := range factories {
		v.addPolled(factory(collectors.Deps{}))
	}
}

func (v *collectorOverrideFactoryVisitor) Window(factories []collectors.WindowFactory) {
	deps := snapshotWindowDeps()
	for _, factory := range factories {
		registered := factory(deps)
		if registered.Collector != nil {
			v.addPolled(registered.Collector)
		}
	}
}

func (v *collectorOverrideFactoryVisitor) Blob(factories []collectors.BlobFactory) {
	for _, factory := range factories {
		candidate := factory(collectors.BlobDeps{})
		v.addKnown(candidate)
		v.blob[candidate.Name()] = true
	}
}

func (v *collectorOverrideFactoryVisitor) O365(factories []collectors.O365Factory) {
	for _, factory := range factories {
		registered := factory(collectors.O365Deps{})
		if registered.Collector != nil {
			v.addKnown(registered.Collector)
		}
	}
}

func (v *collectorOverrideFactoryVisitor) MDCA(factories []collectors.MDCAFactory) {
	for _, factory := range factories {
		registered := factory(collectors.MDCADeps{})
		if registered.Collector != nil {
			v.addKnown(registered.Collector)
		}
	}
}

func (v *collectorOverrideFactoryVisitor) EXO(factories []collectors.EXOFactory) {
	for _, factory := range factories {
		v.addKnown(factory(collectors.EXODeps{}))
	}
}

func (v *collectorOverrideFactoryVisitor) Hunt(factories []collectors.HuntFactory) {
	for _, factory := range factories {
		v.addKnown(factory(collectors.HuntDeps{}))
	}
}

func (v *collectorOverrideFactoryVisitor) addPolled(candidate interface{ Name() string }) {
	v.addKnown(candidate)
	v.polled[candidate.Name()] = true
}

func (v *collectorOverrideFactoryVisitor) addKnown(candidate interface{ Name() string }) {
	v.known[candidate.Name()] = true
}

var _ collectorFactoryVisitor = (*collectorOverrideFactoryVisitor)(nil)

// collectorOverrideInventory returns every logical collector name and the names
// for which source: graph|blob is meaningful. Source switching is a registry
// fact: only a name represented on both the Graph-polled snapshot/window paths
// and the blob path is switchable.
func collectorOverrideInventory() (known, sourceSwitchable map[string]bool) {
	visitor := collectorOverrideFactoryVisitor{
		known:  make(map[string]bool),
		polled: make(map[string]bool),
		blob:   make(map[string]bool),
	}
	visitRegisteredCollectorFactories(&visitor)

	sourceSwitchable = make(map[string]bool)
	for name := range visitor.blob {
		if visitor.polled[name] {
			sourceSwitchable[name] = true
		}
	}
	return visitor.known, sourceSwitchable
}

// loadValidatedConfig is the shared post-load gate for both startup modes.
// Collector override validation runs before callers construct telemetry,
// credentials, checkpoints, or any network client.
func loadValidatedConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	known, sourceSwitchable := collectorOverrideInventory()
	if err := cfg.ValidateCollectorOverrides(known, sourceSwitchable); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}
