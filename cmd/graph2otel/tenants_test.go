package main

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
)

type gateTestCollector struct {
	name         string
	experimental bool
	highVolume   bool
}

func (c gateTestCollector) Name() string                 { return c.name }
func (gateTestCollector) DefaultInterval() time.Duration { return time.Minute }
func (c gateTestCollector) Experimental() bool           { return c.experimental }
func (c gateTestCollector) HighVolume() bool             { return c.highVolume }

type premiumGateTestCollector struct {
	gateTestCollector
	capability license.Capability
}

func (c premiumGateTestCollector) RequiredCapability() license.Capability { return c.capability }

var _ collector.Collector = gateTestCollector{}
var _ collectors.Experimental = gateTestCollector{}
var _ collectors.HighVolume = gateTestCollector{}
var _ license.CapabilityRequirer = premiumGateTestCollector{}

func TestCollectorGate(t *testing.T) {
	trueValue := true
	tests := []struct {
		name      string
		collector collector.Collector
		cfg       *config.Config
		caps      license.Capabilities
		want      bool
	}{
		{
			name:      "missing capability",
			collector: premiumGateTestCollector{gateTestCollector: gateTestCollector{name: "premium"}, capability: license.CapEntraP1},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "experimental default disabled",
			collector: gateTestCollector{name: "beta", experimental: true},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "high volume default disabled",
			collector: gateTestCollector{name: "firehose", highVolume: true},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "explicit experimental enabled",
			collector: gateTestCollector{name: "beta", experimental: true},
			cfg:       &config.Config{Collectors: map[string]config.CollectorConfig{"beta": {Enabled: &trueValue}}}, caps: license.Capabilities{}, want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, _ := collectorGate(tt.collector, tt.cfg, "tenant-a", tt.caps)
			if got != tt.want {
				t.Errorf("collectorGate() enabled = %v, want %v", got, tt.want)
			}
		})
	}
}
