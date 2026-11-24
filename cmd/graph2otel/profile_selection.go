package main

import (
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
)

type collectorSelection struct {
	interval          time.Duration
	disabled          availability.Reason
	explicit          bool
	highVolumeDefault bool
}

func selectCollector(cfg *config.Config, tenantID, name string, profiles, volumeDefaults collector.ProfileSet) collectorSelection {
	override, interval := cfg.CollectorOverrides(tenantID, name)
	selectedProfiles := cfg.SelectedProfiles(tenantID)
	selection := collectorSelection{
		interval:          interval,
		highVolumeDefault: selectedProfiles&volumeDefaults != 0,
	}
	switch {
	case override != nil:
		if !*override {
			selection.disabled = availability.ReasonDisabledByConfig
		} else {
			selection.explicit = true
		}
	case selectedProfiles&profiles == 0:
		selection.disabled = availability.ReasonProfileNotSelected
	}
	return selection
}

func (s collectorSelection) optInReason(experimental, highVolume bool) availability.Reason {
	if experimental && !s.explicit {
		return availability.ReasonExperimentalNotEnabled
	}
	if highVolume && !s.explicit && !s.highVolumeDefault {
		return availability.ReasonHighVolumeNotEnabled
	}
	return ""
}
