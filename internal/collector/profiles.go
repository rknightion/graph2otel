package collector

import (
	"fmt"

	"github.com/rknightion/graph2otel/internal/profile"
)

// ProfileSet describes collector membership independently of transport.
type ProfileSet = profile.Set

const (
	// ProfileGraph preserves the original collector roster, including non-Graph transports.
	ProfileGraph = profile.Graph
	// ProfileTeams selects collectors for a Teams-focused deployment.
	ProfileTeams = profile.Teams
)

// ProfileDeclarer is required on every registered collector across all transport paths.
// Membership must be constant across tenants and factory dependencies.
type ProfileDeclarer interface {
	Profiles() ProfileSet
}

// HighVolumeProfileDefaults is an explicit exception to the high-volume opt-in
// when Teams is selected. A collector must also declare Teams membership and be
// HighVolume. Experimental, capability and transport gates still apply.
type HighVolumeProfileDefaults interface {
	HighVolumeDefaultProfiles() ProfileSet
}

// ProfilePolicy returns a collector's declared membership and its high-volume
// exceptions. A missing, empty or unknown declaration is a registration error.
func ProfilePolicy(c interface{ Name() string }) (membership, highVolumeDefaults ProfileSet, err error) {
	declared, ok := c.(ProfileDeclarer)
	if !ok {
		return 0, 0, fmt.Errorf("collector %q must declare profiles", c.Name())
	}
	membership = declared.Profiles()
	if membership == 0 || membership & ^(ProfileGraph|ProfileTeams) != 0 {
		return 0, 0, fmt.Errorf("collector %q has empty or invalid profiles", c.Name())
	}
	if defaults, ok := c.(HighVolumeProfileDefaults); ok {
		highVolumeDefaults = defaults.HighVolumeDefaultProfiles()
		volume, _ := c.(interface{ HighVolume() bool })
		if highVolumeDefaults != 0 && (highVolumeDefaults != ProfileTeams || membership&ProfileTeams == 0 || volume == nil || !volume.HighVolume()) {
			return 0, 0, fmt.Errorf("collector %q has invalid high-volume profile defaults", c.Name())
		}
	}
	return membership, highVolumeDefaults, nil
}
