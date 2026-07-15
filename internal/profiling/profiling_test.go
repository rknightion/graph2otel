package profiling

import (
	"testing"
	"time"

	"github.com/grafana/pyroscope-go"

	"github.com/rknightion/graph2otel/internal/config"
)

func TestBuildConfigBaseProfileTypesAndVersionTag(t *testing.T) {
	cfg := config.ProfilingConfig{
		Pyroscope: config.ProfilingPyroscope{
			Enabled:           true,
			ServerAddress:     "https://profiles.example/",
			BasicAuthUser:     "123",
			BasicAuthPassword: config.Secret("tok"),
			Tags:              map[string]string{"env": "lab", "service_version": "spoofed"},
		},
	}
	pc := buildConfig(cfg, "graph2otel", "1.2.3")

	if pc.ApplicationName != "graph2otel" {
		t.Errorf("ApplicationName = %q", pc.ApplicationName)
	}
	if pc.ServerAddress != "https://profiles.example/" || pc.BasicAuthUser != "123" || pc.BasicAuthPassword != "tok" {
		t.Errorf("auth/server not mapped: %+v", pc)
	}
	// service_version is always the real version, never a user override.
	if pc.Tags["service_version"] != "1.2.3" {
		t.Errorf("service_version tag = %q, want 1.2.3", pc.Tags["service_version"])
	}
	if pc.Tags["env"] != "lab" {
		t.Errorf("user tag env = %q, want lab", pc.Tags["env"])
	}
	// Base set (no mutex/block) = 6 types.
	if len(pc.ProfileTypes) != 6 {
		t.Errorf("ProfileTypes = %d, want 6 (base set)", len(pc.ProfileTypes))
	}
}

func TestBuildConfigAddsMutexBlockWhenSampled(t *testing.T) {
	cfg := config.ProfilingConfig{
		MutexProfileFraction: 5,
		BlockProfileRate:     10000,
		Pyroscope:            config.ProfilingPyroscope{Enabled: true, UploadRate: 30 * time.Second},
	}
	pc := buildConfig(cfg, "graph2otel", "dev")
	if len(pc.ProfileTypes) != 10 { // 6 base + 2 mutex + 2 block
		t.Errorf("ProfileTypes = %d, want 10 (base+mutex+block)", len(pc.ProfileTypes))
	}
	if pc.UploadRate != 30*time.Second {
		t.Errorf("UploadRate = %v, want 30s", pc.UploadRate)
	}
	has := func(w pyroscope.ProfileType) bool {
		for _, p := range pc.ProfileTypes {
			if p == w {
				return true
			}
		}
		return false
	}
	if !has(pyroscope.ProfileMutexCount) || !has(pyroscope.ProfileBlockDuration) {
		t.Error("mutex/block profile types missing despite non-zero sampling")
	}
}

func TestStartDisabledReturnsNilProfiler(t *testing.T) {
	prof, err := Start(config.ProfilingConfig{}, "graph2otel", "dev", nil)
	if err != nil {
		t.Fatalf("Start(disabled) error = %v", err)
	}
	if prof != nil {
		t.Error("Start(disabled) returned a non-nil profiler; want nil")
	}
}
