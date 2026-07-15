// Package profiling wires optional Grafana Pyroscope continuous profiling.
// It is opt-in (config.ProfilingConfig, default off) and deliberately
// self-contained: the exporter's core job never depends on it, and a failure
// to reach Pyroscope is logged, not fatal.
package profiling

import (
	"fmt"
	"log/slog"
	"runtime"

	"github.com/grafana/pyroscope-go"

	"github.com/rknightion/graph2otel/internal/config"
)

// profileTypes returns the profile types pushed to Pyroscope: the standard CPU
// + alloc/inuse memory set plus goroutines, adding the mutex and block profiles
// only when their runtime sampling is enabled (pushing them otherwise would
// just upload empty profiles).
func profileTypes(p config.ProfilingConfig) []pyroscope.ProfileType {
	types := []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
		pyroscope.ProfileGoroutines,
	}
	if p.MutexProfileFraction > 0 {
		types = append(types, pyroscope.ProfileMutexCount, pyroscope.ProfileMutexDuration)
	}
	if p.BlockProfileRate > 0 {
		types = append(types, pyroscope.ProfileBlockCount, pyroscope.ProfileBlockDuration)
	}
	return types
}

// buildConfig maps the profiling config into a pyroscope.Config. It is pure (no
// side effects, no Logger) so the mapping is unit-testable; the live logger is
// attached by Start. service_version is always tagged and cannot be overridden
// by a user tag.
func buildConfig(cfg config.ProfilingConfig, serviceName, version string) pyroscope.Config {
	p := cfg.Pyroscope
	tags := map[string]string{"service_version": version}
	for k, v := range p.Tags {
		if k != "service_version" {
			tags[k] = v
		}
	}
	pc := pyroscope.Config{
		ApplicationName:   serviceName,
		ServerAddress:     p.ServerAddress,
		BasicAuthUser:     p.BasicAuthUser,
		BasicAuthPassword: p.BasicAuthPassword.Reveal(),
		TenantID:          p.TenantID,
		Tags:              tags,
		ProfileTypes:      profileTypes(cfg),
	}
	if p.UploadRate > 0 {
		pc.UploadRate = p.UploadRate
	}
	return pc
}

// Start applies the runtime mutex/block sampling rates and, when the Pyroscope
// push is enabled, starts the continuous profiler. It returns the profiler (nil
// when push is disabled) so the caller can Stop it on shutdown.
func Start(cfg config.ProfilingConfig, serviceName, version string, logger *slog.Logger) (*pyroscope.Profiler, error) {
	if cfg.MutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(cfg.MutexProfileFraction)
	}
	if cfg.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(cfg.BlockProfileRate)
	}
	if !cfg.Pyroscope.Enabled {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	pc := buildConfig(cfg, serviceName, version)
	pc.Logger = pyroscopeLogger{l: logger}
	return pyroscope.Start(pc)
}

// pyroscopeLogger adapts *slog.Logger to the pyroscope.Logger interface.
type pyroscopeLogger struct{ l *slog.Logger }

func (p pyroscopeLogger) Infof(format string, args ...any)  { p.l.Info(fmt.Sprintf(format, args...)) }
func (p pyroscopeLogger) Debugf(format string, args ...any) { p.l.Debug(fmt.Sprintf(format, args...)) }
func (p pyroscopeLogger) Errorf(format string, args ...any) { p.l.Error(fmt.Sprintf(format, args...)) }
