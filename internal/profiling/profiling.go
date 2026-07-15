// Package profiling wires optional Grafana Pyroscope continuous profiling.
// It is opt-in (config.ProfilingConfig, default off) and deliberately
// self-contained: the exporter's core job never depends on it, and a failure
// to reach Pyroscope is logged, not fatal.
package profiling

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/pprof"

	"github.com/grafana/pyroscope-go"

	"github.com/rknightion/graph2otel/internal/config"
)

// goroutineLeakAvailable reports whether the runtime exposes the goroutineleak
// profile. It is registered only when the binary is built with
// GOEXPERIMENT=goroutineleakprofile (Go 1.26+); a binary built without it simply
// omits the type instead of pushing an empty/erroring profile. Release builds and
// the container image set the experiment; a plain `go build` does not.
func goroutineLeakAvailable() bool {
	return pprof.Lookup("goroutineleak") != nil
}

// profileTypes returns the profile types pushed to Pyroscope: the standard CPU
// + alloc/inuse memory set plus goroutines, the mutex and block contention
// profiles when their runtime sampling is enabled (on by default — see
// config.Default; pushing them with sampling off would just upload empty
// profiles), and goroutine-leak when the runtime exposes it (built with the
// experiment).
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
	if goroutineLeakAvailable() {
		types = append(types, pyroscope.ProfileGoroutineLeak)
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

// Start starts the continuous profiler when the Pyroscope push is enabled,
// applying the process-global mutex/block sampling rates first. It returns the
// profiler (nil when push is disabled) so the caller can Stop it on shutdown.
// The sampling rates are on by default (config.Default) but Pyroscope is the only
// consumer, so they are applied only when it is enabled — a process with
// profiling off pays no sampling overhead for profiles nobody collects.
func Start(cfg config.ProfilingConfig, serviceName, version string, logger *slog.Logger) (*pyroscope.Profiler, error) {
	if !cfg.Pyroscope.Enabled {
		return nil, nil
	}
	if cfg.MutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(cfg.MutexProfileFraction)
	}
	if cfg.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(cfg.BlockProfileRate)
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
