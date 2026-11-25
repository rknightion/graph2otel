package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	teamsAdminTenant      = "00000000-0000-0000-0000-000000000001"
	teamsAdminOtherTenant = "00000000-0000-0000-0000-000000000002"
)

// fakeTeamsAdminCollector stands in for the real teams_admin collectors, which
// land in later pull requests. It is never passed to collectors.Register: the
// global registry feeds the census and the generated docs, and a test double in
// it would appear in both.
type fakeTeamsAdminCollector struct {
	name      string
	transport telemetry.Transport
}

func (f fakeTeamsAdminCollector) Name() string                         { return f.name }
func (fakeTeamsAdminCollector) DefaultInterval() time.Duration         { return time.Hour }
func (fakeTeamsAdminCollector) Profiles() collector.ProfileSet         { return collector.ProfileTeams }
func (f fakeTeamsAdminCollector) IngestTransport() telemetry.Transport { return f.transport }
func (fakeTeamsAdminCollector) Collect(context.Context, telemetry.Emitter, *recordoutcome.Recorder) error {
	return nil
}

func teamsAdminFake() fakeTeamsAdminCollector {
	return fakeTeamsAdminCollector{name: "teams.fake_admin", transport: telemetry.TransportTeamsAdmin}
}

func teamsAdminConfig(enabled *bool) *config.Config {
	cfg := &config.Config{Profiles: []string{"teams"}, Tenants: []config.TenantConfig{
		{TenantID: teamsAdminTenant}, {TenantID: teamsAdminOtherTenant},
	}}
	if enabled != nil {
		cfg.Tenants[0].Teams = &config.TeamsConfig{AdminAPI: &config.AdminAPIConfig{Enabled: *enabled}}
	}
	return cfg
}

func boolPtr(b bool) *bool { return &b }

func TestCollectorGateTeamsAdminRequiresExplicitOptIn(t *testing.T) {
	c := teamsAdminFake()
	for _, tt := range []struct {
		name    string
		enabled *bool
		want    bool
		reason  string
	}{
		{"unset", nil, false, "teams.admin_api.enabled not set"},
		{"explicit false", boolPtr(false), false, "teams.admin_api.enabled not set"},
		{"enabled", boolPtr(true), true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := teamsAdminConfig(tt.enabled)
			_, ok, reason := collectorGate(c, cfg, teamsAdminTenant, license.Capabilities{})
			if ok != tt.want || reason != tt.reason {
				t.Fatalf("collectorGate = (%t, %q), want (%t, %q)", ok, reason, tt.want, tt.reason)
			}
			if _, ok, _ := collectorGate(c, cfg, teamsAdminOtherTenant, license.Capabilities{}); ok {
				t.Fatal("one tenant's opt-in enabled the transport for another tenant")
			}
		})
	}
	// A collector on another transport is untouched by the clause.
	other := fakeTeamsAdminCollector{name: "teams.fake_graph", transport: telemetry.TransportGraph}
	if _, ok, reason := collectorGate(other, teamsAdminConfig(nil), teamsAdminTenant, license.Capabilities{}); !ok {
		t.Fatalf("graph-transport collector gated by teams admin opt-in: %q", reason)
	}
}

func TestAvailabilityTransportConfiguredTeamsAdminSnapshot(t *testing.T) {
	candidate := availabilityCandidate{
		Name:      "teams.fake_admin",
		Family:    availabilityFamilySnapshot,
		Transport: telemetry.TransportTeamsAdmin,
		Profiles:  collector.ProfileTeams,
	}
	graph := candidate
	graph.Transport = telemetry.TransportGraph
	for _, tt := range []struct {
		name    string
		enabled *bool
		want    bool
	}{
		{"unset", nil, false},
		{"explicit false", boolPtr(false), false},
		{"enabled", boolPtr(true), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := teamsAdminConfig(tt.enabled)
			if got := availabilityTransportConfigured(cfg, teamsAdminTenant, candidate, false); got != tt.want {
				t.Errorf("teams_admin snapshot configured = %t, want %t", got, tt.want)
			}
			if !availabilityTransportConfigured(cfg, teamsAdminTenant, graph, false) {
				t.Error("graph snapshot candidate lost its default-on configuration")
			}
			if availabilityTransportConfigured(cfg, teamsAdminOtherTenant, candidate, false) {
				t.Error("one tenant's opt-in configured the transport for another tenant")
			}
		})
	}
}

func TestTransportManualPrerequisitesTeamsAdmin(t *testing.T) {
	got := transportManualPrerequisites(teamsAdminFake())
	if len(got) != 1 || !strings.Contains(got[0], "directory role") || !strings.Contains(got[0], "cannot prove") {
		t.Fatalf("transportManualPrerequisites = %q, want one directory-role prerequisite", got)
	}
	if got := transportManualPrerequisites(fakeTeamsAdminCollector{name: "x", transport: telemetry.TransportGraph}); got != nil {
		t.Fatalf("graph transport prerequisites = %q, want none", got)
	}
}

func TestPreflightSnapshotLoopCarriesTeamsAdminPrerequisite(t *testing.T) {
	type call struct {
		name string
		reqs []string
	}
	var calls []call
	add := func(c collector.Collector, reqs ...string) { calls = append(calls, call{c.Name(), reqs}) }
	factories := []collectors.Factory{
		func(collectors.Deps) collector.SnapshotCollector { return teamsAdminFake() },
		func(collectors.Deps) collector.SnapshotCollector {
			return fakeTeamsAdminCollector{name: "teams.fake_graph", transport: telemetry.TransportGraph}
		},
	}
	polled := addPreflightSnapshotCollectors(factories, collectors.Deps{}, false, add)
	if len(calls) != 2 || !polled["teams.fake_admin"] || !polled["teams.fake_graph"] {
		t.Fatalf("calls = %+v, polled = %v", calls, polled)
	}
	if len(calls[0].reqs) != 1 || calls[0].reqs[0] != teamsAdminManualPrerequisite {
		t.Errorf("teams_admin collector prerequisites = %q, want the directory-role prerequisite", calls[0].reqs)
	}
	if len(calls[1].reqs) != 0 {
		t.Errorf("graph collector prerequisites = %q, want none", calls[1].reqs)
	}
}

func TestTenantTeamsAdminClient(t *testing.T) {
	ta := &auth.TenantAuth{TenantID: teamsAdminTenant}
	var built int
	build := func(got *auth.TenantAuth, opts teamsadminclient.Options) (*teamsadminclient.Client, error) {
		built++
		if got != ta {
			t.Error("builder received a different TenantAuth")
		}
		return teamsadminclient.NewClient(got, opts)
	}

	off, err := tenantTeamsAdminClient(teamsAdminConfig(nil), ta, nil, nil, build)
	if err != nil || off != nil || built != 0 {
		t.Fatalf("off: client=%v err=%v built=%d; want an untyped nil interface and no construction", off, err, built)
	}

	on, err := tenantTeamsAdminClient(teamsAdminConfig(boolPtr(true)), ta, nil, nil, build)
	if err != nil || on == nil || built != 1 {
		t.Fatalf("on: client=%v err=%v built=%d; want a client from one construction", on, err, built)
	}

	boom := errors.New("bad base url")
	failed, err := tenantTeamsAdminClient(teamsAdminConfig(boolPtr(true)), ta, nil, nil,
		func(*auth.TenantAuth, teamsadminclient.Options) (*teamsadminclient.Client, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("failure err = %v, want %v", err, boom)
	}
	if failed != nil {
		t.Fatal("construction failure returned a non-nil interface (typed nil leak)")
	}
}

func TestSkipTeamsAdminCollector(t *testing.T) {
	boom := errors.New("construction failed")
	admin := teamsAdminFake()
	graph := fakeTeamsAdminCollector{name: "teams.fake_graph", transport: telemetry.TransportGraph}
	for _, tt := range []struct {
		name string
		c    collector.Collector
		err  error
		want bool
	}{
		{"admin collector, construction failed", admin, boom, true},
		{"admin collector, construction fine", admin, nil, false},
		{"graph collector, construction failed", graph, boom, false},
	} {
		if got := skipTeamsAdminCollector(tt.c, tt.err); got != tt.want {
			t.Errorf("%s: skip = %t, want %t", tt.name, got, tt.want)
		}
	}
}
