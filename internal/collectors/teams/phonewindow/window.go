// Package phonewindow adapts the two Teams phone report functions to the
// existing paged log pipeline. The functions take time bounds in the URI, not
// as an OData filter, and set their own page size.
package phonewindow

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	base = "https://graph.microsoft.com/v1.0"
	// Until delivery lag is measured, scan a day of overlap behind the
	// completed window. The scheduler already trails the wall clock by 15m.
	overlap = 24 * time.Hour
	// Leave room for overlap within the sink's event horizon even when
	// the scheduler is draining a backlog.
	maxWindow = telemetry.EventHorizon - overlap
)

// Window uses the report's start time for both the query and OTLP logs.
type Window struct {
	*logpipeline.LogCollector
}

// New builds a Teams phone report poller for a single tenant and function.
func New(d collectors.WindowDeps, name, function string, mapper func(map[string]any) (string, telemetry.Event)) *Window {
	return &Window{logpipeline.NewLogCollector(name, 15*time.Minute, 15*time.Minute, d.TenantID, logpipeline.EndpointConfig{
		Path: "/communications/callRecords/" + function, CheckpointKey: name,
		CollectorName: name, TimeField: "startDateTime", NoServerFilter: true,
		Overlap: overlap, Map: mapper,
	}, d.Fetcher, d.Store)}
}

// Registration gives the scheduler the default cold start and slice size. The
// tenant's configured backfill.initial_lookback can override the default.
func Registration(c collector.WindowCollector) collectors.RegisteredWindow {
	return collectors.RegisteredWindow{Collector: c, InitialLookback: 24 * time.Hour, MaxWindow: maxWindow}
}

// RequiredPermissions declares the v1.0 application permission for both functions.
func (*Window) RequiredPermissions() []string { return []string{"CallRecords.Read.All"} }

// CollectWindow drains a complete report window before returning a completed
// cursor. The query overlap, not the newest reported call, handles late rows.
func (c *Window) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
	cfg := c.Config
	cp, err := c.Store.Load(c.TenantID, cfg.CheckpointKey)
	if err != nil {
		return from, fmt.Errorf("%s: load checkpoint: %w", c.Name(), err)
	}
	if !cp.Watermark.IsZero() {
		from = cp.Watermark.Add(-overlap)
	}
	// The sink horizon is shorter than Graph's 90-day request limit and
	// minimum documented/issue retention. Do not fetch expired slices after
	// a long outage, even if the scheduler is still replaying its old cursor.
	oldest := time.Now().Add(-telemetry.EventHorizon)
	from = later(from, oldest)
	if !to.Before(from) && to.After(oldest) {
		cfg.Path += "(fromDateTime=" + from.UTC().Format(time.RFC3339Nano) + ",toDateTime=" + to.UTC().Format(time.RFC3339Nano) + ")"
		fetch := functionPages{PageFetcher: c.Fetcher, firstURL: base + cfg.Path}
		if _, err := logpipeline.Poll(ctx, cfg, cp, from, to, fetch, e, outcomes); err != nil {
			return cp.Watermark, err
		}
	}
	cp.Watermark = later(cp.Watermark, later(to, oldest))
	cp.OverlapWindow = overlap
	cp.EvictStale()
	if err := c.Store.Save(cp); err != nil {
		return cp.Watermark, fmt.Errorf("%s: save checkpoint: %w", c.Name(), err)
	}
	return cp.Watermark, nil
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type functionPages struct {
	logpipeline.PageFetcher
	firstURL string
}

func (f functionPages) FetchPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	// Strip only the engine's synthetic first-page query. Graph sets the
	// page size for these functions; every nextLink stays opaque.
	if pageURL == f.firstURL+"?%24top=1000" {
		pageURL = f.firstURL
	}
	return f.PageFetcher.FetchPage(ctx, pageURL)
}

// EventEmitter observes logs after the pipeline's time and dedupe checks.
type EventEmitter struct {
	telemetry.Emitter
	OnEvent func(telemetry.Event)
}

// LogEvent records the accepted event and forwards it to the caller's emitter.
func (e EventEmitter) LogEvent(ev telemetry.Event) {
	e.OnEvent(ev)
	e.Emitter.LogEvent(ev)
}

// Fields copies only the selected wire fields to log attributes. An omitted
// value is not zero or false; year-one timestamp sentinels are not real times.
func Fields(row map[string]any, keys map[string]string) telemetry.Attrs {
	attrs := make(telemetry.Attrs, len(keys))
	for wire, attr := range keys {
		switch v := row[wire].(type) {
		case string:
			if v != "0001-01-01T00:00:00Z" {
				telemetry.SetStr(attrs, attr, v)
			}
		case float64, bool:
			attrs[attr] = v
		}
	}
	return attrs
}
