package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/rknightion/graph2otel/internal/callnotify"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors/teams/callrecords"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

type callNotifications struct {
	receiver *callnotify.Receiver
	ctx      context.Context
	states   map[string]config.Secret
	callback string
	done     chan struct{}
}

func startCallNotifications(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*callNotifications, error) {
	w := cfg.CallNotifications
	if !w.Enabled {
		return nil, nil
	}
	n := &callNotifications{
		receiver: callnotify.New(), states: make(map[string]config.Secret),
		callback: w.PublicURL, done: make(chan struct{}),
	}
	used := make(map[config.Secret]bool)
	for _, tenant := range cfg.Tenants {
		if tenant.CallNotificationClientStateFile == "" {
			continue
		}
		state, err := callnotify.ReadClientState(tenant.CallNotificationClientStateFile)
		if err != nil {
			return nil, err
		}
		if used[state] {
			return nil, errors.New("call notification client state must be distinct per tenant")
		}
		used[state] = true
		n.states[tenant.TenantID] = state
	}
	certificate, err := tls.LoadX509KeyPair(w.TLSCertFile, w.TLSKeyFile)
	if err != nil {
		return nil, errors.New("cannot load call notification TLS certificate and key")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", w.Addr)
	if err != nil {
		return nil, errors.New("cannot bind call notification TLS listener")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	n.ctx = serveCtx
	go func() {
		defer close(n.done)
		defer cancel() // do not keep subscriptions alive after listener failure
		if callnotify.Serve(serveCtx, listener, certificate, n.receiver) != nil {
			logger.Error("call notification TLS listener stopped; polling remains active")
		}
	}()
	return n, nil
}

func (n *callNotifications) wait() {
	if n != nil {
		<-n.done
	}
}

func (n *callNotifications) attach(tenantID string, registry *collector.Registry, graph *graphclient.Client,
	provider *telemetry.Provider, logger *slog.Logger, wg *sync.WaitGroup,
) error {
	if n == nil || registry == nil {
		return nil
	}
	state, enabled := n.states[tenantID]
	if !enabled {
		return nil
	}
	tlog := logger.With("tenant", tenantID)
	for _, entry := range registry.Entries() {
		poller, ok := entry.Collector.(*callrecords.Collector)
		if !ok {
			continue
		}
		attribution := telemetry.Attribution{
			TenantID: tenantID, Collector: callrecords.Name, Transport: telemetry.TransportGraph,
			TrafficClass: telemetry.TrafficClassSteadyState,
		}
		emitter := telemetry.WithTenant(annotatedCollectorEmitter(provider)(attribution), tenantID)
		manage, consume, err := n.receiver.AddTenant(n.ctx, tenantID, state, n.callback, graph,
			func(ctx context.Context, id string) error {
				outcomes := recordoutcome.NewRecorder()
				err := poller.CollectCall(ctx, id, emitter, outcomes)
				provider.RecordSourceRecords(attribution, outcomes.Snapshot().Counts.Fetched)
				return err
			}, tlog)
		if err != nil {
			return err
		}
		wg.Go(manage)
		wg.Go(consume)
		return nil
	}
	tlog.Warn("call notifications not started because teams.call_records is inactive")
	return nil
}
