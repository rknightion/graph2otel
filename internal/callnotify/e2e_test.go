package callnotify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/teams/callrecords"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const (
	fixtureTenant = "synthetic-tenant"
	fixtureHost   = "receiver.example.invalid"
	fixtureURL    = "https://" + fixtureHost + config.CallNotificationsPath
	fixtureCalls  = "https://graph.microsoft.com/v1.0/communications/callRecords"
	fixtureCall   = "call-a"
)

// memoryListener speaks real TLS and HTTP over net.Pipe without opening ports.
type memoryListener struct {
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

type memoryAddr struct{}

func (memoryAddr) Network() string { return "memory" }
func (memoryAddr) String() string  { return "memory" }

func (l *memoryListener) Addr() net.Addr { return memoryAddr{} }
func (l *memoryListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memoryListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-l.closed:
	case <-ctx.Done():
	}
	_ = client.Close()
	_ = server.Close()
	return nil, net.ErrClosed
}

func syntheticHTTPS(t *testing.T, ctx context.Context, h *Receiver) (*http.Client, func()) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{fixtureHost},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	l := &memoryListener{incoming: make(chan net.Conn), closed: make(chan struct{})}
	transport := &http.Transport{DialContext: l.dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	serveCtx, cancel := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() {
		finished <- Serve(serveCtx, l, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, h)
	}()
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, func() {
		cancel()
		transport.CloseIdleConnections()
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}
}

func sendFixture(ctx context.Context, client *http.Client, method, address string, body []byte) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return 0, "", "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Content-Type"), string(b), err
}

type graphFixture struct {
	mu       sync.Mutex // the renewal clock can wake the manager without a test request
	client   *http.Client
	state    string
	start    time.Time
	current  subscription
	creates  int
	renewals int
	details  int
	version  int
}

func (g *graphFixture) subscriptionStatus() (subscription, int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current, g.creates, g.renewals
}

func (g *graphFixture) removeSubscription() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current = subscription{}
}

func (g *graphFixture) RawSubscription(ctx context.Context, method, address string, body []byte) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var input struct {
		subscription
		State string `json:"clientState"`
	}
	if len(body) != 0 {
		if err := json.Unmarshal(body, &input); err != nil {
			return nil, err
		}
	}
	switch {
	case method == http.MethodGet && address == subscriptionsURL:
		active := []subscription{}
		if g.current.ID != "" {
			active = append(active, g.current)
		}
		return json.Marshal(map[string]any{"value": active}) // Graph intentionally omits clientState
	case method == http.MethodPost && address == subscriptionsURL:
		if g.current.ID != "" || input.Resource != "/communications/callRecords" || input.ChangeType != "updated" ||
			input.Notification != fixtureURL || input.Lifecycle != fixtureURL || input.Rich || input.State != g.state ||
			time.Until(input.Expiration) > 4230*time.Minute {
			return nil, fmt.Errorf("unexpected create subscription request")
		}
		code, typ, token, err := sendFixture(ctx, g.client, http.MethodPost, input.Notification+"?validationToken=synthetic%2Btoken", nil)
		if err != nil {
			return nil, fmt.Errorf("validation request: %w", err)
		}
		if code != http.StatusOK || typ != "text/plain" || token != "synthetic+token" {
			return nil, fmt.Errorf("validation: status %d, type %q, response %q", code, typ, token)
		}
		g.creates++
		g.current = input.subscription
		g.current.ID = "subscription-" + strconv.Itoa(g.creates)
		return json.Marshal(inputWithID(g.current, g.state))
	case method == http.MethodPatch && address == subscriptionsURL+"/"+g.current.ID:
		if input.State != "" || input.Notification != "" || time.Until(input.Expiration) > 4230*time.Minute ||
			!input.Expiration.After(g.current.Expiration) {
			return nil, fmt.Errorf("unexpected renewal subscription request")
		}
		g.renewals++
		g.current.Expiration = input.Expiration
		return json.Marshal(subscription{ID: g.current.ID, Expiration: g.current.Expiration})
	default:
		return nil, fmt.Errorf("unexpected subscription method or URL")
	}
}

func inputWithID(s subscription, state string) any {
	return struct {
		subscription
		State string `json:"clientState"`
	}{s, state}
}

func (g *graphFixture) RawGet(ctx context.Context, address string) ([]byte, error) {
	return g.RawGetWithHeaders(ctx, address, nil)
}

func (g *graphFixture) RawGetWithHeaders(_ context.Context, address string, _ map[string]string) ([]byte, error) {
	switch {
	case address == fixtureCalls+"/"+fixtureCall+"?$expand=sessions($expand=segments)":
		g.details++
		return json.Marshal(map[string]any{"id": fixtureCall, "version": g.version,
			"startDateTime": g.start, "endDateTime": g.start.Add(time.Minute), "sessions": []any{}})
	case address == fixtureCalls+"/"+fixtureCall+"/participants_v2":
		return []byte(`{"value":[]}`), nil
	case strings.HasPrefix(address, fixtureCalls+"?"):
		return json.Marshal(map[string]any{"value": []map[string]any{{"id": fixtureCall, "version": g.version, "startDateTime": g.start}}})
	default:
		return nil, fmt.Errorf("unexpected Graph call-record URL")
	}
}

func notification(tenantID, sub, state, kind string) map[string]any {
	e := map[string]any{"tenantId": tenantID, "subscriptionId": sub, "clientState": state}
	if kind != "" {
		e["lifecycleEvent"] = kind
		return e
	}
	e["changeType"] = "created" // supported even though the subscription asks for updated
	e["resource"] = "communications/callRecords/" + fixtureCall
	e["resourceData"] = map[string]any{"id": fixtureCall, "version": 999, "@odata.id": "https://untrusted.example.invalid/ignored"}
	return e
}

func postEvents(t *testing.T, client *http.Client, want int, events ...map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"value": events})
	if err != nil {
		t.Fatal(err)
	}
	code, _, response, err := sendFixture(t.Context(), client, http.MethodPost, fixtureURL, body)
	if err != nil || code != want || response != "" {
		t.Fatalf("delivery status = %d (want %d), body %q, error %v", code, want, response, err)
	}
}

func fixtureCollector(t *testing.T, g *graphFixture, store *checkpoint.Store) *callrecords.Collector {
	t.Helper()
	for _, factory := range collectors.WindowAll() {
		if c, ok := factory(collectors.WindowDeps{TenantID: fixtureTenant, Graph: g, Store: store}).Collector.(*callrecords.Collector); ok {
			return c
		}
	}
	t.Fatal("missing call-record collector")
	return nil
}

func TestNotificationDeliveryE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		h := New()
		client, closeHTTPS := syntheticHTTPS(t, ctx, h)
		defer closeHTTPS()
		var workers sync.WaitGroup
		defer func() { cancel(); workers.Wait() }()

		state := strings.Repeat("1a", 32)
		stateFile := filepath.Join(t.TempDir(), "client-state")
		if err := os.WriteFile(stateFile, []byte(state+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secret, err := ReadClientState(stateFile)
		if err != nil {
			t.Fatal(err)
		}
		g := &graphFixture{client: client, state: state, version: 2, start: time.Now().Add(-time.Hour)}
		store := checkpoint.NewStore(t.TempDir())
		poller := fixtureCollector(t, g, store)
		rec := telemetrytest.New()
		emitter := telemetry.WithTenant(rec.Emitter(), fixtureTenant)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		manage, consume, err := h.AddTenant(ctx, fixtureTenant, secret, fixtureURL, g,
			func(ctx context.Context, id string) error {
				return poller.CollectCall(ctx, id, emitter, recordoutcome.NewRecorder())
			}, logger)
		if err != nil {
			t.Fatal(err)
		}
		workers.Go(manage)
		workers.Go(consume)
		synctest.Wait()
		current, created, _ := g.subscriptionStatus()
		if created != 1 {
			t.Fatal("Graph did not create and validate the callback")
		}
		first := current.ID
		good := notification(fixtureTenant, first, state, "")
		postEvents(t, client, http.StatusForbidden, good, notification(fixtureTenant, first, strings.Repeat("bad0", 16), ""))
		postEvents(t, client, http.StatusForbidden, notification("another-tenant", first, state, ""))
		postEvents(t, client, http.StatusForbidden, notification(fixtureTenant, "another-subscription", state, ""))
		bad := notification(fixtureTenant, first, state, "")
		bad["resourceData"] = map[string]any{"id": "../other"}
		postEvents(t, client, http.StatusBadRequest, bad)
		bad = notification(fixtureTenant, first, state, "")
		bad["resource"] = "https://untrusted.example.invalid/communications/callRecords/" + fixtureCall
		postEvents(t, client, http.StatusBadRequest, bad)
		code, _, _, err := sendFixture(ctx, client, http.MethodGet, "https://"+fixtureHost+"/api/config.json", nil)
		if err != nil || code != http.StatusNotFound {
			t.Fatalf("admin route was exposed: status %d, error %v", code, err)
		}
		synctest.Wait()
		if g.details != 0 || len(rec.LogRecords()) != 0 {
			t.Fatal("rejected batch triggered a fetch or emission")
		}

		// Notifications supply only the ID. A repeated notification fetches the
		// authoritative version again but emits that version only once.
		postEvents(t, client, http.StatusAccepted, good, good)
		synctest.Wait()
		assertLogs := func(versions ...string) {
			t.Helper()
			logs := rec.LogRecords()
			if len(logs) != len(versions) {
				t.Fatalf("emitted %d events, want %d", len(logs), len(versions))
			}
			for i, want := range versions {
				l := logs[i]
				if l.EventName != "teams.call" || l.Attrs["version"] != want || l.Attrs["call_id"] != fixtureCall ||
					l.Attrs["tenant_id"] != fixtureTenant || l.Attrs["ingest_transport"] != "graph" || !l.Timestamp.Equal(g.start) {
					t.Fatalf("unexpected call event %d: %+v", i, l)
				}
			}
		}
		assertLogs("2")
		cp, err := store.Load(fixtureTenant, callrecords.Name)
		if err != nil || !cp.Watermark.IsZero() || !cp.SeenIDs.Has(fixtureCall+":2") {
			t.Fatal("direct delivery must save the version without moving discovery")
		}
		pollTo := time.Now()
		poll := func() {
			t.Helper()
			if _, err := poller.CollectWindow(ctx, g.start.Add(-time.Minute), pollTo, emitter, recordoutcome.NewRecorder()); err != nil {
				t.Fatal(err)
			}
		}
		poll()
		assertLogs("2")
		g.version = 3 // Poll alone still discovers versions with no notification.
		poll()
		assertLogs("2", "3")
		before, err := store.Load(fixtureTenant, callrecords.Name)
		if err != nil {
			t.Fatal(err)
		}
		g.version = 4
		postEvents(t, client, http.StatusAccepted, good)
		synctest.Wait()
		assertLogs("2", "3", "4")
		after, err := store.Load(fixtureTenant, callrecords.Name)
		if err != nil || before.Watermark.IsZero() || !after.Watermark.Equal(before.Watermark) || !after.SeenIDs.Has(fixtureCall+":4") {
			t.Fatal("direct delivery changed the existing discovery watermark or lost dedupe")
		}

		// Time moves inside the bubble, not on the system clock. No lifecycle
		// event is needed to renew before expiry.
		expires := current.Expiration
		time.Sleep(time.Until(expires.Add(-renewBefore).Add(reconcileEvery)))
		synctest.Wait()
		current, _, renewed := g.subscriptionStatus()
		if renewed != 1 || current.ID != first || !current.Expiration.After(expires) {
			t.Fatal("subscription was not renewed before expiry")
		}
		time.Sleep(time.Second)
		postEvents(t, client, http.StatusAccepted, notification(fixtureTenant, first, state, "reauthorizationRequired"))
		synctest.Wait()
		current, _, renewed = g.subscriptionStatus()
		if renewed != 2 || current.ID != first {
			t.Fatal("reauthorisation did not renew the active subscription")
		}
		postEvents(t, client, http.StatusForbidden, notification(fixtureTenant, "another-subscription", state, "subscriptionRemoved"))
		// Graph removed the subscription. An authentic lifecycle event wakes
		// the manager immediately instead of waiting for the renewal deadline.
		g.removeSubscription()
		postEvents(t, client, http.StatusAccepted, notification(fixtureTenant, first, state, "subscriptionRemoved"))
		synctest.Wait()
		current, created, _ = g.subscriptionStatus()
		if created != 2 || current.ID == first {
			t.Fatal("removed subscription was not recreated")
		}
		postEvents(t, client, http.StatusForbidden, good)

		// Reuse after a process/receiver restart: listing returns no secret.
		cancel()
		workers.Wait()
		nextCtx, stopNext := context.WithCancel(t.Context())
		defer stopNext()
		next := New()
		restartClient, closeRestart := syntheticHTTPS(t, nextCtx, next)
		defer closeRestart()
		g.client = restartClient
		poller = fixtureCollector(t, g, store)
		manage, consume, err = next.AddTenant(nextCtx, fixtureTenant, secret, fixtureURL, g,
			func(ctx context.Context, id string) error {
				return poller.CollectCall(ctx, id, emitter, recordoutcome.NewRecorder())
			}, logger)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { stopNext(); workers.Wait() }()
		workers.Go(manage)
		workers.Go(consume)
		synctest.Wait()
		postEvents(t, restartClient, http.StatusAccepted, notification(fixtureTenant, current.ID, state, ""))
		synctest.Wait()
		_, created, _ = g.subscriptionStatus()
		if created != 2 {
			t.Fatal("restart created a duplicate subscription")
		}
		assertLogs("2", "3", "4")
	})
}

func TestNotificationQueueRejectsWholeBatchOnOverflow(t *testing.T) {
	ctx := t.Context()
	h := New()
	client, closeHTTPS := syntheticHTTPS(t, ctx, h)
	defer closeHTTPS()
	state := strings.Repeat("1a", 32)
	g := &graphFixture{client: client, state: state}
	entered := make(chan string, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, consume, err := h.AddTenant(ctx, fixtureTenant, config.Secret(state), fixtureURL, g,
		func(ctx context.Context, id string) error { entered <- id; <-ctx.Done(); return ctx.Err() }, logger)
	if err != nil {
		t.Fatal(err)
	}
	tenant := h.tenants[fixtureTenant]
	// Hold consumption by not starting the worker until after the offer;
	// shrink the fixture capacity so this can test the boundary in one batch.
	tenant.calls = make(chan string, 1)
	if err := h.reconcile(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	good := notification(fixtureTenant, g.current.ID, state, "")
	postEvents(t, client, http.StatusServiceUnavailable, good, good)
	postEvents(t, client, http.StatusAccepted, good) // the rejected batch did not fill the queue
	postEvents(t, client, http.StatusServiceUnavailable, good)
	consumeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tenant.ctx = consumeCtx
	var consumer sync.WaitGroup
	consumer.Go(consume)
	defer func() { cancel(); consumer.Wait() }()
	select {
	case got := <-entered:
		if got != fixtureCall {
			t.Fatal("accepted offer did not reach the worker as the call ID")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accepted offer did not reach the worker")
	}
}

func TestNotificationExpiredAndForeignSubscription(t *testing.T) {
	h := New()
	ctx := t.Context()
	g := &graphFixture{
		current: subscription{ID: "existing", Resource: resource, ChangeType: "updated", Notification: "https://other.example.invalid/notifications", Expiration: time.Now().Add(time.Hour)},
	}
	state := strings.Repeat("b2", 32)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, _, err := h.AddTenant(ctx, fixtureTenant, config.Secret(state), fixtureURL, g, nil, logger); err != nil {
		t.Fatal(err)
	}
	tenant := h.tenants[fixtureTenant]
	if err := h.reconcile(ctx, tenant); err == nil || g.creates != 0 || g.renewals != 0 || tenant.active.ID != "" {
		t.Fatal("did not fail closed on another callback's active subscription")
	}
	h.install(tenant, "", subscription{ID: "expired", Expiration: time.Now().Add(-time.Minute)})
	if got := h.offer([]delivery{{TenantID: fixtureTenant, SubscriptionID: "expired", ClientState: state, Lifecycle: "missed"}}); got != http.StatusForbidden {
		t.Fatalf("expired subscription status = %d, want 403", got)
	}
}

func TestNotificationMissingOnRenewal(t *testing.T) {
	h := New()
	now := time.Now()
	tenant := &tenant{active: subscription{ID: "missing", Expiration: now.Add(time.Hour)}, wake: make(chan struct{}, 1),
		graph: subscriptionFunc(func(context.Context, string, string, []byte) ([]byte, error) {
			return nil, &graphclient.HTTPStatusError{StatusCode: http.StatusNotFound}
		})}
	if err := h.reconcile(t.Context(), tenant); err == nil || tenant.active.ID != "" || len(tenant.wake) != 1 {
		t.Fatal("missing subscription did not clear the binding and schedule reconciliation")
	}
}

type subscriptionFunc func(context.Context, string, string, []byte) ([]byte, error)

func (f subscriptionFunc) RawSubscription(ctx context.Context, method, address string, body []byte) ([]byte, error) {
	return f(ctx, method, address, body)
}
