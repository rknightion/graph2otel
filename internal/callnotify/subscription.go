package callnotify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
)

const (
	subscriptionsURL = "https://graph.microsoft.com/v1.0/subscriptions"
	changeType       = "updated"
	lifetime         = 69 * time.Hour // below Graph's documented 4,230-minute maximum
	renewBefore      = 12 * time.Hour
	reconcileEvery   = time.Minute
	requestTimeout   = 30 * time.Second
	collectTimeout   = 2 * time.Minute
	queueCapacity    = 128
)

// ReadClientState requires a mounted file containing 32 random bytes encoded
// as 64 hex characters. Error messages deliberately omit the file and value.
func ReadClientState(path string) (config.Secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open call notification client_state_file")
	}
	defer f.Close()
	const limit = stateLen + 8
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	value := strings.TrimSpace(string(b))
	if err != nil || len(b) > limit || len(value) != stateLen {
		return "", errors.New("call notification client_state_file must contain 64 hex characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("call notification client_state_file must contain 64 hex characters")
	}
	return config.Secret(value), nil
}

// Graph manages subscriptions through the same authenticated tenant client as
// the poller. No callback data is accepted as a Graph URL.
type Graph interface {
	RawSubscription(context.Context, string, string, []byte) ([]byte, error)
}

type subscription struct {
	ID           string    `json:"id,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	ChangeType   string    `json:"changeType,omitempty"`
	Notification string    `json:"notificationUrl,omitempty"`
	Lifecycle    string    `json:"lifecycleNotificationUrl,omitempty"`
	Expiration   time.Time `json:"expirationDateTime"`
	Rich         bool      `json:"includeResourceData,omitempty"`
}

type tenant struct {
	ctx     context.Context
	graph   Graph
	url     string
	state   config.Secret
	calls   chan string
	wake    chan struct{}
	collect func(context.Context, string) error
	logger  *slog.Logger

	// Below: accessed only under the receiver's lock. Network calls never
	// hold the lock. HTTP removal wins over an in-flight renewal.
	active      subscription
	removed     string
	reauthorize bool
	missed      bool
}

// AddTenant connects one already gated call-record poller. The caller must
// launch both returned workers and join them after ctx ends.
func (h *Receiver) AddTenant(ctx context.Context, tenantID string, state config.Secret, callback string, graph Graph, collect func(context.Context, string) error, logger *slog.Logger) (manage, consume func(), err error) {
	key := strings.ToLower(tenantID)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.tenants[key]; exists || len(state.Reveal()) != stateLen {
		return nil, nil, errors.New("duplicate tenant or invalid call notification client state")
	}
	for _, existing := range h.tenants {
		if matchesState(existing.state.Reveal(), state.Reveal()) {
			return nil, nil, errors.New("call notification client state must be distinct per tenant")
		}
	}
	t := &tenant{
		ctx: ctx, graph: graph, url: callback, state: state,
		calls: make(chan string, queueCapacity), wake: make(chan struct{}, 1),
		collect: collect, logger: logger,
	}
	h.tenants[key] = t
	return func() { h.manage(t) }, t.consume, nil
}

func (t *tenant) signal() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tenant) consume() {
	for t.ctx.Err() == nil {
		select {
		case <-t.ctx.Done():
			return
		case id := <-t.calls:
			ctx, cancel := context.WithTimeout(t.ctx, collectTimeout)
			err := t.collect(ctx, id)
			cancel()
			if err != nil && t.ctx.Err() == nil {
				t.logger.Warn("call notification fetch failed; polling remains active")
			}
		}
	}
}

func (h *Receiver) manage(t *tenant) {
	for t.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(t.ctx, requestTimeout)
		err := h.reconcile(ctx, t)
		cancel()
		delay := reconcileEvery
		var wake <-chan struct{} = t.wake
		if err != nil && t.ctx.Err() == nil {
			// In particular, POST errors can reflect clientState or URLs.
			var status *graphclient.HTTPStatusError
			if errors.As(err, &status) {
				t.logger.Warn("call notification subscription unavailable; polling remains active", "status", status.StatusCode)
				if status.RetryAfter > delay {
					delay, wake = status.RetryAfter, nil
				}
			} else {
				t.logger.Warn("call notification subscription unavailable; polling remains active")
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-t.ctx.Done():
		case <-timer.C:
		case <-wake:
		}
		timer.Stop()
	}
}

func (h *Receiver) reconcile(ctx context.Context, t *tenant) error {
	now := time.Now().UTC()
	h.mu.Lock()
	if !t.active.Expiration.After(now) {
		t.active = subscription{}
	}
	active, removed := t.active, t.removed
	reauthorize, missed := t.reauthorize, t.missed
	t.reauthorize, t.missed = false, false
	h.mu.Unlock()

	if missed {
		t.logger.Warn("Graph reported missed call notifications; polling remains active")
	}
	if active.ID != "" && !reauthorize && active.Expiration.After(now.Add(renewBefore)) {
		return nil
	}

	if active.ID == "" {
		current, err := t.find(ctx, now, removed)
		if err != nil {
			return err
		}
		if current.ID != "" {
			// Bind before renewal, so a slow PATCH doesn't prevent delivery.
			h.install(t, "", current)
			if current.Expiration.After(now.Add(renewBefore)) {
				return nil
			}
			active = current
		} else {
			created, err := t.create(ctx, now)
			if err == nil {
				h.install(t, "", created)
			}
			return err
		}
	}

	renewed, err := t.write(ctx, http.MethodPatch, subscriptionsURL+"/"+active.ID,
		subscription{Expiration: now.Add(lifetime)}, "", now)
	if err != nil {
		var status *graphclient.HTTPStatusError
		if errors.As(err, &status) && (status.StatusCode == http.StatusNotFound || status.StatusCode == http.StatusGone) {
			h.mu.Lock()
			if t.active.ID == active.ID {
				t.removed = active.ID
				t.active = subscription{}
			}
			h.mu.Unlock()
			t.signal() // list and recreate on the next pass
		} else if reauthorize {
			h.mu.Lock()
			t.reauthorize = t.reauthorize || t.active.ID == active.ID
			h.mu.Unlock()
		}
		return err
	}
	if renewed.ID != active.ID {
		return errors.New("Graph returned a different subscription ID on renewal")
	}
	h.install(t, active.ID, renewed)
	return nil
}

func (h *Receiver) install(t *tenant, expected string, next subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t.active.ID == expected && (next.ID == "" || next.ID != t.removed) {
		t.active = next
	}
}

func (t *tenant) find(ctx context.Context, now time.Time, removed string) (subscription, error) {
	address := subscriptionsURL
	var found subscription
	// A complete list is required before creating. Do not follow an arbitrary
	// next link, and bound pagination even if Graph keeps sending more links.
	for range 20 {
		body, err := t.graph.RawSubscription(ctx, http.MethodGet, address, nil)
		if err != nil {
			return subscription{}, err
		}
		var page struct {
			Value []subscription `json:"value"`
			Next  string         `json:"@odata.nextLink"`
		}
		if json.Unmarshal(body, &page) != nil || page.Value == nil {
			return subscription{}, errors.New("invalid Graph subscription list")
		}
		for _, s := range page.Value {
			if !strings.EqualFold(strings.TrimPrefix(s.Resource, "/"), resource[1:]) || !s.Expiration.After(now) ||
				!slices.Contains(strings.Split(s.ChangeType, ","), changeType) {
				continue
			}
			// List is scoped to this Graph application and tenant, and does
			// not return clientState. Reuse only the identical basic callback.
			// A foreign callback, a duplicate, or a removed ID still visible
			// in the list is never patched or deleted by this process.
			if s.ID == removed || s.Notification != t.url || s.Lifecycle != t.url || s.ChangeType != changeType || s.Rich ||
				!safeID(s.ID) || found.ID != "" {
				return subscription{}, errors.New("conflicting Graph call notification subscription")
			}
			found = s
		}
		if page.Next == "" {
			return found, nil
		}
		u, err := url.Parse(page.Next)
		if err != nil || u.Scheme != "https" || u.Host != "graph.microsoft.com" || u.EscapedPath() != "/v1.0/subscriptions" ||
			u.User != nil || u.Fragment != "" || u.RawQuery == "" {
			return subscription{}, errors.New("invalid Graph subscription next link")
		}
		address = page.Next
	}
	return subscription{}, errors.New("Graph subscription list exceeded page limit")
}

func (t *tenant) create(ctx context.Context, now time.Time) (subscription, error) {
	return t.write(ctx, http.MethodPost, subscriptionsURL, subscription{
		Resource: resource, ChangeType: changeType, Notification: t.url,
		Lifecycle: t.url, Expiration: now.Add(lifetime),
	}, t.state.Reveal(), now)
}

func (t *tenant) write(ctx context.Context, method, address string, fields subscription, state string, now time.Time) (subscription, error) {
	payload := struct {
		subscription
		ClientState string `json:"clientState,omitempty"`
	}{fields, state}
	body, err := json.Marshal(payload)
	if err != nil {
		return subscription{}, err
	}
	result, err := t.graph.RawSubscription(ctx, method, address, body)
	if err != nil {
		return subscription{}, err
	}
	var s subscription
	if json.Unmarshal(result, &s) != nil || !safeID(s.ID) || !s.Expiration.After(now) {
		return subscription{}, errors.New("invalid Graph subscription response")
	}
	return s, nil
}
