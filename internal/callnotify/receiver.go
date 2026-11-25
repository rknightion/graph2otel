// Package callnotify accepts basic Teams call-record change notifications.
// The queue is a latency optimisation; polling owns discovery and recovery.
package callnotify

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

const (
	resource = "/communications/callRecords"
	stateLen = 64 // 32 random bytes, hex-encoded
	maxBody  = 128 << 10
	maxBatch = 128
	maxToken = 4096
)

// Receiver authenticates batches and atomically offers their call IDs to the
// relevant tenant queues. It never does Graph I/O on the HTTP path.
type Receiver struct {
	mu      sync.Mutex // guards membership, subscription bindings and batch admission
	tenants map[string]*tenant
	slots   chan struct{}
}

// New returns an empty notification handler that still answers validation.
func New() *Receiver {
	return &Receiver{tenants: make(map[string]*tenant), slots: make(chan struct{}, 32)}
}

type delivery struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	ClientState    string `json:"clientState"`
	Lifecycle      string `json:"lifecycleEvent"`
	ChangeType     string `json:"changeType"`
	Resource       string `json:"resource"`
	ResourceData   struct {
		ID string `json:"id"`
	} `json:"resourceData"`
}

func (h *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || r.URL.EscapedPath() != config.CallNotificationsPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		echoValidation(w, r.URL.RawQuery)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > maxBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	var batch struct {
		Value []delivery `json:"value"`
	}
	if err != nil || json.Unmarshal(body, &batch) != nil || len(batch.Value) == 0 || len(batch.Value) > maxBatch {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(h.offer(batch.Value))
}

func echoValidation(w http.ResponseWriter, rawQuery string) {
	if len(rawQuery) > len("validationToken=")+maxToken*3 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	query, err := url.ParseQuery(rawQuery)
	tokens := query["validationToken"]
	if err != nil || len(query) != 1 || len(tokens) != 1 || len(tokens[0]) == 0 || len(tokens[0]) > maxToken {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- Graph requires the exact echo; this is text/plain with nosniff, not HTML.
	_, _ = io.WriteString(w, tokens[0])
}

func (h *Receiver) offer(batch []delivery) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	targets := make([]*tenant, 0, len(batch))
	needed := make(map[*tenant]int)
	for _, event := range batch {
		t := h.tenants[strings.ToLower(event.TenantID)]
		if t == nil || !matchesState(t.state.Reveal(), event.ClientState) || t.ctx.Err() != nil ||
			t.active.ID == "" || event.SubscriptionID != t.active.ID || !t.active.Expiration.After(now) {
			return http.StatusForbidden
		}
		switch event.Lifecycle {
		case "":
			id := event.ResourceData.ID
			if !safeID(id) || strings.TrimPrefix(event.Resource, "/") != resource[1:]+"/"+id ||
				(event.ChangeType != "created" && event.ChangeType != "updated") {
				return http.StatusBadRequest
			}
			needed[t]++
		case "subscriptionRemoved", "reauthorizationRequired", "missed":
			// Lifecycle messages lack resource data. Their authority is scoped
			// to the same current tenant, state and subscription binding.
		default:
			return http.StatusBadRequest
		}
		targets = append(targets, t)
	}
	for t, n := range needed {
		if n > cap(t.calls)-len(t.calls) {
			return http.StatusServiceUnavailable
		}
	}
	// All producers hold mu, so only the consumer can change free capacity
	// after the preflight. A rejected batch never partially enqueues.
	for i, event := range batch {
		t := targets[i]
		switch event.Lifecycle {
		case "":
			t.calls <- event.ResourceData.ID
		case "subscriptionRemoved":
			t.removed = event.SubscriptionID
			t.active = subscription{}
			t.signal()
		case "reauthorizationRequired":
			t.reauthorize = true
			t.signal()
		case "missed":
			t.missed = true
			t.signal()
		}
	}
	return http.StatusAccepted
}

func matchesState(expected, actual string) bool {
	// The length is public and fixed; the contents are compared in constant time.
	return len(actual) == stateLen && subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func safeID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
