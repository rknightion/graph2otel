package annotations

import (
	"strings"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
)

// dedupeEndpoint is the checkpoint namespace the annotation dedupe set persists
// under, per tenant. It reuses internal/checkpoint rather than inventing a
// second on-disk format: the store is already atomic, already namespaced per
// (tenant, endpoint), and already lives on the persistent volume production
// installs must mount (#117). A dedupe set that only lived in memory would make
// every restart republish everything inside the source collectors' overlap
// windows, which is exactly the duplicate #400 forbids.
const dedupeEndpoint = "grafana-annotations"

// dedupeStore is the persisted per-tenant set of published annotation dedupe
// keys, scoped by rule so a rule can ask "have I ever seen anything?" — the
// question KindState's silent priming turns on.
//
// The persisted key is "<ruleID>|<hash>". Prefixing rather than nesting keeps
// the on-disk shape a plain checkpoint.SeenIDs (map[string]time.Time), which is
// what makes checkpoint.Checkpoint.EvictStale bound the set for free.
type dedupeStore struct {
	mu        sync.Mutex
	store     *checkpoint.Store
	retention time.Duration
	// states caches the loaded checkpoint per tenant. Load-per-observation would
	// re-read a file on every record.
	states map[string]*checkpoint.Checkpoint
	// dirty marks tenants whose set changed since the last Persist.
	dirty map[string]bool
}

func newDedupeStore(store *checkpoint.Store, retention time.Duration) *dedupeStore {
	return &dedupeStore{
		store:     store,
		retention: retention,
		states:    map[string]*checkpoint.Checkpoint{},
		dirty:     map[string]bool{},
	}
}

// dedupeKeyFor renders the persisted, rule-scoped form of a dedupe key.
func dedupeKeyFor(ruleID, key string) string { return ruleID + "|" + key }

// load returns the tenant's checkpoint, reading it from disk once. A read
// failure yields an empty in-memory set rather than an error: a lost dedupe set
// degrades to "may republish", and refusing to publish at all would be worse
// than the duplicate it prevents.
func (d *dedupeStore) load(tenantID string) *checkpoint.Checkpoint {
	if cp, ok := d.states[tenantID]; ok {
		return cp
	}
	cp, err := d.store.Load(tenantID, dedupeEndpoint)
	if err != nil || cp == nil {
		cp = &checkpoint.Checkpoint{
			TenantID: tenantID,
			Endpoint: dedupeEndpoint,
			SeenIDs:  checkpoint.NewSeenIDs(),
		}
	}
	if cp.SeenIDs == nil {
		cp.SeenIDs = checkpoint.NewSeenIDs()
	}
	cp.OverlapWindow = d.retention
	d.states[tenantID] = cp
	return cp
}

// SeenAny reports whether this (tenant, rule) has any remembered key at all.
// It is the cold-start question: a KindState rule with nothing remembered has no
// previous set to compare against, so its first observed set primes silently.
func (d *dedupeStore) SeenAny(tenantID, ruleID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	prefix := ruleID + "|"
	for key := range d.load(tenantID).SeenIDs {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// Claim records (tenantID, ruleID, key) as published and reports whether this
// caller won the claim. A second call with the same key returns false, which is
// the whole dedupe: the caller publishes only on true.
//
// eventTime is what the entry is evicted against, so it must be the SOURCE
// event time. Using arrival time would keep a re-delivered record's entry alive
// forever on a state stream and expire an event stream's too early.
func (d *dedupeStore) Claim(tenantID, ruleID, key string, eventTime time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := d.load(tenantID)
	stored := dedupeKeyFor(ruleID, key)
	if cp.SeenIDs.Has(stored) {
		// Refresh the entry's clock on a re-delivery so a state stream's
		// still-current identity cannot age out and be republished while it is
		// still being observed every tick.
		cp.SeenIDs.Add(stored, latest(cp.SeenIDs[stored], eventTime))
		d.dirty[tenantID] = true
		return false
	}
	cp.SeenIDs.Add(stored, eventTime)
	if eventTime.After(cp.Watermark) {
		cp.Watermark = eventTime
	}
	cp.EvictStale()
	d.dirty[tenantID] = true
	return true
}

// Persist flushes every dirty tenant's set. Errors are returned joined-free:
// the first failure is reported and the rest are still attempted, because a
// per-tenant file failure must not strand the others.
func (d *dedupeStore) Persist() error {
	d.mu.Lock()
	pending := make([]*checkpoint.Checkpoint, 0, len(d.dirty))
	for tenantID := range d.dirty {
		if cp, ok := d.states[tenantID]; ok {
			pending = append(pending, cp)
		}
		delete(d.dirty, tenantID)
	}
	d.mu.Unlock()

	var firstErr error
	for _, cp := range pending {
		if err := d.store.Save(cp); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
