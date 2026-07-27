package annotations

import (
	"fmt"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Sink accepts annotations the Recorder decided to publish. Publisher is the
// production implementation; a test uses a slice.
//
// Publish MUST NOT block and MUST NOT return an error. That is not a
// convenience: the caller is a collector goroutine mid-poll, and an annotation
// writer that can make a Graph poll wait on Grafana has made a dashboard
// nicety into a collection dependency.
type Sink interface {
	Publish(Annotation)
	// Duplicate reports one occurrence suppressed because its dedupe key was
	// already published. It is counted rather than logged: on a state stream the
	// steady state is every record being a duplicate.
	Duplicate(tenantID string)
}

// runID identifies one collector run. It exists because a KindState rule needs
// to prime over exactly ONE run and then start publishing: the scheduler builds
// a fresh emitter per run (Scheduler.runEmitter), so Decorate is called once per
// run and can hand out a token that a mid-run re-evaluation cannot invalidate.
// Keying priming on a token rather than on "have I seen anything yet" is what
// makes it safe while several collectors for one tenant run concurrently.
type runID struct {
	tenant    string
	collector string
	seq       uint64
}

// Recorder turns emitted records into annotations: it matches the curated rules,
// applies dedupe, primes state streams, and buckets the categories configured to
// roll up. It is safe for concurrent use — every collector goroutine for every
// tenant emits through it.
type Recorder struct {
	cfg    config.GrafanaAnnotationsConfig
	sink   Sink
	now    func() time.Time
	dedupe *dedupeStore

	// byEvent indexes the closed rule set by source event name, so a record that
	// is not annotatable costs one map lookup on the emit path.
	byEvent map[string][]Rule

	mu sync.Mutex
	// runSeq is the per-(tenant, collector) run counter Decorate hands out.
	runSeq map[string]uint64
	// primeRun records, per (tenant, rule), the single run during which a state
	// rule primes silently. Absent means "not yet decided".
	primeRun map[string]runID
	// buckets holds the open rollup buckets.
	buckets map[bucketKey]*bucket
	// license is the per-tenant subscribed-SKU comparison state.
	license map[string]*licenseState
	// licensePending accumulates the two license gauge snapshots of one run.
	licensePending map[string]*licenseObservation
}

// RecorderOptions are the Recorder's dependencies. Now defaults to time.Now.
type RecorderOptions struct {
	Config config.GrafanaAnnotationsConfig
	Sink   Sink
	Dedupe *dedupeStore
	Now    func() time.Time
}

// NewRecorder builds a Recorder over the curated rule set.
func NewRecorder(opts RecorderOptions) *Recorder {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	byEvent := map[string][]Rule{}
	for _, rule := range Rules() {
		byEvent[rule.EventName] = append(byEvent[rule.EventName], rule)
	}
	return &Recorder{
		cfg:            opts.Config,
		sink:           opts.Sink,
		now:            now,
		dedupe:         opts.Dedupe,
		byEvent:        byEvent,
		runSeq:         map[string]uint64{},
		primeRun:       map[string]runID{},
		buckets:        map[bucketKey]*bucket{},
		license:        map[string]*licenseState{},
		licensePending: map[string]*licenseObservation{},
	}
}

// BeginRun allocates the run token for one collector run.
func (r *Recorder) BeginRun(tenantID, collector string) runID {
	key := tenantID + "\x00" + collector
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runSeq[key]++
	return runID{tenant: tenantID, collector: collector, seq: r.runSeq[key]}
}

// enabled reports whether a category is switched on.
func (r *Recorder) enabled(category Category) bool {
	return r.categoryConfig(category).Enabled
}

// rollsUp reports whether a category aggregates per interval.
func (r *Recorder) rollsUp(category Category) bool {
	return r.categoryConfig(category).Rollup
}

func (r *Recorder) categoryConfig(category Category) config.AnnotationCategoryConfig {
	switch category {
	case CategoryConfigPosture:
		return r.cfg.Categories.ConfigPosture
	case CategorySecurityIncident:
		return r.cfg.Categories.SecurityIncident
	case CategoryServiceHealth:
		return r.cfg.Categories.ServiceHealth
	case CategoryLicense:
		return r.cfg.Categories.License
	case CategoryLifecycle:
		// The lifecycle marker is the startup write probe: it is published
		// whenever the writer is configured at all, and has no category gate for
		// the same reason graph2otel.startup has no config key (#310) — a toggle's
		// only real effect would be a deployment whose markers silently stop.
		return config.AnnotationCategoryConfig{Enabled: true, Rollup: false}
	default:
		return config.AnnotationCategoryConfig{}
	}
}

// ObserveEvent offers one emitted log record to the curated rule set.
//
// It never mutates ev, never returns an error and never drops the record from
// the telemetry pipeline — the caller (Tee) has already forwarded it. The worst
// case here is no annotation.
func (r *Recorder) ObserveEvent(run runID, ev telemetry.Event) {
	rules, ok := r.byEvent[ev.Name]
	if !ok {
		return
	}
	eventTime := ev.Timestamp
	if eventTime.IsZero() {
		// A snapshot log twin carries no event time (telemetry stamps arrival).
		// Observation time is then the only honest answer, and unlike a log record
		// it cannot misdate anything a query joins on — an annotation with no time
		// cannot exist at all.
		eventTime = r.now()
	}
	for _, rule := range rules {
		if !r.enabled(rule.Category) {
			continue
		}
		if rule.Match != nil && !rule.Match(ev.Attrs) {
			continue
		}
		identity := make([]string, 0, len(rule.Identity))
		for _, key := range rule.Identity {
			identity = append(identity, attrString(ev.Attrs, key))
		}
		key := DedupeKey(run.tenant, rule.ID, identity...)
		priming := r.claimPrimeRun(run, rule)
		if !r.dedupe.Claim(run.tenant, rule.ID, key, eventTime) {
			r.sink.Duplicate(run.tenant)
			continue
		}
		if priming {
			// Remembered, deliberately not published. See KindState.
			continue
		}
		r.emit(Annotation{
			Category:  rule.Category,
			TenantID:  run.tenant,
			RuleID:    rule.ID,
			Time:      eventTime,
			Text:      renderText(rule, ev.Attrs),
			DedupeKey: key,
			Severity:  attrString(ev.Attrs, rule.SeverityAttr),
		}, rule.Title(ev.Attrs))
	}
}

// claimPrimeRun reports whether this record falls inside rule's silent priming
// run. Only KindState rules prime; a KindEvent record is always a real
// occurrence, so priming it would lose the first event after every cold start.
//
// The priming run is the collector's FIRST run of this process (seq == 1), not
// "the first run in which this rule matched". That distinction is the whole
// correctness of it: m365.service_health_issue feeds two rules, and a tenant
// with nothing resolved yet would otherwise make run 5 — the run carrying the
// first genuine resolution — the resolved rule's priming run, silently swallowing
// exactly the event an operator was waiting for.
//
// A warm restart does not prime, because the persisted set IS the previous set
// and anything absent from it changed during downtime. The one residual gap is a
// state rule that has NEVER fired: its first run after a restart primes again, so
// a first-ever occurrence landing in that one tick is not annotated. That is one
// tick, once, versus annotating every pre-existing entity at once.
func (r *Recorder) claimPrimeRun(run runID, rule Rule) bool {
	if rule.Kind != KindState {
		return false
	}
	key := run.tenant + "\x00" + rule.ID
	r.mu.Lock()
	defer r.mu.Unlock()
	if decided, ok := r.primeRun[key]; ok {
		return decided == run
	}
	if run.seq != 1 || r.dedupe.SeenAny(run.tenant, rule.ID) {
		r.primeRun[key] = runID{}
		return false
	}
	r.primeRun[key] = run
	return true
}

// emit routes an annotation either straight to the sink or into its category's
// rollup bucket.
func (r *Recorder) emit(a Annotation, title string) {
	if !r.rollsUp(a.Category) {
		r.sink.Publish(a)
		return
	}
	start := a.Time.Truncate(r.cfg.RollupInterval).UTC()
	k := bucketKey{tenant: a.TenantID, category: a.Category, start: start}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[k]
	if !ok {
		b = &bucket{titles: map[string]int{}}
		r.buckets[k] = b
	}
	b.count++
	if title == "" {
		title = a.RuleID
	}
	b.titles[title]++
}

// Flush publishes every rollup bucket whose interval has closed by now. It is
// driven by the publisher's ticker; Close calls FlushAll so a shutdown does not
// silently discard the open bucket.
func (r *Recorder) Flush(now time.Time) { r.flush(now, false) }

// FlushAll publishes every open bucket regardless of whether its interval has
// closed.
func (r *Recorder) FlushAll() { r.flush(r.now(), true) }

func (r *Recorder) flush(now time.Time, all bool) {
	interval := r.cfg.RollupInterval
	r.mu.Lock()
	type due struct {
		key bucketKey
		b   *bucket
	}
	var ready []due
	for k, b := range r.buckets {
		if all || !now.Before(k.start.Add(interval)) {
			ready = append(ready, due{key: k, b: b})
			delete(r.buckets, k)
		}
	}
	r.mu.Unlock()

	for _, d := range ready {
		if d.b.count == 0 {
			continue
		}
		end := d.key.start.Add(interval)
		key := DedupeKey(d.key.tenant, rollupRuleID(d.key.category),
			d.key.start.UTC().Format(time.RFC3339))
		if !r.dedupe.Claim(d.key.tenant, rollupRuleID(d.key.category), key, d.key.start) {
			r.sink.Duplicate(d.key.tenant)
			continue
		}
		r.sink.Publish(Annotation{
			Category:  d.key.category,
			TenantID:  d.key.tenant,
			RuleID:    rollupRuleID(d.key.category),
			Time:      d.key.start,
			TimeEnd:   end,
			Text:      fmt.Sprintf("%d %s events: %s", d.b.count, d.key.category, summarize(d.b.titles)),
			DedupeKey: key,
		})
	}
}

// rollupRuleID is the rule id a rolled-up annotation carries. It is distinct
// from every member rule's id so a dashboard query can select either the
// per-event markers or the interval summaries, and so a rollup's dedupe key can
// never collide with a member's.
func rollupRuleID(category Category) string { return string(category) + ".rollup" }

type bucketKey struct {
	tenant   string
	category Category
	start    time.Time
}

type bucket struct {
	count  int
	titles map[string]int
}
