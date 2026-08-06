package telemetry

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rknightion/graph2otel/internal/semconv"
)

const metricAttrsTruncated = "graph2otel.event.attrs_truncated"

// MaxAttributeBytes is how many bytes of log-record attributes may reach the
// exporter. Anything larger is clipped to fit rather than sent and refused.
//
// Loki caps one entry's STRUCTURED METADATA at 65536 bytes
// (`max_structured_metadata_size`), counted as the sum of every key's and every
// value's length, and refuses the entry with a per-entry HTTP 400 when it is
// exceeded — observed on camden 2026-08-06 at '135305' and '74478' bytes
// against that limit (#419). The refused entry is lost; nothing retries it.
//
// The budget sits below 65536 because this guard does not see everything Loki
// counts. The OTLP-to-Loki translation folds the RESOURCE attributes and the
// instrumentation scope name into the same entry's structured metadata, and two
// decorators (WithTenant, WithTransport) stamp their attributes downstream of
// this one. Live-measured on m7kni 2026-08-06, that unseen set runs 627-653
// bytes per record. 60000 clears it with room for a longer host name, a new
// resource attribute, or a future stamp — the same reasoning as EventHorizon's
// three-hour margin, and for the same reason: a guard set at exactly the limit
// still loses records.
const MaxAttributeBytes = 60000

// markerReserve is the slice of the budget held back for the clip markers
// themselves (attrs.truncated, attrs.truncated_bytes, attrs.truncated_keys,
// attrs.dropped). They are added AFTER clipping, so their own bytes have to be
// paid for out of the budget or the guard would hand the exporter a record just
// over the line it was built to keep it under.
const markerReserve = 1024

// attrBudgetEmitter clips oversized log-record attribute sets to fit the
// backend's structured-metadata limit, counting each clip, and passes
// everything else through untouched.
//
// Why clip rather than drop: the project's hard rule is that a record which
// cannot be carried perfectly is DEGRADED, never discarded (#114 — "not a metric
// label means log twin, never dropped"). A 135 KB record is refused whole by the
// backend, so the choice is not "complete record or clipped record", it is
// "clipped record or no record at all". Every attribute survives, and every
// small attribute survives INTACT: a clipped `additional_fields` still names the
// device, the account, and the action, which is most of what the record was for.
//
// Why here and not in the collectors: the limit is a property of the sink, not
// of any one Graph field, and it is the total that matters — a record can exceed
// it with no single attribute anywhere near it. A per-collector cap would have
// to be re-derived in ~130 places and would still miss the sum. This is the one
// boundary every record crosses, which is the same argument horizon.go makes.
//
// Why it does not drop attributes by name: an "awkward to model" argument is not
// an "unsafe to ship" argument, and acting on the first has shipped a real data
// gap on this project three times. The only content exclusion in graph2otel is
// secrets (intune/auditevents' modifiedProperties VALUES); size is not one.
//
// One caveat about accounting, shared with the horizon guard: the owning
// collector counted this record as emitted before it reached here, and it still
// is emitted — clipped, not lost. `graph2otel.event.attrs_truncated` is the
// statement that some of its content did not make it, and
// semconv.AttrAttrsTruncatedKeys on the record itself names which.
type attrBudgetEmitter struct {
	Emitter
	budget           int
	collector        string
	tenant           string
	defaultTransport Transport
}

// WithAttributeBudget returns an emitter that clips a log record's attributes to
// budget bytes before emitting it. A zero or negative budget disables the guard,
// which is what a self-hosted Loki or a non-Loki OTLP sink with no
// structured-metadata limit wants.
func WithAttributeBudget(
	e Emitter,
	budget int,
	collector, tenant string,
	defaultTransport Transport,
) Emitter {
	return &attrBudgetEmitter{
		Emitter:          e,
		budget:           budget,
		collector:        collector,
		tenant:           tenant,
		defaultTransport: defaultTransport,
	}
}

// gaugeSnapshotFor forwards the tenant scope carried by an outer WithTenant
// decorator. Every in-package Emitter decorator must preserve this private
// scope even when it otherwise passes metrics through unchanged.
func (e *attrBudgetEmitter) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {
	snapshotFor(e.Emitter, tenant, name, unit, desc, points)
}

func (e *attrBudgetEmitter) LogEvent(ev Event) {
	if e.budget <= 0 || attrsBytes(ev.Attrs) <= e.budget {
		e.Emitter.LogEvent(ev)
		return
	}

	// Read the transport from the ORIGINAL attributes: the clip can empty a value
	// in the pathological branch, and a metric point that loses its attribution
	// because the record was too big is exactly the wrong failure here.
	transport := e.defaultTransport
	if stamped, ok := ev.Attrs[semconv.AttrIngestTransport].(string); ok && stamped != "" {
		transport = Transport(stamped)
	}

	reserve := min(markerReserve, e.budget/2)
	clipped := clipAttrs(ev.Attrs, e.budget-reserve)
	ev.Attrs = clipped.attrs
	ev.Attrs[semconv.AttrAttrsTruncated] = "true"
	ev.Attrs[semconv.AttrAttrsTruncatedBytes] = strconv.Itoa(clipped.removedBytes)
	if keys := joinKeys(clipped.clippedKeys, min(maxClippedKeysBytes, reserve-fixedMarkerBytes)); keys != "" {
		ev.Attrs[semconv.AttrAttrsTruncatedKeys] = keys
	}
	if clipped.dropped > 0 {
		ev.Attrs[semconv.AttrAttrsDropped] = strconv.Itoa(clipped.dropped)
	}
	e.Emitter.LogEvent(ev)

	attrs := Attrs{
		semconv.AttrCollector:       e.collector,
		semconv.AttrIngestTransport: string(transport),
	}
	if e.tenant != "" {
		attrs[semconv.AttrTenantID] = e.tenant
	}
	// Deliberately NOT attributed by event name or by attribute key: this metric
	// has to be cheap enough to always be on, the collector already identifies
	// which stream is affected, and the offending FIELD is on the record itself.
	e.Counter(
		metricAttrsTruncated,
		semconv.UnitRecords,
		"Log records whose attributes were clipped to fit the backend's structured-metadata "+
			"size limit. The record was still delivered; some attribute content was not.",
		1,
		attrs,
	)
}

// attrsBytes measures an attribute set the way Loki measures structured
// metadata: the sum of every key's length and every RENDERED value's length.
// The rendering goes through logKV, so it is byte-for-byte what the exporter
// will carry rather than a second guess at it.
func attrsBytes(attrs Attrs) int {
	n := 0
	for k, v := range attrs {
		n += len(k) + len(logKV(k, v).Value.String())
	}
	return n
}

// clipResult is the outcome of fitting one attribute set into a budget.
type clipResult struct {
	attrs        Attrs
	clippedKeys  []string
	dropped      int
	removedBytes int
}

// clipAttrs returns a COPY of attrs sized to fit budget bytes. The caller's map
// is never modified: collectors reuse and re-read the maps they build, and
// several assert on them in their own tests.
//
// The fit is water-filling, not greedy: it finds the single largest value
// ceiling under which the whole set fits, then clips every value above it to
// that ceiling. Small attributes are therefore untouched however far over budget
// the record is, and two equally huge values are clipped equally rather than one
// being sacrificed to spare the other.
func clipAttrs(attrs Attrs, budget int) clipResult {
	if budget < 0 {
		budget = 0
	}

	type entry struct {
		key   string
		value any
		size  int // rendered value length
	}
	entries := make([]entry, 0, len(attrs))
	sizes := make([]int, 0, len(attrs))
	keyBytes := 0
	for k, v := range attrs {
		size := len(logKV(k, v).Value.String())
		entries = append(entries, entry{key: k, value: v, size: size})
		sizes = append(sizes, size)
		keyBytes += len(k)
	}
	// Deterministic order so a repeated record clips identically. Map iteration
	// order is random, and a guard whose output changes run to run is a guard
	// nobody can reason about from two samples.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	out := make(Attrs, len(attrs))
	res := clipResult{attrs: out}

	if keyBytes > budget {
		// Pathological: the KEYS alone do not fit, so no value ceiling can save
		// this record. Keep as many whole attributes as the budget allows,
		// shortest key first (most attributes retained), and count the rest.
		// Losing dimensions is a real loss — but it is this record's dimensions,
		// not the record, and the record is what must survive.
		sort.SliceStable(entries, func(i, j int) bool { return len(entries[i].key) < len(entries[j].key) })
		spent := 0
		for _, en := range entries {
			if spent+len(en.key) > budget {
				res.dropped++
				res.removedBytes += len(en.key) + en.size
				continue
			}
			spent += len(en.key)
			out[en.key] = ""
			res.removedBytes += en.size
			res.clippedKeys = append(res.clippedKeys, en.key)
		}
		sort.Strings(res.clippedKeys)
		return res
	}

	ceiling := valueCeiling(sizes, budget-keyBytes)
	for _, en := range entries {
		if en.size <= ceiling {
			out[en.key] = en.value
			continue
		}
		clippedValue, kept := clipValue(en.value, ceiling)
		out[en.key] = clippedValue
		res.removedBytes += en.size - kept
		res.clippedKeys = append(res.clippedKeys, en.key)
	}
	return res
}

// valueCeiling returns the largest per-value length C for which
// sum(min(size_i, C)) <= budget. Sizes may be in any order.
func valueCeiling(sizes []int, budget int) int {
	if budget <= 0 {
		return 0
	}
	lo, hi := 0, 0
	for _, s := range sizes {
		if s > hi {
			hi = s
		}
	}
	for lo < hi {
		mid := (lo + hi + 1) / 2
		total := 0
		for _, s := range sizes {
			total += min(s, mid)
		}
		if total <= budget {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// clipValue shortens one attribute value to at most ceiling rendered bytes,
// returning the replacement and how many bytes it renders to.
//
// A []string is clipped by dropping trailing ELEMENTS, never mid-element: the
// value renders as a comma join, so a byte cut would leave a half-written last
// entry that reads exactly like a real one. A string is cut on a UTF-8 rune
// boundary for the same reason — a severed multi-byte rune is not a shorter
// value, it is an invalid one.
func clipValue(v any, ceiling int) (any, int) {
	if list, ok := v.([]string); ok {
		total, keep := 0, 0
		for i, item := range list {
			next := total + len(item)
			if i > 0 {
				next++ // the joining comma
			}
			if next > ceiling {
				break
			}
			total = next
			keep = i + 1
		}
		return list[:keep], total
	}
	s := logKV("", v).Value.String()
	if len(s) <= ceiling {
		return s, len(s)
	}
	cut := ceiling
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], cut
}

// maxClippedKeysBytes bounds the rendered attrs.truncated_keys marker. The
// markers are paid for out of markerReserve, and a pathological record can clip
// hundreds of keys, so the list that names them has to be bounded too or the
// diagnostic would push the record back over the line it was clipped to clear.
const maxClippedKeysBytes = 900

// fixedMarkerBytes is what the non-list markers cost: attrs.truncated (15+4),
// attrs.truncated_bytes (21 + up to 7 digits), attrs.dropped (13 + up to 7
// digits) and the attrs.truncated_keys key itself (20), rounded up. Subtracting
// it from the reserve is what leaves the key list a budget it cannot overrun.
const fixedMarkerBytes = 96

// joinKeys renders the clipped-key list as a comma join within budget bytes,
// with a "+N" tail when it does not fit. The tail matters: a silently shortened
// list of which attributes were shortened would be the same defect one level up.
func joinKeys(keys []string, budget int) string {
	if len(keys) == 0 || budget <= 0 {
		return ""
	}
	var b strings.Builder
	for i, k := range keys {
		next := len(k)
		if i > 0 {
			next++
		}
		if b.Len()+next > budget {
			return b.String() + ",+" + strconv.Itoa(len(keys)-i)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
	}
	return b.String()
}
