package telemetry

import (
	"context"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// This file owns graph2otel's log event-DOMAIN split (#402).
//
// # Why a resource attribute, and why it forces a provider per domain
//
// Grafana Loki will only promote a RESOURCE attribute to a stream label. A
// single hot stream carrying every log this process emits shards on write and
// is expensive to query by kind, so #402 asks for one coarse dimension —
// graph2otel.event_domain — that an operator can select on.
//
// In the OpenTelemetry Go SDK a resource belongs to the LoggerProvider, not to
// the record: sdklog.Record has a Resource() getter and NO setter, because the
// resource is stamped by the provider that created the logger. So a resource
// attribute that VARIES per record — which is the entire point of this one —
// cannot be set on the record. The only way to vary it inside the SDK's model
// is to build one LoggerProvider per value. That is what provider.go does, and
// it is why this set must be CLOSED and known at startup: a provider is
// constructed per value before any record exists, so the set can never be
// discovered from the data.
//
// The alternative routes were considered and rejected on #402: partitioning
// ResourceLogs inside the vendored third_party/otlploghttp fork (fast to ship,
// expensive to own through an upstream rebase), and lifting the attribute in a
// downstream collector hop (not a repo change, and there is no collector hop).
//
// # Why the first name segment
//
// Domain derivation is deliberately identical to internal/signalcatalog's
// domainOf — the first dot-separated segment of the event name. That is not a
// coincidence to be tidied away: the catalog is the artifact the closed-set
// test checks this file against, and two different derivations would let a
// record be ROUTED to one domain while being CATALOGED under another, which
// is worse than having no split at all. The segments are exactly the telemetry
// namespaces CLAUDE.md already mandates (entra / intune / m365 / purview /
// defender / mdca for domain signals, graph2otel for self-observability), so
// the split costs no new naming decision.
//
// This attribute rides the LOGS resource only. It is deliberately absent from
// the metrics resource: a resource attribute participates in metric series
// identity, and splitting the metrics resource would fork every self-obs series
// by domain for no query benefit (#82).

// ResourceAttrEventDomain is the logs-resource attribute key carrying the
// coarse event domain. Namespaced under graph2otel.* because it describes the
// producing process's own partitioning of its output, not anything Microsoft
// returned.
const ResourceAttrEventDomain = "graph2otel.event_domain"

// EventDomainOther is the fallback domain for an event name whose namespace is
// not in the closed set below.
//
// It exists for a runtime reason a closed set cannot cover on its own: an
// uncataloged or malformed event name must still be EMITTED. Every record is
// produced by some LoggerProvider and therefore necessarily carries some
// resource, so there is no "unrouted" state available — the choice is between a
// named bucket and dropping the record, and dropping would make a new
// collector silently invisible. TestEventDomainsIsClosedAndCoversTheCatalogue
// asserts that nothing cataloged actually lands here, so a value appearing in
// this bucket in production means a genuinely new namespace shipped without
// updating eventDomains.
const EventDomainOther = "other"

// eventDomains is the closed set of domains a LoggerProvider is built for. Kept
// sorted to match the catalog's own ordering, which makes a diff between the
// two readable.
//
// Adding a collector in a NEW top-level namespace means adding it here in the
// same commit; the catalog test fails loudly otherwise.
var eventDomains = []string{
	"defender",
	"entra",
	"graph2otel",
	"intune",
	"m365",
	"mdca",
	"purview",
	EventDomainOther,
}

// EventDomains returns the closed domain set, including the fallback. The
// caller receives a copy: provider construction ranges over this to build one
// LoggerProvider per value, and a shared backing array would let a caller
// silently reorder or corrupt the routing table.
func EventDomains() []string { return slices.Clone(eventDomains) }

// EventDomain maps an event name to its domain, falling back to
// EventDomainOther for anything outside the closed set. Derivation matches
// internal/signalcatalog's domainOf exactly — see the file comment for why that
// is load-bearing rather than incidental.
func EventDomain(name string) string {
	i := strings.IndexByte(name, '.')
	if i <= 0 {
		return EventDomainOther
	}
	d := name[:i]
	if !slices.Contains(eventDomains, d) {
		return EventDomainOther
	}
	return d
}

// domainQueueSize is the per-domain BatchProcessor queue depth.
//
// This number is the whole cost of the per-domain split, so it is set here
// deliberately rather than left at the SDK default. The SDK default is 2048
// records PER PROCESSOR, and there is now one processor per domain — so
// leaving it alone would multiply the process's worst-case buffered log set by
// len(eventDomains), from ~2k records to ~16k. graph2otel's reference
// deployment runs under `mem_limit: 256m` with `GOMEMLIMIT=230MiB`, and a
// worst case is not hypothetical: it is exactly what an OTLP outage produces,
// with every queue filling at once while nothing drains.
//
// 512 x len(eventDomains) = ~4k records worst case, twice today's total
// capacity rather than eight times it. At graph2otel's typical record size
// that is single-digit MB; at the largest record this project emits (a
// service-health post, truncated at 8 KiB) the absolute worst case is ~32 MiB,
// which fits inside GOMEMLIMIT with room for the rest of the process.
//
// The trade accepted here: the hottest domain can buffer 512 rather than the
// 2048 it could previously claim from the shared queue. That only bites during
// an export stall, and the alternative — a larger per-domain queue — spends
// memory on all eight queues to protect one. If camden ever shows log records
// dropping under stall, this is the first knob to raise, and it should be
// raised for all domains together rather than special-cased.
const domainQueueSize = 512

// domainExportMaxBatchSize caps one export payload. Matched to the queue depth
// so a full queue drains in a single export rather than a sequence of them:
// with N processors now sharing one exporter, more round trips per drained
// record would multiply request count by the domain count too.
const domainExportMaxBatchSize = 512

// newDomainLoggerProviders builds one sdklog.LoggerProvider per event domain,
// each stamping base + graph2otel.event_domain=<domain> onto every record it
// creates, and returns both the providers (for Shutdown) and their loggers
// (for the emitter's routing table).
//
// All providers share the ONE exporter passed in. That is what keeps the
// delivery/degraded self-observability wrapper correct without change: it wraps
// the exporter, not the provider, so it still observes every export attempt
// this process makes exactly once, from a single place, however many queues
// feed it.
func newDomainLoggerProviders(base *resource.Resource, exp sdklog.Exporter) (map[string]*sdklog.LoggerProvider, map[string]log.Logger, *sharedLogExporter) {
	shared := &sharedLogExporter{Exporter: exp}
	domains := EventDomains()
	lps := make(map[string]*sdklog.LoggerProvider, len(domains))
	loggers := make(map[string]log.Logger, len(domains))
	for _, d := range domains {
		// resource.Merge's SECOND argument wins on key conflict, and the
		// domain must win — but base is otherwise preserved whole, because it
		// carries service.name/service.version and everything else that
		// identifies this process. Building a fresh resource per domain
		// instead would silently drop all of it.
		res, err := resource.Merge(base, resource.NewSchemaless(attribute.String(ResourceAttrEventDomain, d)))
		if err != nil {
			// Merge only errors on conflicting schema URLs. Falling back to
			// base means this domain's records lose the routing label but are
			// still emitted with correct identity — degraded, not lost.
			res = base
		}
		lp := sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(
				shared,
				sdklog.WithMaxQueueSize(domainQueueSize),
				sdklog.WithExportMaxBatchSize(domainExportMaxBatchSize),
			)),
		)
		lps[d] = lp
		loggers[d] = lp.Logger(scopeName)
	}
	return lps, loggers, shared
}

// sharedLogExporter lets N BatchProcessors share one exporter safely.
//
// sdklog.BatchProcessor.Shutdown flushes its queue and then shuts down the
// exporter it was given. With one exporter behind eight processors that is a
// live bug, not a tidiness issue: the FIRST provider to shut down closes the
// exporter, and every record still queued in the other seven is then handed to
// a closed exporter and silently discarded on exit. It reproduces as an empty
// export on a clean shutdown — the least visible failure mode there is,
// because nothing errors.
//
// So Shutdown here is a deliberate no-op, and Provider.Shutdown closes the
// real exporter itself once every domain provider has drained. ForceFlush and
// Export pass straight through; only the close is deferred.
type sharedLogExporter struct {
	sdklog.Exporter
}

// Shutdown is intentionally inert — see the type comment. The real close is
// closeShared, called by Provider.Shutdown after every provider has flushed.
func (s *sharedLogExporter) Shutdown(context.Context) error { return nil }

// closeShared shuts down the wrapped exporter for real.
func (s *sharedLogExporter) closeShared(ctx context.Context) error {
	return s.Exporter.Shutdown(ctx)
}
