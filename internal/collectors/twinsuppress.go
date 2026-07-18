package collectors

// twinsuppress.go implements the keep-gauges/suppress-twin coordination (#135-C).
//
// A metric-emitting SnapshotCollector (entra.risk, intune.devices) emits BOTH a
// bounded gauge and a per-entity log twin from one poll. Some of those signals
// ALSO arrive as an Azure Monitor diagnostic-settings category, from which a
// blob-sourced collector can emit the SAME per-entity twin — but the blob feed
// cannot produce the current-state gauge (it is a change/inventory stream, not a
// point-in-time count). So the design is NOT a clean source XOR (that is #135-D,
// for log-only collectors): the polled collector KEEPS its gauges and SUPPRESSES
// its own twin when a blob twin owns it, so the per-entity record ships once.
//
// A blob twin collector declares the polled twin event it owns via
// RegisterBlobTwinOwner at init. The composition root turns those declarations
// into a per-tenant SuppressedTwins set (below) and injects it into Deps before
// constructing the polled collectors — so the polled collector reads a stable
// set, never races the blob one, and suppression happens only when the blob twin
// will actually run.

// blobTwinOwner records that a blob-sourced collector owns a per-entity twin a
// polled SnapshotCollector also emits.
type blobTwinOwner struct {
	twinEvent         string // the OTLP log EventName the polled collector emits
	blobCollectorName string // the blob collector that owns it when enabled
}

// blobTwinOwners is populated once at init by blob collectors. Global, like the
// factory registries in this package.
var blobTwinOwners []blobTwinOwner

// RegisterBlobTwinOwner declares that blobCollectorName's blob-sourced twin owns
// the per-entity twinEvent, so a polled collector emitting twinEvent must
// suppress its own copy whenever that blob collector is active. Call from a blob
// collector's init(). Adding a new (blob twin, polled twin) pair is one line
// here plus reading Deps.SuppressedTwins in the polled collector — no
// composition-root edit.
func RegisterBlobTwinOwner(twinEvent, blobCollectorName string) {
	blobTwinOwners = append(blobTwinOwners, blobTwinOwner{twinEvent: twinEvent, blobCollectorName: blobCollectorName})
}

// SuppressedTwins computes the set of per-entity twin event names the polled
// collectors must not emit for a tenant, from the registered blob-twin-owner
// declarations. A twin is suppressed only when blobConfigured is true (the blob
// source exists for this tenant) AND enabled(blobCollectorName) is true (the
// owning blob collector is not disabled) — suppressing a twin whose blob owner
// will not run would silently drop the data, which is worse than a duplicate
// (#135-C, mirrors the source=blob-with-no-blob fallback in #135-D). enabled
// reports a collector name's effective enabled state for the tenant.
func SuppressedTwins(blobConfigured bool, enabled func(name string) bool) map[string]bool {
	out := map[string]bool{}
	if !blobConfigured {
		return out
	}
	for _, o := range blobTwinOwners {
		if enabled(o.blobCollectorName) {
			out[o.twinEvent] = true
		}
	}
	return out
}
