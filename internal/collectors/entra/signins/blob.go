package signins

// blob.go is the second SOURCE of the sign-in signal this package owns: Azure
// Monitor diagnostic settings, read out of Azure Storage, rather than polled
// from Graph (#135). It lives beside the polled streams deliberately — these are
// not a different signal, they are the same sign-in records arriving by a
// different transport, and they share this package's mapSignIn so there is
// exactly one definition of what a sign-in log record looks like.
//
// Why blob at all, given signins.go already polls this data:
//
//   - MicrosoftServicePrincipalSignInLogs has NO Graph endpoint, at all. It is
//     Microsoft's own first-party service-to-service auth against the tenant,
//     and Microsoft offers it "as an opt-in through diagnostic settings only".
//     Live-verified 2026-07-16: 160/160 sampled records were owned by
//     Microsoft's tenant (f8cdef31-…), 541/541 records in the neighboring
//     ServicePrincipalSignInLogs were owned by m7kni, and ZERO sign-in ids
//     overlapped. The two are disjoint datasets, not duplicates — which is why
//     the polled entra.signins.service_principal can never surface this.
//   - ServicePrincipalSignInLogs and NonInteractiveUserSignInLogs retire a beta
//     dependency. Their polled twins are Experimental only because the
//     signInEventTypes $filter is beta-only (v1.0 returns HTTP 400); diagnostic
//     settings emit them as first-class categories with no filter and no beta.
//
// Freshness is NOT the argument for any of them, and must not be sold as one:
// blob latency scales with volume, so on a small tenant polling is far ahead
// (#89, #135).

import (
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// blobInterval is how often each sign-in container is re-listed. Records land
// minutes behind the event and the floor is Azure-side, so polling faster buys
// nothing but list operations — which are billed at the write rate (#89).
const blobInterval = 5 * time.Minute

// blobSpec describes one sign-in diagnostic-settings category.
type blobSpec struct {
	// name is the stable collector key. Where a polled twin exists it carries a
	// ".blob" suffix, so the two are separable in config and self-obs; the
	// category with no Graph route needs no suffix because it has no twin.
	name string
	// container is "insights-logs-" + the diagnostic-settings category name,
	// lowercased — the fixed naming Azure Monitor uses.
	container string
}

// blobSpecs is the set of sign-in categories with a mapper.
//
// ManagedIdentitySignInLogs is deliberately ABSENT despite being the obvious
// fourth: its container does not exist on the verification tenant, so there is
// no live sample to map against. The shape is very probably identical to these
// three — and "very probably" against imagination is exactly the reasoning that
// produced three wrong "permanent gap" verdicts on this project (#109/#100/#130).
// It lands when a tenant emits one. See #135.
var blobSpecs = []blobSpec{
	{
		name:      "entra.signins.microsoft_service_principal",
		container: "insights-logs-microsoftserviceprincipalsigninlogs",
	},
	{
		name:      "entra.signins.service_principal.blob",
		container: "insights-logs-serviceprincipalsigninlogs",
	},
	{
		name:      "entra.signins.non_interactive.blob",
		container: "insights-logs-noninteractiveusersigninlogs",
	},
}

// blobCollectorImpl is one sign-in blob collector: the generic BlobCollector
// plus the license declaration the composition root gates on.
//
// It is NOT Experimental, and that is a decision rather than an omission
// (#135). Configuring blob_ingest.account_url — which means standing up a
// storage account, creating the diagnostic settings, and granting a data-plane
// role — is already an explicit, effortful opt-in; the whole lane does not exist
// without it. Requiring a second opt-in would buy nothing, and marking a
// v1.0-stable source "beta" would contradict the entire reason group B exists.
type blobCollectorImpl struct {
	*blobpipeline.BlobCollector
}

// RequiredCapability declares Entra ID P1, matching the polled streams.
//
// The blob path does not touch Graph, so this is not an API-availability gate:
// it is here because a Free tenant's diagnostic setting emits no sign-in records
// either, so the collector would find an empty container and no-op in silence —
// and "silently doing nothing" is indistinguishable from "the data has not
// arrived yet", the documented way this whole path gets misdiagnosed. A stated
// skip reason on the status page beats a silent nothing.
func (c *blobCollectorImpl) RequiredCapability() license.Capability { return license.CapEntraP1 }

// newBlobCollector builds one sign-in blob collector from its spec. The cursor
// namespace defaults to the container, and each spec has its own container, so
// the three never collide.
func newBlobCollector(s blobSpec, d collectors.BlobDeps) *blobCollectorImpl {
	cfg := blobpipeline.ContainerConfig{
		Container: s.container,
		Prefix:    blobPrefix(d.TenantID),
		Map:       mapBlobSignIn,
	}
	return &blobCollectorImpl{
		BlobCollector: blobpipeline.NewBlobCollector(
			s.name, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger),
	}
}

// blobPrefix returns the listing prefix for a tenant's records: "tenantId=<guid>/".
//
// NOT the documented "resourceId=/tenants/<guid>/providers/microsoft.aadiam/…"
// form — every published Microsoft example is subscription-scoped, while these
// are tenant-level (microsoft.aadiam) settings. Coding to the docs produces a
// collector that lists zero blobs and reports success forever (#89).
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// mapBlobSignIn turns one raw diagnostic-settings record into its OTLP log
// Event: unwrap the envelope, hand the inner object to the canonical mapper,
// and fix the timestamp the envelope would get wrong.
//
// The delegation is the point. The diagnostic-settings `properties` object IS
// the Graph signIn resource — verified field-for-field against live samples of
// all four sign-in categories, with every attribute mapSignIn reads present in
// every one. So a blob-sourced sign-in and a polled sign-in are the same record,
// and an attribute added for one source is automatically right for the other.
//
// The dedupe id mapSignIn returns is discarded: blobpipeline dedupes by byte
// offset, not by id, so it has nothing to do here. (properties.id does equal the
// polled signIn.id, so the two sources remain dedupe-able downstream on the `id`
// attribute if anyone ever runs both.)
func mapBlobSignIn(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}

	ts, ok := blobEventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}

	_, ev := mapSignIn(props)
	ev.Timestamp = ts
	return ev, true
}

// blobEventTime resolves the sign-in's real event time from
// properties.createdDateTime, and from nothing else.
//
// THE trap on this path (#135). The envelope's top-level `time` is when Azure
// INGESTED the record. Across live samples of all three sign-in categories the
// two were never equal — 0 of ~700 records — and the gap was VARIABLE, from 28s
// to 1077s, so it cannot even be recovered by subtracting a constant.
//
// There is deliberately no fallback to `time`: a fallback would silently
// reintroduce the bug this function exists to prevent, on exactly the records
// least able to survive it. A record with no parseable createdDateTime is
// dropped instead — that surfaces as a skipped record, where a wrong timestamp
// surfaces as nothing at all.
//
// Note the neighboring MicrosoftGraphActivityLogs collector binds to the
// envelope `time` and is CORRECT to: there, time and properties.timeGenerated
// are byte-identical. The envelope is not consistent across categories, so this
// rule is per-category and cannot be hoisted into a shared helper.
func blobEventTime(props map[string]any) (time.Time, bool) {
	raw := str(props, "createdDateTime")
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func init() {
	for _, s := range blobSpecs {
		collectors.RegisterBlob(func(d collectors.BlobDeps) collector.SnapshotCollector {
			return newBlobCollector(s, d)
		})
	}
}

// Compile-time checks that the blob collector satisfies every interface the
// composition root type-asserts on. Failing the SnapshotCollector one would make
// it silently never run.
var (
	_ collector.SnapshotCollector = (*blobCollectorImpl)(nil)
	_ license.CapabilityRequirer  = (*blobCollectorImpl)(nil)
)
