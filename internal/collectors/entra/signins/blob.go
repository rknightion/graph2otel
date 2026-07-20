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
	"github.com/rknightion/graph2otel/internal/semconv"
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
	// conflictsWith names the polled collector this category is a second
	// TRANSPORT for — the same sign-in records, arriving by diagnostic settings
	// instead of Graph. Empty means this category has no polled twin.
	//
	// It is a per-spec field rather than a method on the shared impl because
	// the three specs disagree, and that disagreement is the whole point: two
	// of them duplicate a polled stream and one is a disjoint dataset. See
	// blobSpecs. Enforced by collectors.CheckConflicts at startup (#144).
	conflictsWith []string
}

// blobSpecs is the set of sign-in categories with a mapper.
//
// ManagedIdentitySignInLogs is the fourth category, added once a tenant actually
// emitted one (#135): mapped 2026-07-20 against a live m7kni sample (a synthetic
// user-assigned managed identity signing in to Azure Resource Manager), NOT
// against the assumption that its shape matches the other three — "very probably
// identical" against imagination is the reasoning that produced three wrong
// "permanent gap" verdicts on this project (#109/#100/#130). The live record
// settled it: properties IS the same signIn resource (id, appId,
// servicePrincipalId, status.errorCode, createdDateTime, conditionalAccessStatus),
// so mapSignIn and deriveSignin map it unchanged; signInEventTypes is
// ["managedIdentity"] and there is no user block.
//
// It is a ".blob" category with a conflictsWith, like service_principal.blob and
// non_interactive.blob — NOT a disjoint one like microsoft_service_principal.
// graph2otel DOES poll managed-identity sign-ins (the beta signInEventTypes
// stream entra.signins.managed_identity, signins.go), so this is a second
// TRANSPORT for the same records. Overlap confirmed live 2026-07-20: the polled
// beta stream returned the exact sign-in id (f7d36837-…) carried in the blob —
// 1/1 (the tenant's only managed-identity sign-in). Running both ships every
// record twice into one stream, so the pair is refused at startup (#144). By
// default only the blob runs — the polled twin is Experimental/opt-in (the
// filter is beta-only), the blob is on whenever blob_ingest is configured.
//
// Note the conflictsWith column, which is NOT uniform and must not be made so
// (#144). The two ".blob" categories are a second transport for records their
// polled twin already emits — measured live on camden 2026-07-16, the polled
// collector's own checkpoint seen_ids intersected against the ids in its blob
// container gave 18/18 and 1375/1375, i.e. TOTAL overlap. Running both ships
// every record twice into one stream, so the pair is refused at startup.
// MicrosoftServicePrincipalSignInLogs declares nothing, because it duplicates
// nothing: 160/160 sampled records were owned by Microsoft's own tenant, ZERO
// ids overlapped the polled service-principal stream, and it has no Graph route
// at all. Copying the declaration onto it — the obvious tidy-up, since it sits
// in the same table — would suppress a stream that has no duplicate.
var blobSpecs = []blobSpec{
	{
		name:      "entra.signins.microsoft_service_principal",
		container: "insights-logs-microsoftserviceprincipalsigninlogs",
	},
	{
		name:          "entra.signins.service_principal.blob",
		container:     "insights-logs-serviceprincipalsigninlogs",
		conflictsWith: []string{"entra.signins.service_principal"},
	},
	{
		name:          "entra.signins.non_interactive.blob",
		container:     "insights-logs-noninteractiveusersigninlogs",
		conflictsWith: []string{"entra.signins.non_interactive"},
	},
	{
		name:          "entra.signins.managed_identity.blob",
		container:     "insights-logs-managedidentitysigninlogs",
		conflictsWith: []string{"entra.signins.managed_identity"},
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
	// conflicts is this category's polled twin, if it has one. Carried per
	// instance because the three specs sharing this type disagree about it.
	conflicts []string
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

// ConflictsWith names the polled collector this category duplicates, so the
// composition root refuses to start with both enabled (#144). It returns nil —
// no conflict — for the category with no polled twin.
//
// The declaration lives on the blob side rather than the polled side because
// this side is the one that KNOWS: signins.go's polled streams predate blob
// ingest entirely, and a category is added here by someone who has just
// verified what it overlaps. It also keeps the fact next to the evidence in
// blobSpecs.
//
// Nothing derives this from the event name, and nothing may: every collector in
// this package emits "entra.signin", including entra.signins.interactive, which
// conflicts with none of them. Same name, disjoint records.
func (c *blobCollectorImpl) ConflictsWith() []string { return c.conflicts }

// newBlobCollector builds one sign-in blob collector from its spec. The cursor
// namespace defaults to the container, and each spec has its own container, so
// the three never collide.
func newBlobCollector(s blobSpec, d collectors.BlobDeps) *blobCollectorImpl {
	cfg := blobpipeline.ContainerConfig{
		Container:     s.container,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobSignIn,
		CollectorName: s.name,
		// exclude_self (#154): a sign-in record carries the signing-in app's appId,
		// so a poller-authored sign-in is droppable. Self-only and per-tenant: the
		// filter compares blobSelfAppID against the tenant's own client_id and
		// no-ops when either is off/unset — a third party (including Microsoft's own
		// first-party SPs in MicrosoftServicePrincipalSignInLogs) always passes.
		ExcludeSelf:  d.ExcludeSelf,
		SelfClientID: d.SelfClientID,
		SelfAppID:    blobSelfAppID,
		// Derive the bounded entra.signin.count counter (#187 F3), gated so a
		// backfilled sign-in is never credited to now. RecencyWindow comes from
		// the tenant's config (default 20m); the gate lives in the pipeline, not
		// here. One shared deriver across all three sign-in blob containers,
		// mirroring the shared Map — the record shape is identical.
		Derive:        deriveSignin,
		RecencyWindow: d.MetricRecencyWindow,
	}
	return &blobCollectorImpl{
		BlobCollector: blobpipeline.NewBlobCollector(
			s.name, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger),
		conflicts: s.conflictsWith,
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
// The dedupe id mapSignIn returns is discarded, because blobpipeline tracks
// progress by byte offset and has nowhere to put it. That is a known gap rather
// than a tidy fact: Azure's diagnostic-settings delivery is AT-LEAST-ONCE (~2.3%
// of records arrive twice, byte-identical payload, fresh envelope `time`), so
// these collectors ship those duplicates through today — see #138, which is
// where that id would be threaded if the engine grows a seen-id set. It is not a
// cursor bug: both copies are real distinct bytes, and the engine was verified
// to emit each record exactly as many times as Azure wrote it.
//
// properties.id equals the polled signIn.id, so both the blob duplicates and any
// polled/blob overlap are dedupe-able downstream on the `id` attribute today.
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

// deriveSignin emits the bounded entra.signin.count counter for one sign-in
// blob record (#187, fast-follow to #128/#135). Only bounded, tenant-shaped
// labels (#112) — result, conditional access status, risk level, client app
// used. Per-entity fields (id, appId, servicePrincipalId, ipAddress, UPN,
// appDisplayName, resourceDisplayName) stay log-only in mapSignIn and never
// appear here; errorCode itself also stays log-only (high-cardinality),
// collapsed here to the bounded success/failure result label.
//
// One shared deriver across all three sign-in blob containers, mirroring the
// shared mapSignIn — every category's `properties` object is the same Graph
// signIn resource shape, so one definition of "what a sign-in metric looks
// like" is correct for all of them.
//
// Labels are always assigned directly (never telemetry.SetStr, which omits
// empty values) so every point carries the same four keys and series shape
// never depends on which fields a particular sign-in happened to populate.
func deriveSignin(rec map[string]any, _ telemetry.Event) []blobpipeline.MetricPoint {
	props := nested(rec, "properties")
	if props == nil {
		return nil
	}
	attrs := telemetry.Attrs{}
	attrs[semconv.AttrResult] = signinResult(props)
	attrs[semconv.AttrConditionalAccessStatus] = str(props, "conditionalAccessStatus")
	attrs[semconv.AttrRiskLevelDuringSignIn] = str(props, "riskLevelDuringSignIn")
	attrs[semconv.AttrClientAppUsed] = str(props, "clientAppUsed")
	return []blobpipeline.MetricPoint{{
		Name:  "entra.signin.count",
		Kind:  blobpipeline.MetricCounter,
		Unit:  "{signin}",
		Desc:  "Sign-ins against the tenant, by result, conditional access status, risk level, and client app used (#187).",
		Value: 1,
		Attrs: attrs,
	}}
}

// signinResult reads properties.status.errorCode and collapses it to the
// bounded "success"/"failure" label mapSignIn's own body-summary logic uses
// (signInBody): 0, or an absent status/errorCode, means success; any other
// value means failure. The numeric errorCode itself is deliberately not
// carried onto the metric — it is per-failure-reason detail, unbounded across
// a tenant's history, and stays log-only via status_error_code.
func signinResult(props map[string]any) string {
	st := nested(props, "status")
	if st == nil {
		return "success"
	}
	f, ok := st["errorCode"].(float64)
	if !ok || f == 0 {
		return "success"
	}
	return "failure"
}

// blobSelfAppID returns the sign-in's actor appId, read from the properties
// object — the SAME properties.appId that mapSignIn labels the record with (via
// mapBlobSignIn, which hands it the unwrapped properties object). It is shared
// with the exclude_self filter (#154) so the filter compares the field that
// actually ships, never a divergent one.
func blobSelfAppID(rec map[string]any) string {
	return str(nested(rec, "properties"), "appId")
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
	_ collectors.ConflictsWith    = (*blobCollectorImpl)(nil)
)
