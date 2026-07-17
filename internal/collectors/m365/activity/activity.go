// Package activity is the Microsoft 365 unified-audit log source over the
// Office 365 Management Activity API — the subscribe/list/fetch content feed at
// manage.office.com, rather than Graph (#100).
//
// # Why this exists when m365.unified_audit already ships this signal
//
// Not for different data — for a STABLE transport. m365.unified_audit is
// Experimental for exactly one reason: POST /security/auditLog/queries is
// beta-only on a real tenant (live 2026-07-16: /v1.0 -> HTTP 404, /beta -> 201).
// This API is v1.0 stable, quotes 2,000 req/min per tenant rather than
// 429-ing on rapid query creation (#98), and is built for continuous SIEM
// ingest (subscription -> content blobs) instead of a >10-minute async query.
// Dropping the beta dependency IS the deliverable, which is why this collector
// is default-on and not Experimental.
//
// #100 was previously closed as "redundant" on a data-equivalence test ("same
// rows as the query API" — true) when the question was ingest fitness. That was
// the wrong question, and this package is the reopened answer.
//
// # This collector and m365.unified_audit are the SAME signal
//
// The Management API record IS the query API's auditData sub-object: the query
// API WRAPS the classic O365 Management schema, this API serves it RAW at the
// top level. (Same relationship as blob `properties` == the Graph resource, and
// the same conclusion as entra/signins' polled-vs-blob sources.) So both emit
// the SAME event name "m365.audit" with the SAME record Id, and are drop-in
// equivalents that dedupe against each other downstream on the `id` attribute.
//
// That equivalence is a CONTRACT, not a coincidence, and holding it up costs
// real work: the two sources disagree on the type of RecordType and UserType
// (int here, string there), on the casing of ClientIP, on where Workload lives,
// and on whether `service` exists at all. See recordtypes.go, and mapRecord's
// comments per field. Any attribute added here must be checked against
// unifiedaudit.mapRecord, and vice versa.
//
// # User identity: two identifiers, two names, same meaning on both transports
//
// The classic schema carries TWO distinct user identifiers, and this collector
// and its twin name them identically (#151):
//
//	user_key <- classic UserKey  (an opaque key)
//	user_id  <- classic UserId   (usually a UPN, sometimes a sentinel)
//
// The trap is that the query API's top-level `userId` field is NOT the classic
// UserId — it is the classic UserKey, and its `userPrincipalName` is the classic
// UserId (live-verified 500/500, 2026-07-17). So on the twin the two fields are
// CROSSED between wire and attribute. Taking the wire names at face value
// produced #151: an attribute called `user_id` meaning UserKey on one transport
// and UserId on the other, with nothing on the record saying which. Both
// transports map to what the field CONTAINS, not what Microsoft calls it.
//
// `user_id` is deliberately NOT called `user_principal_name`, which is the name
// it carried until 2026-07-17. The classic UserId is UPN-shaped on only ~91% of
// live records — the rest are bare GUIDs, the literal "Not Available",
// "ServicePrincipal_<guid>", or a display name — so the old name asserted
// something false about roughly one record in eleven. `user_id` is what the
// classic schema calls the field and what it actually holds.
//
// Exactly TWO user-identity attributes ship on each transport. Do not add a
// third: #151 was `user_id` and `user_principal_name` set from ONE variable,
// unconditionally, byte-identical on every record forever. See
// TestUserIdentityAttrsAreExactlyKeyAndID.
//
// Running both at once therefore DUPLICATES every overlapping record. That is
// degraded, not broken (same id, so downstream dedupe works), and it resolves
// when m365.unified_audit is retired — which is deliberately not part of this
// change, so the two can coexist while this one is proven live.
//
// # Ship everything fetched
//
// No record-type include-list. m365.unified_audit filters server-side because
// the query API can; this API has NO server-side filtering at all, so filtering
// here would mean fetching per-entity rows and discarding them — a bug under
// #112's hard rule. record_type and workload are attributes; consumers filter
// in LogQL. Volume is instead controlled at the SUBSCRIPTION, by choosing which
// content types to enable (config), which is a real server-side choice.
//
// # Namespace and cardinality
//
// M365 activity is neither an Entra nor an Intune signal, so it shares the
// top-level "m365.audit" log EventName with its sibling. This collector emits
// only LOGS and no metrics.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the record id, UPN, client IP, object id, actor ids —
// belongs here as structured log attributes. That same data must NEVER become a
// metric label. See CLAUDE.md: the boundary is a data-modeling rule, not a
// privacy control.
//
// # Secret redaction — the ONE genuine content exclusion
//
// These records carry ModifiedProperties with OldValue/NewValue, which for a
// credential or certificate change IS the credential. mapRecord emits the
// changed property NAMES and never their values, exactly as intune/auditevents
// does. That is the whole exclusion.
//
// ExtendedProperties[].Value IS emitted, and the earlier decision to withhold it
// was wrong. It was withheld on a SHAPE argument — the value is a JSON-encoded
// string (#100) of unbounded, workload-defined form — but "awkward to model" is
// not "unsafe to ship", and CLAUDE.md is explicit that reading the exclusion as
// general caution is what produced #110 and #111. What these values actually
// carry, live: additionalDetails ({"User-Agent":…,"AppId":…}),
// extendedAuditEventCategory ("ServicePrincipal"), and LoginError
// ("…;PP_E_BAD_PASSWORD;The entered and stored passwords do not match."). For a
// SIEM that is the signal, not the noise — anomalous user agents and repeated
// login errors are what you build detections on. Withholding them would be #83
// exactly: fetch a per-entity row, judge it too messy to keep, and it reaches no
// pipeline at all.
//
// The line, stated so it is not re-drawn by feel: ModifiedProperties values are
// excluded because they can BE a credential. Nothing else is excluded.
//
// PII is emphatically NOT excluded and must not be: UPN, client IP and object
// id are emitted here by design — graph2otel is a SIEM feed.
//
// # The read-only property
//
// POST /subscriptions/start is a WRITE — the second break in graph2otel's
// read-only property after the Intune reports-export job. It creates a
// subscription rather than mutating tenant data, and ActivityFeed.Read (a read
// scope) authorizes it, so the break is narrower than the export-job one. It is
// still a write. The engine owns when it happens; this package only declares
// the scope.
//
// See GitHub issue #100.
package activity

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/o365pipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Schedule tuning. Unlike m365.unified_audit — whose 30-minute floor exists
// because creating queries in rapid succession returns HTTP 429 (#98) — this
// API quotes 2,000 req/min per tenant and content lists ~2 MINUTES after the
// event (live, #100), so the cadence is set by usefulness rather than by
// throttling. One tick is one list plus one fetch per NEW blob per content
// type; on the live tenant that is ~22 fetches/day.
//
// lag keeps the window's upper bound off "now": records land minutes behind the
// event, and blobs are explicitly non-sequential ("one content blob can contain
// events that occurred prior to an earlier content blob"), so querying up to now
// would repeatedly miss late arrivals. The engine's own overlap + dual
// contentId/record-Id dedupe is what actually catches them; lag just avoids
// making it do that work every tick.
const (
	interval        = 10 * time.Minute
	lag             = 5 * time.Minute
	initialLookback = 4 * time.Hour
	// maxWindow matches the API's hard 24h range cap on /subscriptions/content.
	// Over that, the API rejects with AF20055 or — worse — returns HTTP 200 with
	// SILENTLY PARTIAL results. o365activityclient chunks internally so a wider
	// window would still be correct, but keeping it at the cap keeps one tick to
	// one request per content type.
	maxWindow = 24 * time.Hour
)

// defaultContentTypes is what a default deployment subscribes to.
//
// This API has NO server-side filtering, so the subscription is the only place
// volume can be controlled — which makes this a cost decision taken on other
// operators' behalf, not a technical one. graph2otel is public OSS and other
// operators pay per GB; Loki being free on the verification tenant is not a
// reason to ship everyone a firehose.
//
// Deliberately excluded, each for its own reason:
//
//   - Audit.General: 95.8% endpoint-DLP noise live (3,865 of 4,035 records from
//     ONE host on a SIX-device tenant, #100) — precisely the record type #98
//     already excluded as "high volume, low signal". Opt-in. Note the cost of
//     enabling it is bandwidth and CPU, NOT quota: 22 fetches/day against a
//     2,000 req/min ceiling. Affordable but absurd.
//   - Audit.AzureActiveDirectory: duplicates entra.directory_audits and
//     entra.signins.interactive (a live blob held 8 UserLoggedIn of 20 records,
//     #100). Both are logs-only, so running them together ships dupes.
//   - DLP.All: needs the ActivityFeed.ReadDlp role this collector does not
//     declare, and had zero content live (m7kni has no DLP policy matches), so
//     its record shape is unverified.
//
// Once enabled, a content type ships EVERY record it carries — no record-type
// include-list. #112: fetching per-entity rows and discarding them is a bug.
var defaultContentTypes = []o365activityclient.ContentType{
	o365activityclient.ContentExchange,
	o365activityclient.ContentSharePoint,
}

const (
	// collectorName is the stable collector key / config key.
	collectorName = "m365.activity"
	// eventName is the OTLP LogRecord EventName every record carries. It is
	// deliberately IDENTICAL to m365.unified_audit's: the two are one signal
	// over two transports, and forking the name would make them un-joinable
	// (see the package doc).
	eventName = "m365.audit"
	// checkpointKey namespaces this collector's cursor. It is deliberately NOT
	// interchangeable with m365.unified_audit's: that one stores a query
	// watermark over createdDateTime, this one a watermark plus seen contentIds
	// and record Ids over contentCreated. Sharing a namespace would make each
	// dedupe the other's records away. Distinct keys are also why the two can
	// coexist during migration rather than needing a checkpoint conversion.
	checkpointKey = "/activity/feed/subscriptions/content#m365"
)

// collectorImpl is the M365 activity WindowCollector: the generic
// o365pipeline.ActivityCollector plus the policy declarations that are this
// SIGNAL's rather than the transport's — which conflicts it duplicates, and
// which app role it needs. Mirrors unifiedaudit.collectorImpl over
// jobpipeline.JobCollector.
//
// The Name/DefaultInterval/Lag/CollectWindow adapter used to live here, because
// this was the engine's only collector. It now lives in o365pipeline alongside
// the engine, next to logpipeline.LogCollector and jobpipeline.JobCollector:
// the bridge from Collect(ctx, from, to, e) error to collector.WindowCollector
// is a property of the engine's shape, so every collector on it needs the same
// one. This package keeps only the tuning constants it passes in.
//
// It is deliberately NOT Experimental — see the package doc.
type collectorImpl struct {
	*o365pipeline.ActivityCollector
}

// ConflictsWith declares m365.unified_audit: the two are one signal over two
// transports, emitting the same event name with the same record Id, so enabling
// both ships every M365 audit record twice into one stream (#144).
//
// The composition root refuses to start rather than warning. Downstream dedupe
// on `id` does work — which is exactly what makes the state dangerous, because
// it looks fine until someone counts. Both collectors report success on every
// tick and nothing carries provenance (#141), so the duplication is invisible
// at the source and indistinguishable from real volume at the sink.
//
// The declaration is here rather than on m365.unified_audit because this
// collector is the second transport: it was written knowing the other exists
// (see the package doc), while m365.unified_audit predates it.
//
// Which one to disable is a genuine trade, not a formality — see the collector
// reference. This one wins on transport (stable v1.0, 2,000 req/min, ~2 min to
// content); m365.unified_audit wins on volume control (server-side
// recordTypeFilters can take Teams while excluding the endpoint-DLP firehose,
// which this API's five content-type buckets cannot express) at the cost of a
// beta dependency.
func (c *collectorImpl) ConflictsWith() []string {
	return []string{"m365.unified_audit"}
}

// RequiredPermissions declares the least-privilege application role.
//
// ActivityFeed.Read alone covers the whole feed AND authorizes POST
// /subscriptions/start — the WRITE that is graph2otel's second read-only break
// after the Intune reports-export job. That the write needs no ReadWrite scope
// is what makes this break the narrower of the two; the export job genuinely
// requires a DeviceManagement*.ReadWrite.All.
//
// ActivityFeed.ReadDlp is deliberately NOT declared: it gates DLP.All's
// sensitive-data detail, which is not a default content type. A tenant opting
// into DLP.All needs that role granted separately.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"ActivityFeed.Read"}
}

// newCollector builds the M365 activity collector for one tenant, wiring the
// engine to the tenant's Management Activity API client and checkpoint store.
//
// The tenant's configured ContentTypes REPLACE the default rather than extend
// it: this API has no server-side filtering, so every subscribed content type
// is fetched in full, and quietly adding the default to an explicit config would
// double an operator's bill without their asking.
//
// The cold-start lookback lives in exactly ONE place: this collector's
// RegisteredWindow.InitialLookback, which collector.nextWindow honors when it
// computes [from, to]. o365pipeline.EndpointConfig deliberately has no lookback
// field to set — it briefly did, and setting it in both places would have let
// the engine and the scheduler disagree about the same window, with the
// scheduler winning silently. On a cold start the engine now takes our `from`
// verbatim; on a warm tick it ignores it and resumes from watermark minus
// o365pipeline.DefaultOverlap. The 7-day API bound stays enforced either way:
// the client's ListContent clamps startTime and warns when it fires, so an
// over-eager lookback here is clamped rather than rejected.
func newCollector(d collectors.O365Deps) *collectorImpl {
	contentTypes := d.ContentTypes
	if len(contentTypes) == 0 {
		contentTypes = defaultContentTypes
	}
	cfg := o365pipeline.EndpointConfig{
		CollectorName: collectorName,
		ContentTypes:  contentTypes,
		CheckpointKey: checkpointKey,
		EventName:     eventName,
		Map:           mapRecord,
	}
	return &collectorImpl{
		ActivityCollector: o365pipeline.NewActivityCollector(
			collectorName, interval, lag, d.Client, d.Store, cfg),
	}
}

func init() {
	collectors.RegisterO365(func(d collectors.O365Deps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on. Failing the WindowCollector one would make
// it silently never run.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
	_ collectors.ConflictsWith  = (*collectorImpl)(nil)
)

// creationTimeLayouts are the layouts tried, in order, against CreationTime.
//
// THE trap on this path: CreationTime is documented UTC but arrives with NO
// ZONE and NO Z — "2015-06-29T20:03:19" (Microsoft's own documented example,
// mirrored in o365activityclient/content_test.go). time.Parse(time.RFC3339, …)
// FAILS on that outright, so the obvious layout drops every record silently.
//
// RFC3339Nano is tried first anyway so that a Z or an offset — should Microsoft
// ever start sending one — is honored rather than misread. The zone-less
// layout is second and, having no zone in the layout, time.Parse returns it as
// UTC, which is what the schema says it is. Its ".999999999" makes fractional
// seconds optional, so it covers both "…:19" and "…:19.123".
var creationTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
}

// mapRecord turns one raw Management Activity API record into its dedupe id
// (the record's immutable Id) and the OTLP log Event.
//
// ok=false DROPS the record, and there is exactly ONE reason for it: no
// parseable CreationTime. There is deliberately no "now" fallback — a zero
// Timestamp means "now" to telemetry.Event, so falling back would stamp a stale
// record with the poll time and silently misplace it in time, which is the #135
// bug exactly. A wrong timestamp surfaces as nothing at all; a dropped record
// surfaces as a drop.
//
// A record with no Id is NOT dropped, and that is deliberate: it is emitted with
// an empty dedupe id, per #112 (data reaching no pipeline is a bug) and per the
// engine's stated contract, which honors an empty id. Such a record cannot be
// deduped, but every record on this API carries an Id — it is mandatory in the
// Common Schema — so this is a should-never-happen path, and shipping an
// undedupeable record beats silently discarding one.
//
// Every attribute below that has a query-API twin MUST agree with
// unifiedaudit.mapRecord's value for the same event — see the package doc.
// It sets only the attributes actually present, so a record without a UPN or
// client IP omits them rather than emitting empty ones.
func mapRecord(rec map[string]any) (string, telemetry.Event, bool) {
	ts, ok := eventTime(rec)
	if !ok {
		return "", telemetry.Event{}, false
	}
	id := str(rec, "Id")

	operation := str(rec, "Operation")
	// `service` is ABSENT on this API. The query API emits it, and on the live
	// #98 record it was byte-identical to auditData.Workload — so Workload
	// feeds both attributes, keeping `service` present on both transports
	// rather than leaving a hole on one.
	workload := str(rec, "Workload")
	// UserId on the classic schema IS the query API's userPrincipalName —
	// live-verified byte-identical on 500/500 records over the same tenant and
	// window (2026-07-17, #100), sentinels and all. So it feeds `user_id` on
	// both transports, and the copy is UNCONDITIONAL.
	//
	// The unconditional part is the whole finding and it is counter-intuitive.
	// UserId is NOT always UPN-shaped: live it is a bare GUID, the literal
	// "Not Available", "ServicePrincipal_<guid>", or a display name on ~9% of
	// records. Gating the copy on UPN shape therefore looks careful — and is
	// wrong, because the query API applies no such gate and emits
	// userPrincipalName="Not Available" verbatim. A gate here would omit the
	// attribute on exactly the records where the twin emits it. This attribute
	// was withheld entirely on a first pass for the same "would be inventing a
	// value" reasoning; the wire settled it. See
	// TestUserIDIsTheClassicUserIDVerbatim.
	//
	// That same ~9% is why this is `user_id` and not `user_principal_name` (the
	// name it carried until 2026-07-17): a value that is a GUID or "Not
	// Available" is not a principal NAME, so the old name was wrong on roughly
	// one record in eleven. Renaming lost nothing — same field, same value, a
	// name that matches the classic schema's own.
	//
	// Do NOT re-add `user_principal_name` alongside this. That is #151 rebuilt:
	// the bug was these two names set from this one variable, unconditionally,
	// identical by construction with no branch that could ever separate them.
	userID := str(rec, "UserId")
	result := str(rec, "ResultStatus")

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "operation", operation)
	setStr(attrs, "workload", workload)
	setStr(attrs, "service", workload)
	setStr(attrs, "result_status", result)
	// The classic UserId. The query API carries the same value in its
	// `userPrincipalName` field and emits it under this same name, so `user_id`
	// means the classic UserId on both transports. See the comment above for why
	// this is an unconditional copy rather than a UPN-shape-gated one, and why
	// no `user_principal_name` sits alongside it.
	setStr(attrs, "user_id", userID)
	// The classic UserKey. The query API carries the same value in its
	// (misnamed) top-level `userId` field and emits it under this same name, so
	// `user_key` means the classic UserKey on both transports (#151).
	setStr(attrs, "user_key", str(rec, "UserKey"))
	// ClientIP here, clientIp on the query API — same attribute either way.
	setStr(attrs, "client_ip", str(rec, "ClientIP"))
	setStr(attrs, "object_id", str(rec, "ObjectId"))
	setStr(attrs, "organization_id", str(rec, "OrganizationId"))

	// RecordType / UserType are INTs here and STRINGs on the query API. Emit
	// the int unconditionally (it is the only lossless form, and Microsoft's
	// published table does not cover every value this tenant emits) and the
	// converged name only when it resolves — never a guess. See recordtypes.go.
	if n, present := num(rec, "RecordType"); present {
		attrs["record_type_id"] = itoa(n)
		if name, known := recordTypeName(n); known {
			attrs["record_type"] = name
		}
	}
	if n, present := num(rec, "UserType"); present {
		attrs["user_type_id"] = itoa(n)
		if name, known := userTypeName(n); known {
			attrs["user_type"] = name
		}
	}
	if n, present := num(rec, "Version"); present {
		attrs["version"] = itoa(n)
	}
	// AzureActiveDirectoryEventType is an int enum with no query-API twin
	// (unifiedaudit does not read auditData for it), so it is additive-only and
	// carries no convergence risk. It is emitted un-named: no live sample pins
	// its int-to-name mapping, and recordtypes.go's rule is that a guessed name
	// is worse than none.
	if n, present := num(rec, "AzureActiveDirectoryEventType"); present {
		attrs["azure_ad_event_type"] = itoa(n)
	}

	// SECURITY: names only, never OldValue/NewValue — those can carry
	// credentials and certificates. The names must still be emitted: excluding
	// the values must not decay into dropping the field (#112).
	setStrs(attrs, "modified_property_names", namesOf(rec, "ModifiedProperties", "Name"))
	// ExtendedProperties values ARE emitted, unlike ModifiedProperties'. They are
	// event metadata, not changed-property values, and cannot BE a credential:
	// live they carry additionalDetails ({"User-Agent":…,"AppId":…}),
	// extendedAuditEventCategory, and LoginError. A SIEM builds detections on
	// exactly those. They were withheld in a first pass because the value is a
	// JSON-encoded string of workload-defined shape (#100) — but that is an
	// argument about being awkward to model, not about being unsafe, and
	// withholding per-entity data for tidiness is #83's bug and #110/#111's
	// reasoning error.
	//
	// Names and values are parallel slices, index-aligned, rather than one
	// attribute per property name: the names are workload-defined and unbounded,
	// so attribute-per-name would mint unbounded attribute KEYS.
	setStrs(attrs, "extended_property_names", namesOf(rec, "ExtendedProperties", "Name"))
	setStrs(attrs, "extended_property_values", namesOf(rec, "ExtendedProperties", "Value"))
	// Actor[] is per-entity identity data with no query-API twin. #112: it must
	// reach a pipeline rather than the floor, and a log attribute is where
	// per-entity data belongs.
	setStrs(attrs, "actor_ids", namesOf(rec, "Actor", "ID"))

	// Severity uses the same predicate as unifiedaudit.mapRecord, so the same
	// event cannot arrive INFO from one transport and WARN from the other. The
	// vocabulary spans both "Failed" (classic) and "Failure" (Entra).
	sev := telemetry.SeverityInfo
	if result == "Failed" || result == "Failure" {
		sev = telemetry.SeverityWarn
	}

	return id, telemetry.Event{
		Name:      eventName,
		Body:      auditBody(operation, workload, userID),
		Severity:  sev,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// eventTime resolves the record's event time from CreationTime, and from
// nothing else. See creationTimeLayouts for why the layout list is not just
// RFC3339, and mapRecord for why there is no fallback.
func eventTime(rec map[string]any) (time.Time, bool) {
	raw := str(rec, "CreationTime")
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range creationTimeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// auditBody builds a short human-readable summary line, in the same shape
// unifiedaudit.auditBody produces, so the two transports read identically in a
// log pane.
func auditBody(operation, service, who string) string {
	if who == "" {
		who = "unknown principal"
	}
	if operation == "" {
		operation = "activity"
	}
	if service == "" {
		return fmt.Sprintf("%s by %s", operation, who)
	}
	return fmt.Sprintf("%s by %s [%s]", operation, who, service)
}

// --- small defensive accessors for untyped JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// num coerces a JSON number field to int64, tolerating every representation it
// could plausibly arrive as.
//
// float64 is the one that actually happens — encoding/json decodes every JSON
// number into map[string]any as float64, so a .(int) assertion would silently
// match nothing. The rest are defense against the #89 lesson that Microsoft's
// field types are not stable across sources or even within one record: this
// same field is already a string on the query API.
func num(m map[string]any, key string) (int64, bool) {
	switch v := m[key].(type) {
	case float64:
		return int64(v), true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

// namesOf extracts field `field` from every object in the array at rec[key],
// skipping anything that is not a string. It is the ONLY way this package reads
// ModifiedProperties and ExtendedProperties, which is what structurally
// prevents an OldValue/NewValue from ever reaching an attribute.
func namesOf(m map[string]any, key, field string) []string {
	arr, ok := m[key].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		obj, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if v := str(obj, field); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// itoa renders an enum/scalar int as a string.
//
// Every attribute this package emits is a string, matching every sibling
// collector (intune/auditevents, entra/signins) and the backend: a log
// attribute becomes Loki STRUCTURED METADATA, which is string-valued, so an
// int64 attribute buys no fidelity downstream. It also costs: telemetrytest
// cannot render a log.Int64 ("AsString: invalid Kind"), so an int-valued
// attribute reads as empty in any recorder-based assertion — a silent trap for
// the next test written here.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// setStr adds key=val only when val is non-empty, so absent fields don't emit
// empty attributes.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// setStrs adds key=vals only when vals is non-empty.
func setStrs(attrs telemetry.Attrs, key string, vals []string) {
	if len(vals) > 0 {
		attrs[key] = vals
	}
}
