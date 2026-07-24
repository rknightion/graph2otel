// Package unifiedaudit is the Microsoft 365 unified-audit log source: a single
// WindowCollector over POST /security/auditLog/queries (Microsoft Purview Audit
// exposed through Graph), emitting one OTLP log record per audit record through
// the async job-poll engine (internal/jobpipeline). It is the FIRST
// jobpipeline-based collector — the async counterpart to the logpipeline-based
// window collectors (sign-ins, directory audits, security alerts). See #97; the
// live-verification that grounds the record shape and filter values is #98.
//
// Why the job engine, not logpipeline: this endpoint does not answer a single
// paged GET. A query is POSTed, runs server-side, is polled to status
// "succeeded", then its records are paged — create → poll → page. jobpipeline
// owns that cycle plus the shared checkpoint (watermark + overlap + SeenIDs)
// and per-record dedupe by the immutable auditLogRecord.id.
//
// Namespace: M365 activity is neither an Entra nor an Intune signal, so it uses
// a NEW top-level log EventName "m365.audit" (the metric-namespace rule reserves
// entra.*/intune.* for those domains; this collector emits no domain metric at
// all — see the cardinality note). The collector's stable name/config key is
// "m365.unified_audit".
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the record id, UPN, client IP, object id, operation —
// belongs here as structured log attributes. That same data must NEVER become a
// metric label; this package emits no DOMAIN metric. Its one metric is
// self-observability, graph2otel.api.unexpected, whose labels are all strings
// from graph2otel's own source (#234).
//
// Experimental / opt-in: this targets a licensing-gated Purview Audit surface
// (Standard, included with E3, minimum; Premium/E5 for high-value records like
// MailItemsAccessed and 1-year retention — verified live in #98) and is new, so
// it is marked Experimental and registers only when config explicitly enables
// it. A default deployment does not poll it.
//
// # What this collector watches, and what it deliberately does not (#234)
//
// Three of this package's load-bearing facts were established by ONE capture and
// are then trusted forever, and every one of them fails SILENTLY — the API keeps
// answering 200 and the records keep looking reasonable. Those three are watched
// as wirecheck INVARIANTS, plus the dedupe key as a MissingField:
//
//   - Invariant(record_type_filter). The curated recordTypeFilters include-list
//     is the only thing keeping this collector off the tenant's firehose (3,003
//     of #98's 3,837 records were endpoint-DLP FileDeleted from one host). That
//     the filter EXCLUDES server-side has never actually been measured — #98
//     verified each entry is accepted and returns records, which is the other
//     half. See the check for how it is tested without guessing at record-type
//     spellings.
//
//   - Invariant(audit_data_object). auditData arrives as a plain nested object on
//     this transport, NOT the doubly-JSON-encoded string entra/riskdetections'
//     additionalInfo is. Six attributes are read straight out of it — workload,
//     result_status, client_ip, network_message_id, release_to, request_type — so
//     if it ever arrives as a string, nested() returns nil and all six disappear
//     at once with no error anywhere.
//
//   - Invariant(user_field_crossing). The wire's `userId` holds the classic
//     UserKey and its `userPrincipalName` holds the classic UserId — crossed,
//     500/500 byte-identical on the 2026-07-17 capture. Taking the names at face
//     value IS #151. Each record carries the classic names inside auditData, so
//     the crossing is checked against the record's own envelope rather than
//     against a remembered measurement.
//
//   - MissingField(id). jobpipeline dedupes on the immutable auditLogRecord.id.
//     An empty id is not merely undedupeable: the first record adds "" to
//     SeenIDs and then EVERY later record with an empty id is deduped away
//     silently. That is data loss wearing the shape of a quiet tenant.
//
//   - NOT WATCHED: RequestType. #234 names it, and it stays unwatched. It is an
//     UNDOCUMENTED integer enum — Microsoft publishes no member list — and this
//     repository contains exactly one observed value (2 on a
//     QuarantineReleaseMessage record). One integer is not a range, and guessing
//     a bound would fire on the first legitimate member outside it. It is emitted
//     as the raw number for the same reason; see the mapper.
//     WHAT WOULD CLOSE IT: quarantine audit records covering each operation
//     (release, preview, delete, policy change) so the integers can be paired
//     with the operations that produce them, or a Microsoft-published member list.
//
//   - NOT WATCHED: ResultStatus. The evidence in this package positively argues
//     AGAINST declaring it — the live captures carry "Success" (AAD sign-in) and
//     "Successful" (quarantine), two spellings of the same outcome from two
//     workloads, and mapRecord already tests for both "Failed" and "Failure" on
//     the other side. A field whose spelling varies by workload has no single set
//     to declare from four fixtures.
//
//   - NOT WATCHED: operation, workload, service, userType. Free-form
//     per-workload vocabularies (`operation` alone spans every Exchange,
//     SharePoint and Teams verb), all log-only, none bucketed to "unknown" by
//     this collector — it passes them through raw. There is no assumed set here
//     to break.
//
//   - NOT WATCHED: NetworkMessageId's presence on quarantine records, and this
//     one is a near-miss worth recording. It is the join key onto
//     defender.quarantine and defender.email_post_delivery, so the
//     MissingField case looks identical to theirs — except two of the four
//     quarantine record types in the include-list (updateQuarantineMetadata, and
//     quarantine-policy changes generally) describe POLICY, not a message, and
//     legitimately carry no message id at all. The check would fire on correct
//     data every time an admin edited a quarantine policy.
package unifiedaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	// createPath is the Graph path that creates an audit-log query.
	createPath = "/security/auditLog/queries"
	// betaBaseURL is the Graph beta service root. The audit query API is
	// beta-only on the m7kni tenant (live 2026-07-16: POST /v1.0/security/
	// auditLog/queries -> HTTP 404 UnknownError; POST /beta/... -> 201). Graph's
	// docs list a v1.0 form, but it isn't served here — same beta-only reality
	// as the signInEventTypes filter. So this Experimental collector targets
	// beta via QueryConfig.BaseURLOverride.
	betaBaseURL = "https://graph.microsoft.com/beta"
	// name is the stable collector key / config key.
	name = "m365.unified_audit"
	// eventName is the OTLP LogRecord EventName every unified-audit record
	// carries — a NEW top-level m365.* namespace (this is neither an Entra nor
	// an Intune signal).
	eventName = "m365.audit"
	// timeField is the audit record's event-time field (RFC3339 string) the
	// engine uses to timestamp the log and evict SeenIDs.
	timeField = "createdDateTime"
	// checkpointKey namespaces this collector's watermark/SeenIDs independently
	// from a future Purview unified-audit-event collector that would poll the
	// SAME createPath with different recordTypeFilters (#98) — without a distinct
	// key the two would collide on one checkpoint and dedupe each other away.
	checkpointKey = createPath + "#m365"
)

// Schedule tuning. Creating queries in rapid succession returns HTTP 429 (#98),
// so the interval MUST stay coarse. The unified audit log's record-availability
// latency is long (Microsoft: up to 30 min–24 h), so lag and safetyLag trail
// "now" generously; overlap is large but idempotent via SeenIDs dedupe.
const (
	interval        = 30 * time.Minute
	lag             = 1 * time.Hour
	safetyLag       = 1 * time.Hour
	overlap         = 4 * time.Hour
	pageSize        = 200
	initialLookback = 4 * time.Hour
	maxWindow       = 24 * time.Hour
)

// recordTypeFilters is the curated Exchange/SharePoint/OneDrive/Teams
// include-list applied at ingest so the query returns only workloads this
// collector covers, rather than pulling everything the tenant emits.
//
// Values are the camelCase recordTypeFilters form of the PascalCase record
// types returned (filter "exchangeAdmin" ↔ record "ExchangeAdmin", per the POST
// auditLogQueries doc), and every entry here was verified PRESENT in the live
// tenant in #98. OneDrive activity is carried by the SharePoint* record types
// (there is no separate OneDrive record type; OneDrive file/sharing operations
// surface as SharePointFileOperation/SharePointSharingOperation with the
// OneDrive workload).
//
// The quarantine group is the exception to the "verified in #98" provenance
// above: those four were verified ACCEPTED by the API on the live tenant on
// 2026-07-23 instead — a query carrying all four returned HTTP 201, completed,
// and returned real records `[live-measured 2026-07-23, #233]`. They earn a
// place in a curated include-list because quarantine is low-volume and
// high-signal: it is the audit trail of a message being HELD or RELEASED
// (plus previewed, deleted, and quarantine-policy changes), not a firehose like
// the DLPEndpoint traffic excluded below. teamsQuarantineMetadata is the
// Teams-message quarantine record type, and is the near-term route to Teams
// quarantine coverage.
//
// Deliberately EXCLUDED: DLPEndpoint (3,003 of #98's 3,837 records were
// endpoint-DLP FileDeleted from one host — high volume, low signal),
// AzureActiveDirectory / *StsLogon (covered by the sign-in and directory-audit
// collectors), and the Defender/MDI/MIP/Purview record types (a future Purview
// collector's concern — note this does NOT extend to the quarantine record
// types below, which are Exchange Online Protection's own audit trail and are
// included). Other Exchange record types exist (exchangeItem,
// exchangeItemGroup); add them here if a tenant needs them.
var recordTypeFilters = []string{
	"exchangeAdmin",
	"exchangeItemAggregated",
	"sharePointFileOperation",
	"sharePointListOperation",
	"sharePointFieldOperation",
	"sharePointSharingOperation",
	"microsoftTeams",
	"microsoftTeamsAdmin",
	// Quarantine (#233): message held/released/previewed/deleted, and
	// quarantine-policy changes.
	"quarantine",
	"quarantineMetadata",
	"teamsQuarantineMetadata",
	"updateQuarantineMetadata",
}

// The wire assumptions this collector watches at runtime (#234). Each names a
// guarantee taken from a single capture; see the package doc for what each one
// costs when it stops holding.
const (
	// ruleRecordTypeFilter: a record type this collector never asked for came
	// back from a filtered query.
	ruleRecordTypeFilter = "record_type_filter"
	// ruleAuditDataObject: auditData stopped being a plain nested object.
	ruleAuditDataObject = "audit_data_object"
	// ruleUserFieldCrossing: the crossed user fields stopped being crossed.
	ruleUserFieldCrossing = "user_field_crossing"
)

// excludedRecordTypes is the evidence-backed half of the record-type filter
// check: record types LIVE-OBSERVED in this tenant that recordTypeFilters
// deliberately does not ask for. If one of them comes back from a filtered
// query, the include-list has stopped filtering server-side — no inference
// required.
//
// It is deliberately NOT the complement of recordTypeFilters. The filter values
// are camelCase ("sharePointFileOperation") while the returned
// auditLogRecordType is PascalCase ("SharePointFileOperation"), and the mapping
// between the two forms is asserted by Microsoft's documentation, confirmed on
// the wire for exactly one pair (quarantine -> Quarantine, live-measured
// 2026-07-23). Deriving the whole allowed set from that transformation would
// make the watchdog fire on a correct record whose PascalCase spelling differs
// from the mechanical one — the exact failure mode #234 forbids. So this checks
// only what was measured: the five types the 2026-07-17 census actually counted
// in this tenant (DLPEndpoint 468, DataInsightsRestApiAudit 18, AuditSearch 6,
// AzureActiveDirectoryStsLogon 6, AzureActiveDirectory 2), every one of them
// excluded on purpose. Three are pinned as fixtures in this package's tests;
// DLPEndpoint and AzureActiveDirectory come from that census.
//
// The consequence of a break is not subtle: DLPEndpoint alone was 78% of an
// unfiltered window, so the collector would silently start ingesting several
// times its intended volume.
var excludedRecordTypes = wirecheck.NewEnum(
	"DLPEndpoint",
	"DataInsightsRestApiAudit",
	"AuditSearch",
	"AzureActiveDirectoryStsLogon",
	"AzureActiveDirectory",
)

// watcher carries the wire-assumption reporter across jobpipeline's mapper
// boundary (#234).
//
// jobpipeline.QueryConfig.Map is func(record) (id, Event) — it is handed no
// emitter. wirecheck needs one: the WARN log alone is not alertable, and the
// counter is the whole point. Rather than widen a signature the engine's other
// callers share, this collector BINDS the emitter of the window that is running
// for the duration of its own CollectWindow, and the mapper reads it back.
//
// Map runs synchronously inside CollectWindow, so the mapper always sees the
// emitter of the window it is part of. The mutex is not for that: it is because
// nothing promises CollectWindow is never entered twice at once, and a data race
// on a plain field would be a real one under -race.
type watcher struct {
	r *wirecheck.Reporter

	mu sync.Mutex
	e  telemetry.Emitter
}

// bind sets the emitter findings are counted onto; bind(nil) clears it. A nil
// emitter still logs the WARN, it just cannot count — see wirecheck.report.
func (w *watcher) bind(e telemetry.Emitter) {
	w.mu.Lock()
	w.e = e
	w.mu.Unlock()
}

func (w *watcher) emitter() telemetry.Emitter {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.e
}

// mapRecord is the engine's Map hook: the wire checks, then the pure mapper.
// Report-only — nothing here can change the id, the event, or whether the record
// is emitted.
func (w *watcher) mapRecord(rec map[string]any) (string, telemetry.Event) {
	w.check(rec)
	return mapRecord(rec)
}

// check reports anything on this record that contradicts what the collector was
// built against. See the package doc for why each check exists, and for the
// fields deliberately left unwatched.
func (w *watcher) check(rec map[string]any) {
	e := w.emitter()

	// The dedupe key. An empty id poisons SeenIDs: the first one is emitted and
	// remembered as "", and every later record with an empty id is then deduped
	// away as already seen.
	if str(rec, "id") == "" {
		w.r.MissingField(e, semconv.AttrId)
	}

	// The include-list is what keeps this collector off the tenant's firehose.
	if rt := str(rec, "auditLogRecordType"); excludedRecordTypes.Has(rt) {
		w.r.Invariant(e, ruleRecordTypeFilter,
			"record type "+rt+" came back from a query that did not ask for it — recordTypeFilters is no longer filtering server-side, and this collector is ingesting record types it deliberately excludes")
	}

	// auditData as anything but a nested object takes six attributes with it.
	raw, present := rec["auditData"]
	if present && raw != nil {
		if _, ok := raw.(map[string]any); !ok {
			w.r.Invariant(e, ruleAuditDataObject,
				fmt.Sprintf("auditData arrived as %T, not a nested object — workload, result_status, client_ip, network_message_id, release_to and request_type are all silently dropped", raw))
		}
	}

	// The crossed user fields, checked against the record's OWN envelope: the
	// classic O365 field names live inside auditData, so a record proves or
	// disproves the crossing by itself. Only compared when both sides are
	// populated — an absent side is the normal case, not a break.
	if data := nested(rec, "auditData"); data != nil {
		if classic, top := str(data, "UserKey"), str(rec, "userId"); classic != "" && top != "" && classic != top {
			w.r.Invariant(e, ruleUserFieldCrossing,
				"the envelope's userId no longer holds auditData.UserKey — user_key is mapped from that crossing (#151)")
		}
		if classic, top := str(data, "UserId"), str(rec, "userPrincipalName"); classic != "" && top != "" && classic != top {
			w.r.Invariant(e, ruleUserFieldCrossing,
				"the envelope's userPrincipalName no longer holds auditData.UserId — user_id is mapped from that crossing (#151)")
		}
	}
}

// collectorImpl is the M365 unified-audit WindowCollector: the generic
// jobpipeline.JobCollector plus the experimental-opt-in and permission
// declarations the composition root gates on.
type collectorImpl struct {
	*jobpipeline.JobCollector
	watch *watcher
}

// CollectWindow binds the window's emitter for the duration of the poll, so
// findings raised inside the mapper reach the counter, then delegates to the
// generic collector. See the watcher type for why the emitter has to travel this
// way.
func (c *collectorImpl) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	c.watch.bind(e)
	defer c.watch.bind(nil)
	return c.JobCollector.CollectWindow(ctx, from, to, e)
}

// Experimental marks the collector opt-in (beta/licensing-gated surface); the
// composition root registers it only on an explicit config enable.
func (c *collectorImpl) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// AuditLogsQuery.Read.All is the broad scope used for v1. Granular per-workload
// variants exist and gate independently (AuditLogsQuery-Exchange.Read.All,
// -SharePoint.Read.All, -OneDrive.Read.All — verified live, #98); the broad
// scope is used here to keep the include-list free to span workloads without a
// scope change. All are read-only — no ReadWrite exception like Intune export.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"AuditLogsQuery.Read.All"}
}

// buildRequest returns the JSON query body for the window [from, to]: RFC3339
// UTC start/end plus the curated recordTypeFilters include-list.
func buildRequest(from, to time.Time) ([]byte, error) {
	req := struct {
		FilterStartDateTime string   `json:"filterStartDateTime"`
		FilterEndDateTime   string   `json:"filterEndDateTime"`
		RecordTypeFilters   []string `json:"recordTypeFilters"`
	}{
		FilterStartDateTime: from.UTC().Format(time.RFC3339),
		FilterEndDateTime:   to.UTC().Format(time.RFC3339),
		RecordTypeFilters:   recordTypeFilters,
	}
	return json.Marshal(req)
}

// mapRecord turns one raw auditLogRecord (the #98 live shape) into its dedupe id
// (the immutable auditLogRecord.id) and the OTLP log Event. It sets only the
// attributes actually present, so a record without a UPN or client IP simply
// omits them rather than emitting empty ones. Workload, ResultStatus, and
// ClientIP all come from the polymorphic auditData sub-object (the classic
// O365 Management schema embedded there) — see the client_ip comment below for
// why, unlike additionalInfo on entra/riskdetections, auditData needs no
// second JSON decode here.
func mapRecord(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	operation := str(rec, "operation")
	recordType := str(rec, "auditLogRecordType")
	service := str(rec, "service")

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, id)
	telemetry.SetStr(attrs, semconv.AttrOperation, operation)
	telemetry.SetStr(attrs, semconv.AttrRecordType, recordType)
	telemetry.SetStr(attrs, semconv.AttrService, service)
	telemetry.SetStr(attrs, semconv.AttrUserType, str(rec, "userType"))
	// The two user fields are CROSSED between wire and attribute — NOT a typo,
	// and the single most counter-intuitive pair of lines in this package:
	//
	//	wire userId            -> attr user_key : it holds the classic UserKey
	//	wire userPrincipalName -> attr user_id  : it holds the classic UserId
	//
	// The wire's `userId` is a Microsoft misnomer: its CONTENT is the classic
	// O365 schema's UserKey, not the classic UserId. Live-verified 500/500 over
	// the same tenant and window as the m365.activity twin (2026-07-17,
	// #100/#151):
	//
	//	userId            == classic UserKey : 500/500
	//	userPrincipalName == classic UserId  : 500/500 (byte-identical)
	//
	// Taking the wire names at face value IS #151: it made `user_id` mean UserKey
	// here and UserId on m365.activity — one attribute, two meanings, with
	// nothing on the record saying which. Each attribute is named for what it
	// CONTAINS, so both transports emit `user_key` (classic UserKey) and
	// `user_id` (classic UserId), and no attribute carries two meanings. See
	// TestTopLevelUserIDIsTheClassicUserKey.
	//
	// `user_id` was called `user_principal_name` until 2026-07-17. The classic
	// UserId is UPN-shaped on only ~91% of live records (bare GUIDs, "Not
	// Available", "ServicePrincipal_<guid>", display names make up the rest), so
	// that name was false on the rest. Do not re-add it alongside `user_id`:
	// two attributes from one field, identical by construction, is #151 exactly.
	telemetry.SetStr(attrs, semconv.AttrUserKey, str(rec, "userId"))
	telemetry.SetStr(attrs, semconv.AttrUserId, str(rec, "userPrincipalName"))
	telemetry.SetStr(attrs, semconv.AttrObjectId, str(rec, "objectId"))

	sev := telemetry.SeverityInfo
	if data := nested(rec, "auditData"); data != nil {
		telemetry.SetStr(attrs, semconv.AttrWorkload, str(data, "Workload"))
		result := str(data, "ResultStatus")
		telemetry.SetStr(attrs, semconv.AttrResultStatus, result)
		if result == "Failed" || result == "Failure" {
			sev = telemetry.SeverityWarn
		}
		// The envelope's top-level clientIp is null on every record this
		// project has ever captured (500/500, #170); the real address lives
		// nested in auditData, which is already a decoded map[string]any at
		// this point (unlike entra/riskdetections' additionalInfo, auditData
		// is NOT a doubly-JSON-encoded string on this transport — it arrives
		// as a plain nested object, same as Workload/ResultStatus above), so
		// no second json.Unmarshal is needed to reach it.
		telemetry.SetStr(attrs, semconv.AttrClientIp, str(data, "ClientIP"))
		// The quarantine record types' payload (#233), present only on those
		// records — SetStr/SetNum omit an absent value, so no record-type branch
		// is needed here (and a `recordType == "Quarantine"` guard would be both
		// dead weight and wrong: it would miss the other three types).
		//
		// network_message_id is the join key. defender.email,
		// defender.email_post_delivery and defender.email_url all key on the
		// same id, so it is what ties "this message was released from
		// quarantine" to the message itself — the whole reason these records are
		// worth collecting rather than counting.
		//
		// RequestType is an UNDOCUMENTED integer enum: Microsoft publishes no
		// member list for it, so it is emitted as the raw number rather than a
		// guessed label. Do not invent a mapping — a wrong label is worse than a
		// number a reader can look up once the enum is known.
		telemetry.SetStr(attrs, semconv.AttrNetworkMessageId, str(data, "NetworkMessageId"))
		telemetry.SetStr(attrs, semconv.AttrReleaseTo, str(data, "ReleaseTo"))
		telemetry.SetNum(attrs, semconv.AttrRequestType, data, "RequestType")
	}

	return id, telemetry.Event{
		Name:     eventName,
		Body:     auditBody(operation, service, str(rec, "userPrincipalName")),
		Severity: sev,
		Attrs:    attrs,
	}
}

// auditBody builds a short human-readable summary line for an audit record.
//
// userID is the classic UserId (the wire's userPrincipalName). It is NOT
// necessarily a UPN — ~9% of live records carry a GUID or a sentinel — which is
// why neither the parameter nor the attribute calls it one.
func auditBody(operation, service, userID string) string {
	who := userID
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

// newCollector builds the M365 unified-audit WindowCollector for one tenant. It
// wires the async QueryConfig to the tenant's shared, instrumented JobClient
// (deps.JobClient) and checkpoint store (deps.Store).
func newCollector(d collectors.WindowDeps) *collectorImpl {
	w := &watcher{r: wirecheck.New(name, d.Logger)}
	cfg := jobpipeline.QueryConfig{
		CreatePath:      createPath,
		BaseURLOverride: betaBaseURL,
		CheckpointKey:   checkpointKey,
		BuildRequest:    buildRequest,
		Map:             w.mapRecord,
		TimeField:       timeField,
		SafetyLag:       safetyLag,
		Overlap:         overlap,
		PageSize:        pageSize,
	}
	jc := jobpipeline.NewJobCollector(name, interval, lag, d.TenantID, cfg, d.JobClient, d.Store)
	return &collectorImpl{JobCollector: jc, watch: w}
}

// --- small defensive accessors for untyped Graph JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func nested(m map[string]any, key string) map[string]any {
	n, _ := m[key].(map[string]any)
	return n
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
	_ collectors.Experimental   = (*collectorImpl)(nil)
)
