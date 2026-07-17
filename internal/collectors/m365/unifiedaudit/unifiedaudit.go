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
// entra.*/intune.* for those domains; this collector emits only logs, no
// metrics). The collector's stable name/config key is "m365.unified_audit".
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the record id, UPN, client IP, object id, operation —
// belongs here as structured log attributes. That same data must NEVER become a
// metric label; this package emits no metrics.
//
// Experimental / opt-in: this targets a licensing-gated Purview Audit surface
// (Standard, included with E3, minimum; Premium/E5 for high-value records like
// MailItemsAccessed and 1-year retention — verified live in #98) and is new, so
// it is marked Experimental and registers only when config explicitly enables
// it. A default deployment does not poll it.
package unifiedaudit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/jobpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
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
// Deliberately EXCLUDED: DLPEndpoint (3,003 of #98's 3,837 records were
// endpoint-DLP FileDeleted from one host — high volume, low signal),
// AzureActiveDirectory / *StsLogon (covered by the sign-in and directory-audit
// collectors), and the Defender/MDI/MIP/Purview record types (a future Purview
// collector's concern). Other Exchange record types exist (exchangeItem,
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
}

// collectorImpl is the M365 unified-audit WindowCollector: the generic
// jobpipeline.JobCollector plus the experimental-opt-in and permission
// declarations the composition root gates on.
type collectorImpl struct {
	*jobpipeline.JobCollector
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
	cfg := jobpipeline.QueryConfig{
		CreatePath:      createPath,
		BaseURLOverride: betaBaseURL,
		CheckpointKey:   checkpointKey,
		BuildRequest:    buildRequest,
		Map:             mapRecord,
		TimeField:       timeField,
		SafetyLag:       safetyLag,
		Overlap:         overlap,
		PageSize:        pageSize,
	}
	jc := jobpipeline.NewJobCollector(name, interval, lag, d.TenantID, cfg, d.JobClient, d.Store)
	return &collectorImpl{JobCollector: jc}
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
