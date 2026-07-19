// Package cloudpcaudit is the Windows 365 / Cloud PC admin-audit blob collector
// (#198): one OTLP log per Cloud PC control-plane operation (provisioning-policy
// create/patch/delete, user-setting change, reprovision, grace-period end),
// read from the shared Azure Storage account's `Windows365AuditLogs` diagnostic
// category rather than polled from Graph.
//
// There is NO Graph endpoint for this stream — Windows 365 admin audit exists
// only as an Azure Monitor diagnostic-settings category, so blob is the sole
// transport (like the Defender advanced-hunting tables and MicrosoftGraphActivityLogs).
// It is intune-domain: Cloud PC is administered through Intune / the virtualEndpoint
// surface, and this is the CloudPC peer of intune.audit_events — it reuses that
// collector's attribute vocabulary field-for-field so the two audit streams query
// alike.
//
// # The OtherExtendedProperties wire format
//
// Unlike every other diagnostic category, the actionable payload here is NOT a
// nested JSON object — it is a single semi-structured STRING in
// properties.OtherExtendedProperties, a flat comma-separated `key:value` list
// whose scalar values never contain a comma, terminated by a `resources:[...]`
// array of objects. Each resource is `{DisplayName, Type, ResourceId,
// ModifiedProperty:[{Name,OldValue,NewValue}]}`. Live-captured verbatim across 8
// operation types (2026-07-19, #198); Microsoft documents none of this, so it is
// parsed against the wire (#142).
//
// Secret boundary (#112): only modified-property NAMES are emitted, never their
// Old/New VALUES — a NewValue can be a credential or arbitrary config, and the
// value carries no query benefit a name does not. Parsing names-only also side-
// steps the one hard case: an `assignments` NewValue is itself a JSON array with
// its own braces/commas, which a value-parser would have to survive; a
// name-only parser never touches it.
//
// # Event time
//
// Bound to the inner activityDateTime inside OtherExtendedProperties (the moment
// the operation happened, US-format e.g. "7/19/2026 3:07:15 PM", UTC), NOT the
// envelope `time`, which is Azure's export clock ~1s later (live-measured
// 2026-07-19, the same envelope-vs-event skew every category shows — #135). No
// fallback: a record with no parseable activityDateTime is dropped rather than
// mis-dated (CLAUDE.md emitter rule).
package cloudpcaudit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// name is the stable collector key and config-enable key.
	name = "intune.cloud_pc_audit"
	// blobContainer is the Azure Monitor diagnostic-settings category for
	// Windows 365 admin audit, lowercased into its fixed container name.
	blobContainer = "insights-logs-windows365auditlogs"
	// eventName is the OTLP LogRecord EventName every Cloud PC audit record carries.
	eventName = "intune.cloud_pc_audit"
	// blobInterval is how often the container is re-listed. Records land minutes
	// behind the event and the floor is Azure-side, so polling faster only bills
	// list operations (#89).
	blobInterval = 5 * time.Minute
	// usTimeLayout parses the US-format, timezone-less activityDateTime the wire
	// carries inside OtherExtendedProperties; it reads as UTC (verified against the
	// envelope `time` Z clock, #198).
	usTimeLayout = "1/2/2006 3:04:05 PM"
)

// Scalar-field extractors for the flat head of OtherExtendedProperties. Every
// scalar value is comma-free on the wire (guids, enum words, and the space-but-
// comma-free US timestamp), so each value is simply everything up to the next
// comma. Order-independent by construction.
var (
	reOperationType = regexp.MustCompile(`operationType:([^,]*)`)
	reCategory      = regexp.MustCompile(`category:([^,]*)`)
	reActivityTime  = regexp.MustCompile(`activityDateTime:([^,]*)`)
	reAuditEventID  = regexp.MustCompile(`auditEvenId:([^,]*)`) // Microsoft's spelling, kept verbatim
	reCorrelationID = regexp.MustCompile(`correlationId:([^,]*)`)
	// Resource-object extractors. Each anchors on the field that FOLLOWS it in
	// every resource object, so a modified-property Name that happens to contain
	// "Type" or "DisplayName" (e.g. "MicrosoftManagedDesktop.Type") cannot match:
	// only the resource-level occurrences are followed by ", <nextfield>:".
	reResDisplayName = regexp.MustCompile(`DisplayName:(.*?), Type:`)
	// ", Type:" (not bare "Type:") so the leading "operationType:" scalar cannot
	// match; the resource-level Type is always preceded by ", " after DisplayName.
	reResType = regexp.MustCompile(`, Type:(.*?), ResourceId:`)
	reResID   = regexp.MustCompile(`ResourceId:(.*?), ModifiedProperty:`)
	// A modified-property name is everything between "{Name:" and ", OldValue:".
	// The "{" prefix stops it matching the "Name:" tail of "DisplayName:"; names
	// are comma-free property paths, and anchoring on ", OldValue:" makes an
	// arbitrary NewValue (even nested JSON) irrelevant.
	reModName = regexp.MustCompile(`\{Name:(.*?), OldValue:`)
)

// first returns the first capture group of re in s, "" when it does not match.
func first(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// allFirst returns the first capture group of every non-overlapping match of re
// in s, in wire order, dropping empty captures.
func allFirst(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if v := strings.TrimSpace(m[1]); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// identity0 pulls the first entry's Identity from one of the record's `identity`
// arrays (UPN/ObjectID/ApplicationID), each an array-of-objects [{Identity:…}].
func identity0(id map[string]any, key string) string {
	arr, _ := id[key].([]any)
	if len(arr) == 0 {
		return ""
	}
	m, _ := arr[0].(map[string]any)
	s, _ := m["Identity"].(string)
	return s
}

// mapRecord turns one raw Windows365AuditLogs record into its OTLP log Event.
// The actor's `identity.Other` block (the app's granted-scope list + the constant
// "Windows 365 Ibiza Extension" proxy-app display name) is deliberately ignored:
// it is the permission-string noise the #198 spike flagged, and the real
// initiator is the UPN.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props, _ := rec["properties"].(map[string]any)
	if props == nil {
		return telemetry.Event{}, false
	}
	oep, _ := props["OtherExtendedProperties"].(string)
	if oep == "" {
		return telemetry.Event{}, false
	}
	ts, err := time.Parse(usTimeLayout, first(reActivityTime, oep))
	if err != nil {
		return telemetry.Event{}, false
	}

	operationName, _ := rec["operationName"].(string)
	resultType, _ := rec["resultType"].(string)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, first(reAuditEventID, oep))
	telemetry.SetStr(attrs, semconv.AttrActivity, operationName)
	telemetry.SetStr(attrs, semconv.AttrActivityOperationType, first(reOperationType, oep))
	telemetry.SetStr(attrs, semconv.AttrActivityResult, resultType)
	telemetry.SetStr(attrs, semconv.AttrCategory, first(reCategory, oep))
	telemetry.SetStr(attrs, semconv.AttrComponentName, str(props, "ComponentName"))
	telemetry.SetStr(attrs, semconv.AttrCorrelationId, first(reCorrelationID, oep))

	if id, _ := rec["identity"].(map[string]any); id != nil {
		telemetry.SetStr(attrs, semconv.AttrActorUserPrincipalName, identity0(id, "UPN"))
		telemetry.SetStr(attrs, semconv.AttrActorUserId, identity0(id, "ObjectID"))
		telemetry.SetStr(attrs, semconv.AttrActorApplicationId, identity0(id, "ApplicationID"))
	}

	telemetry.SetStrs(attrs, semconv.AttrResourceTypes, allFirst(reResType, oep))
	telemetry.SetStrs(attrs, semconv.AttrResourceDisplayNames, allFirst(reResDisplayName, oep))
	telemetry.SetStrs(attrs, semconv.AttrResourceIds, allFirst(reResID, oep))
	telemetry.SetStrs(attrs, semconv.AttrModifiedPropertyNames, dedupeSorted(allFirst(reModName, oep)))

	sev := telemetry.SeverityInfo
	if resultType != "" && resultType != "Success" {
		sev = telemetry.SeverityWarn
	}

	body := operationName
	if resultType != "" {
		body = fmt.Sprintf("%s (%s)", operationName, resultType)
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      body,
		Severity:  sev,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// dedupeSorted returns the unique values of in, sorted — so the modified-property
// name set is deterministic (a stable signals golden) regardless of wire order or
// a name repeated across resources.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// blobCollector wraps the generic BlobCollector in a package-local named type so
// collectordoc can recover THIS package (and its signals golden) by reflection —
// a bare *blobpipeline.BlobCollector resolves to the blobpipeline package instead.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newBlobCollector builds the Windows 365 audit blob collector. It is read-only
// Azure Storage ingest (not Experimental — that is reserved for beta Graph APIs,
// #183); setting blob_ingest.account_url plus streaming the Windows365AuditLogs
// diagnostic category is the whole opt-in.
func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobContainer,
		Prefix:        "tenantId=" + d.TenantID + "/",
		Map:           mapRecord,
		CollectorName: name,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(name, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var _ collector.SnapshotCollector = blobCollector{}
