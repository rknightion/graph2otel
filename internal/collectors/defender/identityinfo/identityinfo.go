// Package identityinfo is the Defender advanced-hunting IdentityInfo blob
// collector (#106): one OTLP log per periodic identity snapshot Defender for
// Identity/Entra reports, read from the shared Azure Storage account.
//
// IdentityInfo is a SNAPSHOT-shaped table, not an event stream — it carries the
// current state of one identity (account, HR/contact metadata, risk level,
// criticality, and Entra PIM role assignment), refreshed periodically per
// identity. There is no ActionType and no InitiatingProcess block (nothing
// "happened"; this is "what the identity looks like right now"), so this
// mapper does not call defender.StampDeviceCommon or
// defender.StampInitiatingProcess. This is per-identity data Graph does not
// expose directly (CriticalityLevel, BlastRadius, PIM roles) — high value for
// the SIEM feed this project is.
//
// ReportId here is a STRING (a GUID), unlike the small numeric ReportId on the
// Device* event tables or the huge-int-string ReportId on DeviceInfo — so it is
// mapped as a StrField, not via defender.StampNums/telemetry.SetNum
// (live-measured against the fixture, 2026-07-18, #106).
package identityinfo

import (
	"fmt"
	"strconv"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/defender"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// name is the stable collector key and config-enable key.
	name = "defender.identity_info"
	// table is the advanced-hunting table, lowercased into its container.
	table = "identityinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.identity_info"
)

// identityInfoStrFields is the IdentityInfo-specific string column set: account
// identity, HR/contact metadata, risk/lifecycle state, and lineage. ReportId is
// included here (a GUID on this table, unlike the event tables' small numeric
// ReportId or DeviceInfo's huge-int-string ReportId).
var identityInfoStrFields = []defender.StrField{
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrIdentityId, Src: "IdentityId"},
	{Attr: semconv.AttrAccountName, Src: "AccountName"},
	{Attr: semconv.AttrAccountDomain, Src: "AccountDomain"},
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrAccountDisplayName, Src: "AccountDisplayName"},
	{Attr: semconv.AttrGivenName, Src: "GivenName"},
	{Attr: semconv.AttrSurname, Src: "Surname"},
	{Attr: semconv.AttrDepartment, Src: "Department"},
	{Attr: semconv.AttrJobTitle, Src: "JobTitle"},
	{Attr: semconv.AttrEmailAddress, Src: "EmailAddress"},
	{Attr: semconv.AttrManager, Src: "Manager"},
	{Attr: semconv.AttrAddress, Src: "Address"},
	{Attr: semconv.AttrCity, Src: "City"},
	{Attr: semconv.AttrCountry, Src: "Country"},
	{Attr: semconv.AttrPhone, Src: "Phone"},
	{Attr: semconv.AttrCreatedDateTime, Src: "CreatedDateTime"},
	{Attr: semconv.AttrDistinguishedName, Src: "DistinguishedName"},
	{Attr: semconv.AttrOnPremSid, Src: "OnPremSid"},
	{Attr: semconv.AttrCloudSid, Src: "CloudSid"},
	{Attr: semconv.AttrSourceProvider, Src: "SourceProvider"},
	{Attr: semconv.AttrChangeSource, Src: "ChangeSource"},
	{Attr: semconv.AttrBlastRadius, Src: "BlastRadius"},
	{Attr: semconv.AttrCompanyName, Src: "CompanyName"},
	{Attr: semconv.AttrDeletedDateTime, Src: "DeletedDateTime"},
	{Attr: semconv.AttrEmployeeId, Src: "EmployeeId"},
	{Attr: semconv.AttrOtherMailAddresses, Src: "OtherMailAddresses"},
	{Attr: semconv.AttrRiskLevel, Src: "RiskLevel"},
	{Attr: semconv.AttrRiskLevelDetails, Src: "RiskLevelDetails"},
	{Attr: semconv.AttrState, Src: "State"},
	{Attr: semconv.AttrUserAccountControl, Src: "UserAccountControl"},
	{Attr: semconv.AttrIdentityEnvironment, Src: "IdentityEnvironment"},
	{Attr: semconv.AttrOnPremObjectId, Src: "OnPremObjectId"},
	{Attr: semconv.AttrPrivilegedEntraPimRoles, Src: "PrivilegedEntraPimRoles"},
	{Attr: semconv.AttrSipProxyAddress, Src: "SipProxyAddress"},
	{Attr: semconv.AttrType, Src: "Type"},
}

// identityInfoNumFields is the numeric part: the per-identity criticality
// score.
var identityInfoNumFields = []defender.NumField{
	{Attr: semconv.AttrCriticalityLevel, Src: "CriticalityLevel"},
}

// identityInfoBoolFields is the boolean part: whether the account is enabled.
var identityInfoBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsAccountEnabled, Src: "IsAccountEnabled"},
}

// strSlice reads a JSON array-of-strings column (Tags, SourceProviders),
// dropping any non-string element. An absent or non-array column yields an
// empty slice.
func strSlice(props map[string]any, key string) []string {
	raw, _ := props[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// criticalityStr renders the numeric CriticalityLevel column for the Body
// summary line, "" when absent or non-numeric.
func criticalityStr(props map[string]any) string {
	f, ok := props["CriticalityLevel"].(float64)
	if !ok {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// mapRecord turns one raw IdentityInfo record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// string/numeric/bool field families plus the Tags/SourceProviders arrays.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props := defender.Props(rec)
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := defender.EventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}

	attrs := telemetry.Attrs{}
	defender.StampStrings(attrs, props, identityInfoStrFields)
	defender.StampNums(attrs, props, identityInfoNumFields)
	defender.StampBools(attrs, props, identityInfoBoolFields)
	telemetry.SetStrs(attrs, semconv.AttrTags, strSlice(props, "Tags"))
	telemetry.SetStrs(attrs, semconv.AttrSourceProviders, strSlice(props, "SourceProviders"))

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s (%s): criticality=%s",
			defender.Str(props, "AccountDisplayName"),
			defender.Str(props, "AccountUpn"),
			criticalityStr(props)),
		Severity:  telemetry.SeverityInfo,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection (a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package).
type blobCollector struct {
	*blobpipeline.BlobCollector
}

func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	return blobCollector{defender.New(name, table, mapRecord, d)}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var _ collector.SnapshotCollector = blobCollector{}
