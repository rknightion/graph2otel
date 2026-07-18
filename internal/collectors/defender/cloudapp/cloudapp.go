// Package cloudapp is the Defender advanced-hunting CloudAppEvents blob
// collector (#106): one OTLP log per cloud-app activity Defender for Cloud
// Apps (MCAS) observed — SharePoint/Exchange/OAuth file operations, ACL
// changes, mail access, and third-party OAuth app activity — read from the
// shared Azure Storage account.
//
// CloudAppEvents is an EVENT table (it carries ActionType/ActivityType) but is
// NOT a Device* table: it has no InitiatingProcess, no DeviceId, no file
// hashes. Its identity block is the account/app/session that performed the
// activity, so every field here is mapped table-specifically rather than via
// defender.StampDeviceCommon/StampInitiatingProcess.
package cloudapp

import (
	"encoding/json"
	"fmt"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/defender"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// name is the stable collector key and config-enable key.
	name = "defender.cloud_app_event"
	// table is the advanced-hunting table, lowercased into its container.
	table = "cloudappevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.cloud_app_event"
)

// cloudAppStrFields is the table-specific string column set: action/activity
// identity, the account and application involved, network/geo context, and the
// object the activity acted on.
var cloudAppStrFields = []defender.StrField{
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrAccountDisplayName, Src: "AccountDisplayName"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrAccountId, Src: "AccountId"},
	{Attr: semconv.AttrDeviceType, Src: "DeviceType"},
	{Attr: semconv.AttrOsPlatform, Src: "OSPlatform"},
	{Attr: semconv.AttrIpAddress, Src: "IPAddress"},
	{Attr: semconv.AttrCountryCode, Src: "CountryCode"},
	{Attr: semconv.AttrCity, Src: "City"},
	{Attr: semconv.AttrIsp, Src: "ISP"},
	{Attr: semconv.AttrUserAgent, Src: "UserAgent"},
	{Attr: semconv.AttrActivityType, Src: "ActivityType"},
	{Attr: semconv.AttrObjectName, Src: "ObjectName"},
	{Attr: semconv.AttrObjectType, Src: "ObjectType"},
	{Attr: semconv.AttrObjectId, Src: "ObjectId"},
	{Attr: semconv.AttrAccountType, Src: "AccountType"},
	{Attr: semconv.AttrIpCategory, Src: "IPCategory"},
	{Attr: semconv.AttrUserAgentTags, Src: "UserAgentTags"},
	{Attr: semconv.AttrAuditSource, Src: "AuditSource"},
	{Attr: semconv.AttrOauthAppId, Src: "OAuthAppId"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrApplication, Src: "Application"},
}

// cloudAppNumFields is the numeric column set: application/instance ids.
var cloudAppNumFields = []defender.NumField{
	{Attr: semconv.AttrApplicationId, Src: "ApplicationId"},
	{Attr: semconv.AttrAppInstanceId, Src: "AppInstanceId"},
}

// cloudAppBoolFields is the boolean column set.
var cloudAppBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsAnonymousProxy, Src: "IsAnonymousProxy"},
	{Attr: semconv.AttrIsAdminOperation, Src: "IsAdminOperation"},
	{Attr: semconv.AttrIsExternalUser, Src: "IsExternalUser"},
	{Attr: semconv.AttrIsImpersonated, Src: "IsImpersonated"},
}

// jsonStr re-marshals a native JSON value (object, array, or null) back to its
// JSON string form, for the columns this table carries as nested
// objects/arrays rather than scalars. nil (an absent or JSON-null column) and
// a marshal error both yield "", so the caller's SetStr omits the attribute
// rather than emitting a bogus value.
func jsonStr(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// strSlice reads props[key] as a native JSON array and returns only its string
// elements, dropping anything that isn't a string. A missing or non-array
// column yields an empty slice.
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

// mapRecord turns one raw CloudAppEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, stamp the
// string/numeric/bool field families, then the object-shaped columns
// (AdditionalFields, RawEventData, ActivityObjects, LastSeenForUser,
// SessionData) re-marshaled verbatim to JSON strings, and finally the
// native-array columns (IPTags, UncommonForUser) as string lists.
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
	defender.StampStrings(attrs, props, cloudAppStrFields)
	defender.StampNums(attrs, props, cloudAppNumFields)
	defender.StampBools(attrs, props, cloudAppBoolFields)

	telemetry.SetStr(attrs, semconv.AttrAdditionalFields, jsonStr(props["AdditionalFields"]))
	telemetry.SetStr(attrs, semconv.AttrRawEventData, jsonStr(props["RawEventData"]))
	telemetry.SetStr(attrs, semconv.AttrActivityObjects, jsonStr(props["ActivityObjects"]))
	telemetry.SetStr(attrs, semconv.AttrLastSeenForUser, jsonStr(props["LastSeenForUser"]))
	telemetry.SetStr(attrs, semconv.AttrSessionData, jsonStr(props["SessionData"]))

	telemetry.SetStrs(attrs, semconv.AttrIpTags, strSlice(props, "IPTags"))
	telemetry.SetStrs(attrs, semconv.AttrUncommonForUser, strSlice(props, "UncommonForUser"))

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s/%s on %s by %s", defender.Str(props, "ActionType"), defender.Str(props, "ActivityType"), defender.Str(props, "ObjectName"), defender.Str(props, "AccountDisplayName")),
		Severity:  telemetry.SeverityInfo,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection (a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package), and so Experimental() marks it opt-in.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// Experimental reports true: the Defender advanced-hunting tables are the
// highest-volume surface graph2otel touches, so each is off by default and
// enabled explicitly per tenant (#106).
func (blobCollector) Experimental() bool { return true }

func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	return blobCollector{defender.New(name, table, mapRecord, d)}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var (
	_ collector.SnapshotCollector = blobCollector{}
	_ collectors.Experimental     = blobCollector{}
)
