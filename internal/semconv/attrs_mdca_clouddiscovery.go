package semconv

// Attribute keys used only by mdca.cloud_discovery (#361) — the Defender for
// Cloud Apps Cloud Discovery APP INVENTORY signal, over the Graph BETA
// dataDiscovery surface. This is a different transport from mdca.discovery_parse
// (attrs_mdca.go): that collector reaches the legacy MDCA portal API with a
// static token; this one is ordinary Graph app-only auth against
// /beta/security/dataDiscovery/cloudAppDiscovery. Shared keys these records
// also emit (id via AttrId, display_name via AttrDisplayName, category via
// AttrCategory, tags via AttrTags, risk_score via AttrRiskScore,
// created_date_time via AttrCreatedDateTime, last_modified_date_time via
// AttrLastModifiedDateTime) are reused from attrs.go/attrs_shared.go/
// attrs_defender.go/attrs_entra.go, never redeclared. Every key here is a
// semconv.Attr* constant (Gate B); no value duplicates another constant
// (Gate A).
const (
	// AttrLastDataReceivedDateTime is an uploadedStream's lastDataReceivedDateTime
	// — when this stream last actually received log data, distinct from
	// AttrLastModifiedDateTime (when the stream's own CONFIGURATION last changed).
	AttrLastDataReceivedDateTime = "last_data_received_date_time"
	// AttrSupportedEntityTypes is an uploadedStream's supportedEntityTypes array
	// (e.g. "userName", "ipAddress", "machineName") — what identity shapes this
	// stream's log format can carry, not per-entity data.
	AttrSupportedEntityTypes = "supported_entity_types"
	// AttrSupportedTrafficTypes is an uploadedStream's supportedTrafficTypes array
	// (e.g. "uploadedBytes", "downloadedBytes").
	AttrSupportedTrafficTypes = "supported_traffic_types"
	// AttrAnonymizeMachineData / AttrAnonymizeUserData are an uploadedStream's
	// privacy-posture switches. Both are decoded as pointers upstream: a plain
	// bool would fabricate `false` for a privacy setting Graph never reported,
	// which is the worst field on this collector to get that wrong.
	AttrAnonymizeMachineData = "anonymize_machine_data"
	AttrAnonymizeUserData    = "anonymize_user_data"
	// AttrIsSnapshotReport distinguishes a one-off imported report from a live
	// continuous upload stream. It is also a bounded metric label
	// (mdca.cloud_discovery.streams{is_snapshot_report}) — three values
	// (true/false/unknown), never per-stream identity.
	AttrIsSnapshotReport = "is_snapshot_report"
	// AttrLogFileCount is an uploadedStream's logFileCount — the raw per-stream
	// count on the twin. The metric side never labels by stream identity; see
	// mdca.cloud_discovery.log_files.total (unlabeled sum) instead.
	AttrLogFileCount = "log_file_count"
	// AttrAppsDiscovered is how many discovered-app rows a discovery_stream twin
	// saw for that stream (post-cap), so a reader can trace a stream to its own
	// app count without a LogQL join.
	AttrAppsDiscovered = "apps_discovered"
	// AttrAppsTruncated marks that a stream's app list hit maxAppsPerStream — a
	// silent cap would report clean success over an unknown remainder. Carried on
	// both the discovery_stream twin (per stream, string bool) and the bounded
	// mdca.cloud_discovery.apps_truncated metric (an unlabeled count of streams,
	// not a label — the metric answers "how many streams", the twin answers
	// "which one").
	AttrAppsTruncated = "apps_truncated"
	// AttrRiskBand is OUR banding of a discovered app's riskScore (low/medium/
	// high/critical) — a bounded metric label an operator can alert on, distinct
	// from the raw 1-10 AttrRiskScore (attrs_defender.go) the twin also carries.
	AttrRiskBand = "risk_band"
	// AttrUserCount / AttrIpAddressCount are a discovered app's userCount /
	// ipAddressCount — bounded aggregate counts on the log twin only, never a
	// metric label (the count itself, like every per-entity number here, is not
	// what's bounded — the APP is what would be unbounded as a label).
	AttrUserCount      = "user_count"
	AttrIpAddressCount = "ip_address_count"
	// AttrDomains is a discovered app's domains array, CAPPED at maxDomains with
	// its true (uncapped) AttrDomainCount and an AttrDomainsTruncated flag — the
	// widest app observed live (2026-07-28, #361) carries 355 domains, so
	// truncation is the normal case here, not an edge case.
	AttrDomains          = "domains"
	AttrDomainCount      = "domain_count"
	AttrDomainsTruncated = "domains_truncated"
	// AttrStreamId / AttrStreamDisplayName let a discovered_app twin be traced
	// back to the discovery_stream that saw it, without re-deriving the app's own
	// id/display_name attributes for that purpose.
	AttrStreamId          = "stream_id"
	AttrStreamDisplayName = "stream_display_name"
	// AttrUploadBytes / AttrDownloadBytes are a discovered app's
	// uploadNetworkTrafficInBytes / downloadNetworkTrafficInBytes over the
	// aggregation period.
	AttrUploadBytes   = "upload_bytes"
	AttrDownloadBytes = "download_bytes"
	// AttrLastSeenDateTime is a discovered app's lastSeenDateTime.
	AttrLastSeenDateTime = "last_seen_date_time"
)
