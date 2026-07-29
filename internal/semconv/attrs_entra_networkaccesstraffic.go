package semconv

// Attribute keys introduced by entra.network_access_traffic (#338): one
// entra.network_access_traffic log record per Global Secure Access connection,
// from GET /beta/networkAccess/logs/traffic.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrAction,
// AttrDeviceCategory (attrs_defender.go), AttrDestinationIpAddress,
// AttrDestinationPort (attrs_defender.go), AttrDeviceId, AttrPolicyId,
// AttrPolicyName (attrs_intune.go), AttrUserId, AttrUserPrincipalName
// (attrs_shared.go), AttrAgentVersion (attrs_defender_exposuregraph.go) and
// AttrUserAgent (attrs_entra.go).
//
// # Everything here is LOG-ONLY, and that is the whole design
//
// This collector emits no metrics at all. Per-connection detail — who, which
// device, which destination, which policy — is exactly the shape #112 forbids
// as a metric label: a series keyed by destination FQDN or user grows with
// traffic, and a LogQL `count by` over these attributes answers the same
// question for free. Measured volume is ~3,695 records/hour from a SINGLE
// client (live 2026-07-29), so a label here would be the most expensive
// mistake available in this project.
//
// # Empty string is Microsoft's "no value" on this endpoint
//
// On the live wire ~20 fields per row are structurally PRESENT and set to "",
// while a separate group (httpMethod, responseCode, operationStatus,
// policyType, isAgentic and every nested detail object) uses JSON null. Two
// encodings of absence in one record. Every string below therefore goes
// through telemetry.SetStr, which omits the key on empty — so an attribute's
// presence means Microsoft actually sent a value.
const (
	// AttrTransactionId is the record's transactionId — the immutable
	// per-connection identifier the window engine dedupes on. Not a
	// correlation id: it identifies one connection, not a request chain.
	AttrTransactionId = "transaction_id"

	// AttrConnectionId is the record's connectionId, the GSA client's own
	// connection handle (e.g. "KwKgUW29cUuVhV2b.0"). Distinct from
	// AttrTransactionId and not globally unique — the trailing ordinal
	// suggests reuse per client session, so it is not a dedupe key.
	AttrConnectionId = "connection_id"

	// AttrSessionId is the record's sessionId. Empty on every observed row,
	// so it is carried for the day it is populated rather than mapped from a
	// known shape.
	AttrSessionId = "session_id"

	// AttrTrafficType is the record's trafficType: which forwarding profile
	// carried the connection (`internet`, `microsoft365`, and `private` for
	// Private Access). Observed values on m7kni are internet and
	// microsoft365 only.
	AttrTrafficType = "traffic_type"

	// AttrDestinationFqdn is the connection's destinationFQDN. This is the
	// field an investigation actually starts from, and the single strongest
	// reason this collector exists — no other signal in this project names
	// the host a managed device reached.
	AttrDestinationFqdn = "destination_fqdn"

	// AttrDestinationUrl is the connection's destinationUrl. Populated on
	// only 9 of 3,000 observed rows (it needs TLS inspection to resolve), so
	// its absence is normal rather than a mapping failure.
	AttrDestinationUrl = "destination_url"

	// AttrSourceIp is the connection's sourceIp — the client's egress
	// address as GSA saw it.
	AttrSourceIp = "source_ip"

	// AttrSourcePort is the connection's sourcePort.
	AttrSourcePort = "source_port"

	// AttrTransportProtocol is the record's transportProtocol (tcp/udp).
	AttrTransportProtocol = "transport_protocol"

	// AttrNetworkProtocol is the record's networkProtocol (ipv4/ipv6).
	AttrNetworkProtocol = "network_protocol"

	// AttrDeviceOperatingSystem is the client's deviceOperatingSystem, as the
	// GSA agent reports it (e.g. "Windows 11 Enterprise Evaluation") — the
	// agent's own string, not Intune's normalized platform value, so do not
	// join it to intune.devices' os field without normalizing.
	AttrDeviceOperatingSystem = "device_operating_system"

	// AttrDeviceOperatingSystemVersion is the client's
	// deviceOperatingSystemVersion (e.g. "10.0.26200").
	AttrDeviceOperatingSystemVersion = "device_operating_system_version"

	// AttrPolicyRuleId is the record's policyRuleId — which RULE inside the
	// policy matched, as distinct from AttrPolicyId. A blocked connection
	// without a rule id was blocked by something other than a filtering rule.
	AttrPolicyRuleId = "policy_rule_id"

	// AttrPolicyRuleName is the record's policyRuleName. `*` on the live
	// catch-all rule, which is a real value and not a wildcard placeholder.
	AttrPolicyRuleName = "policy_rule_name"

	// AttrFilteringProfileId is the record's filteringProfileId.
	AttrFilteringProfileId = "filtering_profile_id"

	// AttrFilteringProfileName is the record's filteringProfileName (e.g.
	// "Baseline profile") — the profile whose rules produced the action.
	AttrFilteringProfileName = "filtering_profile_name"

	// AttrSentBytes is the connection's sentBytes.
	AttrSentBytes = "sent_bytes"

	// AttrReceivedBytes is the connection's receivedBytes. Both byte counters
	// are 0 on the overwhelming majority of observed rows (31 of 3,000 carry
	// a non-zero sentBytes) — a blocked connection transfers nothing — so a
	// zero here is a real measurement, not a missing one, and both are
	// emitted unconditionally.
	AttrReceivedBytes = "received_bytes"

	// AttrInitiatingProcessName is the record's initiatingProcessName: the
	// process on the client that opened the connection (e.g.
	// "taskhostw.exe"). Process ARGUMENTS are deliberately not emitted — see
	// the collector's package doc.
	AttrInitiatingProcessName = "initiating_process_name"

	// AttrHttpMethod is the record's httpMethod. null unless TLS inspection
	// resolved the request.
	AttrHttpMethod = "http_method"

	// AttrResponseCode is the record's responseCode. Pointer-modeled: it is
	// null on most rows, and a bare int would publish a fabricated HTTP 0.
	AttrResponseCode = "response_code"

	// AttrOperationStatus is the record's operationStatus (`success` on every
	// row that carries it). Note this is the status of GSA's own processing,
	// NOT of the connection: 2,941 of 3,000 rows are action=block with
	// operationStatus=success, so reading it as connection success is the
	// obvious and wrong interpretation.
	AttrOperationStatus = "operation_status"

	// AttrThreatType is the record's threatType. Either "" or "NoneFound" on
	// observed rows — two different spellings of nothing, and only the second
	// survives into the record, so a query filtering on absence must handle
	// both.
	AttrThreatType = "threat_type"

	// AttrApplicationProtocol is the record's applicationProtocol
	// (http/https), null when GSA could not determine it.
	AttrApplicationProtocol = "application_protocol"

	// AttrPopProcessingRegion is the record's popProcessingRegion (e.g.
	// "UKSouth") — which GSA point of presence handled the connection.
	AttrPopProcessingRegion = "pop_processing_region"

	// AttrDestinationWebCategory is destinationWebCategory.name: the content
	// category GSA assigned the destination. It arrives as a single
	// COMMA-JOINED string ("ComputersAndTechnology,Business") and is emitted
	// verbatim rather than split, for the same reason
	// entra.auth_strength keeps its combinations intact (#322): the wire's own
	// grouping is the datum, and splitting it invents a structure Microsoft
	// did not send. displayName is identical to name on every observed row,
	// so only one is carried.
	AttrDestinationWebCategory = "destination_web_category"

	// AttrIsAgentic is the record's isAgentic flag — whether GSA attributed
	// the connection to an AI agent rather than a human. Pointer-modeled: it
	// is null on the microsoft365 rows and false on the internet ones, and
	// those are different facts.
	AttrIsAgentic = "is_agentic"

	// AttrTlsAction is tlsDetails.action (e.g. "bypassed") — whether the
	// connection was TLS-inspected. Populated on 2,944 of 3,000 observed
	// rows, so the nested tlsDetails object is the common case here rather
	// than an exception.
	AttrTlsAction = "tls_action"

	// AttrTlsStatus is tlsDetails.status.
	AttrTlsStatus = "tls_status"

	// AttrTlsPolicyId is tlsDetails.policyId — the TLS inspection policy, a
	// different policy object from AttrPolicyId.
	AttrTlsPolicyId = "tls_policy_id"

	// AttrTlsPolicyName is tlsDetails.policyName.
	AttrTlsPolicyName = "tls_policy_name"

	// AttrTlsRuleId is tlsDetails.ruleId.
	AttrTlsRuleId = "tls_rule_id"

	// AttrTlsRuleName is tlsDetails.ruleName (e.g. "System Bypass TLS
	// inspection rule").
	AttrTlsRuleName = "tls_rule_name"
)
