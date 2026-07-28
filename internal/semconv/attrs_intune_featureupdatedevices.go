package semconv

// intune.feature_update_devices attributes (#351) — the per-device residual
// #38/#193 named when they shipped the FeatureUpdatePolicyStatusSummary
// aggregate. The summary answers "how many devices are stuck"; this answers
// "which one, and why".
//
// Reused where a key already exists: AttrPolicyId / AttrPolicyName (the feature
// update profile), AttrDeviceId / AttrDeviceName, AttrUpn, and
// AttrFeatureUpdateVersion (attrs_intune.go, already used by the summary
// collector — the two collectors join on it and on AttrPolicyId).
//
// # Every status column ships TWICE, and only one of the two may be a label
//
// Live-measured 2026-07-28: the FeatureUpdateDeviceState export's CSV header is
//
//	PolicyId, DeviceId, DeviceName, UPN, AggregateState, AggregateState_loc,
//	CurrentDeviceUpdateStatus, CurrentDeviceUpdateStatus_loc,
//	LatestAlertMessage, LatestAlertMessage_loc
//
// The bare column is the stable machine value and the `_loc` suffix is a
// LOCALIZED display string — `CurrentDeviceUpdateStatus` is the code `"8"` while
// `CurrentDeviceUpdateStatus_loc` is the English `"Installed"`. Which language
// that is depends on the tenant, so a `_loc` value keyed as a metric label
// changes series identity when the tenant's locale changes and silently splits
// one signal into two.
//
// So: the bare column keys the bounded gauge; the `_loc` string rides the log
// twin only, under the *Localized keys below. That is not a stylistic split —
// the raw code alone is unreadable ("8" tells an operator nothing) and the
// localized string alone is unstable, so the record needs both and the metric
// needs exactly one of them.
//
// AggregateState is where this stops being theoretical. Its bare value looks
// like a safe word — but the live 9-row export carries BOTH states, and they
// render as:
//
//	AggregateState "Success"    -> AggregateState_loc "Success"     (identical)
//	AggregateState "InProgress" -> AggregateState_loc "In progress"  (DIFFERENT)
//
// So a mapper that sampled only the Success rows would conclude the two columns
// are interchangeable and key the gauge off the localized one, and the bug would
// stay invisible until a device happened to be mid-update. The bare column is
// used for every one of the three pairs, always.
const (
	// AttrAggregateState is the rolled-up per-device outcome ("Success", and
	// whatever the failure members turn out to be — only Success has been
	// observed live, so nothing here is declared to internal/wirecheck). It is
	// the primary bounded metric dimension.
	AttrAggregateState = "aggregate_state"
	// AttrDeviceUpdateStatus is the finer-grained current status CODE. Also a
	// bounded metric dimension: it is a small closed set of integers.
	AttrDeviceUpdateStatus = "device_update_status"
	// AttrLatestAlertMessage is the failure-reason CODE ("0" for none). Bounded,
	// and the one that answers "why" once a device actually fails.
	AttrLatestAlertMessage = "latest_alert_message"

	// The localized twins of the three above. Log-only, always.
	AttrAggregateStateLocalized     = "aggregate_state_localized"
	AttrDeviceUpdateStatusLocalized = "device_update_status_localized"
	AttrLatestAlertMessageLocalized = "latest_alert_message_localized"
)
