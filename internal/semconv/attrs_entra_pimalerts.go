package semconv

// Attribute keys introduced by entra.pim_alerts (#256), Microsoft's own
// pre-computed privileged-access findings on
// `/beta/identityGovernance/roleManagementAlerts`.
//
// # Most of the record's keys are NOT here, and that is the point
//
// A PIM alert is three joined records — the alert (state), its definition
// (meaning) and its configuration (whether it is even switched on) — and the
// bulk of what they carry already has a constant in this package:
//
//	id                   -> AttrAlertId       (attrs_defender.go)
//	<stripped type>      -> AttrAlertType     (attrs_intune.go)
//	displayName          -> AttrDisplayName   (attrs_shared.go)
//	description          -> AttrDescription   (attrs_purview.go)
//	severityLevel        -> AttrSeverity      (attrs_shared.go)
//	isEnabled            -> AttrIsEnabled     (attrs_entra.go)
//	lastModifiedDateTime -> AttrLastModifiedDateTime (attrs_m365.go)
//
// Those are REUSED rather than re-coined, so a `severity` filter means the same
// thing across entra.pim_alerts, entra.security_alerts and the Defender
// signals. The registry's no-duplicate-values gate enforces it from the other
// direction: a second constant carrying "severity" is a build failure.
//
// # Every key below is LOG-ONLY except two
//
// AttrIsActive is a bounded two-value flag and rides the alert gauge;
// everything else here is either free prose (the remediation text) or a
// per-alert number, and belongs on the twin (#112/#114). AttrIncidentCount is
// the sharpest case: it is the COUNT of flagged entities, so it is a metric
// VALUE (entra.pim.alert.incidents) and a twin attribute — never a label.
const (
	// AttrIsActive is the alert's `isActive`: whether Microsoft's last scan
	// found the condition present. It is a metric label — two values, fixed —
	// and the axis an operator alerts on. A row that never states it reads
	// "unknown" rather than "false", because a fabricated inactive alert is a
	// fabricated clean bill of health.
	AttrIsActive = "is_active"
	// AttrIncidentCount is the alert's `incidentCount`: how many entities the
	// finding covers (11 roles without MFA, 5 assignments made outside PIM).
	// The entities themselves are NOT reachable — the `alertIncidents` segment
	// 400s even with the mandatory scope filter (live-measured 2026-07-24) — so
	// this count is the finest granularity that exists on this surface.
	AttrIncidentCount = "incident_count"
	// AttrLastScannedDateTime is the alert's `lastScannedDateTime`: when
	// Microsoft last evaluated the condition. Distinct from
	// AttrLastModifiedDateTime, which is when the finding last CHANGED — and
	// which is the .NET zero date on an alert that has never fired.
	AttrLastScannedDateTime = "last_scanned_date_time"
	// AttrSecurityImpact is the definition's `securityImpact`: Microsoft's prose
	// on what an attacker gains from the condition.
	AttrSecurityImpact = "security_impact"
	// AttrMitigationSteps is the definition's `mitigationSteps`: what to do
	// about the finding now.
	AttrMitigationSteps = "mitigation_steps"
	// AttrHowToPrevent is the definition's `howToPrevent`: what to change so it
	// does not recur. Some values carry HTML anchors and CR-LF-separated bullets
	// verbatim off the wire; they are emitted unaltered.
	AttrHowToPrevent = "how_to_prevent"
	// AttrIsRemediatable is the definition's `isRemediatable`: whether PIM can
	// fix the finding itself. graph2otel never remediates — this says whether a
	// human has a one-click path.
	AttrIsRemediatable = "is_remediatable"
	// AttrIsConfigurable is the definition's `isConfigurable`: whether the
	// alert's thresholds can be changed at all. False on the alerts whose
	// configuration carries no threshold fields.
	AttrIsConfigurable = "is_configurable"
	// AttrAlertEvaluationWindowSeconds is the configuration's `duration`
	// (ISO-8601, "P30D" on both rows that carry it), converted to seconds: the
	// lookback the alert evaluates. It is what makes "2 stale accounts" a
	// statement about 30 days rather than an unqualified number.
	AttrAlertEvaluationWindowSeconds = "alert_evaluation_window_seconds"
	// AttrTimeBetweenActivationsSeconds is the sequential-activation
	// configuration's `timeIntervalBetweenActivations` (ISO-8601, "PT10S"),
	// converted to seconds.
	AttrTimeBetweenActivationsSeconds = "time_between_activations_seconds"
	// AttrSequentialActivationCounterThreshold is that same configuration's
	// `sequentialActivationCounterThreshold` — how many activations inside the
	// interval above trip the alert.
	AttrSequentialActivationCounterThreshold = "sequential_activation_counter_threshold"
	// AttrGlobalAdminCountThreshold is the too-many-global-admins
	// configuration's `globalAdminCountThreshold`.
	AttrGlobalAdminCountThreshold = "global_admin_count_threshold"
	// AttrGlobalAdminPercentageThreshold is that configuration's
	// `percentageOfGlobalAdminsOutOfRolesThreshold` — the second, independent
	// trip wire, expressed as a percentage of all privileged role holders.
	AttrGlobalAdminPercentageThreshold = "global_admin_percentage_threshold"
)
