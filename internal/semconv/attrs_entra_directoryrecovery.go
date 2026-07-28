package semconv

// Attribute keys introduced by entra.directory_recovery (#334): one
// entra.directory_recovery_snapshot event per retained directory snapshot and
// one entra.directory_recovery_job event per recovery job, from
// GET /directory/recovery/{snapshots,jobs}.
//
// REUSED rather than re-coined (the registry's no-duplicate-values gate would
// fail a second constant carrying any of these strings): AttrId
// (attrs_shared.go — the snapshot's or job's own id), AttrCreatedDateTime
// (attrs_entra.go — the snapshot's createdDateTime) and AttrStatus
// (attrs_shared.go — the job's recoveryStatus, which is also this collector's
// only bounded metric label).
//
// Live-measured 2026-07-28 against m7kni as graph2otel-poller: 7 snapshots
// carrying ONLY `id` and `createdDateTime`, and an empty jobs collection. The
// job keys below are therefore modeled from the EDM's recoveryJobBase /
// recoveryJob property set, not from an observed row — every one of them is
// emitted only when the wire actually carries it.
const (
	// AttrSnapshotAgeSeconds is how old a snapshot was at poll time, in
	// seconds, derived from its createdDateTime. Carried on the log twin as
	// well as driving the newest_snapshot_age gauge, so a single record
	// answers "how stale is this" without the reader having to subtract
	// timestamps in a query.
	AttrSnapshotAgeSeconds = "snapshot_age_seconds"

	// AttrTotalChangedObjects is the snapshot's totalChangedObjects.
	//
	// DECLARED IN THE EDM AND NEVER RETURNED ON THE WIRE (live-measured
	// 2026-07-28): absent from every one of the 7 live snapshots, still
	// absent when named explicitly in $select, and still absent under
	// $expand=recoveryJobs. It is modeled as a POINTER and emitted only when
	// present precisely because a bare int would publish a fabricated 0 —
	// "nothing changed in the directory since the last snapshot", which reads
	// as a healthy quiet tenant rather than as the absence it actually is.
	AttrTotalChangedObjects = "total_changed_objects"

	// AttrJobStartDateTime is the recovery job's jobStartDateTime.
	AttrJobStartDateTime = "job_start_date_time"

	// AttrJobCompletionDateTime is the recovery job's jobCompletionDateTime.
	// Absent on a job that has not finished, and emitted only when present —
	// a zero-valued completion time on a running job would date its
	// completion to year 1 (the .NET DateTime.MinValue shape this project has
	// now seen on three separate Graph surfaces).
	AttrJobCompletionDateTime = "job_completion_date_time"

	// AttrTargetStateDateTime is the recovery job's targetStateDateTime — the
	// point in time the directory is being restored TO, which is a different
	// question from when the job ran.
	AttrTargetStateDateTime = "target_state_date_time"

	// AttrTotalChangedObjectsCalculated is the job's
	// totalChangedObjectsCalculated: how many objects the job determined
	// differ from the target state. Pointer-modeled; see
	// AttrTotalChangedObjects.
	AttrTotalChangedObjectsCalculated = "total_changed_objects_calculated"

	// AttrTotalChangedLinksCalculated is the job's
	// totalChangedLinksCalculated. Pointer-modeled.
	AttrTotalChangedLinksCalculated = "total_changed_links_calculated"

	// AttrTotalObjectsModified is the job's totalObjectsModified — present on
	// recoveryJob but not on recoveryPreviewJob, so absent by design on a
	// preview. Pointer-modeled.
	AttrTotalObjectsModified = "total_objects_modified"

	// AttrTotalLinksModified is the job's totalLinksModified. Pointer-modeled.
	AttrTotalLinksModified = "total_links_modified"

	// AttrTotalFailedChanges is the job's totalFailedChanges — the failure
	// signal this collector exists to surface. Pointer-modeled: a fabricated
	// 0 here would assert a clean restore that was never reported.
	AttrTotalFailedChanges = "total_failed_changes"

	// AttrIsPreview reports whether the job is a recoveryPreviewJob rather
	// than a recoveryJob. Derived from the @odata.type discriminator, so an
	// unrecognized subtype leaves it absent rather than guessing.
	AttrIsPreview = "is_preview"
)
