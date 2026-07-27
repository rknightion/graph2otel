package semconv

// Attribute keys introduced by m365.service_health_post (#367), the
// checkpointed M365 service-health timeline-post twin: one log record per NEW
// post on a serviceHealthIssue, deduplicated across polls and restarts.
//
// # Why a post needs a derived identity
//
// A serviceHealthIssue post carries exactly three keys on the wire
// (live-measured 2026-07-27, #367, probed as graph2otel-poller against
// m7kni: 829 posts across 100 issues) — createdDateTime, description,
// postType. There is no id. The dedupe key is therefore derived from
// (issue id, createdDateTime, postType) — the only combination the wire
// supports — which is why AttrIssueId exists here rather than reusing the
// bare AttrId the parent issueTwin already carries: this is a foreign key to
// the PARENT issue, not this record's own identity, the same distinction
// dlppolicies draws between AttrPolicyId (parent) and AttrRuleId (self) on
// its rule twin.
//
// # Reused rather than re-coined
//
// The post body reuses two existing keys rather than coining new ones:
//
//	description.content     -> AttrDescription  (attrs_purview.go)
//	description.contentType -> AttrContentType   (attrs_m365.go)
//
// # RAW HTML, on purpose
//
// AttrDescription carries description.content VERBATIM — no HTML tag
// stripping. Decided 2026-07-27 on #367: stripping is a lossy transformation
// of source content, a correct stripper is more subtle than it looks, and
// this repo's line is that logs carry what the source said; the noise cost
// is the operator's to filter, not this collector's to pre-decide.
//
// # Bounded, not dropped, on an oversized body
//
// Measured body size: min 42 B, median 1068 B, mean 1059 B, p95 1792 B, max
// 2176 B (2026-07-27, #367, n=829). The cap is 8192 bytes — 3.8x the observed
// max and 4.6x p95, so nothing on the wire today is touched — enforced in
// internal/collectors/m365/servicehealth. A body over the cap is TRUNCATED,
// never dropped: CLAUDE.md's rule ("undedupeable is degraded; misdated is
// wrong — only wrong justifies a drop") generalizes here, because a
// truncated body still carries a correct post identity, issue linkage, and
// event time — a dropped post would instead be a missing timeline entry,
// which is the exact failure #367 exists to fix. AttrBodyTruncated is always
// set (true/false); AttrDescriptionOriginalLength is set only when truncated
// is true, so the loss is visible and measurable without publishing a
// redundant length on every untruncated post.
const (
	// AttrIssueId is the parent serviceHealthIssue's id — the FK a post twin
	// carries back to the issue it belongs to. Deliberately not the shared
	// AttrId: that already means "this record's own id" on the sibling
	// issueTwin, and a post has no id of its own to hold there.
	AttrIssueId = "issue_id"
	// AttrPostType is postType verbatim ("regular" or "quick" observed live;
	// see #367 for the wirecheck watch on this field, wired in the collector's
	// composition-root pass, not here).
	AttrPostType = "post_type"
	// AttrBodyTruncated is whether AttrDescription was cut to the collector's
	// byte cap. Always set (true/false) — see the package doc.
	AttrBodyTruncated = "body_truncated"
	// AttrDescriptionOriginalLength is the pre-truncation byte length of
	// description.content. Set ONLY when AttrBodyTruncated is true.
	AttrDescriptionOriginalLength = "description_original_length"
)
