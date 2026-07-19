package semconv

// Attribute keys used by the m365.teams collector (#121). Shared keys these
// records also emit (display_name via AttrDisplayName, description via
// AttrDescription, id via AttrId) are reused, never redeclared. Every key is a
// semconv.Attr* constant (Gate B); no value duplicates another constant (Gate A).
const (
	// AttrVisibility is a team's visibility: public / private / hiddenMembership.
	// A bounded closed set, so it is safe as a metric label.
	AttrVisibility = "visibility"
	// AttrRole buckets a membership count by role: owner / member / guest. Bounded.
	AttrRole = "role"
	// AttrOwnersCount / AttrMembersCount / AttrGuestsCount are a team's membership
	// counts from teams.summary. Per-entity on the LOG twin only — never a metric
	// label (they are the metric VALUES, bucketed by role).
	AttrOwnersCount  = "owners_count"
	AttrMembersCount = "members_count"
	AttrGuestsCount  = "guests_count"
	// AttrIsArchived marks an archived team — an archived team is the desired
	// end-state, not an orphan, so it is excluded from the ownerless count but
	// still carries a log twin.
	AttrIsArchived = "is_archived"
)
