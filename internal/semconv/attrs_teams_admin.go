package semconv

// Teams admin API (teams_admin transport) shared attributes. AttrEnabled
// ("enabled") is reused from attrs_intune.go for the pstn_gateway gauge label.
const (
	// AttrConfigSHA256 is the hex SHA-256 of a twin's exported attributes
	// (adminmap.Hash); AttrConfigHashVersion is bumped when that set changes.
	AttrConfigSHA256      = "config_sha256"
	AttrConfigHashVersion = "config_hash_version"

	// Gauge labels: bounded enum values only.
	AttrRoutingMethod = "routing_method"
	AttrCoverage      = "coverage"

	// AttrTeamsAdminResource labels the teams_admin client's own HTTP metrics
	// with the configuration or collection name, derived from the request path.
	AttrTeamsAdminResource = "teams_admin.resource"
)
