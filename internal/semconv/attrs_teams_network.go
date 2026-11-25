package semconv

// Teams network topology (teams.network_topology, #721) twin attributes. Each key
// is the event prefix plus the snake_case of the wire field (adminmap.SnakeKey);
// the derived keys (cidr and the two CSV reconciliation keys) are the exceptions.
const (
	// teams.network_region.
	AttrNetworkRegionIdentity    = "network_region_identity"
	AttrNetworkRegionDescription = "network_region_description"
	AttrNetworkRegionCentralSite = "network_region_central_site"
	AttrNetworkRegionAuthority   = "network_region_authority"

	// teams.network_site.
	AttrNetworkSiteIdentity                   = "network_site_identity"
	AttrNetworkSiteNetworkRegionId            = "network_site_network_region_id"
	AttrNetworkSiteDescription                = "network_site_description"
	AttrNetworkSiteEnableLocationBasedRouting = "network_site_enable_location_based_routing"
	AttrNetworkSiteLocationPolicy             = "network_site_location_policy"
	AttrNetworkSiteEmergencyCallRoutingPolicy = "network_site_emergency_call_routing_policy"
	AttrNetworkSiteEmergencyCallingPolicy     = "network_site_emergency_calling_policy"
	AttrNetworkSiteNetworkRoamingPolicy       = "network_site_network_roaming_policy"
	AttrNetworkSiteSiteAddress                = "network_site_site_address"
	AttrNetworkSiteAuthority                  = "network_site_authority"

	// teams.network_subnet. Cidr, CsvCoverage and CsvSite are derived.
	AttrNetworkSubnetIdentity      = "network_subnet_identity"
	AttrNetworkSubnetSubnetId      = "network_subnet_subnet_id"
	AttrNetworkSubnetMaskBits      = "network_subnet_mask_bits"
	AttrNetworkSubnetNetworkSiteId = "network_subnet_network_site_id"
	AttrNetworkSubnetDescription   = "network_subnet_description"
	AttrNetworkSubnetAuthority     = "network_subnet_authority"
	AttrNetworkSubnetCidr          = "network_subnet_cidr"
	AttrNetworkSubnetCsvCoverage   = "network_subnet_csv_coverage"
	AttrNetworkSubnetCsvSite       = "network_subnet_csv_site"
)
