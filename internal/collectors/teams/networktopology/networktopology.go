// Package networktopology is the Teams tenant network topology collector
// (#721): regions, sites and subnets from the Teams admin API
// (internal/teamsadminclient), plus a reconciliation of the Teams subnets
// against the operator's sites CSV (teams.sites_file).
//
// Three Skype.Policy configurations are read each tick (TenantNetworkRegion,
// TenantNetworkSite, TenantNetworkSubnet). Each object is one log twin carrying
// its configuration and a config_sha256 (adminmap.Hash) so a query can see a
// change between two polls. One bounded gauge,
// teams.network_subnet.csv_coverage{coverage}, counts the subnets by whether the
// sites CSV maps them.
//
// # Sites CSV reconciliation
//
// One Deps.TeamsSites.Snapshot() is taken per tick, so a reload cannot change the
// answer part-way through. A subnet is:
//
//   - no_csv when no sites file is configured (nil TeamsSites or nil snapshot);
//   - uncovered when Lookup(cidr, "") finds no site. The empty IP stops Lookup
//     falling back to an endpoint address. Lookup needs ONE CSV prefix that
//     contains the whole Teams subnet, so a Teams subnet wider than every CSV
//     prefix, or split across several narrower ones, is uncovered. A subnet
//     whose address or mask is missing cannot be written as a CIDR and is also
//     uncovered (it is reported through wirecheck as a missing field);
//   - covered otherwise, and the twin carries the CSV site name.
//
// # Wire fields not exported (live-measured fixtures, 2026-11-25)
//
//   - Region NetworkRegionID: repeats Identity.
//   - Site NetworkSiteID: repeats Identity.
//   - Site Subnets, Postalcodes and PhoneNumbers: null in every sample, and the
//     subnet-to-site relation is already exported by each subnet's
//     NetworkSiteID.
//   - Subnet Identity is the bare address, exported as network_subnet_identity;
//     the CIDR is derived (network_subnet_cidr).
//
// No exported field is a list, so no twin carries a "_count" attribute.
//
// A state snapshot, not an event stream: every twin is stamped at poll time.
package networktopology

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	collectorName = "teams.network_topology"
	eventRegion   = "teams.network_region"
	eventSite     = "teams.network_site"
	eventSubnet   = "teams.network_subnet"
	// metricCoverage counts Teams subnets by sites CSV coverage.
	metricCoverage = "teams.network_subnet.csv_coverage"
	unitSubnet     = "{subnet}"
	// interval: network topology changes when an admin edits it.
	interval = time.Hour

	configRegion = "TenantNetworkRegion"
	configSite   = "TenantNetworkSite"
	configSubnet = "TenantNetworkSubnet"
)

// Values of the coverage label and of network_subnet_csv_coverage.
const (
	coverageCovered   = "covered"
	coverageUncovered = "uncovered"
	coverageNoCSV     = "no_csv"
)

// Collector reads the Teams tenant network topology.
type Collector struct {
	client collectors.TeamsAdminClient
	files  *sites.File
	watch  *wirecheck.Reporter
}

// New builds the collector. A zero Deps is valid (the census builds every
// collector that way); Collect then errors.
func New(d collectors.Deps) *Collector {
	return &Collector{client: d.TeamsAdmin, files: d.TeamsSites, watch: wirecheck.New(collectorName, d.Logger)}
}

// Name implements collector.Collector.
func (*Collector) Name() string { return collectorName }

// Profiles declares this collector's profile membership.
func (*Collector) Profiles() collector.ProfileSet { return collector.ProfileTeams }

// DefaultInterval implements collector.Collector.
func (*Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Teams admin API.
func (*Collector) IngestTransport() telemetry.Transport { return telemetry.TransportTeamsAdmin }

// RequiredPermissions is empty: access is an Entra directory role on the
// poller, not a Graph scope.
func (*Collector) RequiredPermissions() []string { return nil }

// Collect reads the three configurations, then emits the coverage gauge and one
// twin per object. All three reads happen first: they share one endpoint and one
// credential, so a failure is a failure of the tick.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if c.client == nil {
		return errors.New("teams network topology: the Teams admin API client is not configured (tenants[].teams.admin_api.enabled)")
	}
	e = telemetry.WithTransport(e, telemetry.TransportTeamsAdmin)

	var lists [3][]map[string]any
	for i, name := range []string{configRegion, configSite, configSubnet} {
		recs, err := c.client.Configurations(ctx, name)
		if err != nil {
			if teamsadminclient.IsPermission(err) {
				outcomes.Cause(recordoutcome.CausePermissionDenied)
			} else {
				outcomes.Cause(recordoutcome.CauseSourceError)
			}
			return fmt.Errorf("teams admin %s: %w", name, err)
		}
		lists[i] = recs
	}
	regions, siteRecs, subnets := lists[0], lists[1], lists[2]
	total := uint64(len(regions) + len(siteRecs) + len(subnets))
	outcomes.Add(recordoutcome.OutcomeFetched, total)

	var table *sites.Table
	if c.files != nil {
		table = c.files.Snapshot()
	}

	counts := map[string]int{coverageCovered: 0, coverageUncovered: 0, coverageNoCSV: 0}
	for _, r := range regions {
		e.LogEvent(regionTwin(r))
	}
	for _, r := range siteRecs {
		e.LogEvent(siteTwin(r))
	}
	for _, r := range subnets {
		ev, cov := c.subnetTwin(e, r, table)
		counts[cov]++
		e.LogEvent(ev)
	}
	outcomes.Add(recordoutcome.OutcomeMapped, total)
	outcomes.Add(recordoutcome.OutcomeEmitted, total)

	pts := make([]telemetry.GaugePoint, 0, len(counts))
	for _, cov := range []string{coverageCovered, coverageUncovered, coverageNoCSV} {
		pts = append(pts, telemetry.GaugePoint{Value: float64(counts[cov]), Attrs: telemetry.Attrs{semconv.AttrCoverage: cov}})
	}
	e.GaugeSnapshot(metricCoverage, unitSubnet,
		"Teams tenant network subnets by sites CSV coverage: covered (one CSV prefix contains the whole subnet), uncovered (no such prefix) or no_csv (no teams.sites_file configured).",
		pts)
	return nil
}

func regionTwin(r map[string]any) telemetry.Event {
	a := telemetry.Attrs{}
	telemetry.SetStr(a, semconv.AttrNetworkRegionIdentity, str(r, "Identity"))
	telemetry.SetStr(a, semconv.AttrNetworkRegionDescription, str(r, "Description"))
	telemetry.SetStr(a, semconv.AttrNetworkRegionCentralSite, str(r, "CentralSite"))
	telemetry.SetStr(a, semconv.AttrNetworkRegionAuthority, authority(r))
	return twin(eventRegion, "network region "+str(r, "Identity"), a)
}

func siteTwin(r map[string]any) telemetry.Event {
	a := telemetry.Attrs{}
	telemetry.SetStr(a, semconv.AttrNetworkSiteIdentity, str(r, "Identity"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteNetworkRegionId, str(r, "NetworkRegionID"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteDescription, str(r, "Description"))
	if b, ok := r["EnableLocationBasedRouting"].(bool); ok {
		telemetry.SetBool(a, semconv.AttrNetworkSiteEnableLocationBasedRouting, b)
	}
	telemetry.SetStr(a, semconv.AttrNetworkSiteLocationPolicy, str(r, "LocationPolicy"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteEmergencyCallRoutingPolicy, str(r, "EmergencyCallRoutingPolicy"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteEmergencyCallingPolicy, str(r, "EmergencyCallingPolicy"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteNetworkRoamingPolicy, str(r, "NetworkRoamingPolicy"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteSiteAddress, str(r, "SiteAddress"))
	telemetry.SetStr(a, semconv.AttrNetworkSiteAuthority, authority(r))
	return twin(eventSite, "network site "+str(r, "Identity"), a)
}

// subnetTwin maps one subnet and returns its coverage class.
func (c *Collector) subnetTwin(e telemetry.Emitter, r map[string]any, table *sites.Table) (telemetry.Event, string) {
	a := telemetry.Attrs{}
	telemetry.SetStr(a, semconv.AttrNetworkSubnetIdentity, str(r, "Identity"))
	subnetID := str(r, "SubnetID")
	telemetry.SetStr(a, semconv.AttrNetworkSubnetSubnetId, subnetID)
	if subnetID == "" {
		c.watch.MissingField(e, "SubnetID")
	}
	bits, hasBits := wholeNumber(r["MaskBits"])
	if hasBits {
		a[semconv.AttrNetworkSubnetMaskBits] = bits
	} else {
		c.watch.MissingField(e, "MaskBits")
	}
	telemetry.SetStr(a, semconv.AttrNetworkSubnetNetworkSiteId, str(r, "NetworkSiteID"))
	telemetry.SetStr(a, semconv.AttrNetworkSubnetDescription, str(r, "Description"))
	telemetry.SetStr(a, semconv.AttrNetworkSubnetAuthority, authority(r))

	cidr := ""
	if subnetID != "" && hasBits {
		cidr = fmt.Sprintf("%s/%d", subnetID, bits)
		a[semconv.AttrNetworkSubnetCidr] = cidr
	}

	label := cidr
	if label == "" {
		label = str(r, "Identity")
	}
	// Hash first: coverage is derived from the operator's sites CSV, not from
	// Teams, so a CSV edit must not read as a Teams configuration change.
	ev := twin(eventSubnet, "network subnet "+label, a)

	cov := coverageNoCSV
	if table != nil {
		cov = coverageUncovered
		// The empty endpoint and reflexive IPs stop Lookup falling back to an
		// address match: only a CSV prefix containing the whole subnet counts.
		if cidr != "" {
			if site, src := table.Lookup(cidr, "", ""); src == sites.MatchSubnet && site.Name != sites.Unmapped {
				cov = coverageCovered
				a[semconv.AttrNetworkSubnetCsvSite] = site.Name
			}
		}
	}
	a[semconv.AttrNetworkSubnetCsvCoverage] = cov
	return ev, cov
}

// twin stamps the change hash and returns the Info-level event.
func twin(name, body string, a telemetry.Attrs) telemetry.Event {
	a[semconv.AttrConfigSHA256] = adminmap.Hash(a)
	a[semconv.AttrConfigHashVersion] = adminmap.HashVersion
	return telemetry.Event{Name: name, Body: body, Severity: telemetry.SeverityInfo, Attrs: a}
}

// str reads a string field, "" when absent, null or not a string.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// authority reads ConfigMetadata.Authority.
func authority(m map[string]any) string {
	meta, _ := m["ConfigMetadata"].(map[string]any)
	return str(meta, "Authority")
}

// wholeNumber reads a JSON number with no fractional part.
func wholeNumber(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
