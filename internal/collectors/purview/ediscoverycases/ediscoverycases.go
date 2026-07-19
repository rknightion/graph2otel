// Package ediscoverycases is the Microsoft Purview eDiscovery case inventory
// collector: a bounded gauge counting eDiscovery cases by status, plus a log
// twin per case carrying the per-case detail the metric never carries (id,
// display name, custodial description, external id, created/closed times).
//
// # Opt-in — but NOT for beta reasons (#102)
//
// GET /security/cases/ediscoveryCases is Graph v1.0 (GA), not a beta/preview
// endpoint. It is nevertheless Experimental (opt-in — the composition root
// registers it only when a config explicitly enables it) for a DIFFERENT reason
// than every other Experimental collector, which are beta/schema-unstable: a
// granted eDiscovery.Read.All scope is NOT sufficient on its own here. The
// Purview / Security & Compliance data plane returns 401 until the app's service
// principal is separately registered there via PowerShell (New-ServicePrincipal
// + Add-RoleGroupMember eDiscoveryManager + Add-eDiscoveryCaseAdmin). That is a
// manual, tenant-specific prerequisite most deployments will not have, so this
// collector must never run on the default-enabled state — a default deployment
// would 401 on every poll. See docs/data-plane-registration.md and
// docs/permissions.md §4b for the full enable procedure.
// [live-verified 2026-07-17/19, #102]
//
// # Metric/log split (#112)
//
// Case count by status is a bounded aggregate over the ediscoveryCaseStatus enum
// (active, closing, closed, ...) — a metric. Per-case identity (id, display
// name, custodial description, external id) is per-entity detail — a log twin,
// never a metric label.
//
// # Wire traps (live-measured 2026-07-19, #102)
//
//   - createdDateTime / lastModifiedDateTime on the auto-created default
//     "Content Search" case are the .NET zero value 0001-01-01T00:00:00Z, not a
//     real timestamp. realDateTime drops those rather than emit a year-0001 date.
//   - closedBy / lastModifiedBy are identitySet OBJECTS (null on every observed
//     record). Their populated shape has not been seen on the wire, so they are
//     deliberately NOT mapped — mapping an unseen shape is the #142 mistake.
package ediscoverycases

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector name (the stable config / self-observability / admin-status key),
// the metric it emits, and the log-twin EventName.
const (
	casesName     = "purview.ediscovery_cases"
	casesMetric   = "purview.ediscovery.cases"
	caseEventName = "purview.ediscovery_case"
)

// ediscoveryCase mirrors the ediscoveryCase fields this collector uses. Status
// buckets the metric; ID/DisplayName/Description/ExternalID/dates feed only the
// log twin, never a metric label (#112). closedBy/lastModifiedBy (identitySet
// objects) and reviewSet/custodian sub-collections are not decoded — see the
// package doc.
type ediscoveryCase struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	Status          string `json:"status"`
	ExternalID      string `json:"externalId"`
	CreatedDateTime string `json:"createdDateTime"`
	ClosedDateTime  string `json:"closedDateTime"`
}

// CasesCollector polls the tenant's eDiscovery case inventory.
type CasesCollector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// NewCases builds the eDiscovery case-inventory collector. A nil logger falls
// back to the slog default.
func NewCases(g collectors.GraphClient, logger *slog.Logger) *CasesCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &CasesCollector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *CasesCollector) Name() string { return casesName }

// DefaultInterval implements collector.Collector. eDiscovery cases are created
// and closed by humans and drift slowly; an hourly poll is ample.
func (c *CasesCollector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks this collector opt-in. NOT because the endpoint is beta (it
// is v1.0 GA) but because it needs the Security & Compliance data-plane
// registration a granted scope does not provide — see the package doc.
func (c *CasesCollector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// eDiscovery.Read.All is necessary but NOT sufficient — see the package doc and
// docs/data-plane-registration.md for the second, non-Graph half.
func (c *CasesCollector) RequiredPermissions() []string {
	return []string{"eDiscovery.Read.All"}
}

// Collect fetches the eDiscovery case inventory, emits purview.ediscovery.cases
// bucketed by status, and one purview.ediscovery_case log per case carrying the
// per-case detail the metric can't.
//
// # Every fetch error fails this collector
//
// There is deliberately no skip path. This collector is opt-in — an operator
// who enabled it has asserted the data-plane registration is done, so an error
// is a real misconfiguration, not an expected steady state. A 401 in particular
// means the S&C registration is missing despite the scope being granted; the
// error names that fix so the next reader does not re-run #102's investigation.
func (c *CasesCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/cases/ediscoveryCases", nil)
	if err != nil {
		if strings.Contains(err.Error(), "status 401") {
			return fmt.Errorf("%s: list: eDiscovery.Read.All is granted but the app's service principal must ALSO be registered in the Security & Compliance data plane (a 401 here is that missing registration, not a Graph scope gap) — see docs/data-plane-registration.md: %w",
				casesName, err)
		}
		return fmt.Errorf("%s: list: %w", casesName, err)
	}

	byStatus := map[string]int64{}
	for _, raw := range raws {
		var ec ediscoveryCase
		if err := json.Unmarshal(raw, &ec); err != nil {
			c.logger.Warn("ediscovery cases: skipping unparseable entry", "collector", casesName, "error", err)
			continue
		}
		status := ec.Status
		if status == "" {
			status = "unknown"
		}
		byStatus[status]++

		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrId, ec.ID)
		telemetry.SetStr(attrs, semconv.AttrDisplayName, ec.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrDescription, ec.Description)
		telemetry.SetStr(attrs, semconv.AttrStatus, status)
		telemetry.SetStr(attrs, semconv.AttrExternalId, ec.ExternalID)
		telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realDateTime(ec.CreatedDateTime))
		telemetry.SetStr(attrs, semconv.AttrClosedDateTime, realDateTime(ec.ClosedDateTime))
		e.LogEvent(telemetry.Event{
			Name:  caseEventName,
			Body:  fmt.Sprintf("eDiscovery case: %s (%s)", ec.DisplayName, status),
			Attrs: attrs,
		})
	}

	points := make([]telemetry.GaugePoint, 0, len(byStatus))
	for st, n := range byStatus {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrStatus: st},
		})
	}
	e.GaugeSnapshot(casesMetric, "{case}",
		"Purview eDiscovery cases, counted per case status.", points)
	return nil
}

// realDateTime returns s only if it parses to a real (non-zero) RFC3339 instant.
// Graph serializes an unset case createdDateTime/closedDateTime as the .NET zero
// value 0001-01-01T00:00:00Z (live-measured, #102); that must never be emitted
// as a year-0001 timestamp, so it — and any unparseable value — collapses to "".
func realDateTime(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1 {
		return ""
	}
	return s
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return NewCases(d.Graph, d.Logger)
	})
}
