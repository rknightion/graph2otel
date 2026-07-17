// Package appletokens is the Intune Apple integration-token expiry
// collector: days-until-expiry gauges for the three Apple MDM onboarding
// tokens — the tenant-wide APNS push certificate (v1.0 singleton), VPP
// tokens (v1.0, tiny collection), and DEP onboarding settings (beta, tiny
// collection).
//
// The APNS certificate is a single point of failure for ALL Apple MDM on a
// tenant: if it expires, every enrolled Apple device loses management
// simultaneously. VPP and DEP each expire independently per token. DEP is
// beta-only (no v1.0 equivalent exists), but the collector as a whole is NOT
// marked Experimental — its APNS/VPP signals are v1.0 and default-on; the DEP
// fetch is polled best-effort with isolated error handling so a beta-surface
// failure never drops the APNS/VPP gauges.
package appletokens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.apple_tokens"

// Metric names this collector emits.
const (
	daysUntilExpiryMetric   = "intune.apple_token.days_until_expiry"
	syncedDeviceCountMetric = "intune.apple_token.synced_device_count"
)

// defaultBaseURL is the Graph v1.0 root; betaBaseURL is used only for the DEP
// onboarding settings fetch (no v1.0 equivalent exists for that endpoint).
const (
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	betaBaseURL    = "https://graph.microsoft.com/beta"
)

// applePushCert is the subset of the v1.0 applePushNotificationCertificate
// singleton this collector reads.
type applePushCert struct {
	ExpirationDateTime      string `json:"expirationDateTime"`
	CertificateUploadStatus string `json:"certificateUploadStatus"`
}

// vppTokenResource is the subset of the v1.0 vppToken resource this collector
// reads. organizationName is a bounded, admin-assigned label (a handful of
// tokens per tenant) used only to disambiguate multiple tokens that share the
// same type+state, per the tracker issue's cardinality guidance — never a
// per-entity identifier.
type vppTokenResource struct {
	OrganizationName   string `json:"organizationName"`
	ExpirationDateTime string `json:"expirationDateTime"`
	State              string `json:"state"`
}

// depOnboardingSettingResource is the subset of the beta depOnboardingSetting
// resource this collector reads. depOnboardingSetting has no explicit
// state/status enum like vppToken does, so state is derived from
// lastSyncErrorCode (0 = ok, non-zero = sync_error) — a bounded two-value
// dimension distinguishing an expiring-but-healthy token from one already
// failing to sync.
type depOnboardingSettingResource struct {
	TokenName               string `json:"tokenName"`
	TokenExpirationDateTime string `json:"tokenExpirationDateTime"`
	LastSyncErrorCode       int    `json:"lastSyncErrorCode"`
	SyncedDeviceCount       int    `json:"syncedDeviceCount"`
}

// Collector polls the Apple MDM integration tokens: APNS certificate, VPP
// tokens, and DEP onboarding settings.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so days-until-expiry
	// is computed against a deterministic clock.
	now func() time.Time
}

// New builds the apple-tokens collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Apple integration tokens
// live for roughly a year; a daily poll is more than enough, so this uses a
// long cadence rather than the minutes-scale interval of the inventory
// collectors.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the least-privilege Graph application scopes:
// DeviceManagementServiceConfig.Read.All for the APNS certificate and DEP
// onboarding settings, DeviceManagementApps.Read.All for VPP tokens.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementServiceConfig.Read.All", "DeviceManagementApps.Read.All"}
}

// Collect fetches all three token sources independently and emits
// days-until-expiry (plus DEP synced-device-count) gauge snapshots. Each
// source is isolated: a 403/404 (missing scope, unlicensed, or - for DEP -
// beta endpoint unavailable) is skipped-and-logged, any other failure is
// logged and joined into the returned error, but every other source's points
// still emit. This is deliberate for DEP in particular: its beta endpoint
// must never be able to take down the v1.0 APNS/VPP gauges.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	now := c.now()
	var errs []error
	var expiry []telemetry.GaugePoint
	var deviceCounts []telemetry.GaugePoint

	if p, ok, err := c.apnsPoint(ctx, now); err != nil {
		if ferr := c.handleFetchErr("apns certificate", err); ferr != nil {
			errs = append(errs, ferr)
		}
	} else if ok {
		expiry = append(expiry, p)
	}

	vppPoints, err := c.vppPoints(ctx, now)
	if err != nil {
		if ferr := c.handleFetchErr("vpp tokens", err); ferr != nil {
			errs = append(errs, ferr)
		}
	}
	expiry = append(expiry, vppPoints...)

	depExpiry, depDeviceCounts, err := c.depPoints(ctx, now)
	if err != nil {
		if ferr := c.handleFetchErr("dep onboarding settings (beta)", err); ferr != nil {
			errs = append(errs, ferr)
		}
	}
	expiry = append(expiry, depExpiry...)
	deviceCounts = append(deviceCounts, depDeviceCounts...)

	e.GaugeSnapshot(daysUntilExpiryMetric, "d",
		"Days until expiry for each Apple MDM integration token (APNS certificate, VPP tokens, DEP onboarding settings); negative once expired.",
		expiry)
	e.GaugeSnapshot(syncedDeviceCountMetric, "{device}",
		"Devices synced through each Apple DEP onboarding setting.",
		deviceCounts)

	return errors.Join(errs...)
}

// apnsPoint fetches the tenant-wide APNS certificate singleton. ok is false
// (with a nil error) when the certificate has no expirationDateTime yet (not
// configured) - a single missing data point, not a failure.
func (c *Collector) apnsPoint(ctx context.Context, now time.Time) (telemetry.GaugePoint, bool, error) {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/applePushNotificationCertificate")
	if err != nil {
		return telemetry.GaugePoint{}, false, err
	}
	var cert applePushCert
	if err := json.Unmarshal(body, &cert); err != nil {
		return telemetry.GaugePoint{}, false, fmt.Errorf("decode apns certificate: %w", err)
	}
	days, ok := daysUntil(cert.ExpirationDateTime, now)
	if !ok {
		c.logger.Info("apple_tokens: apns certificate has no expirationDateTime yet, skipping", "collector", collectorName)
		return telemetry.GaugePoint{}, false, nil
	}
	return telemetry.GaugePoint{
		Value: days,
		Attrs: telemetry.Attrs{semconv.AttrType: "apns", semconv.AttrState: orUnknown(cert.CertificateUploadStatus), semconv.AttrTokenName: ""},
	}, true, nil
}

// vppPoints fetches the VPP token collection (tiny, admin-configured -
// typically 1-5 tokens) and returns one point per token with a parseable
// expirationDateTime.
func (c *Collector) vppPoints(ctx context.Context, now time.Time) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceAppManagement/vppTokens", nil)
	if err != nil {
		return nil, err
	}
	points := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var tok vppTokenResource
		if err := json.Unmarshal(r, &tok); err != nil {
			c.logger.Warn("apple_tokens: skipping unparseable vpp token", "collector", collectorName, "error", err)
			continue
		}
		days, ok := daysUntil(tok.ExpirationDateTime, now)
		if !ok {
			c.logger.Info("apple_tokens: vpp token has no expirationDateTime, skipping",
				"collector", collectorName, "organization", tok.OrganizationName)
			continue
		}
		points = append(points, telemetry.GaugePoint{
			Value: days,
			Attrs: telemetry.Attrs{semconv.AttrType: "vpp", semconv.AttrState: orUnknown(tok.State), semconv.AttrTokenName: tok.OrganizationName},
		})
	}
	return points, nil
}

// depPoints fetches the beta DEP onboarding settings collection (tiny,
// admin-configured - typically 1-3 settings) and returns the
// days-until-expiry points plus the synced-device-count points.
func (c *Collector) depPoints(ctx context.Context, now time.Time) ([]telemetry.GaugePoint, []telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, betaBaseURL+"/deviceManagement/depOnboardingSettings", nil)
	if err != nil {
		return nil, nil, err
	}
	expiry := make([]telemetry.GaugePoint, 0, len(raw))
	deviceCounts := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var setting depOnboardingSettingResource
		if err := json.Unmarshal(r, &setting); err != nil {
			c.logger.Warn("apple_tokens: skipping unparseable dep onboarding setting", "collector", collectorName, "error", err)
			continue
		}
		state := "ok"
		if setting.LastSyncErrorCode != 0 {
			state = "sync_error"
		}
		if days, ok := daysUntil(setting.TokenExpirationDateTime, now); ok {
			expiry = append(expiry, telemetry.GaugePoint{
				Value: days,
				Attrs: telemetry.Attrs{semconv.AttrType: "dep", semconv.AttrState: state, semconv.AttrTokenName: setting.TokenName},
			})
		} else {
			c.logger.Info("apple_tokens: dep onboarding setting has no tokenExpirationDateTime, skipping",
				"collector", collectorName, "token_name", setting.TokenName)
		}
		deviceCounts = append(deviceCounts, telemetry.GaugePoint{
			Value: float64(setting.SyncedDeviceCount),
			Attrs: telemetry.Attrs{semconv.AttrTokenName: setting.TokenName},
		})
	}
	return expiry, deviceCounts, nil
}

// handleFetchErr classifies a source fetch error: a 403/404 (missing scope,
// unlicensed, or a beta endpoint unavailable on this tenant) is skipped and
// logged at Info, returning nil so it never surfaces as a Collect error; any
// other failure is logged at Warn and returned wrapped with context so it
// still surfaces via errors.Join for self-obs visibility.
func (c *Collector) handleFetchErr(source string, err error) error {
	if isUnavailable(err) {
		c.logger.Info("apple_tokens: "+source+" unavailable on this tenant; skipping",
			"collector", collectorName, "error", err)
		return nil
	}
	c.logger.Warn("apple_tokens: "+source+" fetch failed", "collector", collectorName, "error", err)
	return fmt.Errorf("%s: %w", source, err)
}

// isUnavailable reports whether err is a 4xx from a source being
// unavailable/unlicensed/under-scoped on the tenant (403 forbidden, 404 not
// found) — an expected "no data here" condition, not a failure. Mirrors the
// entra/recommendations beta collector's classifier.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

// daysUntil parses a Graph timestamp and returns the (possibly negative)
// number of days from now until it. ok is false when raw is empty or
// unparsable - mirroring the credentialexpiry collector's malformed-timestamp
// handling, this is a single skipped data point, never a Collect-level error.
func daysUntil(raw string, now time.Time) (days float64, ok bool) {
	if raw == "" {
		return 0, false
	}
	end, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		end, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return 0, false
		}
	}
	return end.Sub(now).Hours() / 24, true
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
