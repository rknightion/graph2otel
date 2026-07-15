// Package credentialexpiry is the flagship Entra compliance-metrics
// collector: application (app-registration) and service-principal credential
// (secret + certificate) expiry, aggregated into a fixed set of bucket
// counters. It pages `/applications` and `/servicePrincipals` selecting only
// keyCredentials and passwordCredentials, buckets every credential's
// endDateTime relative to "now", and emits ONLY the bounded aggregate —
// never a per-credential or per-app series. See the cardinality note below;
// this is the load-bearing decision for this collector.
package credentialexpiry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.credential_expiry"

// metricName is the single gauge this collector emits.
const metricName = "entra.credentials.expiring.total"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Bucket boundaries (inclusive upper bound), deliberately few and fixed so
// the emitted series set never grows with tenant size:
//
//	expired : endDateTime <= now
//	lt_7d   : now         <  endDateTime <= now+7d
//	lt_30d  : now+7d      <  endDateTime <= now+30d
//	lt_90d  : now+30d     <  endDateTime <= now+90d
//	gt_90d  : now+90d     <  endDateTime
const (
	windowLt7d  = 7 * 24 * time.Hour
	windowLt30d = 30 * 24 * time.Hour
	windowLt90d = 90 * 24 * time.Hour
)

// expiryBuckets is the fixed, ordered set of bucket labels. Cardinality of
// the emitted metric is exactly len(ownerTypes) * len(credentialTypes) *
// len(expiryBuckets), regardless of how many applications, service
// principals, or credentials the tenant has.
var expiryBuckets = []string{"expired", "lt_7d", "lt_30d", "lt_90d", "gt_90d"}

// credentialTypes is the fixed set of credential kinds: keyCredentials are
// certificates, passwordCredentials are secrets.
var credentialTypes = []string{"certificate", "secret"}

// ownerType pairs a bounded `owner_type` attribute value with its Graph list
// path. Both applications and servicePrincipals carry identical
// keyCredentials/passwordCredentials shapes.
type ownerType struct {
	attr string
	path string
}

var ownerTypes = []ownerType{
	{"application", "/applications"},
	{"service_principal", "/servicePrincipals"},
}

// selectQuery is deliberately minimal: only the two credential collections
// are requested, and within them only endDateTime is ever read. No appId,
// displayName, or keyId is fetched — this collector has no use for
// per-entity identity, so it never asks Graph for it.
const selectQuery = "$select=keyCredentials,passwordCredentials"

// credential is the subset of keyCredential/passwordCredential this collector
// reads. Both resource types carry endDateTime with identical semantics, so
// one struct field covers either.
type credential struct {
	EndDateTime string `json:"endDateTime"`
}

// appCredentials is the subset of the application/servicePrincipal resource
// this collector reads. Deliberately does not decode appId, displayName, id,
// or any keyId/customKeyIdentifier — those never enter memory here, so they
// can never leak into a metric label by accident.
type appCredentials struct {
	KeyCredentials      []credential `json:"keyCredentials"`
	PasswordCredentials []credential `json:"passwordCredentials"`
}

// bucketKey is the fully-bounded key for one emitted series.
type bucketKey struct {
	ownerType      string
	credentialType string
	expiryBucket   string
}

// Collector polls application and service-principal credential expiry.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now returns the instant bucket boundaries are computed relative to.
	// Defaults to time.Now; tests override it for deterministic buckets.
	now func() time.Time
}

// New builds the credential-expiry collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. This collector pages the
// full applications and servicePrincipals collections (unlike a cheap
// $count), so it runs on a longer cadence than the directory-summary
// collector.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph scope: Application.Read.All
// is the least-privileged application permission for listing both
// /applications and /servicePrincipals (verified against current Graph v1.0
// docs; Directory.Read.All is a higher-privileged alternative, not required).
func (c *Collector) RequiredPermissions() []string { return []string{"Application.Read.All"} }

// Collect pages each owner type's credentials and buckets every credential's
// endDateTime relative to now. A fetch failure on one owner type is logged
// and that owner type's buckets are omitted from the snapshot entirely
// (rather than reported as a false zero), but the other owner type still
// emits; the aggregated error is returned so the partial failure is visible
// in scrape self-obs without hiding the data that did succeed.
//
// Cardinality (NON-NEGOTIABLE): only the bucket counters are emitted. No
// appId, displayName, or keyId is ever read from the response, let alone
// attached to a metric point — per-credential/per-app detail belongs in the
// logs pipeline (M3/M5), never in this gauge.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	now := c.now()
	counts := map[bucketKey]int64{}
	var errs []error

	for _, ot := range ownerTypes {
		url := c.baseURL + ot.path + "?" + selectQuery
		items, err := collectors.GetAllValues(ctx, c.g, url, nil)
		if err != nil {
			c.logger.Warn("credential list failed", "collector", collectorName, "owner_type", ot.attr, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", ot.attr, err))
			continue
		}

		// Seed every credential_type x expiry_bucket combo for this owner
		// type at zero, so a bucket with no matching credentials still emits
		// a dense series rather than silently disappearing.
		for _, credType := range credentialTypes {
			for _, bucket := range expiryBuckets {
				counts[bucketKey{ot.attr, credType, bucket}] = 0
			}
		}

		for _, raw := range items {
			var ac appCredentials
			if err := json.Unmarshal(raw, &ac); err != nil {
				c.logger.Warn("credential entry decode failed", "collector", collectorName, "owner_type", ot.attr, "error", err)
				continue
			}
			for _, cred := range ac.KeyCredentials {
				c.bucketCredential(counts, ot.attr, "certificate", cred.EndDateTime, now)
			}
			for _, cred := range ac.PasswordCredentials {
				c.bucketCredential(counts, ot.attr, "secret", cred.EndDateTime, now)
			}
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				"owner_type":      k.ownerType,
				"credential_type": k.credentialType,
				"expiry_bucket":   k.expiryBucket,
			},
		})
	}
	e.GaugeSnapshot(metricName, "{credential}",
		"Count of application and service-principal credentials (secrets and certificates) by expiry window.",
		points)
	return errors.Join(errs...)
}

// bucketCredential parses endDateTime and increments the matching bucket. An
// unparsable or empty endDateTime is logged and skipped — it is a single
// malformed data point, not a Graph API failure, so it does not surface as a
// Collect error.
func (c *Collector) bucketCredential(counts map[bucketKey]int64, owner, credType, endDateTime string, now time.Time) {
	end, err := time.Parse(time.RFC3339, endDateTime)
	if err != nil {
		var perr error
		end, perr = time.Parse(time.RFC3339Nano, endDateTime)
		if perr != nil {
			c.logger.Warn("credential endDateTime unparsable, skipping",
				"collector", collectorName, "owner_type", owner, "credential_type", credType, "error", err)
			return
		}
	}
	bucket := expiryBucketFor(now, end)
	counts[bucketKey{owner, credType, bucket}]++
}

// expiryBucketFor maps an endDateTime to one of the fixed expiryBuckets,
// relative to now. See the const block above for the exact boundaries.
func expiryBucketFor(now, end time.Time) string {
	d := end.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d <= windowLt7d:
		return "lt_7d"
	case d <= windowLt30d:
		return "lt_30d"
	case d <= windowLt90d:
		return "lt_90d"
	default:
		return "gt_90d"
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
