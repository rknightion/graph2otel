// Package credentialexpiry is the flagship Entra compliance collector:
// application (app-registration) and service-principal credential (secret +
// certificate) expiry. It pages `/applications` and `/servicePrincipals`
// selecting keyCredentials, passwordCredentials, and the owning entity's
// id/appId/displayName, then emits BOTH sides of the cardinality boundary
// from that single fetch:
//
//   - a bounded GAUGE counted by owner_type x credential_type x expiry_bucket
//     (fixed cardinality regardless of tenant size, never a per-app or
//     per-credential series);
//   - one LOG record per credential (entra.app_credential) carrying the
//     per-entity detail the gauge cannot: which app/service principal, which
//     key, and its dates.
//
// The log twin is not optional garnish — it is the other half of the rule.
// This collector previously decoded only endDateTime and discarded appId,
// displayName, and every key identifier, so it could answer "N credentials
// expire in 7 days" but never "WHICH app" — unactionable for both outage
// prevention and incident rotation-priority. That was a bug (#114), not a
// privacy control: graph2otel exports this detail by design, and the logs
// pipeline is where it belongs. See SECURITY.md.
//
// This is a STATE feed, not an event stream: a credential is re-emitted every
// cycle for as long as it exists, which is what makes "which credentials were
// live on date X" answerable. Volume scales with the credential population
// (bounded by tenant size), not with the poll interval.
//
// Deliberately NOT decoded, ever: keyCredential.key (the certificate's raw
// public key material) and passwordCredential.secretText/hint (secret-bearing
// or secret-derived — secretText is write-once and never returned by a GET
// anyway, and hint leaks three characters of the actual password). Only
// customKeyIdentifier (a thumbprint-like public identifier, not secret
// material) is decoded for certificates.
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
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.credential_expiry"

// metricName is the single gauge this collector emits.
const metricName = "entra.credentials.expiring.total"

// eventAppCredential is the log twin's EventName: one record per credential
// per cycle, carrying the per-entity detail the gauge cannot. See the
// package doc.
const eventAppCredential = "entra.app_credential" //nolint:gosec // G101 false positive: a log event name, not a credential

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

// selectQuery requests exactly what the metric and its log twin need: the
// two credential collections, plus the minimal identity (id/appId/
// displayName) needed to say WHICH app/service principal a credential
// belongs to. Nothing wider — see the CLAUDE.md gotcha on the ~150 req/min
// throttle for $select=keyCredentials on a collection GET.
const selectQuery = "$select=id,appId,displayName,keyCredentials,passwordCredentials"

// credential is the subset of keyCredential/passwordCredential this collector
// reads (field names verified against learn.microsoft.com). Both resource
// types share keyId/displayName/startDateTime/endDateTime with identical
// semantics; CustomKeyIdentifier/Type/Usage are meaningful for keyCredential
// (certificate) only and are simply left zero for passwordCredential
// (secret) entries, since neither is emitted for that credential type (see
// credentialLogTwin).
//
// keyCredential.key (raw public key blob) and passwordCredential.secretText/
// hint are deliberately NOT fields here — see the package doc.
type credential struct {
	KeyID         string `json:"keyId"`
	DisplayName   string `json:"displayName"`
	StartDateTime string `json:"startDateTime"`
	EndDateTime   string `json:"endDateTime"`

	// keyCredential (certificate) only.
	CustomKeyIdentifier string `json:"customKeyIdentifier"`
	Type                string `json:"type"`
	Usage               string `json:"usage"`
}

// ownerEntity is the subset of the application/servicePrincipal resource this
// collector reads: its two credential collections, plus enough identity
// (id/appId/displayName) to say WHICH app or service principal a credential
// belongs to in the log twin. The metric side never reads these identity
// fields off of this struct — only Collect's owner_type loop variable
// (application/service_principal) reaches the gauge.
type ownerEntity struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`

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

// Collect pages each owner type's credentials, buckets every credential's
// endDateTime relative to now, and emits BOTH sides of the cardinality
// boundary from that single fetch: the bounded GaugeSnapshot, and one log
// record per credential carrying the per-entity detail the gauge cannot. A
// fetch failure on one owner type is logged and that owner type's buckets
// (and log twins) are omitted from the snapshot entirely (rather than
// reported as a false zero), but the other owner type still emits; the
// aggregated error is returned so the partial failure is visible in scrape
// self-obs without hiding the data that did succeed.
//
// Cardinality (NON-NEGOTIABLE): only owner_type/credential_type/expiry_bucket
// ever reach the gauge's attributes. appId/displayName/id/keyId ARE decoded
// (see ownerEntity/credential above) but flow ONLY into the log twin
// (credentialLogTwin) — never into a telemetry.GaugePoint. See the package
// doc and TestCollectMetricsNeverCarryPerEntityAttrs.
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
			var ent ownerEntity
			if err := json.Unmarshal(raw, &ent); err != nil {
				c.logger.Warn("credential entry decode failed", "collector", collectorName, "owner_type", ot.attr, "error", err)
				continue
			}
			for _, cred := range ent.KeyCredentials {
				c.processCredential(e, counts, ot, "certificate", ent, cred, now)
			}
			for _, cred := range ent.PasswordCredentials {
				c.processCredential(e, counts, ot, "secret", ent, cred, now)
			}
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrOwnerType:      k.ownerType,
				semconv.AttrCredentialType: k.credentialType,
				semconv.AttrExpiryBucket:   k.expiryBucket,
			},
		})
	}
	e.GaugeSnapshot(metricName, "{credential}",
		"Count of application and service-principal credentials (secrets and certificates) by expiry window.",
		points)
	return errors.Join(errs...)
}

// processCredential buckets one credential's endDateTime and emits its log
// twin. An unparsable or empty endDateTime is logged and the credential is
// skipped entirely — from both the bucket AND the log twin, since
// expiry_bucket (a field on every log record) cannot be computed for it, and
// this is a single malformed data point, not a Graph API failure, so it does
// not surface as a Collect error.
func (c *Collector) processCredential(e telemetry.Emitter, counts map[bucketKey]int64, owner ownerType, credType string, ent ownerEntity, cred credential, now time.Time) {
	end, err := parseEndDateTime(cred.EndDateTime)
	if err != nil {
		c.logger.Warn("credential endDateTime unparsable, skipping",
			"collector", collectorName, "owner_type", owner.attr, "credential_type", credType, "error", err)
		return
	}
	bucket := expiryBucketFor(now, end)
	counts[bucketKey{owner.attr, credType, bucket}]++
	e.LogEvent(credentialLogTwin(owner, credType, ent, cred, bucket))
}

// parseEndDateTime accepts either RFC3339 or RFC3339Nano, matching the two
// forms Graph is observed to return for DateTimeOffset fields. On failure it
// returns the RFC3339 parse error (the more informative of the two for a
// malformed value).
func parseEndDateTime(s string) (time.Time, error) {
	end, err := time.Parse(time.RFC3339, s)
	if err != nil {
		var perr error
		end, perr = time.Parse(time.RFC3339Nano, s)
		if perr != nil {
			return time.Time{}, err
		}
	}
	return end, nil
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

// credentialLogTwin renders one credential as an OTLP log record — the
// per-entity detail (which app, which key, which dates) the bounded gauge
// cannot carry. See the package doc.
//
// Certificate-only fields (custom_key_identifier/key_type/key_usage) are
// attached only when credType is "certificate": they come from keyCredential,
// which passwordCredential does not carry, so attaching them for a secret
// would either be a stale zero value or (worse) accidentally wired to the
// wrong field in a future edit. telemetry.SetStr's omit-if-empty behavior
// would mask that mistake, so the certificate-only fields are gated
// explicitly instead.
func credentialLogTwin(owner ownerType, credType string, ent ownerEntity, cred credential, bucket string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrOwnerType, owner.attr)
	telemetry.SetStr(attrs, semconv.AttrAppId, ent.AppID)
	telemetry.SetStr(attrs, semconv.AttrAppObjectId, ent.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, ent.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrCredentialType, credType)
	telemetry.SetStr(attrs, semconv.AttrKeyId, cred.KeyID)
	telemetry.SetStr(attrs, semconv.AttrCredentialDisplayName, cred.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrStartDateTime, cred.StartDateTime)
	telemetry.SetStr(attrs, semconv.AttrEndDateTime, cred.EndDateTime)
	telemetry.SetStr(attrs, semconv.AttrExpiryBucket, bucket)
	if credType == "certificate" {
		telemetry.SetStr(attrs, semconv.AttrCustomKeyIdentifier, cred.CustomKeyIdentifier)
		telemetry.SetStr(attrs, semconv.AttrKeyType, cred.Type)
		telemetry.SetStr(attrs, semconv.AttrKeyUsage, cred.Usage)
	}

	// Only "expired" and "lt_7d" escalate to WARN: those are the two buckets
	// this collector's own boundaries already treat as actionable-now (a
	// dead credential, or one about to become one within a week). lt_30d/
	// lt_90d/gt_90d are routine background state on any real tenant, and
	// warning on them would make the severity dimension useless for
	// filtering — the same reasoning the risk collector applies to
	// riskLevel, applied here to expiry_bucket since this resource has no
	// risk-level field of its own.
	sev := telemetry.SeverityInfo
	if bucket == "expired" || bucket == "lt_7d" {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventAppCredential,
		Body: fmt.Sprintf("%s credential %s for %s %s: expiry_bucket=%s end_date_time=%s",
			credType, displayOfCredential(cred), owner.attr, displayOfEntity(ent), bucket, cred.EndDateTime),
		Severity: sev,
		Attrs:    attrs,
	}
}

// displayOfEntity picks the most human-readable identifier the owning
// app/service principal carries, falling back through to its object id.
func displayOfEntity(ent ownerEntity) string {
	for _, s := range []string{ent.DisplayName, ent.AppID, ent.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// displayOfCredential picks the most human-readable identifier a credential
// carries, falling back to its keyId.
func displayOfCredential(cred credential) string {
	for _, s := range []string{cred.DisplayName, cred.KeyID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
