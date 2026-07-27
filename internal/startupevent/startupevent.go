// Package startupevent emits graph2otel's process-lifecycle marker: one
// `graph2otel.startup` log record per process start, carrying the build version
// and a one-way, secret-free fingerprint of the effective configuration (#310).
//
// # Why a LOG and not a metric
//
// The marker exists so a dashboard can answer "what changed at 14:00" — a
// point-in-time event with a handful of attributes, which is a log record's
// shape and not a time series'. There is also already a metric for the build
// identity: graph2otel.build_info is a constant-1 gauge carrying `version` and
// `go.version`. A second metric would duplicate it while adding nothing an
// annotation can render, and every metric label is paid for forever under
// Grafana Cloud's active-series billing.
//
// # Scope: process-wide facts, tenant-stamped delivery
//
// Everything this record says is process-wide — one binary, one build, one
// effective configuration. Delivery is nevertheless ONE RECORD PER CONFIGURED
// TENANT, stamped by telemetry.WithTenant, because tenant_id is on every other
// signal (#143) and every dashboard panel and annotation query filters on it. A
// single unstamped process record would be filtered out of every tenant-scoped
// view — present in Loki, invisible exactly where an operator looks for it.
//
// That is not a lie, but it is asymmetric in one direction worth stating: the
// fingerprint covers the WHOLE effective configuration, so changing tenant B's
// collector settings moves the fingerprint on tenant A's marker too. The marker
// therefore means "this process's configuration changed", never "your tenant's
// configuration changed". Over-reporting was chosen deliberately over the
// alternative — a per-tenant fingerprint over the tenant's own subtree would
// MISS a change to the global `collectors:` map that does alter what that tenant
// collects, and a marker that silently fails to fire is worse than one that
// fires for a neighbor's change.
//
// With no tenant configured (stdout mode) exactly one unstamped record is
// emitted, so the marker never silently disappears.
//
// # No opt-out, deliberately
//
// There is no configuration key gating this event, matching
// graph2otel.build_info. Its volume is one record per tenant per process start;
// the only thing a toggle could buy is a deployment where the deploy/config
// markers silently stop appearing on dashboards that depend on them.
package startupevent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/version"
)

// EventName is the OTEL EventName of the startup marker. It sits in the
// graph2otel.* self-observability namespace: it describes the exporter, not a
// Microsoft tenant's data.
const EventName = "graph2otel.startup"

// fingerprintDomain domain-separates the configuration fingerprint's hash input
// and versions the scheme. Two purposes:
//
//   - A fingerprint can never equal, and so can never be confirmed by, a hash of
//     the same bytes computed anywhere else.
//   - Changing what the fingerprint covers is a breaking change for an operator
//     comparing markers across a restart, so the scheme carries a version. Bump
//     the /v1 when the covered surface changes; every fingerprint moves once,
//     which is the honest signal that the definition changed.
//
// The NUL terminator keeps the prefix unambiguous against the JSON that follows.
const fingerprintDomain = "graph2otel/config-fingerprint/v1\x00"

// fingerprintHexLen is how many hex characters of the SHA-256 digest are
// emitted. 16 hex characters is 64 bits: collision-free for the handful of
// configurations one deployment ever has, short enough to read off an annotation
// tooltip, and a further truncation of an already one-way digest.
const fingerprintHexLen = 16

// Fingerprint returns the one-way configuration fingerprint for cfg: 16
// lowercase hex characters, deterministic, and impossible to reverse into the
// configuration.
//
// # Exactly what it covers
//
// Everything in config.Config, as a DENY-list rather than an allow-list: the
// canonical input is the JSON encoding of the whole struct. That direction is
// the load-bearing choice. An allow-list of "operationally meaningful" keys
// would silently stop covering every key added afterwards, and a fingerprint
// that quietly under-reports is worse than none — the marker would say "nothing
// changed" about a change that did happen. The cost of the deny-list is
// over-sensitivity: a cosmetic config edit moves the fingerprint. That is the
// safe direction.
//
// # Exactly what it excludes, and why
//
//   - Credentials. Every credential on the config surface is typed
//     config.Secret, whose MarshalJSON renders "REDACTED" for any non-empty
//     value, so secret BYTES cannot reach the hash input — mechanically, by the
//     type, not by a list this package maintains. A rotated credential therefore
//     does not move the fingerprint, while a credential going from unset to set
//     does (""/"REDACTED" differ), which is the operationally meaningful half of
//     the change. Tenant auth material (AZURE_CLIENT_SECRET, certificates) is
//     not on this surface at all — azidentity reads it from the environment.
//   - Unexported fields, which encoding/json skips. The only one is
//     collectorEnvOrigins, a diagnostic map of which env var supplied which
//     dynamic collector override; it changes nothing about behavior.
//
// # Why it is one-way
//
// SHA-256, truncated to 64 bits, over an input containing no credential. There
// is no inverse: the digest is not reversible, the truncation discards 192
// further bits, and even a brute-force search over candidate configurations
// recovers nothing secret because nothing secret is in the input.
func Fingerprint(cfg *config.Config) (string, error) {
	canon, err := canonical(cfg)
	if err != nil {
		return "", fmt.Errorf("canonicalize config for fingerprint: %w", err)
	}
	return hashHex([]byte(fingerprintDomain), canon), nil
}

// canonical renders cfg as the deterministic byte string the fingerprint hashes.
//
// encoding/json is the canonicalizer because it is deterministic for this shape
// (struct fields in declaration order, map keys sorted) AND because it is the
// encoding config.Secret redacts under. A hand-rolled walk would have to
// re-derive that redaction and could forget a future Secret field; here the
// exclusion is a property of the type being encoded.
func canonical(cfg *config.Config) ([]byte, error) {
	return json.Marshal(cfg)
}

// hashHex returns the truncated hex SHA-256 of domain||body.
func hashHex(domain, body []byte) string {
	h := sha256.New()
	h.Write(domain)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))[:fingerprintHexLen]
}

// Emit records the startup marker: one log record per configured tenant, or
// exactly one unstamped record when no tenant is configured.
//
// startedAt is the process start time and MUST be non-zero. telemetry.Emitter
// treats a zero Timestamp as "stamp on arrival", which for this record would
// claim the process started whenever the OTLP batch happened to be exported —
// a marker that is wrong by exactly the interval an operator is trying to line
// up against. An unknown event time is dropped, never stamped (#226), so a zero
// startedAt emits nothing and returns an error for the caller to log.
func Emit(base telemetry.Emitter, cfg *config.Config, startedAt time.Time) error {
	if cfg == nil {
		return fmt.Errorf("%s not emitted: no configuration to fingerprint", EventName)
	}
	if startedAt.IsZero() {
		return fmt.Errorf("%s not emitted: process start time is unknown, and a marker "+
			"stamped with arrival time would misdate the deployment", EventName)
	}
	fp, err := Fingerprint(cfg)
	if err != nil {
		return fmt.Errorf("%s not emitted: %w", EventName, err)
	}

	body := fmt.Sprintf("graph2otel %s started; config fingerprint %s", version.String(), fp)
	newEvent := func() telemetry.Event {
		return telemetry.Event{
			Name:      EventName,
			Body:      body,
			Severity:  telemetry.SeverityInfo,
			Timestamp: startedAt,
			Attrs: telemetry.Attrs{
				// version and go.version come from the SAME source as
				// graph2otel.build_info (internal/version.String and
				// runtime.Version). There is deliberately no second version
				// source: the ldflags target is internal/version.Version, so
				// anything else would report "dev" on a release build.
				semconv.AttrVersion:           version.String(),
				semconv.AttrGoVersion:         runtime.Version(),
				semconv.AttrConfigFingerprint: fp,
				// tenant_count is a bounded operator-chosen number, and it makes
				// a single-record marker legible: a reader can tell "one tenant"
				// from "one of six tenants" without correlating.
				semconv.AttrConfigTenantCount: len(cfg.Tenants),
			},
		}
	}

	if len(cfg.Tenants) == 0 {
		base.LogEvent(newEvent())
		return nil
	}
	for _, tenant := range cfg.Tenants {
		// A fresh Event (and therefore a fresh Attrs map) per tenant: the
		// decorators copy before stamping, but sharing one map across two
		// tenant-decorated emitters is the shape that has raced before.
		telemetry.WithTenant(base, tenant.TenantID).LogEvent(newEvent())
	}
	return nil
}
