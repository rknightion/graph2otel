package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// GrafanaAnnotationsConfig configures the opt-in Grafana annotation writer
// (#400): graph2otel publishing a curated, closed set of Microsoft domain
// events into a Grafana organization as annotations, so a dashboard can explain
// "what changed at 14:00" without an external automation.
//
// # This is the ONE authorized second egress path
//
// graph2otel is OTLP-push-only. #310 recorded a NARROW amendment to that
// invariant for annotations and nothing else: telemetry still leaves the process
// exclusively over OTLP, and this block configures a single additional HTTP
// destination whose only supported call is POST /api/annotations. It is not a
// generic output framework and must not grow into one.
//
// # Why the URL is the opt-in and the token is a secret
//
// URL is a plain (non-secret) key so it can live in committed YAML, exactly like
// mdca.portal_url and blob_ingest.account_url — setting it IS the opt-in, and an
// unset URL registers nothing at all, with no warning. The token is a
// credential, so it follows the graph2otel credential convention: an env Secret
// (G2O_GRAFANA_ANNOTATIONS__TOKEN) or a mounted file (token_file), never
// committed YAML. Both land in the Secret-typed field so the value redacts in
// every dump and cannot reach #310's configuration fingerprint as bytes.
//
// # The required Grafana permission
//
// The service-account token needs exactly ONE Grafana action:
//
//	action: annotations:create
//	scope:  annotations:type:organization   (or annotations:type:dashboard
//	        when dashboard_uid is set)
//
// The fixed role that grants it is `fixed:annotations:writer` (the "Annotations
// writer" role in the UI) — that is the ROLE name the maintainer specified;
// `annotations:create` on the annotation-type scope is the action/scope pair the
// API actually checks (Grafana RBAC reference, docs-only evidence). graph2otel
// must not require, request or use any other Grafana permission: no dashboard
// read, no alert-rule access, no folder management. A broader token still works,
// but the documented minimum is annotation write, because that narrowness is the
// entire thing carrying #310's invariant amendment.
type GrafanaAnnotationsConfig struct {
	// URL is the Grafana base URL, e.g. "https://grafana.example.com" (no
	// trailing path). Setting it is the whole opt-in: empty — the default —
	// registers no annotation writer, opens no HTTP client, and logs nothing.
	URL string `yaml:"url"`
	// Token is the Grafana service-account token. Supply it through
	// G2O_GRAFANA_ANNOTATIONS__TOKEN or token_file; never commit it to YAML.
	Token Secret `yaml:"token"`
	// TokenFile is a path to a file holding the token — the k8s/Docker
	// secret-mount alternative to Token, resolved by resolveSecretFiles.
	// value XOR file: set one, never both.
	TokenFile string `yaml:"token_file"`
	// DashboardUID optionally scopes every published annotation to one
	// dashboard. Empty (the default) publishes ORGANIZATION annotations, which
	// is what lets a single annotation appear on every dashboard whose
	// annotation query selects graph2otel's tags — the shape #400 wants. Set it
	// only to deliberately confine the annotations to one board.
	DashboardUID string `yaml:"dashboard_uid"`
	// Timeout bounds one POST /api/annotations request.
	Timeout time.Duration `yaml:"timeout"`
	// MaxPerMinute is the publisher's token-bucket ceiling on annotations
	// actually written, per process. It exists because enough annotations turn
	// every dashboard into an unreadable picket fence, at which point operators
	// stop reading them and the feature is worse than absent. Exceeding it drops
	// the annotation and counts the drop; it never blocks collection.
	MaxPerMinute int `yaml:"max_per_minute"`
	// QueueSize bounds the publisher's hand-off buffer. A full queue drops the
	// annotation and counts it — the collector goroutine must never block on
	// Grafana being slow or down.
	QueueSize int `yaml:"queue_size"`
	// RollupInterval is the bucket width for categories whose Rollup is true:
	// one annotation per interval per category per tenant, carrying a count and
	// a bounded summary instead of one annotation per event.
	RollupInterval time.Duration `yaml:"rollup_interval"`
	// DedupeRetention is how long a published annotation's dedupe key is
	// remembered. It bounds the persisted key set and must comfortably exceed
	// the widest overlap window any source collector re-queries, since the
	// source records arrive through at-least-once paths and a duplicate
	// annotation is indistinguishable from a second real event.
	DedupeRetention time.Duration `yaml:"dedupe_retention"`
	// Categories gates the four curated event categories independently.
	Categories AnnotationCategoriesConfig `yaml:"categories"`
}

// AnnotationCategoriesConfig gates the four curated annotation categories.
//
// It is four named fields rather than a map keyed by category name for one
// mechanical reason: koanf's env provider cannot bind a value into a map entry
// the way it binds a struct field, so a map would make every category
// file-only. Named fields also make the closed set of categories a compile-time
// fact instead of a string an operator can typo into silence.
type AnnotationCategoriesConfig struct {
	// ConfigPosture covers Conditional Access policy changes, Intune
	// compliance/configuration policy changes, admin consent grants and app
	// credential additions — the classic "what changed at 14:00" question.
	// Rolled up by default: it is the highest-volume of the four on an active
	// tenant, and its rate scales with administrative activity.
	ConfigPosture AnnotationCategoryConfig `yaml:"config_posture"`
	// SecurityIncident covers medium/high security alerts and incidents
	// becoming active. Timeline context, deliberately not a page. Individually
	// annotated: naturally low volume, and a rolled-up count would lose the one
	// thing an operator needs, which incident.
	SecurityIncident AnnotationCategoryConfig `yaml:"security_incident"`
	// ServiceHealth covers Microsoft 365 service-health incidents opening and
	// closing — the annotation that explains collector degradation which is NOT
	// graph2otel's fault. Individually annotated for the same reason.
	ServiceHealth AnnotationCategoryConfig `yaml:"service_health"`
	// License covers subscribed-SKU set changes and license exhaustion, which
	// explain a collector flipping to limited/partial_license — a state #292
	// made non-alerting precisely because it is not a failure. Rolled up by
	// default: a tenant-wide license change moves many SKUs at once.
	License AnnotationCategoryConfig `yaml:"license"`
}

// AnnotationCategoryConfig gates and shapes one annotation category.
type AnnotationCategoryConfig struct {
	// Enabled publishes this category. All four default to true, but the
	// feature as a whole is off until GrafanaAnnotationsConfig.URL is set, so
	// this changes nothing on a default deployment.
	Enabled bool `yaml:"enabled"`
	// Rollup replaces per-event annotations with one annotation per
	// RollupInterval per tenant for this category, carrying a count and a
	// bounded summary.
	Rollup bool `yaml:"rollup"`
}

// Configured reports whether the annotation writer is switched on. A set URL is
// the whole opt-in, matching MDCAConfig.Configured and blob_ingest.account_url.
func (a GrafanaAnnotationsConfig) Configured() bool {
	return strings.TrimSpace(a.URL) != ""
}

// validate checks the annotation block in isolation. An unset block is valid
// (opt-out); a set URL requires a credential and sane tunables.
func (a GrafanaAnnotationsConfig) validate() error {
	if !a.Configured() {
		// A credential mounted for a switched-off feature does nothing, silently,
		// while reading to whoever mounted it as "annotations are on".
		if a.Token.Reveal() != "" {
			return fmt.Errorf("token is set but url is empty (the annotation writer is off unless url is set)")
		}
		if strings.TrimSpace(a.TokenFile) != "" {
			return fmt.Errorf("token_file is set but url is empty (the annotation writer is off unless url is set)")
		}
		return nil
	}

	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("url %q is not a valid absolute URL", a.URL)
	}
	if a.Token.Reveal() == "" && strings.TrimSpace(a.TokenFile) == "" {
		return fmt.Errorf("token or token_file is required when url is set: the Grafana " +
			"service-account token needs the annotations:create action " +
			"(role fixed:annotations:writer) and nothing else")
	}
	if a.Timeout <= 0 {
		return fmt.Errorf("timeout %v invalid: must be > 0", a.Timeout)
	}
	if a.MaxPerMinute <= 0 {
		return fmt.Errorf("max_per_minute %d invalid: must be > 0", a.MaxPerMinute)
	}
	if a.QueueSize <= 0 {
		return fmt.Errorf("queue_size %d invalid: must be > 0", a.QueueSize)
	}
	if a.RollupInterval <= 0 {
		return fmt.Errorf("rollup_interval %v invalid: must be > 0", a.RollupInterval)
	}
	if a.DedupeRetention <= 0 {
		return fmt.Errorf("dedupe_retention %v invalid: must be > 0", a.DedupeRetention)
	}
	return nil
}

// defaultGrafanaAnnotations is the shipped shape: off (no URL), with tunables
// already set so enabling the feature needs one key plus a credential.
func defaultGrafanaAnnotations() GrafanaAnnotationsConfig {
	return GrafanaAnnotationsConfig{
		Timeout:      10 * time.Second,
		MaxPerMinute: 60,
		QueueSize:    512,
		// Five minutes is short enough that a rolled-up marker still lines up
		// against a metric step on any dashboard an operator is reading, and long
		// enough that a burst of policy edits collapses into one marker.
		RollupInterval: 5 * time.Minute,
		// 48h comfortably exceeds every source collector's overlap window and
		// initial backfill lookback (the widest is 24h, entra.security_incidents),
		// so a restart cannot re-publish an event it already annotated.
		DedupeRetention: 48 * time.Hour,
		Categories: AnnotationCategoriesConfig{
			ConfigPosture:    AnnotationCategoryConfig{Enabled: true, Rollup: true},
			SecurityIncident: AnnotationCategoryConfig{Enabled: true, Rollup: false},
			ServiceHealth:    AnnotationCategoryConfig{Enabled: true, Rollup: false},
			License:          AnnotationCategoryConfig{Enabled: true, Rollup: true},
		},
	}
}
