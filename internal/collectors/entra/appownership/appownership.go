// Package appownership is the Entra application-ownership and federated-identity
// collector (#244). It surfaces two trust gaps no other signal graph2otel ships
// can see:
//
//   - OWNERLESS applications and service principals. An app registration nobody
//     owns is one nobody can be asked "is this still needed?" — the entry point
//     to credential sprawl, accumulating silently. 21 of 27 applications on m7kni
//     are ownerless (live-measured 2026-07-23).
//   - FEDERATED IDENTITY CREDENTIALS — the gap entra.credential_expiry
//     structurally cannot see. That collector buckets secret/certificate expiry;
//     a federated credential has NO expiry, so an app whose trust is a GitHub
//     OIDC subject reports perfectly clean while anyone with write access to that
//     repo can authenticate as it. The subject string is the whole signal.
//
// # Bounded gauges, log twins
//
// Counts ride bounded gauges (ownership by has_owner × audience/type; FICs by
// issuer_host); per-entity identity — app ids, owner UPNs, the OIDC subject —
// rides log twins (#114), never a metric label.
//
// # Validated vs unvalidated on this tenant
//
// The ownership COUNTS are wire-validated (every app/SP on m7kni is ownerless).
// The owner-UPN detail and the FIC record shape are NOT: every owners array and
// every federatedIdentityCredentials array is empty here, so those mappers are
// written against the documented shape and are docs-only until a tenant with an
// owner or a FIC exercises them (the #142/#165 rule). Stated, not hidden.
package appownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const collectorName = "entra.app_ownership"

const (
	metricAppOwnership = "entra.application.ownership"
	metricSPOwnership  = "entra.service_principal.ownership"
	metricFIC          = "entra.application.federated_credentials"
)

const (
	eventApplication = "entra.application"
	eventFIC         = "entra.federated_identity_credential"
)

const (
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	betaBaseURL    = "https://graph.microsoft.com/beta"
)

// The three fetches. Ownership is v1.0; the federatedIdentityCredentials $expand
// is beta-only. Graph allows only ONE $expand per query, so FIC is a separate
// application fetch from owners (live-verified 2026-07-23).
const (
	appsOwnersPath = "/applications?$select=id,appId,displayName,signInAudience,createdDateTime&$expand=owners&$top=999"
	spsOwnersPath  = "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType&$expand=owners&$top=999"
	appsFICPath    = "/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials&$top=999"
)

// Collector polls application/service-principal ownership and federated
// credentials.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	betaURL string
	logger  *slog.Logger
}

// New builds the app-ownership collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, betaURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Ownership and trust edges are
// configuration, not events — a long interval is ample.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// RequiredPermissions declares the read scope all three fetches share; it is in
// the poller's token already.
func (c *Collector) RequiredPermissions() []string { return []string{"Application.Read.All"} }

type directoryObject struct {
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
}

type application struct {
	ID              string            `json:"id"`
	AppID           string            `json:"appId"`
	DisplayName     string            `json:"displayName"`
	SignInAudience  string            `json:"signInAudience"`
	CreatedDateTime string            `json:"createdDateTime"`
	Owners          []directoryObject `json:"owners"`
	FICs            []federatedCred   `json:"federatedIdentityCredentials"`
}

type servicePrincipal struct {
	ID                   string            `json:"id"`
	AppID                string            `json:"appId"`
	DisplayName          string            `json:"displayName"`
	ServicePrincipalType string            `json:"servicePrincipalType"`
	Owners               []directoryObject `json:"owners"`
}

// federatedCred is a federatedIdentityCredential (beta $expand). UNVALIDATED on
// m7kni (zero FICs); shape is documented, not observed.
type federatedCred struct {
	Name      string   `json:"name"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Audiences []string `json:"audiences"`
}

// Collect fetches ownership (v1.0) and federated credentials (beta), emitting the
// bounded gauges and per-entity twins. The three fetches are independent.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	if err := c.collectAppOwnership(ctx, e); err != nil {
		errs = append(errs, fmt.Errorf("application ownership: %w", err))
	}
	if err := c.collectSPOwnership(ctx, e); err != nil {
		errs = append(errs, fmt.Errorf("service principal ownership: %w", err))
	}
	if err := c.collectFICs(ctx, e); err != nil {
		errs = append(errs, fmt.Errorf("federated identity credentials: %w", err))
	}
	return errors.Join(errs...)
}

func (c *Collector) collectAppOwnership(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+appsOwnersPath, nil)
	if err != nil {
		return err
	}
	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var a application
		if err := json.Unmarshal(raw, &a); err != nil {
			return fmt.Errorf("decode application: %w", err)
		}
		hasOwner := len(a.Owners) > 0
		counts[[2]string{boolStr(hasOwner), a.SignInAudience}]++

		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrAppId, a.AppID)
		telemetry.SetStr(attrs, semconv.AttrDisplayName, a.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrSignInAudience, a.SignInAudience)
		telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, a.CreatedDateTime)
		attrs[semconv.AttrOwnerCount] = int64(len(a.Owners))
		telemetry.SetStrs(attrs, semconv.AttrOwnerPrincipalNames, ownerUPNs(a.Owners))

		sev := telemetry.SeverityInfo
		if !hasOwner {
			sev = telemetry.SeverityWarn
		}
		e.LogEvent(telemetry.Event{
			Name:     eventApplication,
			Body:     fmt.Sprintf("application %s: owners=%d audience=%s", displayOr(a.DisplayName, a.AppID), len(a.Owners), a.SignInAudience),
			Severity: sev,
			Attrs:    attrs,
		})
	}
	e.GaugeSnapshot(metricAppOwnership, "{application}", "Applications by whether they have an owner and by sign-in audience.", ownershipPoints(counts, semconv.AttrSignInAudience))
	return nil
}

func (c *Collector) collectSPOwnership(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+spsOwnersPath, nil)
	if err != nil {
		return err
	}
	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var s servicePrincipal
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("decode service principal: %w", err)
		}
		counts[[2]string{boolStr(len(s.Owners) > 0), s.ServicePrincipalType}]++
	}
	e.GaugeSnapshot(metricSPOwnership, "{service_principal}", "Service principals by whether they have an owner and by type.", ownershipPoints(counts, semconv.AttrServicePrincipalType))
	return nil
}

func (c *Collector) collectFICs(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.betaURL+appsFICPath, nil)
	if err != nil {
		return err
	}
	byHost := map[string]int64{}
	for _, raw := range raws {
		var a application
		if err := json.Unmarshal(raw, &a); err != nil {
			return fmt.Errorf("decode application FICs: %w", err)
		}
		for _, fic := range a.FICs {
			byHost[issuerHost(fic.Issuer)]++
			attrs := telemetry.Attrs{}
			telemetry.SetStr(attrs, semconv.AttrAppId, a.AppID)
			telemetry.SetStr(attrs, semconv.AttrDisplayName, a.DisplayName)
			telemetry.SetStr(attrs, semconv.AttrCredentialName, fic.Name)
			telemetry.SetStr(attrs, semconv.AttrIssuer, fic.Issuer)
			telemetry.SetStr(attrs, semconv.AttrSubject, fic.Subject)
			telemetry.SetStrs(attrs, semconv.AttrAudiences, fic.Audiences)
			// A federated credential has no expiry; its existence on an app is the
			// trust edge credential_expiry cannot represent, so it is always worth a
			// Warn for review.
			e.LogEvent(telemetry.Event{
				Name:     eventFIC,
				Body:     fmt.Sprintf("federated identity credential %s on %s: issuer=%s subject=%s", fic.Name, displayOr(a.DisplayName, a.AppID), fic.Issuer, fic.Subject),
				Severity: telemetry.SeverityWarn,
				Attrs:    attrs,
			})
		}
	}
	points := make([]telemetry.GaugePoint, 0, len(byHost))
	for host, n := range byHost {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrIssuerHost: host},
		})
	}
	e.GaugeSnapshot(metricFIC, "{credential}", "Application federated identity credentials, by issuer host.", points)
	return nil
}

// ownershipPoints turns a (has_owner, secondary) count map into gauge points.
func ownershipPoints(counts map[[2]string]int64, secondaryKey string) []telemetry.GaugePoint {
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrHasOwner: k[0], secondaryKey: k[1]},
		})
	}
	return points
}

func ownerUPNs(owners []directoryObject) []string {
	out := make([]string, 0, len(owners))
	for _, o := range owners {
		if o.UserPrincipalName != "" {
			out = append(out, o.UserPrincipalName)
		}
	}
	return out
}

// issuerHost reduces a FIC issuer URL to its host, the bounded dimension
// (token.actions.githubusercontent.com, sts.windows.net, a k8s OIDC host). An
// unparseable issuer collapses to "unknown" rather than becoming an unbounded
// label.
func issuerHost(issuer string) string {
	if issuer == "" {
		return "unknown"
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

func displayOr(name, fallback string) string {
	if name != "" {
		return name
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
