// Package teamsadminclient is graph2otel's GET-only client for the Teams admin
// REST API behind the MicrosoftTeams PowerShell Get-Cs* cmdlets (#712). The wire
// facts it relies on are recorded in docs/teams-admin-api.md.
//
// SEAM FROZEN FOR PARALLEL LANES (#719): the exported names and signatures in
// this file are the contract internal/collectors and cmd/graph2otel build on.
// The implementation lane may move them between files but must not change them.
package teamsadminclient

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// DefaultBaseURL is the commercial-cloud Teams admin API host.
	DefaultBaseURL = "https://api.interfaces.records.teams.microsoft.com"
	// DefaultScope is the "Skype and Teams Tenant Admin API" resource. It is
	// Microsoft's first-party application ID, not a secret.
	DefaultScope = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
)

// VoiceAppKind selects a Teams.VoiceApps collection.
type VoiceAppKind int

const (
	// AutoAttendants reads /Teams.VoiceApps/auto-attendants (object ID field "Id").
	AutoAttendants VoiceAppKind = iota + 1
	// CallQueues reads /Teams.VoiceApps/callqueues?FilterInvalidObos=False
	// (object ID field "Identity").
	CallQueues
)

// Diagnostic is one entry of a Teams.VoiceApps envelope's Diagnostics array.
// The wire carries no object reference.
type Diagnostic struct {
	Level   string
	Message string
}

// VoiceAppsResult is every object of one VoiceApps collection, across all pages.
type VoiceAppsResult struct {
	Records     []map[string]any
	Diagnostics []Diagnostic
}

// Options configures a Client. The zero value is usable.
type Options struct {
	Emitter      telemetry.Emitter
	BaseURL      string        // empty means DefaultBaseURL
	Scope        string        // empty means DefaultScope; never derived from BaseURL
	Limiter      *rate.Limiter // nil means DefaultLimiter()
	Timeout      time.Duration // per request; 0 means 30 s
	CallDeadline time.Duration // per VoiceApps call; 0 means 5 minutes
	Logger       *slog.Logger  // nil means slog.Default()
}

// APIError is a non-2xx response from the Teams admin API.
type APIError struct {
	StatusCode int
	Path       string
	Code       string
	Message    string
	ErrorCode  int
}

// ErrToken wraps a failure to acquire a token for DefaultScope.
var ErrToken = errors.New("teams admin API token acquisition failed")

// Client is a per-tenant Teams admin API client, safe for concurrent use.
type Client struct {
	impl *client
}

// NewClient builds a Client for one tenant. It performs no network I/O.
func NewClient(ta *auth.TenantAuth, opts Options) (*Client, error) { return newClient(ta, opts) }

// Configurations GETs /Skype.Policy/configurations/{name}, which must be a JSON array.
func (c *Client) Configurations(ctx context.Context, name string) ([]map[string]any, error) {
	return c.impl.configurations(ctx, name)
}

// VoiceApps GETs every page of one Teams.VoiceApps collection.
func (c *Client) VoiceApps(ctx context.Context, kind VoiceAppKind) (VoiceAppsResult, error) {
	return c.impl.voiceApps(ctx, kind)
}

// IsPermission reports whether err is an HTTP 403 from the Teams admin API.
func IsPermission(err error) bool { return isPermission(err) }
