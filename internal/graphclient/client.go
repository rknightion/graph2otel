// Package graphclient builds per-tenant Microsoft Graph clients that run every
// call through graph2otel's own OTEL-instrumented HTTP transport while
// re-attaching Kiota's default middleware chain — critically the 429/503 retry
// handler.
//
// # Why the re-attach matters
//
// The msgraph-sdk-go request adapter installs Kiota's default middlewares
// (retry, redirect, compression, parameters-name-decoding, user-agent,
// headers-inspection) ONLY when it is passed a nil *http.Client. Passing any
// custom client — which graph2otel must, to instrument the transport — silently
// drops that whole chain, including the retry handler, with no compensating
// backoff anywhere. That is the latent bug in the closest prior art
// (cloudeteer/m365-exporter). This package re-attaches the default chain
// explicitly (see transport.go) so the retry behavior survives instrumentation.
//
// The default retry handler honors Retry-After when present and covers the
// directory workload's throttling. It is NOT sufficient for the reporting and
// Identity-Protection workloads, which return 429 with NO Retry-After — those
// need the client-side per-workload rate limiters + own backoff added in #5,
// layered onto this transport.
package graphclient

import (
	"context"
	"fmt"

	"net/http"

	azureauth "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// defaultValidHosts is the allow-list of hosts the auth provider will attach a
// token to. Restricting it prevents a redirected request from leaking the Graph
// bearer token to an unexpected host.
var defaultValidHosts = []string{"graph.microsoft.com"}

// Options configures a Graph client.
type Options struct {
	// Emitter records the outbound-HTTP instrumentation metric. Nil disables
	// instrumentation (the transport still works).
	Emitter telemetry.Emitter
	// ValidHosts overrides the token-attachment host allow-list (default
	// {"graph.microsoft.com"}).
	ValidHosts []string
	// RetryDelaySeconds overrides the retry handler's backoff (0 = Kiota default
	// of 3s). Primarily a test seam to keep the 429-retry test fast.
	RetryDelaySeconds int
	// MaxRetries overrides the retry handler's attempt cap (0 = Kiota default of 3).
	MaxRetries int

	// baseTransport overrides the base RoundTripper under the middleware pipeline
	// (test seam; nil = http.DefaultTransport).
	baseTransport http.RoundTripper
}

// Client wraps a per-tenant GraphServiceClient plus the shared instrumented,
// retrying HTTP client it runs on (reused by the raw-REST escape hatch for beta
// endpoints).
type Client struct {
	// Graph is the typed msgraph-sdk-go client for v1.0 endpoints.
	Graph *msgraphsdk.GraphServiceClient
	// TenantID identifies which tenant this client authenticates against.
	TenantID string

	httpClient *http.Client
	cred       tokenCredential
}

// NewClient builds a Graph client for one tenant from its credential (#3). It
// wires the AzureIdentity auth provider (scope https://graph.microsoft.com/.default)
// to a request adapter built on our instrumented+retrying transport, so every
// SDK call is measured and retried. Construction performs no network I/O.
func NewClient(_ context.Context, ta *auth.TenantAuth, opts Options) (*Client, error) {
	if ta == nil {
		return nil, fmt.Errorf("graphclient: nil TenantAuth")
	}
	hosts := opts.ValidHosts
	if len(hosts) == 0 {
		hosts = defaultValidHosts
	}

	authProvider, err := azureauth.NewAzureIdentityAuthenticationProviderWithScopesAndValidHosts(
		ta.Cred, []string{auth.GraphDefaultScope}, hosts)
	if err != nil {
		return nil, fmt.Errorf("graphclient: tenant %q: auth provider: %w", ta.TenantID, err)
	}

	httpClient := newGraphHTTPClient(opts)

	// nil parse-node/serialization factories -> the adapter registers Graph's
	// default JSON (de)serializers. Passing our own httpClient is what forces the
	// re-attach handled in transport.go.
	adapter, err := msgraphsdk.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		authProvider, nil, nil, httpClient)
	if err != nil {
		return nil, fmt.Errorf("graphclient: tenant %q: request adapter: %w", ta.TenantID, err)
	}

	return &Client{
		Graph:      msgraphsdk.NewGraphServiceClient(adapter),
		TenantID:   ta.TenantID,
		httpClient: httpClient,
		cred:       ta.Cred,
	}, nil
}
