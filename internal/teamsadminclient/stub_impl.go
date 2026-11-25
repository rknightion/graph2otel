package teamsadminclient

// STUB (#719): the implementation lane replaces this file.

import (
	"context"
	"errors"

	"github.com/rknightion/graph2otel/internal/auth"
)

type client struct{}

var errStub = errors.New("teamsadminclient: not implemented")

func newClient(*auth.TenantAuth, Options) (*Client, error) { return &Client{impl: &client{}}, nil }
func (*client) configurations(context.Context, string) ([]map[string]any, error) {
	return nil, errStub
}
func (*client) voiceApps(context.Context, VoiceAppKind) (VoiceAppsResult, error) {
	return VoiceAppsResult{}, errStub
}
func isPermission(error) bool { return false }
func (e *APIError) Error() string { return "teams admin API error" }
