package networkaccesstraffic

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit. This
// collector is log-only, so the gate's job here is to catch a metric appearing
// at all: every field it reads is per-connection (user, device, destination
// FQDN, policy rule) and a series keyed by any of them would grow with traffic
// at ~88,700 records/day from a single client. See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
