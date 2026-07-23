package tenantpolicy

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 (no per-entity metric label) and #164 (golden not
// thin) over everything this package's tests emit. See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
