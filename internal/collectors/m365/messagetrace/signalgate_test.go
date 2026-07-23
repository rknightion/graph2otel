package messagetrace

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit. It matters
// more here than almost anywhere else in the tree: this collector sees one
// record per message per recipient, so a single per-message metric label —
// recipient, sender, subject, message id — is one series per message and the
// bill scales with mail traffic rather than with tenant size.
func TestMain(m *testing.M) { signalcapture.Main(m) }
