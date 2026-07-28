package directoryrecovery

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain enforces #112 over everything this package's tests emit: no metric
// label may carry per-entity data. The only metric label here is the job
// status — a bounded EDM enum — while snapshot and job ids, timestamps and
// change counts stay on the log twins. See internal/signalcapture.
func TestMain(m *testing.M) { signalcapture.Main(m) }
