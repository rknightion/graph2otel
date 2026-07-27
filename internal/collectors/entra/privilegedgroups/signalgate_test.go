package privilegedgroups

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestMain captures what this package emits, which feeds both the #112
// per-entity-label gate and the generated collector reference (#140).
//
// It matters more here than almost anywhere else: this is the ONE collector
// that deliberately puts a group_id on a metric label, so the capture is the
// standing record of exactly which labels that exception covers. group_id is
// bounded by the operator's allowlist, not by tenant size; nothing else
// per-entity may join it.
func TestMain(m *testing.M) { signalcapture.Main(m) }
