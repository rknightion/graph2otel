package license

import (
	"flag"
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite testdata/signals.json")

func TestSignalGolden(t *testing.T) {
	t.Parallel()

	rec := telemetrytest.New()
	EmitLicenseTier(rec.Emitter(), "capture-tenant", Capabilities{
		CapEntraP1: true,
		CapIntune:  true,
	})

	if err := signalcapture.GoldenAt("testdata/signals.json", *updateSignalGolden, rec); err != nil {
		t.Fatal(err)
	}
}
