package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readProjectDoc(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func TestOperatorEntryPointsDescribeTheShippedV1Surface(t *testing.T) {
	stale := map[string][]string{
		"../../README.md": {
			"Status:** pre-1.0",
			"`v0.1.0`",
			"once it lands",
			"remaining categories below are the roadmap",
			"Open, pending live-verify",
		},
		"../../docs/getting-started.md": {
			"Pre-1.0 and pre-first-release",
			"A Helm chart is planned but not published yet",
		},
		"../../CLAUDE.md": {
			"The only open issue is #78",
			"Helm defaults and the compose reference mount one",
		},
	}
	for path, phrases := range stale {
		body := readProjectDoc(t, path)
		for _, phrase := range phrases {
			if strings.Contains(body, phrase) {
				t.Errorf("%s still contains stale shipped-v1 claim %q", path, phrase)
			}
		}
	}
}

func TestOperatorDocsReflectTheCanonicalCollectorCensus(t *testing.T) {
	candidates := availabilityCandidates()
	logical := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		logical[candidate.Name] = struct{}{}
	}

	for _, path := range []string{
		"../../README.md",
		"../../docs/index.md",
		"../../docs/configuration.md",
		"../../docs/signals.md",
		"../../docs/architecture.md",
	} {
		body := readProjectDoc(t, path)
		want := fmt.Sprintf("%d logical collectors", len(logical))
		if !strings.Contains(body, want) {
			t.Errorf("%s missing drift-gated collector census %q", path, want)
		}
	}

	pathCount := reflect.TypeOf((*collectorFactoryVisitor)(nil)).Elem().NumMethod()
	for _, path := range []string{
		"../../CLAUDE.md",
		"../../docs/index.md",
		"../../docs/configuration.md",
		"../../docs/signals.md",
		"../../docs/architecture.md",
	} {
		body := readProjectDoc(t, path)
		want := fmt.Sprintf("%d registration paths", pathCount)
		if !strings.Contains(body, want) {
			t.Errorf("%s missing drift-gated registration-path count %q", path, want)
		}
	}

	architecture := readProjectDoc(t, "../../docs/architecture.md")
	wantCandidates := fmt.Sprintf("%d registration-path candidates", len(candidates))
	if !strings.Contains(architecture, wantCandidates) {
		t.Errorf("docs/architecture.md missing drift-gated architecture fact %q", wantCandidates)
	}

	pipelineDirs, err := filepath.Glob("../../internal/*pipeline")
	if err != nil {
		t.Fatalf("list ingest-engine packages: %v", err)
	}
	engineCount := 0
	for _, path := range pipelineDirs {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		if info.IsDir() {
			engineCount++
		}
	}
	for _, path := range []string{
		"../../CLAUDE.md",
		"../../docs/index.md",
		"../../docs/configuration.md",
		"../../docs/architecture.md",
	} {
		body := readProjectDoc(t, path)
		want := fmt.Sprintf("%d ingest engine shapes", engineCount)
		if !strings.Contains(body, want) {
			t.Errorf("%s missing source-derived engine count %q", path, want)
		}
	}

	signals := readProjectDoc(t, "../../docs/signals.md")
	if !strings.Contains(signals, wantCandidates) {
		t.Errorf("docs/signals.md missing drift-gated registration census %q", wantCandidates)
	}
}

func TestArchitectureDocumentsCurrentTransportSeams(t *testing.T) {
	architecture := readProjectDoc(t, "../../docs/architecture.md")
	for _, want := range []string{
		"Raw REST",
		"internal/license/graphclient_adapter.go",
		"internal/logpipeline",
		"internal/jobpipeline",
		"internal/blobpipeline",
		"internal/o365pipeline",
		"Snapshot",
		"Window",
		"Blob",
		"O365",
		"MDCA",
		"EXO",
		"Hunt",
	} {
		if !strings.Contains(architecture, want) {
			t.Errorf("docs/architecture.md missing current seam %q", want)
		}
	}
	for _, stale := range []string{"Kiota client", "Wraps `msgraph-sdk-go`"} {
		if strings.Contains(architecture, stale) {
			t.Errorf("docs/architecture.md retains obsolete SDK claim %q", stale)
		}
	}
}

func TestDocsSiteNavigationIncludesShippedIngestAndGeneratedReferences(t *testing.T) {
	nav := readProjectDoc(t, "../../zensical.toml")
	for _, page := range []string{
		"collectors.md",
		"env-vars.md",
		"blob-ingest.md",
		"o365-management-api.md",
		"deploying-observability.md",
		// Every generated alert rule carries a runbook_url pointing at this page
		// (#307). If the nav drops it the page stops being published and every
		// runbook link 404s — silently, from the operator's point of view, at the
		// exact moment they are following one.
		"runbooks.md",
		// The hunting library (#313) is where every paused detection's
		// tuning_required measurement is actually taken, and the runbooks deep-link
		// into it. An orphaned page here means a rule tells an operator to make a
		// measurement whose query is unpublished.
		"hunting.md",
	} {
		if !strings.Contains(nav, page) {
			t.Errorf("zensical navigation omits shipped reference %q", page)
		}
	}
}

func TestEvidenceBackedReferencesDoNotRegressToSupersededClaims(t *testing.T) {
	stale := map[string][]string{
		"../../internal/collectordoc/annotations.go": {
			"grant-blocked piece",
		},
		"../../internal/collectors/entra/gsa/gsa.go": {
			"traffic-logs half of #239 is grant-blocked",
		},
		"../../docs/graph-api-gotchas.md": {
			"traffic`) still 403",
			"needs a `NetworkAccess.Read.All`",
		},
		"../../docs/collectors.md": {
			"grant-blocked piece",
			"~2.3%",
		},
		"../../docs/o365-management-api.md": {
			"## Open items",
			"current residual list",
		},
		"../../internal/semconv/attrs.go": {
			"all 58 collectors",
		},
		"../../cmd/graph2otel/tenants.go": {
			"all 58 collectors",
		},
		"../../internal/collectordoc/collectordoc.go": {
			"If a fifth construction path is ever added",
		},
		"../../internal/o365pipeline/o365pipeline.go": {
			"measured ~2.3%",
		},
		"../../internal/collectors/entra/signins/blob.go": {
			"AT-LEAST-ONCE (~2.3%",
			"records arrive twice",
		},
		"../../scripts/regen-generated.sh": {
			"All four are generated",
			"collectors.All + WindowAll + BlobAll + O365All",
			"Helm chart docs/schema are NOT yet wired here",
		},
	}
	for path, phrases := range stale {
		body := readProjectDoc(t, path)
		for _, phrase := range phrases {
			if strings.Contains(body, phrase) {
				t.Errorf("%s retains superseded evidence claim %q", path, phrase)
			}
		}
	}

	current := map[string][]string{
		"../../docs/graph-api-gotchas.md": {
			"data-blocked",
			"200",
			"empty",
		},
		"../../docs/collectors.md": {
			"2.7–4%",
			"multiplicity reaches ×4",
		},
		"../../docs/o365-management-api.md": {
			"All four #100 residuals are discharged",
		},
	}
	for path, phrases := range current {
		body := readProjectDoc(t, path)
		for _, phrase := range phrases {
			if !strings.Contains(body, phrase) {
				t.Errorf("%s missing current evidence claim %q", path, phrase)
			}
		}
	}
}

func TestPublishedHelmInstallEnablesPersistentCheckpoints(t *testing.T) {
	for _, path := range []string{
		"../../charts/graph2otel/README.md.gotmpl",
		"../../charts/graph2otel/README.md",
	} {
		body := readProjectDoc(t, path)
		if !strings.Contains(body, `--set persistence.enabled=true`) {
			t.Errorf("%s published install omits persistent checkpoint storage", path)
		}
	}
}
