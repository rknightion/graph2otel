package main

import (
	"os"
	"strings"
	"testing"
)

func TestDockerfileCopiesLocalReplacementManifestsBeforeModuleDownload(t *testing.T) {
	raw, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerfile := string(raw)
	downloadAt := strings.Index(dockerfile, "RUN go mod download")
	if downloadAt < 0 {
		t.Fatal("Dockerfile has no go mod download layer")
	}

	for _, manifest := range []string{
		"third_party/otlploghttp/go.mod",
		"third_party/otlpmetrichttp/go.mod",
	} {
		copyAt := strings.Index(dockerfile, manifest)
		if copyAt < 0 {
			t.Errorf("Dockerfile does not copy local replacement manifest %q", manifest)
			continue
		}
		if copyAt > downloadAt {
			t.Errorf("Dockerfile copies %q after go mod download; local replace resolution fails in the build layer", manifest)
		}
	}
}
