// Command graphdrift is graph2otel's Microsoft Graph *beta* drift canary.
//
// It fetches the live beta CSDL ($metadata, anonymous — no credentials), slices
// it down to the operations spec/graph-beta-surface.json says graph2otel
// consumes, and diffs that slice against spec/graph-beta-snapshot.json.
//
//	graphdrift                 # diff live beta metadata against the snapshot
//	graphdrift -update         # refresh the snapshot from live metadata
//	graphdrift -metadata f.xml # use a local CSDL file instead of fetching
//
// Exit codes: 0 = no actionable drift (clean, or additions only); 3 = breaking
// drift on a consumed operation; 2 = usage/IO error.
//
// Graph v1.0 is deliberately out of scope: it is a versioned, contractually
// stable surface, so drift value concentrates on beta. See docs/api-drift.md.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	exitDrift   = 3
	exitFailure = 2
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "graphdrift:", err)
	}
	os.Exit(code)
}

// run is main's testable body: it returns the process exit code, and an error
// for usage/IO problems.
func run(args []string, out io.Writer) (int, error) {
	fs := newFlagSet()
	if err := fs.parse(args); err != nil {
		return exitFailure, err
	}

	manifestBytes, err := os.ReadFile(fs.manifest)
	if err != nil {
		return exitFailure, fmt.Errorf("read manifest: %w", err)
	}
	man, err := ParseManifest(manifestBytes)
	if err != nil {
		return exitFailure, err
	}

	csdl, err := loadCSDL(fs, man.MetadataURL)
	if err != nil {
		return exitFailure, err
	}
	model, err := ParseCSDL(csdl)
	closeErr := csdl.Close()
	if err != nil {
		return exitFailure, err
	}
	if closeErr != nil {
		return exitFailure, fmt.Errorf("close metadata source: %w", closeErr)
	}

	built := BuildSnapshot(man, model)

	if fs.update {
		b, err := MarshalSnapshot(built)
		if err != nil {
			return exitFailure, err
		}
		if err := os.WriteFile(fs.snapshot, b, 0o644); err != nil {
			return exitFailure, fmt.Errorf("write snapshot: %w", err)
		}
		fmt.Fprintf(out, "wrote %s (%d operations, %d types, %d bytes)\n",
			fs.snapshot, len(built.Operations), len(built.Types), len(b))
		return 0, nil
	}

	committedBytes, err := os.ReadFile(fs.snapshot)
	if err != nil {
		return exitFailure, fmt.Errorf("read snapshot: %w", err)
	}
	committed, err := ParseSnapshot(committedBytes)
	if err != nil {
		return exitFailure, err
	}

	changes := Diff(committed, built)
	if err := render(out, fs.format, changes); err != nil {
		return exitFailure, err
	}
	if HasActionable(changes) {
		return exitDrift, nil
	}
	return 0, nil
}

func render(out io.Writer, format string, changes []Change) error {
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if changes == nil {
			changes = []Change{}
		}
		if err := enc.Encode(changes); err != nil {
			return fmt.Errorf("render json: %w", err)
		}
	case "md":
		fmt.Fprint(out, RenderMarkdown(changes))
	default:
		return fmt.Errorf("unknown -format %q (want md or json)", format)
	}
	return nil
}

// loadCSDL opens the metadata source: a local file when -metadata is set,
// otherwise an anonymous GET of the manifest's metadata_url. The beta
// $metadata document is served without authentication (live-verified), so the
// canary needs no tenant credentials in CI.
func loadCSDL(fs *flags, url string) (io.ReadCloser, error) {
	if fs.metadata != "" {
		f, err := os.Open(fs.metadata)
		if err != nil {
			return nil, fmt.Errorf("open -metadata: %w", err)
		}
		return f, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
