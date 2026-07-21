package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes a manifest and a CSDL document into a temp dir and returns the
// flag arguments that point the tool at them.
func fixture(t *testing.T) (dir string, args []string) {
	t.Helper()
	dir = t.TempDir()
	manifest := filepath.Join(dir, "surface.json")
	metadata := filepath.Join(dir, "metadata.xml")
	snapshot := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(manifest, []byte(testManifestJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte(testCSDL), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, []string{"-manifest", manifest, "-metadata", metadata, "-snapshot", snapshot}
}

func TestRunUpdateThenCleanDiff(t *testing.T) {
	_, args := fixture(t)

	var out bytes.Buffer
	code, err := run(append(args, "-update"), &out)
	if err != nil || code != 0 {
		t.Fatalf("run -update = (%d, %v)", code, err)
	}
	if !strings.Contains(out.String(), "wrote ") {
		t.Errorf("-update output = %q", out.String())
	}

	out.Reset()
	code, err = run(args, &out)
	if err != nil || code != 0 {
		t.Fatalf("run = (%d, %v), want a clean exit against the snapshot it just wrote", code, err)
	}
	if !strings.Contains(out.String(), "No drift") {
		t.Errorf("clean diff output = %q", out.String())
	}
}

func TestRunExitsThreeOnBreakingDrift(t *testing.T) {
	dir, args := fixture(t)

	var out bytes.Buffer
	if code, err := run(append(args, "-update"), &out); err != nil || code != 0 {
		t.Fatalf("run -update = (%d, %v)", code, err)
	}

	// Drop a property the collector decodes from the "live" document.
	stripped := strings.Replace(testCSDL, `<Property Name="createdDateTime" Type="Edm.DateTimeOffset" />`, "", 1)
	if stripped == testCSDL {
		t.Fatal("fixture edit did not apply")
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.xml"), []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	code, err := run(args, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitDrift {
		t.Errorf("exit code = %d, want %d on breaking drift", code, exitDrift)
	}
	if !strings.Contains(out.String(), "property_removed") || !strings.Contains(out.String(), "createdDateTime") {
		t.Errorf("drift report does not name the removed property:\n%s", out.String())
	}
}

func TestRunExitsZeroOnAdditiveDrift(t *testing.T) {
	dir, args := fixture(t)

	var out bytes.Buffer
	if code, err := run(append(args, "-update"), &out); err != nil || code != 0 {
		t.Fatalf("run -update = (%d, %v)", code, err)
	}

	grown := strings.Replace(testCSDL,
		`<Property Name="createdDateTime" Type="Edm.DateTimeOffset" />`,
		`<Property Name="createdDateTime" Type="Edm.DateTimeOffset" /><Property Name="freshlyAdded" Type="Edm.String" />`, 1)
	if err := os.WriteFile(filepath.Join(dir, "metadata.xml"), []byte(grown), 0o600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	code, err := run(args, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0 — additive upstream churn must not fire the canary", code)
	}
	if !strings.Contains(out.String(), "property_added") {
		t.Errorf("additive change not reported:\n%s", out.String())
	}
}

func TestRunJSONFormat(t *testing.T) {
	_, args := fixture(t)
	var out bytes.Buffer
	if code, err := run(append(args, "-update"), &out); err != nil || code != 0 {
		t.Fatalf("run -update = (%d, %v)", code, err)
	}
	out.Reset()
	if code, err := run(append(args, "-format", "json"), &out); err != nil || code != 0 {
		t.Fatalf("run -format json = (%d, %v)", code, err)
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Errorf("json clean output = %q, want []", out.String())
	}
}

func TestRunRejectsUnknownFormat(t *testing.T) {
	_, args := fixture(t)
	var out bytes.Buffer
	if code, err := run(append(args, "-update"), &out); err != nil || code != 0 {
		t.Fatalf("run -update = (%d, %v)", code, err)
	}
	out.Reset()
	code, err := run(append(args, "-format", "yaml"), &out)
	if err == nil {
		t.Fatal("run accepted an unknown -format")
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d for a usage error", code, exitFailure)
	}
}

func TestRunMissingManifestIsAFailureNotDrift(t *testing.T) {
	var out bytes.Buffer
	code, err := run([]string{"-manifest", filepath.Join(t.TempDir(), "nope.json")}, &out)
	if err == nil {
		t.Fatal("run accepted a missing manifest")
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}
