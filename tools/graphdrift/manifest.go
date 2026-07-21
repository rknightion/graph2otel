package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Manifest is the hand-maintained record of the Microsoft Graph *beta* surface
// graph2otel consumes: one entry per Go package that talks to the beta service
// root, listing the paths it requests.
//
// It is the canary's input, and it is code-verified from the other side —
// internal/collectordoc's TestBetaSurfaceManifestCoversEveryBetaConsumer fails
// when a package builds a beta URL and is not listed here, so the canary cannot
// silently stop watching something.
type Manifest struct {
	MetadataURL string            `json:"metadata_url"`
	Note        string            `json:"note,omitempty"`
	Packages    []ManifestPackage `json:"packages"`
}

// ManifestPackage is one beta-consuming Go package, by repo-relative path.
type ManifestPackage struct {
	Package    string      `json:"package"`
	Collectors []string    `json:"collectors"`
	Operations []Operation `json:"operations"`
}

// Operation is one path a collector requests against the beta service root,
// written without the "/beta" prefix and with "{id}" for key segments.
type Operation struct {
	Path string `json:"path"`
	// ResolveAs is the equivalent path the EDM *can* walk, for the cases where
	// the wire path takes a shortcut the model does not describe — an implicit
	// derived-type segment, or a literal alternate key where the model wants a
	// key segment. Set it only when the two genuinely differ.
	ResolveAs string `json:"resolve_as,omitempty"`
	// Unmodeled marks a path that works on the wire but has no EDM binding at
	// all. Requires Type (the type whose shape the collector decodes, so the
	// canary still watches it) and Note (the evidence).
	Unmodeled bool   `json:"unmodeled,omitempty"`
	Type      string `json:"type,omitempty"`
	Note      string `json:"note,omitempty"`
}

// ParseManifest decodes and validates the manifest document. Unknown fields are
// rejected: the tool and the main module's coverage test decode the same file
// independently, and a field only one of them knows about is a silent hole.
func ParseManifest(b []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var man Manifest
	if err := dec.Decode(&man); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := man.validate(); err != nil {
		return nil, err
	}
	return &man, nil
}

func (m *Manifest) validate() error {
	if m.MetadataURL == "" {
		return fmt.Errorf("manifest: metadata_url is required")
	}
	if len(m.Packages) == 0 {
		return fmt.Errorf("manifest: no packages")
	}
	seenPkg := map[string]bool{}
	seenPath := map[string]Operation{}
	for _, p := range m.Packages {
		if p.Package == "" {
			return fmt.Errorf("manifest: a package entry has no package path")
		}
		if seenPkg[p.Package] {
			return fmt.Errorf("manifest: package %s listed twice", p.Package)
		}
		seenPkg[p.Package] = true
		if len(p.Collectors) == 0 {
			return fmt.Errorf("manifest: package %s names no collectors", p.Package)
		}
		if len(p.Operations) == 0 {
			return fmt.Errorf("manifest: package %s has no operations", p.Package)
		}
		for _, op := range p.Operations {
			if !strings.HasPrefix(op.Path, "/") {
				return fmt.Errorf("manifest: %s: path %q must start with /", p.Package, op.Path)
			}
			switch {
			case op.Unmodeled:
				if op.Type == "" {
					return fmt.Errorf("manifest: %s: unmodeled path %q needs the type it decodes", p.Package, op.Path)
				}
				if op.Note == "" {
					return fmt.Errorf("manifest: %s: unmodeled path %q needs a note recording the evidence", p.Package, op.Path)
				}
				if op.ResolveAs != "" {
					return fmt.Errorf("manifest: %s: path %q is unmodeled, so resolve_as means nothing", p.Package, op.Path)
				}
			case op.Type != "":
				return fmt.Errorf("manifest: %s: path %q is modeled, so its type is resolved from the EDM, not declared", p.Package, op.Path)
			}
			if prev, ok := seenPath[op.Path]; ok && prev != op {
				return fmt.Errorf("manifest: path %q is declared twice with different settings", op.Path)
			}
			seenPath[op.Path] = op
		}
	}
	return nil
}

// Operations returns every distinct operation across all packages, sorted by
// path. Two packages requesting the same path is normal (several Intune
// collectors share deviceHealthScripts); the canary watches it once.
func (m *Manifest) Operations() []Operation {
	seen := map[string]Operation{}
	for _, p := range m.Packages {
		for _, op := range p.Operations {
			seen[op.Path] = op
		}
	}
	out := make([]Operation, 0, len(seen))
	for _, op := range seen {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
