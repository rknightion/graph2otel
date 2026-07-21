package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Snapshot is the committed slice of the beta EDM: the type each consumed
// operation resolves to, plus the definition of every type in that closure.
//
// It deliberately does NOT record the service's schema version, generation
// timestamp, or anything else that moves without the contract moving — the
// whole file must stay byte-identical across days when nothing graph2otel
// consumes has changed, or the canary cries wolf daily and gets ignored.
type Snapshot struct {
	Source     string                `json:"source"`
	Operations []OperationSnapshot   `json:"operations"`
	Types      map[string]*NamedType `json:"types"`
}

// OperationSnapshot binds one consumed path to the type it lands on.
type OperationSnapshot struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
	// Resolution is "model" (walked through the EDM) or "unmodeled" (declared
	// in the manifest because the EDM has no binding for this path).
	Resolution string `json:"resolution"`
	// Error records why a modeled path failed to resolve. A failure is drift,
	// not a tool error, so it is recorded rather than raised.
	Error string `json:"error,omitempty"`
}

// BuildSnapshot slices the model down to the manifest's operations.
//
// The type closure is the resolved type, its base-type chain, and the
// complex/enum types its own properties reference (one hop) with their base
// chains. Navigation targets are NOT followed: a navigation property a
// collector actually requests is its own manifest entry, and following them
// blindly pulls in most of the 5,800-type document.
func BuildSnapshot(man *Manifest, m *Model) *Snapshot {
	snap := &Snapshot{
		Source: man.MetadataURL,
		Types:  map[string]*NamedType{},
	}
	for _, op := range man.Operations() {
		entry := OperationSnapshot{Path: op.Path}
		switch {
		case op.Unmodeled:
			entry.Resolution = "unmodeled"
			entry.Type = op.Type
			if _, ok := m.Lookup(op.Type); !ok {
				entry.Error = fmt.Sprintf("declared type %s is not in the EDM", op.Type)
			}
		default:
			entry.Resolution = "model"
			path := op.Path
			if op.ResolveAs != "" {
				path = op.ResolveAs
			}
			fq, err := m.ResolvePath(path)
			if err != nil {
				entry.Error = err.Error()
			} else {
				entry.Type = fq
			}
		}
		if entry.Type != "" {
			addClosure(snap.Types, m, entry.Type)
		}
		snap.Operations = append(snap.Operations, entry)
	}
	return snap
}

// addClosure adds fq, its base chain, and the named types its own properties
// reference (with their base chains) to dst.
func addClosure(dst map[string]*NamedType, m *Model, fq string) {
	for _, name := range baseChain(m, fq) {
		nt, ok := m.Lookup(name)
		if !ok {
			continue
		}
		dst[name] = nt
		for _, ref := range nt.Properties {
			elem := ElementType(ref)
			if strings.HasPrefix(elem, "Edm.") {
				continue
			}
			for _, refName := range baseChain(m, elem) {
				if rt, ok := m.Lookup(refName); ok {
					dst[refName] = rt
				}
			}
		}
	}
}

// baseChain returns fq followed by its base types, outermost first.
func baseChain(m *Model, fq string) []string {
	var out []string
	seen := map[string]bool{}
	for fq != "" && !seen[fq] {
		seen[fq] = true
		out = append(out, fq)
		nt, ok := m.Lookup(fq)
		if !ok {
			break
		}
		fq = nt.BaseType
	}
	return out
}

// MarshalSnapshot renders a snapshot as the committed artifact: indented JSON,
// map keys sorted by encoding/json, trailing newline.
func MarshalSnapshot(s *Snapshot) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseSnapshot decodes a committed snapshot.
func ParseSnapshot(b []byte) (*Snapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &s, nil
}
