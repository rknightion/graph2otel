package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Model is the parsed OData EDM (CSDL) document, reduced to the pieces this
// canary reasons about: named types, the service container's roots, and bound
// operations. Everything else in $metadata — annotations, key definitions,
// navigation property bindings, referential constraints — is deliberately
// dropped: it churns constantly upstream and none of it changes how a
// collector's JSON decodes.
type Model struct {
	// Types is keyed by fully-qualified name (alias-expanded).
	Types map[string]*NamedType
	// Roots maps an EntityContainer child name (entity set or singleton) to
	// the fully-qualified type it exposes.
	Roots map[string]string

	aliases map[string]string
	bound   map[string][]boundOp
}

// NamedType is one EntityType, ComplexType or EnumType. Property and
// navigation-property type references keep their Collection(...) wrapper, since
// a single-valued property becoming a collection breaks a decoder just as hard
// as a rename.
type NamedType struct {
	Name                 string            `json:"-"`
	Kind                 string            `json:"kind"`
	BaseType             string            `json:"base_type,omitempty"`
	Properties           map[string]string `json:"properties,omitempty"`
	NavigationProperties map[string]string `json:"navigation_properties,omitempty"`
	Members              []string          `json:"members,omitempty"`
}

type boundOp struct {
	binding string // fully-qualified element type of the binding parameter
	returns string // fully-qualified element type of the return type
}

// ---- raw XML shapes ----------------------------------------------------

type xEdmx struct {
	Schemas []xSchema `xml:"DataServices>Schema"`
}

type xSchema struct {
	Namespace  string       `xml:"Namespace,attr"`
	Alias      string       `xml:"Alias,attr"`
	EntityType []xType      `xml:"EntityType"`
	Complex    []xType      `xml:"ComplexType"`
	Enum       []xEnum      `xml:"EnumType"`
	Functions  []xOperation `xml:"Function"`
	Actions    []xOperation `xml:"Action"`
	Containers []xContainer `xml:"EntityContainer"`
}

type xType struct {
	Name       string  `xml:"Name,attr"`
	BaseType   string  `xml:"BaseType,attr"`
	Properties []xProp `xml:"Property"`
	NavProps   []xProp `xml:"NavigationProperty"`
}

type xProp struct {
	Name string `xml:"Name,attr"`
	Type string `xml:"Type,attr"`
}

type xEnum struct {
	Name    string `xml:"Name,attr"`
	Members []struct {
		Name string `xml:"Name,attr"`
	} `xml:"Member"`
}

type xOperation struct {
	Name       string `xml:"Name,attr"`
	IsBound    string `xml:"IsBound,attr"`
	Parameters []struct {
		Name string `xml:"Name,attr"`
		Type string `xml:"Type,attr"`
	} `xml:"Parameter"`
	ReturnType struct {
		Type string `xml:"Type,attr"`
	} `xml:"ReturnType"`
}

type xContainer struct {
	EntitySets []struct {
		Name       string `xml:"Name,attr"`
		EntityType string `xml:"EntityType,attr"`
	} `xml:"EntitySet"`
	Singletons []struct {
		Name string `xml:"Name,attr"`
		Type string `xml:"Type,attr"`
	} `xml:"Singleton"`
}

// ---- parsing -----------------------------------------------------------

// ParseCSDL decodes a CSDL ($metadata) document into a Model.
func ParseCSDL(r io.Reader) (*Model, error) {
	var doc xEdmx
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode csdl: %w", err)
	}
	if len(doc.Schemas) == 0 {
		return nil, fmt.Errorf("decode csdl: no <Schema> elements")
	}

	m := &Model{
		Types:   make(map[string]*NamedType),
		Roots:   make(map[string]string),
		aliases: make(map[string]string),
		bound:   make(map[string][]boundOp),
	}

	// Aliases are document-scoped in CSDL, so they must all be collected
	// before any type reference is expanded. On the live beta document
	// "graph" aliases microsoft.graph and — the trap — "self" is a declared
	// alias for microsoft.graph.security, not a self-reference.
	for _, s := range doc.Schemas {
		if s.Alias != "" {
			m.aliases[s.Alias] = s.Namespace
		}
	}

	for _, s := range doc.Schemas {
		for _, t := range s.EntityType {
			m.addType(s.Namespace, "EntityType", t)
		}
		for _, t := range s.Complex {
			m.addType(s.Namespace, "ComplexType", t)
		}
		for _, e := range s.Enum {
			nt := &NamedType{Name: s.Namespace + "." + e.Name, Kind: "EnumType"}
			for _, mem := range e.Members {
				nt.Members = append(nt.Members, mem.Name)
			}
			sort.Strings(nt.Members)
			m.Types[nt.Name] = nt
		}
		for _, op := range append(append([]xOperation{}, s.Functions...), s.Actions...) {
			if op.IsBound != "true" || len(op.Parameters) == 0 {
				continue
			}
			m.bound[op.Name] = append(m.bound[op.Name], boundOp{
				binding: ElementType(m.Qualify(op.Parameters[0].Type)),
				returns: ElementType(m.Qualify(op.ReturnType.Type)),
			})
		}
		for _, c := range s.Containers {
			for _, es := range c.EntitySets {
				m.Roots[es.Name] = ElementType(m.Qualify(es.EntityType))
			}
			for _, sg := range c.Singletons {
				m.Roots[sg.Name] = ElementType(m.Qualify(sg.Type))
			}
		}
	}
	return m, nil
}

func (m *Model) addType(ns, kind string, t xType) {
	nt := &NamedType{
		Name:     ns + "." + t.Name,
		Kind:     kind,
		BaseType: ElementType(m.Qualify(t.BaseType)),
	}
	for _, p := range t.Properties {
		if nt.Properties == nil {
			nt.Properties = make(map[string]string)
		}
		nt.Properties[p.Name] = m.Qualify(p.Type)
	}
	for _, p := range t.NavProps {
		if nt.NavigationProperties == nil {
			nt.NavigationProperties = make(map[string]string)
		}
		nt.NavigationProperties[p.Name] = m.Qualify(p.Type)
	}
	m.Types[nt.Name] = nt
}

// Lookup returns the named type for a fully-qualified name.
func (m *Model) Lookup(fq string) (*NamedType, bool) {
	nt, ok := m.Types[fq]
	return nt, ok
}

// Qualify expands a namespace alias in a type reference, preserving any
// Collection(...) wrapper. Edm.* primitives and already-qualified references
// pass through unchanged.
func (m *Model) Qualify(ref string) string {
	if ref == "" {
		return ""
	}
	inner, wrapped := strings.CutPrefix(ref, "Collection(")
	if wrapped {
		inner = strings.TrimSuffix(inner, ")")
	}
	if i := strings.LastIndex(inner, "."); i > 0 {
		if ns, ok := m.aliases[inner[:i]]; ok {
			inner = ns + inner[i:]
		}
	}
	if wrapped {
		return "Collection(" + inner + ")"
	}
	return inner
}

// ElementType strips a Collection(...) wrapper.
func ElementType(ref string) string {
	if inner, ok := strings.CutPrefix(ref, "Collection("); ok {
		return strings.TrimSuffix(inner, ")")
	}
	return ref
}

// navigationProperty looks up a navigation property on fq, walking the base
// type chain (Graph models most navigation on derived types but some on bases).
func (m *Model) navigationProperty(fq, name string) (string, bool) {
	seen := map[string]bool{}
	for fq != "" && !seen[fq] {
		seen[fq] = true
		nt, ok := m.Lookup(fq)
		if !ok {
			return "", false
		}
		if ref, ok := nt.NavigationProperties[name]; ok {
			return ref, true
		}
		fq = nt.BaseType
	}
	return "", false
}

// ResolvePath walks an API path (no /beta prefix, no host) through the EDM and
// returns the fully-qualified type of its final segment.
//
// Segment handling: the first segment is an EntityContainer entity set or
// singleton; "{...}" is a key segment and is skipped; a segment containing a
// "." is a derived-type cast; otherwise it is a navigation property, and
// failing that a bound function or action whose binding parameter matches the
// current type. A "?..." query string is ignored.
func (m *Model) ResolvePath(path string) (string, error) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	var segs []string
	for _, s := range strings.Split(strings.Trim(path, "/"), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return "", fmt.Errorf("empty path")
	}

	cur, ok := m.Roots[segs[0]]
	if !ok {
		return "", fmt.Errorf("%q is not an entity set or singleton on the service container", segs[0])
	}
	for _, s := range segs[1:] {
		switch {
		case strings.HasPrefix(s, "{"):
			// key segment — the type is unchanged
		case strings.Contains(s, "."):
			cast := m.Qualify(s)
			if _, ok := m.Lookup(cast); !ok {
				return "", fmt.Errorf("cast segment %q resolves to unknown type %q", s, cast)
			}
			cur = cast
		default:
			if ref, ok := m.navigationProperty(cur, s); ok {
				cur = ElementType(ref)
				continue
			}
			if next, ok := m.boundReturn(cur, s); ok {
				cur = next
				continue
			}
			return "", fmt.Errorf("segment %q is neither a navigation property nor a bound operation on %s", s, cur)
		}
	}
	return cur, nil
}

// boundReturn resolves a bound function/action segment against the current type.
func (m *Model) boundReturn(cur, name string) (string, bool) {
	for _, op := range m.bound[name] {
		if op.binding == cur && op.returns != "" {
			return op.returns, true
		}
	}
	return "", false
}
