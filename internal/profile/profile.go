// Package profile defines the collector profiles shared by configuration and registry metadata.
package profile

// Set describes collector membership independently of transport.
type Set uint8

const (
	// Graph preserves the original collector roster, including non-Graph transports.
	Graph Set = 1 << iota
	// Teams selects collectors for a Teams-focused deployment.
	Teams
)

// Parse returns the bit for a single configuration token, or zero for an unknown token.
func Parse(name string) Set {
	switch name {
	case "graph":
		return Graph
	case "teams":
		return Teams
	default:
		return 0
	}
}

// Names returns the canonical names in documentation order.
func (s Set) Names() []string {
	var names []string
	if s&Graph != 0 {
		names = append(names, "graph")
	}
	if s&Teams != 0 {
		names = append(names, "teams")
	}
	return names
}
