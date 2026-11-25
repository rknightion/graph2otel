// Package adminmap holds the mapping helpers every teams_admin collector shares
// (#712): the twin change hash, integer enum mapping with wirecheck reporting,
// capped ID lists and the attribute naming rule.
//
// SEAM FROZEN FOR PARALLEL LANES (#719): exported names and signatures are the
// contract; the implementation lane fills the bodies.
package adminmap

import (
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// HashVersion is exported as config_hash_version; bump it when the exported
// attribute set of any teams_admin twin changes.
const HashVersion = 1

// MaxIDs is the cap on an exported string list.
const MaxIDs = 100

// Hash returns the hex SHA-256 of attrs: keys sorted, each value JSON-encoded,
// string slices in order, excluding config_sha256, config_hash_version,
// tenant_id and ingest_transport.
func Hash(attrs telemetry.Attrs) string { panic("adminmap.Hash: not implemented") }

// MapEnum maps a decoded JSON value through table. A float64 with no fractional
// part is an integer. An integer not in table returns ("unknown", n, false) and
// reports through rep.Value with an Enum built from table's keys. A missing or
// non-integer value returns ("unknown", 0, false) and reports rep.MissingField.
func MapEnum(rep *wirecheck.Reporter, e telemetry.Emitter, field string, raw any, table map[int]string) (name string, rawInt int, ok bool) {
	panic("adminmap.MapEnum: not implemented")
}

// SetIDs sets key to ids cut to MaxIDs (omitted when ids is empty), key+"_count"
// to len(ids) (0 for an empty, non-nil slice; nothing for nil), and
// key+"_truncated" true when cut.
func SetIDs(attrs telemetry.Attrs, key string, ids []string) { panic("adminmap.SetIDs: not implemented") }

// SnakeKey applies the naming rule: prefix + snake_case(wireField), splitting on
// case changes and keeping acronym runs together.
func SnakeKey(prefix, wireField string) string { panic("adminmap.SnakeKey: not implemented") }
