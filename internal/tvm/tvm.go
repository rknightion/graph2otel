// Package tvm holds the wire-decode helpers and the row-cap partitioning shared
// by the three Defender threat-and-vulnerability-management collectors (#249):
// defender.vulnerabilities, defender.secure_config and defender.software_inventory.
//
// They all read advanced-hunting query results (internal/huntclient), which have
// two quirks documentation does not warn about and that every mapper must handle
// identically:
//
//   - Every boolean column arrives as an SByte NUMBER (0/1), decoded into Go as a
//     float64, NEVER as a JSON bool. Reading such a column with a bool type
//     assertion silently yields the zero value. SByteBool reads it correctly.
//   - A null datetime or dynamic cell arrives as {} (an empty JSON object),
//     decoded as map[string]any, not as nil and not as a string. Str returns ""
//     for it, so a downstream SetStr omits the attribute rather than emitting a
//     stringified empty map.
//
// And they all face the same hard limit: advanced hunting returns at most 100,000
// rows per query. PlanPartitions turns a known row count into enough hash shards
// that each per-entity twin fetch stays under the cap, so a large tenant is never
// silently truncated.
package tvm

import (
	"fmt"
	"strconv"
)

// HardRowCap is the advanced-hunting API's per-query row ceiling: 100,000 rows,
// hard (#249). A query returning more is truncated with no error.
const HardRowCap = 100_000

// Str reads a string column, returning "" when the key is absent or its value is
// not a string. The hunting API decorates several columns with sidecar
// "<Name>@odata.type" keys and returns null cells as {} — reading by exact name
// with a string assertion ignores both.
func Str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// SByteBool reads a boolean column that the hunting API encodes as an SByte
// number (0/1, decoded as float64). It returns (value, true) when the column is
// present as a number, (false, false) when it is absent or a non-number — the
// same shape a comma-ok type assertion has, so callers can distinguish "false" on
// the wire from "not present".
func SByteBool(m map[string]any, key string) (bool, bool) {
	f, ok := m[key].(float64)
	if !ok {
		return false, false
	}
	return f != 0, true
}

// FmtBool renders a bool as the string "true"/"false", for use as a bounded
// metric-label value. It mirrors telemetry.SetBool's string encoding so a label
// and its log-twin attribute read identically.
func FmtBool(b bool) string { return strconv.FormatBool(b) }

// Partition is one hash shard of a per-entity twin fetch. Of == 1 means the fetch
// fits in a single unsharded query.
type Partition struct {
	Shard int
	Of    int
}

// PlanPartitions turns a known row count into the shards needed to keep every
// twin fetch under cap. It returns exactly ceil(count/cap) partitions (always at
// least one), numbered 0..Of-1, so their hash predicates tile the rows with no
// gap and no overlap — the property that makes a large fetch safe from silent
// truncation. A non-positive cap falls back to HardRowCap.
func PlanPartitions(count int64, cap int) []Partition {
	if cap <= 0 {
		cap = HardRowCap
	}
	n := 1
	if count > int64(cap) {
		n = int((count + int64(cap) - 1) / int64(cap)) // ceil
	}
	parts := make([]Partition, n)
	for i := range parts {
		parts[i] = Partition{Shard: i, Of: n}
	}
	return parts
}

// Predicate returns the KQL fragment that selects this shard by hashing col into
// Of buckets, or "" when the fetch is unsharded (Of <= 1). hash(col, Of) returns
// 0..Of-1 in Kusto, so the Of predicates partition the rows exactly.
func (p Partition) Predicate(col string) string {
	if p.Of <= 1 {
		return ""
	}
	return fmt.Sprintf(" | where hash(%s, %d) == %d", col, p.Of, p.Shard)
}
