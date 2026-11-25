// Package adminmap holds the mapping helpers every teams_admin collector shares
// (#712): the twin change hash, integer enum mapping with wirecheck reporting,
// capped ID lists and the attribute naming rule.
//
// The exported names and signatures are the contract the teams_admin collector
// packages build on.
package adminmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// HashVersion is exported as config_hash_version; bump it when the exported
// attribute set of any teams_admin twin changes.
const HashVersion = 1

// MaxIDs is the cap on an exported string list.
const MaxIDs = 100

// hashExcluded are the keys that never take part in the hash: the hash itself,
// its version, and the two stamps the emitter adds.
var hashExcluded = map[string]struct{}{
	semconv.AttrConfigSHA256:      {},
	semconv.AttrConfigHashVersion: {},
	semconv.AttrTenantID:          {},
	semconv.AttrIngestTransport:   {},
}

// Hash returns the hex SHA-256 of attrs: keys sorted, each value JSON-encoded,
// string slices in order, excluding config_sha256, config_hash_version,
// tenant_id and ingest_transport.
func Hash(attrs telemetry.Attrs) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		if _, skip := hashExcluded[k]; !skip {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		enc, err := json.Marshal(attrs[k])
		if err != nil {
			enc = []byte(fmt.Sprintf("%#v", attrs[k]))
		}
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(enc)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MapEnum maps a decoded JSON value through table. A float64 with no fractional
// part is an integer. An integer not in table returns ("unknown", n, false) and
// reports through rep.Value with an Enum built from table's keys. A missing or
// non-integer value returns ("unknown", 0, false) and reports rep.MissingField.
func MapEnum(rep *wirecheck.Reporter, e telemetry.Emitter, field string, raw any, table map[int]string) (name string, rawInt int, ok bool) {
	n, isInt := asInt(raw)
	if !isInt {
		if rep != nil {
			rep.MissingField(e, field)
		}
		return "unknown", 0, false
	}
	if name, found := table[n]; found {
		return name, n, true
	}
	if rep != nil {
		known := make([]string, 0, len(table))
		for k := range table {
			known = append(known, strconv.Itoa(k))
		}
		rep.Value(e, field, strconv.Itoa(n), wirecheck.NewEnum(known...))
	}
	return "unknown", n, false
}

func asInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || math.Abs(v) > 1<<53 {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := strconv.Atoi(v.String())
		return n, err == nil
	}
	return 0, false
}

// SetIDs sets key to ids cut to MaxIDs (omitted when ids is empty), key+"_count"
// to len(ids) (0 for an empty, non-nil slice; nothing for nil), and
// key+"_truncated" true when cut.
func SetIDs(attrs telemetry.Attrs, key string, ids []string) {
	if ids == nil {
		return
	}
	attrs[key+"_count"] = len(ids)
	cut := ids
	if len(ids) > MaxIDs {
		cut = ids[:MaxIDs]
		attrs[key+"_truncated"] = true
	}
	telemetry.SetStrs(attrs, key, slices.Clone(cut))
}

// SnakeKey applies the naming rule: prefix + snake_case(wireField), splitting on
// case changes and keeping acronym runs together.
func SnakeKey(prefix, wireField string) string {
	runes := []rune(wireField)
	var b strings.Builder
	b.WriteString(prefix)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
