package telemetry

import (
	"regexp"
	"strconv"
	"strings"
)

// This file hosts the exported attribute-setting helpers shared by collectors.
// Each mirrors, byte-for-byte, a helper that was previously copy-pasted into
// individual collector packages (setStr recurred in 27 packages; the others in
// one each). Behavior is deliberately unchanged — this is a de-duplication seam
// only. They live in package telemetry because Attrs is defined here.

// SetStr sets attrs[key] = val, but only when val is non-empty. An empty string
// omits the attribute rather than emitting a blank one.
func SetStr(attrs Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// SetBool sets attrs[key] to the string "true"/"false". Booleans are stamped as
// strings (not native bools) to keep them queryable as Loki structured metadata.
func SetBool(attrs Attrs, key string, val bool) {
	attrs[key] = strconv.FormatBool(val)
}

// SetNum copies the float64 at m[srcKey] into attrs[key], when present. srcKey is
// the SOURCE (Graph JSON) field name; key is the destination attribute name. A
// missing or non-float64 source value omits the attribute.
func SetNum(attrs Attrs, key string, m map[string]any, srcKey string) {
	if f, ok := m[srcKey].(float64); ok {
		attrs[key] = f
	}
}

// SetList splits val on whitespace (strings.Fields) and sets attrs[key] to the
// resulting []string, when at least one field is present. An empty or
// whitespace-only val omits the attribute.
func SetList(attrs Attrs, key, val string) {
	if parts := strings.Fields(val); len(parts) > 0 {
		attrs[key] = parts
	}
}

// SetStrs sets attrs[key] = vals, but only when vals is non-empty.
func SetStrs(attrs Attrs, key string, vals []string) {
	if len(vals) > 0 {
		attrs[key] = vals
	}
}

// SetDurationSeconds parses an ISO-8601 duration in val into total seconds and
// sets attrs[key] to that float64, when the string parses. An empty or
// unparseable duration omits the attribute.
func SetDurationSeconds(attrs Attrs, key, val string) {
	if seconds, ok := parseISO8601DurationSeconds(val); ok {
		attrs[key] = seconds
	}
}

// isoDurationPattern matches an ISO-8601 duration string as returned by Graph
// for elapsed-time fields (e.g. "PT4M32S" or "PT1H2M3.5S"). The pattern tolerates
// the full ISO-8601 duration grammar, including a leading "-" for a negative
// duration, for robustness.
var isoDurationPattern = regexp.MustCompile(`^(-)?P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$`)

// parseISO8601DurationSeconds parses an ISO-8601 duration string into total
// seconds. A negative result (client clock skew between start and end
// timestamps) is CLAMPED to zero rather than returned negative. Returns ok=false
// for an empty or unparseable string, or one with no duration component at all
// (e.g. bare "P"), so the caller can omit the attribute rather than emit a bogus
// zero.
func parseISO8601DurationSeconds(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	m := isoDurationPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	years, months, days, hours, minutes, seconds := m[2], m[3], m[4], m[5], m[6], m[7]
	if years == "" && months == "" && days == "" && hours == "" && minutes == "" && seconds == "" {
		return 0, false
	}
	total := parseFloat(years)*365*24*3600 +
		parseFloat(months)*30*24*3600 +
		parseFloat(days)*24*3600 +
		parseFloat(hours)*3600 +
		parseFloat(minutes)*60 +
		parseFloat(seconds)
	if m[1] == "-" {
		total = -total
	}
	if total < 0 {
		total = 0
	}
	return total, true
}

// parseFloat parses s as a float64, returning 0 for an empty or unparseable
// string (capture groups are validated by isoDurationPattern before this is
// called, so a parse failure here cannot happen in practice).
func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}
