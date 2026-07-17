// Package signalcapture turns what a collector's tests actually emitted into an
// assertable value, and gates the cardinality rule (#112) mechanically.
//
// # Why this exists
//
// #112's rule — metrics carry bounded aggregates, logs carry entities — was
// enforced by convention and by per-collector guard tests. Nothing enforced it
// globally, so a collector that put a UPN on a metric label was invisible to CI.
// That is not hypothetical: #110/#111/#114 exist because twelve collectors
// quietly broke the rule, and #83 is a thirteenth that survived the #114 sweep —
// it shipped app_name as a metric label, 1,870 series on a six-device tenant.
// Every one was found by a human reading code.
//
// # How it works, and why it is shaped this way
//
// The capture is the union of every Recorder a package's tests built, which
// telemetrytest.New collects automatically. That indirection is the point: 52 of
// 57 collector test files already drive a faked client into the Recorder
// (measured, #140), so the emissions are already there to be read — no fixture
// has to be written twice, and no test has to opt in. A gate a new test can
// silently escape is not a gate.
//
// # Known limit, stated rather than implied
//
// The union is a LOWER BOUND on a collector's true signal surface: a code path
// no test exercises emits nothing here, so it cannot be judged. This gate
// therefore proves "nothing a test exercises breaks the rule", not "nothing
// breaks the rule". That is a real limit, but it fails in the safe direction —
// it never green-lights an emission it has seen — and a signal no test reaches
// is a coverage problem worth having anyway.
package signalcapture

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// MetricSignal is one metric name and the union of the attribute keys observed
// on it. Keys only, never values: values are whatever a fixture happened to
// contain, so goldening them would churn on every fixture edit while telling us
// nothing about cardinality. The KEY is what decides series count.
type MetricSignal struct {
	Name     string
	AttrKeys []string
}

// LogSignal is one log event name and the union of its observed attribute keys.
type LogSignal struct {
	EventName string
	AttrKeys  []string
}

// Signals is everything a package emitted, deduplicated and sorted.
type Signals struct {
	Metrics []MetricSignal
	Logs    []LogSignal
}

// Union merges every recorder's emissions into one Signals.
//
// Merging matters: two tests exercising different branches of one collector see
// different attribute sets, and judging a collector on whichever test ran last
// would make the gate depend on test order.
func Union(recs []*telemetrytest.Recorder) Signals {
	metrics := map[string]map[string]struct{}{}
	logs := map[string]map[string]struct{}{}

	for _, r := range recs {
		for _, name := range r.MetricNames() {
			keys, ok := metrics[name]
			if !ok {
				keys = map[string]struct{}{}
				metrics[name] = keys
			}
			for _, p := range r.MetricPoints(name) {
				for k := range p.Attrs {
					keys[k] = struct{}{}
				}
			}
		}
		for _, l := range r.LogRecords() {
			keys, ok := logs[l.EventName]
			if !ok {
				keys = map[string]struct{}{}
				logs[l.EventName] = keys
			}
			for k := range l.Attrs {
				keys[k] = struct{}{}
			}
		}
	}

	var s Signals
	for name, keys := range metrics {
		s.Metrics = append(s.Metrics, MetricSignal{Name: name, AttrKeys: sortedKeys(keys)})
	}
	for name, keys := range logs {
		s.Logs = append(s.Logs, LogSignal{EventName: name, AttrKeys: sortedKeys(keys)})
	}
	sort.Slice(s.Metrics, func(i, j int) bool { return s.Metrics[i].Name < s.Metrics[j].Name })
	sort.Slice(s.Logs, func(i, j int) bool { return s.Logs[i].EventName < s.Logs[j].EventName })
	return s
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// perEntityKeys are attribute keys that must never appear on a METRIC label,
// because a series keyed by one grows with tenant size (or gets exactly one
// sample ever) — #112's definition of a bug.
//
// This is an explicit, exact-match list rather than a heuristic on purpose. A
// pattern like "anything ending in _id" would flag policy_id and app_id, which
// are bounded by the tenant's POLICY count, not its user or device count — the
// exact shape #112 wants on metrics.
//
// # Why this list is narrower than it first looks — a key name cannot see boundedness
//
// The first draft of this list included app_name, citing #83 (app_name as a
// metric label: 1,870 series on a six-device tenant). Run against the tree it
// immediately flagged intune.detected_apps.device_count and
// intune.uxa.app_crash_count — and BOTH were wrong. Each bounds app_name with a
// fixed, package-level allow-list (defaultAllowedApps) and filters at the emit
// site, so their series count is a compile-time constant. That is precisely the
// bounded aggregate the rule wants.
//
// #83's app_name was the whole detected-app CATALOG (unbounded); theirs is an
// allow-list (bounded). Same key, opposite cardinality — decided by the
// collector's own logic, which a key-name check cannot see. So the gate was
// wrong, not the collectors, and app_name/app_display_name are deliberately NOT
// listed here. `[live-measured 2026-07-17, #140]`
//
// The bar for an entry is therefore stricter than "is often per-entity": a key
// belongs here only when a BOUNDED use of it is implausible — nobody allow-lists
// UPNs or serial numbers. Keys a collector could legitimately bound (app_name,
// issuer_name: a tenant has a handful of issuing CAs) are excluded, because a
// false positive here trains people to add exemptions, and an exempted gate is
// worse than none.
var perEntityKeys = map[string]string{
	"user_principal_name":    "identifies a user; grows with tenant user count",
	"user_id":                "identifies a user; grows with tenant user count",
	"user_display_name":      "identifies a user; grows with tenant user count",
	"upn":                    "identifies a user; grows with tenant user count",
	"device_id":              "identifies a device; grows with fleet size",
	"device_name":            "identifies a device; grows with fleet size",
	"managed_device_id":      "identifies a device; grows with fleet size",
	"serial_number":          "identifies a device; grows with fleet size",
	"imei":                   "identifies a device; grows with fleet size",
	"azure_ad_device_id":     "identifies a device; grows with fleet size",
	"ip_address":             "identifies a network endpoint; effectively unbounded",
	"correlation_id":         "identifies one event; one sample per series, forever",
	"request_id":             "identifies one event; one sample per series, forever",
	"id":                     "identifies one entity or event; one sample per series",
	"object_id":              "identifies one directory object; grows with tenant size",
	"service_principal_id":   "identifies a service principal; grows with tenant size",
	"service_principal_name": "identifies a service principal; grows with tenant size",
	"thumbprint":             "identifies one certificate; grows with cert count",
}

// selfObsPrefix marks the one metric namespace whose labels are exempt: the
// scrape/self-observability signals are bounded by collector count and tenant
// count, and tenant_id is deliberately a label there and ONLY there (#143).
const selfObsPrefix = "graph2otel."

// Violation is one per-entity attribute key found on a metric label.
type Violation struct {
	Metric  string
	AttrKey string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("metric %q carries per-entity label %q (%s)", v.Metric, v.AttrKey, v.Reason)
}

// PerEntityViolations reports every metric label that breaks #112.
//
// It deliberately inspects METRICS ONLY. Per-entity data on a LOG attribute is
// not a violation — it is the design. graph2otel is a SIEM feed and exports
// UPNs, device serials and IPs to the backend on purpose; #112 is a
// data-modeling rule about which pipeline carries what, not a privacy control.
// The "PII guidance" misreading of it caused #110/#111 and a third recurrence on
// #100, so a gate that flagged log attributes would automate the exact mistake.
func PerEntityViolations(s Signals) []Violation {
	var out []Violation
	for _, m := range s.Metrics {
		if strings.HasPrefix(m.Name, selfObsPrefix) {
			continue
		}
		for _, k := range m.AttrKeys {
			if reason, bad := perEntityKeys[k]; bad {
				out = append(out, Violation{Metric: m.Name, AttrKey: k, Reason: reason})
			}
		}
	}
	return out
}

// Main is the one-line TestMain a collector package installs to enforce #112
// over everything its tests emit:
//
//	func TestMain(m *testing.M) { signalcapture.Main(m) }
//
// It runs the package's tests, then fails the package if any metric a test
// exercised carries a per-entity label. Putting the check in TestMain rather
// than in a test is what makes it unforgettable — it needs no test to call it,
// so it covers emissions from tests written later by someone who has never heard
// of #112.
func Main(m *testing.M) {
	telemetrytest.StartCapture()
	code := m.Run()
	if code == 0 {
		if v := PerEntityViolations(Union(telemetrytest.Live())); len(v) > 0 {
			fmt.Fprintf(os.Stderr, "\n#112 cardinality violation — per-entity data on a metric label.\n"+
				"Metrics carry bounded, tenant-shaped aggregates; per-entity detail belongs on the\n"+
				"log twin (telemetry.Emitter.LogEvent). \"Not a metric label\" means LOG TWIN, never\n"+
				"dropped (#114) — entra/risk is the reference shape.\n\n")
			for _, x := range v {
				fmt.Fprintf(os.Stderr, "  - %s\n", x)
			}
			fmt.Fprintln(os.Stderr)
			code = 1
		}
	}
	os.Exit(code)
}
