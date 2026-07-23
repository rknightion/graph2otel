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
// # The lower bound is wide, and here is what actually causes it
//
// The union is a LOWER BOUND on a collector's true signal surface: this gate
// proves "nothing a test exercises breaks the rule", not "nothing breaks the
// rule". Do not read that as an edge case. Measured across the tree on
// 2026-07-17 (#164), 12 of 51 packages understated what they emit —
// entra/graphactivity goldened `"Logs": null`, nothing at all, against a mapper
// setting 22 attributes; intune/auditevents 4 of 18; entra/provisioning 3 of 14.
//
// The cause is NOT what a "lower bound" usually implies. It is not dead code or
// an exotic branch no test reaches. The normal shape of a collector package here
// is a RICH LIVE fixture that only ever reaches the MAPPER — asserted on
// directly, never emitted — plus a MINIMAL SYNTHETIC fixture that is the only
// thing driven through the engine into a Recorder. The golden faithfully
// captures the synthetic one. The rich fixture is already in the tree; it simply
// does not reach the emitter. That is the norm, not the exception, and it is why
// the shortfall is measured in whole attribute sets rather than in odd branches.
//
// # The two halves of the gate fail differently, and only one fails safe
//
// For the #112 CARDINALITY half, the lower bound fails in the safe direction: it
// never green-lights an emission it has seen, so a truncated golden means an
// unjudged metric, not an approved one.
//
// For the #140 DRIFT half it does not fail safe at all — it is weakened exactly
// in proportion to the shortfall, because a golden that never saw an attribute
// cannot detect that attribute changing. m365/unifiedaudit's golden covered no
// user attribute, so the user_principal_name → user_id rename (#163) did not
// trip its drift gate; its twin m365/activity, same signal and same event name,
// caught it. That asymmetry is the reason a thin golden is a defect rather than
// a coverage aspiration: it looks like a passing gate and is not one.
//
// ThinReasons is the mechanical floor against regressing to zero (#164). Above
// that floor the remedy is per package and is not automatable without becoming
// the static analysis this package must not be: drive the richest LIVE fixture
// end-to-end into a Recorder. entra/riskdetections is the reference — doing it
// took its golden from 4 attribute keys to 23.
package signalcapture

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// MetricSignal is one metric name, the union of the attribute keys observed on
// it, and the unit and aggregation kind it was emitted with. Attribute VALUES
// are deliberately never captured: they are whatever a fixture happened to
// contain, so goldening them would churn on every fixture edit while telling us
// nothing about cardinality. The KEY is what decides series count.
//
// # Why unit and kind are here (#235)
//
// The keys decide how MANY series a metric has. The unit and the aggregation
// kind decide what may legally be DONE with them when there are too many.
// Summing the tail of a device count into an `other` bucket is correct; summing
// the tail of a health score emits a number that was never real. #235's limiter
// reads that distinction off the unit, so the unit has to be a gated, visible
// property of every metric rather than an argument nobody ever looks at.
//
// Recording them also makes a unit or kind change a review prompt instead of a
// silent event — the same thing the attribute-key half has always bought, for
// the two fields that were missing from it.
type MetricSignal struct {
	Name string
	// Unit is the UCUM unit as passed to the emitter, e.g. "{device}", "%", "s".
	// Annotation units ("{thing}") are counts; "1", "%", "s" and friends are not.
	Unit string
	// Kind is the SDK's AGGREGATION kind — "sum", "gauge" or "histogram" — not
	// the instrument kind. That is the right granularity here: additivity is a
	// property of the aggregation, and a Counter and an UpDownCounter are both
	// sums that fold identically.
	Kind     string
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
	// shapes holds the FIRST unit/kind seen for each metric name. First-seen is
	// not an arbitrary tie-break: the emitter creates the OTEL instrument on first
	// use and caches it BY NAME, so a later call site passing a different unit
	// never reaches the wire at all. The golden records what actually ships.
	//
	// That caching is also why a disagreement is invisible from here: by the time
	// a point reaches the Recorder the SDK has already collapsed it to the cached
	// instrument's unit, so this capture structurally cannot observe a second unit
	// for the same name within a package. Cross-package disagreement IS visible —
	// it is checked by the tree walk over every golden, not here.
	type metricShape struct{ unit, kind string }
	shapes := map[string]*metricShape{}

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
				if _, ok := shapes[name]; !ok {
					shapes[name] = &metricShape{unit: p.Unit, kind: p.Kind}
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
		sh := shapes[name]
		if sh == nil {
			sh = &metricShape{}
		}
		s.Metrics = append(s.Metrics, MetricSignal{
			Name: name, Unit: sh.unit, Kind: sh.kind, AttrKeys: sortedKeys(keys),
		})
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
// intune.uxa.app_crash_count — and BOTH were wrong, because each bounded
// app_name at the emit site with a fixed package-level allow-list. Same key,
// opposite cardinality, decided by collector logic a key-name check cannot see.
// `[live-measured 2026-07-17, #140]`
//
// #235 retired both allow-lists, and app_name still does not belong here. What
// bounds those metrics moved rather than disappeared: the central cardinality
// limiter keeps the top N by value and folds the tail into app_name="other", so
// the series count is bounded by configuration instead of by a compile-time
// list. The conclusion is unchanged and now rests on a stronger footing — the
// bound is no longer something each collector has to remember to implement.
//
// The bar for an entry is therefore stricter than "is often per-entity": a key
// belongs here only when a BOUNDED use of it is implausible. A key the limiter
// can meaningfully rank and fold (app_name by device count, issuer_name: a
// tenant has a handful of issuing CAs) is excluded, because a false positive
// trains people to add exemptions, and an exempted gate is worse than none.
//
// The keys that ARE listed fail that test on a different axis, and the limiter
// does not rescue them: with a 5000 cap on a 50,000-user tenant, a UPN-keyed
// metric buys an arbitrary 5000 series plus a meaningless bucket, at full cost,
// answering nothing the log twin does not answer better. #112/#114 stand.
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

// frameworkStamped are the attribute keys a collector does NOT author: the
// emitter decorators add them to every log record that passes through, whatever
// the collector put in the Event. telemetry.WithTransport stamps
// ingest_transport (#141) and telemetry.WithTenant stamps tenant_id (#143).
//
// They are named via semconv rather than as literals so that renaming a stamp
// moves this set with it. A literal here would drift silently, and a
// thin-golden check that has quietly stopped recognizing the stamps would pass
// hollow records — the failure shape this whole gate exists to prevent.
var frameworkStamped = map[string]struct{}{
	semconv.AttrIngestTransport: {},
	semconv.AttrTenantID:        {},
}

// ThinReasons reports why a package's captured signals are too thin to gate
// anything, or nil when they are usable. It is #164's mechanical check.
//
// # What it is for
//
// Golden below fails when a package's emissions CHANGE. It says nothing about
// whether there were any emissions to begin with, so a package whose tests never
// drove a record into a Recorder goldens `{"Metrics": null, "Logs": null}` and
// passes forever. entra/graphactivity shipped exactly that — nothing at all,
// against a mapper setting 22 attributes — and 11 more packages goldened a
// fraction of their surface (#164, measured 2026-07-17). The cause is not an
// unexercised code path: it is that the rich live fixture stops at the mapper
// while a minimal synthetic one is the only thing driven end-to-end. The golden
// faithfully captures the synthetic one. Nothing failed, which is the problem.
//
// # The two rules, and why there is no third
//
//  1. A package that emitted NOTHING is thin. This is the floor #164 asks for.
//  2. A LOG record carrying only frameworkStamped keys is thin: the collector
//     contributed none of them, so the record proves the emitter ran and nothing
//     more. This closes rule 1's cheapest escape — driving an empty record
//     through an engine makes a golden non-empty while keeping it worthless.
//
// The tempting third rule, "every signal must carry an attribute", is a
// FALSE-POSITIVE GENERATOR and is deliberately absent: 11 of 52 packages
// legitimately emit an unlabeled metric (entra.secure_score.current,
// entra.organization.age_days, intune.devices.overview.enrolled_device_count) —
// a tenant-wide total has nothing to break down by. It would have cried wolf on
// a fifth of the tree on day one. `[live-measured 2026-07-17, #164]`
//
// # Why it does not read the collector's source
//
// #164's obvious framing is "fail when a golden is empty while its source sets
// attributes", which invites a regex over the mapper. This does not do that, for
// the reason #164 gives for the golden itself: the golden's one real guarantee
// is that it is built FROM emissions, so it cannot describe a signal that does
// not exist. A source regex reintroduces exactly that credibility gap, one level
// up — and worse, it is an EXEMPTION. A package whose emit style the regex fails
// to match is silently excused, which is #139/#100's shape verbatim: a gate
// reporting coverage it does not have.
//
// The "is this a collector package that ought to emit?" question needs no regex,
// because the tree already answers it. Every package under internal/collectors
// installs Main, and cmd/graph2otel's TestEveryCollectorPackageEnforcesCardinality
// walks the tree to prove it. So Main running IS the coarse signal: this is a
// collector package, and a collector that emits nothing is not a collector. That
// enumeration is tree-walked rather than hand-kept precisely so it cannot rot.
//
// # Its honest limit
//
// This is a floor, not a measure. It catches "nothing" and "nothing but stamps";
// it cannot catch a golden that captures 4 of 22 real attributes, because
// judging that needs to know what the mapper COULD emit — which is the static
// analysis #164 forbids. Rules 1 and 2 stop the next collector regressing to
// zero silently; keeping a golden honest above zero is a review duty, discharged
// by driving the package's richest live fixture end-to-end (entra/riskdetections
// is the reference shape: 4 keys goldened became 23 once its live record reached
// the emitter).
func ThinReasons(s Signals) []string {
	if len(s.Metrics) == 0 && len(s.Logs) == 0 {
		return []string{"this package's tests emitted no signals at all, so testdata/signals.json " +
			"gates nothing: it cannot detect an attribute changing that it never saw"}
	}

	var out []string
	for _, l := range s.Logs {
		authored := 0
		for _, k := range l.AttrKeys {
			if _, stamped := frameworkStamped[k]; !stamped {
				authored++
			}
		}
		if authored == 0 {
			out = append(out, fmt.Sprintf("log %q carries no attribute the collector authored "+
				"(only %v, stamped by the emitter for every record): the record proves the emitter "+
				"ran, not what this collector emits", l.EventName, l.AttrKeys))
		}
	}
	return out
}

// Golden writes or verifies a package's captured signals against
// testdata/signals.json, and is the drift gate #140 asks for: it fails a plain
// `go test` when a package's real emissions change.
//
// Why a golden file per package rather than a check against the doc's prose:
// docs/collectors.md's signal column is hand-written English with a contextual
// shorthand — `entra.organization.directory.sync.last_sync_age_seconds`,
// `.age_days`, `.verified_domains.total` — where the base a `.suffix` hangs off
// is inferred by the READER, and inferred differently for different entries.
// It is not machine-parseable without guessing, and a gate that guesses is worse
// than none (#140). The golden is truth by construction instead: it is produced
// FROM the emissions, so it cannot describe a signal that does not exist.
//
// What a diff here means: you changed what a collector emits. That is often
// correct — accept it with `-update`. It is a REVIEW prompt, not an error; the
// point is that it can never happen silently, which is how the doc drifted from
// reality in the first place.
func Golden(update bool) error {
	got := Union(telemetrytest.Live())
	body, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	const path = "testdata/signals.json"
	if update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, body, 0o600)
	}

	want, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no %s: this package's emitted signals are ungated.\n"+
				"Create it with: go test ./<this package> -update", path)
		}
		return err
	}
	if string(want) != string(body) {
		return fmt.Errorf("emitted signals changed — %s is stale.\n"+
			"If the change is intended, accept it with: go test ./<this package> -update\n"+
			"want:\n%s\ngot:\n%s", path, want, body)
	}
	return nil
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
//
// The -update flag is registered HERE, inside Main, rather than at package
// var-init time: internal/collectordoc imports this package for the plain
// Signals/MetricSignal/LogSignal types (#140), not for Main, but a
// package-level flag.Bool runs on import regardless — which collided with
// cmd/graph2otel's own pre-existing "-update" flag the moment collectordoc
// started importing this package, panicking with "flag redefined: update" in
// every run of `go test ./cmd/graph2otel`. Main is the only reader of the
// flag and only collector packages that install it as their TestMain ever
// call it, so registering it here means importing this package's TYPES alone
// — as collectordoc now does — never touches the flag package at all.
func Main(m *testing.M) {
	telemetrytest.StartCapture()
	update := flag.Bool("update", false, "rewrite this package's testdata/signals.json golden")
	if !flag.Parsed() {
		flag.Parse()
	}
	code := m.Run()
	// Thinness is checked BEFORE Golden, and therefore before -update writes
	// anything. A thin golden is created by an -update run, so refusing to write
	// one fails at the moment of the mistake rather than goldening it and
	// reporting it later — by which time the file looks like an accepted baseline.
	if code == 0 {
		if r := ThinReasons(Union(telemetrytest.Live())); len(r) > 0 {
			fmt.Fprintf(os.Stderr, "\nthin signal golden (#164) — this package's tests do not drive\n"+
				"their fixture all the way into a Recorder, so testdata/signals.json understates what\n"+
				"the collector emits and cannot detect those attributes changing.\n\n")
			for _, x := range r {
				fmt.Fprintf(os.Stderr, "  - %s\n", x)
			}
			fmt.Fprintf(os.Stderr, "\nDrive this package's RICHEST LIVE fixture end-to-end (through the\n"+
				"collector into a telemetrytest Recorder), not just into the mapper.\n"+
				"entra/riskdetections' TestCollectorEmitsLiveRecordEndToEnd is the reference\n"+
				"shape: doing this took its golden from 4 attribute keys to 23.\n\n")
			code = 1
		}
	}
	if code == 0 {
		if err := Golden(*update); err != nil {
			fmt.Fprintf(os.Stderr, "\nsignal drift (#140): %v\n\n", err)
			code = 1
		}
	}
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
