package annotations

import (
	"fmt"
	"sort"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// The two gauge snapshots the license category is derived from. Both are emitted
// by internal/collectors/entra/licensing in one Collect, keyed by `sku`.
//
// This category is derived from METRICS rather than from a log record on
// purpose, because there is no log record that carries it: entra.license_group_error
// reports groups with failed assignments, not the subscribed-SKU set. "The SKU
// set changed" and "a SKU is exhausted" are COMPARISONS between two snapshots,
// so they are properties of neither snapshot alone. Deriving them here keeps the
// #400 constraint intact — nothing new is polled, and the licensing collector is
// untouched.
const (
	metricLicenseConsumed = "entra.license.consumed"
	metricLicenseEnabled  = "entra.license.enabled"
)

// skuAttr is the attribute key both license gauges are keyed by.
const skuAttr = "sku"

// licenseSKU is one subscribed SKU's unit position.
type licenseSKU struct {
	consumed float64
	enabled  float64
}

// exhausted reports whether this SKU has no headroom left. enabled == 0 is
// excluded: a SKU with zero prepaid units is not "exhausted", it is not
// purchased, and annotating it would fire on every trial SKU forever.
func (s licenseSKU) exhausted() bool { return s.enabled > 0 && s.consumed >= s.enabled }

// licenseState is the previous comparison point for one tenant.
type licenseState struct {
	skus map[string]licenseSKU
}

// licenseObservation accumulates the two gauge snapshots of ONE run, so the
// comparison happens against a complete picture. Evaluating on the first
// snapshot alone would compare consumed units against an absent enabled count
// and report every SKU as exhausted.
type licenseObservation struct {
	run      runID
	consumed map[string]float64
	enabled  map[string]float64
}

// ObserveGaugeSnapshot offers one gauge snapshot to the license category. Every
// other metric is ignored on a single map-key comparison.
func (r *Recorder) ObserveGaugeSnapshot(run runID, metric string, points []telemetry.GaugePoint) {
	if metric != metricLicenseConsumed && metric != metricLicenseEnabled {
		return
	}
	if !r.enabled(CategoryLicense) {
		return
	}
	values := make(map[string]float64, len(points))
	for _, p := range points {
		sku := attrString(p.Attrs, skuAttr)
		if sku == "" {
			continue
		}
		values[sku] = p.Value
	}

	r.mu.Lock()
	obs, ok := r.licensePending[run.tenant]
	if !ok || obs.run != run {
		obs = &licenseObservation{run: run}
		r.licensePending[run.tenant] = obs
	}
	if metric == metricLicenseConsumed {
		obs.consumed = values
	} else {
		obs.enabled = values
	}
	if obs.consumed == nil || obs.enabled == nil {
		r.mu.Unlock()
		return
	}
	current := map[string]licenseSKU{}
	for sku, enabled := range obs.enabled {
		current[sku] = licenseSKU{consumed: obs.consumed[sku], enabled: enabled}
	}
	previous := r.license[run.tenant]
	r.license[run.tenant] = &licenseState{skus: current}
	delete(r.licensePending, run.tenant)
	r.mu.Unlock()

	if previous == nil {
		// First complete observation in this process: there is no previous set, so
		// every SKU would read as "added". Prime silently, exactly as a KindState
		// log rule does.
		return
	}
	r.compareLicense(run.tenant, previous.skus, current)
}

// compareLicense emits the license-category annotations implied by the move from
// previous to current. Every occurrence gets a dedupe key derived from the
// VALUES involved, so a repeat observation of the same position is suppressed
// while a genuine second change (a resize back and forth) is not.
func (r *Recorder) compareLicense(tenantID string, previous, current map[string]licenseSKU) {
	for _, sku := range sortedKeys(current) {
		cur := current[sku]
		prev, existed := previous[sku]
		switch {
		case !existed:
			r.emitLicense(tenantID, RuleLicenseSKUAdded, "SKU added",
				fmt.Sprintf("subscribed SKU added: %s (%s prepaid units)", sku, units(cur.enabled)),
				sku, units(cur.enabled))
		case cur.enabled != prev.enabled:
			r.emitLicense(tenantID, RuleLicenseUnitsChanged, "SKU units changed",
				fmt.Sprintf("SKU %s prepaid units %s -> %s", sku, units(prev.enabled), units(cur.enabled)),
				sku, units(prev.enabled), units(cur.enabled))
		}
		// Exhaustion is reported on the TRANSITION only. A SKU that sits at its
		// ceiling for a month is one event, not one per poll — the dedupe key
		// alone would not achieve that, because it is keyed on the values and a
		// consumed count that drifts by one would mint a new key every tick.
		if cur.exhausted() && (!existed || !prev.exhausted()) {
			r.emitLicense(tenantID, RuleLicenseExhausted, "SKU license exhausted",
				fmt.Sprintf("SKU %s license exhausted: %s of %s units consumed",
					sku, units(cur.consumed), units(cur.enabled)),
				sku, units(cur.consumed), units(cur.enabled))
		}
	}

	for _, sku := range sortedKeys(previous) {
		if _, stillThere := current[sku]; stillThere {
			continue
		}
		r.emitLicense(tenantID, RuleLicenseSKURemoved, "SKU removed",
			fmt.Sprintf("subscribed SKU removed: %s (was %s prepaid units)",
				sku, units(previous[sku].enabled)),
			sku, units(previous[sku].enabled))
	}
}

// emitLicense publishes one license-category occurrence. title is the SHORT
// label a rolled-up summary groups by — the full text carries the numbers, and
// grouping by that would make every rollup a list of one.
func (r *Recorder) emitLicense(tenantID, ruleID, title, text string, identity ...string) {
	now := r.now()
	key := DedupeKey(tenantID, ruleID, identity...)
	if !r.dedupe.Claim(tenantID, ruleID, key, now) {
		r.sink.Duplicate(tenantID)
		return
	}
	r.emit(Annotation{
		Category:  CategoryLicense,
		TenantID:  tenantID,
		RuleID:    ruleID,
		Time:      now,
		Text:      text,
		DedupeKey: key,
	}, title)
}

// units renders a unit count without a spurious decimal point. The gauges are
// float64 because the Emitter facade is, but a license count is an integer.
func units(v float64) string { return fmt.Sprintf("%.0f", v) }

func sortedKeys(m map[string]licenseSKU) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
