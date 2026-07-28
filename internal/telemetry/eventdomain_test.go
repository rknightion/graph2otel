package telemetry

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestEventDomainDerivesTheFirstNameSegment pins the routing function itself.
// The value must equal internal/signalcatalog's domainOf, because the catalog
// is what the closed-set assertion below is checked against — two different
// derivations would let a record be routed to one domain and cataloged under
// another.
func TestEventDomainDerivesTheFirstNameSegment(t *testing.T) {
	cases := map[string]string{
		"entra.signin":            "entra",
		"intune.device":           "intune",
		"m365.activity":           "m365",
		"purview.label":           "purview",
		"defender.alert_evidence": "defender",
		"mdca.discovery_parse":    "mdca",
		"graph2otel.scrape":       "graph2otel",
	}
	for name, want := range cases {
		if got := EventDomain(name); got != want {
			t.Errorf("EventDomain(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestEventDomainFallsBackForAnUnknownOrMalformedName covers the runtime path a
// closed set cannot: an event name from a namespace nobody has cataloged yet
// must still be EMITTED, and it must still carry a domain value, because the
// resource attribute is stamped by whichever LoggerProvider handles it and
// there is no such thing as a record with no resource. Dropping the record
// instead would make an uncataloged collector silently invisible.
func TestEventDomainFallsBackForAnUnknownOrMalformedName(t *testing.T) {
	for _, name := range []string{"", "nodots", "azure.something", ".leading"} {
		if got := EventDomain(name); got != EventDomainOther {
			t.Errorf("EventDomain(%q) = %q, want %q", name, got, EventDomainOther)
		}
	}
}

// TestEventDomainsIsClosedAndCoversTheCatalogue is the closed-set assertion
// #402 asks for. The domain set is code-defined (a provider is constructed per
// value at startup, so it cannot be discovered at runtime), and this test is
// what stops it drifting away from the signals actually emitted: a collector
// introducing a new top-level namespace fails here rather than silently
// landing in the "other" bucket forever.
func TestEventDomainsIsClosedAndCoversTheCatalogue(t *testing.T) {
	raw, err := os.ReadFile("../../spec/signal-catalog.json")
	if err != nil {
		t.Fatalf("read signal catalog: %v", err)
	}
	var cat struct {
		Domains []string `json:"domains"`
		Logs    []struct {
			EventName string `json:"event_name"`
			Domain    string `json:"domain"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatalf("decode signal catalog: %v", err)
	}
	if len(cat.Logs) == 0 {
		t.Fatal("signal catalog carries no log events — the assertion below would be vacuous")
	}

	domains := EventDomains()
	if !slices.Contains(domains, EventDomainOther) {
		t.Errorf("EventDomains() = %v, must contain the fallback %q", domains, EventDomainOther)
	}

	// Every cataloged domain must have a provider built for it.
	for _, d := range cat.Domains {
		if !slices.Contains(domains, d) {
			t.Errorf("cataloged domain %q has no LoggerProvider — add it to eventDomains", d)
		}
	}
	// And nothing may route to the fallback in practice: a cataloged event
	// landing in "other" is the drift this test exists to catch.
	for _, l := range cat.Logs {
		if got := EventDomain(l.EventName); got == EventDomainOther {
			t.Errorf("cataloged event %q routes to the %q fallback", l.EventName, EventDomainOther)
		} else if got != l.Domain {
			t.Errorf("event %q: EventDomain = %q, catalog says %q", l.EventName, got, l.Domain)
		}
	}
}
