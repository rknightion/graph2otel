package adminmap

import (
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

func TestHashIgnoresKeyOrderAndExcludedKeys(t *testing.T) {
	base := telemetry.Attrs{"a": "x", "b": 2, "c": []string{"1", "2"}}
	want := Hash(base)

	withExcluded := telemetry.Attrs{
		"c": []string{"1", "2"}, "b": 2, "a": "x",
		"config_sha256": "zzz", "config_hash_version": 9,
		"tenant_id": "t", "ingest_transport": "teams_admin",
	}
	if got := Hash(withExcluded); got != want {
		t.Errorf("Hash with excluded keys = %s, want %s", got, want)
	}
	if len(want) != 64 {
		t.Errorf("Hash length = %d, want 64 hex chars", len(want))
	}
}

func TestHashChangesOnValueChangeAndListOrder(t *testing.T) {
	base := func() telemetry.Attrs {
		return telemetry.Attrs{"a": "x", "b": 2, "c": []string{"1", "2"}, "d": true}
	}
	want := Hash(base())
	for name, mutate := range map[string]func(telemetry.Attrs){
		"string":     func(a telemetry.Attrs) { a["a"] = "y" },
		"int":        func(a telemetry.Attrs) { a["b"] = 3 },
		"bool":       func(a telemetry.Attrs) { a["d"] = false },
		"list order": func(a telemetry.Attrs) { a["c"] = []string{"2", "1"} },
		"list item":  func(a telemetry.Attrs) { a["c"] = []string{"1", "3"} },
		"added key":  func(a telemetry.Attrs) { a["e"] = "new" },
		"removed":    func(a telemetry.Attrs) { delete(a, "d") },
		"key/value boundary": func(a telemetry.Attrs) {
			delete(a, "a")
			a["ax"] = ""
		},
	} {
		a := base()
		mutate(a)
		if got := Hash(a); got == want {
			t.Errorf("Hash unchanged after %s change", name)
		}
	}
}

var testTable = map[int]string{0: "zero", 1: "one", 4: "four"}

func newReporter() (*wirecheck.Reporter, *telemetrytest.Recorder) {
	return wirecheck.New("teams.test", slog.New(slog.NewTextHandler(io.Discard, nil))), telemetrytest.New()
}

func TestMapEnumKnownValue(t *testing.T) {
	rep, rec := newReporter()
	name, n, ok := MapEnum(rep, rec.Emitter(), "RoutingMethod", float64(4), testTable)
	if name != "four" || n != 4 || !ok {
		t.Errorf("MapEnum(4) = %q, %d, %v", name, n, ok)
	}
	if pts := rec.MetricPoints(wirecheck.MetricUnexpected); len(pts) != 0 {
		t.Errorf("known value reported %d findings", len(pts))
	}
}

func TestMapEnumUnknownInteger(t *testing.T) {
	rep, rec := newReporter()
	name, n, ok := MapEnum(rep, rec.Emitter(), "RoutingMethod", float64(7), testTable)
	if name != "unknown" || n != 7 || ok {
		t.Errorf("MapEnum(7) = %q, %d, %v; want unknown, 7, false", name, n, ok)
	}
	pts := rec.MetricPoints(wirecheck.MetricUnexpected)
	if len(pts) != 1 || pts[0].Attrs["kind"] != wirecheck.KindUnmappedValue || pts[0].Attrs["field"] != "RoutingMethod" {
		t.Errorf("findings = %+v, want one unmapped_value for RoutingMethod", pts)
	}
}

func TestMapEnumMissingAndNonInteger(t *testing.T) {
	for name, raw := range map[string]any{
		"nil": nil, "string": "4", "fraction": 1.5, "bool": true,
	} {
		t.Run(name, func(t *testing.T) {
			rep, rec := newReporter()
			got, n, ok := MapEnum(rep, rec.Emitter(), "RoutingMethod", raw, testTable)
			if got != "unknown" || n != 0 || ok {
				t.Errorf("MapEnum(%v) = %q, %d, %v; want unknown, 0, false", raw, got, n, ok)
			}
			pts := rec.MetricPoints(wirecheck.MetricUnexpected)
			if len(pts) != 1 || pts[0].Attrs["kind"] != wirecheck.KindMissingField {
				t.Errorf("findings = %+v, want one missing_field", pts)
			}
		})
	}
}

func TestSetIDs(t *testing.T) {
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "id-" + strconv.Itoa(i)
		}
		return out
	}
	for _, tc := range []struct {
		n         int
		wantList  int
		truncated bool
	}{
		{0, 0, false}, {1, 1, false}, {99, 99, false}, {100, 100, false}, {101, 100, true},
	} {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			in := ids(tc.n)
			attrs := telemetry.Attrs{}
			SetIDs(attrs, "k", in)
			if got := attrs["k_count"]; got != tc.n {
				t.Errorf("k_count = %v, want %d", got, tc.n)
			}
			list, has := attrs["k"].([]string)
			if tc.wantList == 0 && has {
				t.Errorf("k present for empty list: %v", list)
			}
			if tc.wantList > 0 && len(list) != tc.wantList {
				t.Errorf("len(k) = %d, want %d", len(list), tc.wantList)
			}
			trunc, hasTrunc := attrs["k_truncated"]
			if hasTrunc != tc.truncated || (hasTrunc && trunc != true) {
				t.Errorf("k_truncated = %v (present %v), want present=%v", trunc, hasTrunc, tc.truncated)
			}
			if tc.n > 0 && tc.n <= 100 && list[tc.n-1] != "id-"+strconv.Itoa(tc.n-1) {
				t.Errorf("last kept id = %q", list[tc.n-1])
			}
			if tc.truncated && list[99] != "id-99" {
				t.Errorf("cut kept the wrong entries: last = %q", list[99])
			}
		})
	}
}

func TestSetIDsNilWritesNothing(t *testing.T) {
	attrs := telemetry.Attrs{}
	SetIDs(attrs, "k", nil)
	if len(attrs) != 0 {
		t.Errorf("SetIDs(nil) wrote %v", attrs)
	}
}

func TestSetIDsDoesNotAliasInput(t *testing.T) {
	in := []string{"a", "b"}
	attrs := telemetry.Attrs{}
	SetIDs(attrs, "k", in)
	in[0] = "changed"
	if got := attrs["k"].([]string)[0]; got != "a" {
		t.Errorf("exported list aliases the caller's slice: %q", got)
	}
}

func TestSnakeKey(t *testing.T) {
	for _, tc := range []struct{ prefix, in, want string }{
		{"x_", "IPAddressVersion", "x_ip_address_version"},
		{"pstn_gateway_", "OutbundTeamsNumberTranslationRules", "pstn_gateway_outbund_teams_number_translation_rules"},
		{"sip_devices_", "HotDeskingIdleTimeoutInMinutes", "sip_devices_hot_desking_idle_timeout_in_minutes"},
		{"call_queue_", "FailoverTimeSeconds", "call_queue_failover_time_seconds"},
		{"call_queue_", "Name", "call_queue_name"},
		{"", "LanguageId", "language_id"},
		{"a_", "E164Number", "a_e164_number"},
		{"a_", "SipURI", "a_sip_uri"},
	} {
		if got := SnakeKey(tc.prefix, tc.in); got != tc.want {
			t.Errorf("SnakeKey(%q, %q) = %q, want %q", tc.prefix, tc.in, got, tc.want)
		}
	}
}
