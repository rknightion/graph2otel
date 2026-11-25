package callrecords

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Synthetic and docs-derived, not Graph captures. Fixture shapes are based on
// the request and resource links in wire.go and map.go, plus the field list in
// https://github.com/rknightion/graph2otel/issues/657 (Teams call records).
var now = time.Date(2026, time.January, 2, 16, 0, 0, 0, time.UTC)

type fakeGraph func(address, prefer string) ([]byte, error)

func (f fakeGraph) RawGet(_ context.Context, address string) ([]byte, error) { return f(address, "") }
func (f fakeGraph) RawGetWithHeaders(_ context.Context, address string, headers map[string]string) ([]byte, error) {
	return f(address, headers["Prefer"])
}

func collectorForTest(t *testing.T, deps collectors.WindowDeps) *Collector {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := newCollector(deps).Collector.(*Collector)
	c.now = func() time.Time { return now }
	return c
}

func syntheticDetail(t *testing.T, id string, version int, start time.Time) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/synthetic-detail.json")
	if err != nil {
		t.Fatal(err)
	}
	replace := strings.NewReplacer("CALL_ID", id, "CALL_START", stamp(start), "CALL_END", stamp(start.Add(time.Minute)),
		"SEGMENT_START", stamp(start.Add(2*time.Second)), "STREAM_START", stamp(start.Add(3*time.Second)))
	var d map[string]any
	if err := json.Unmarshal([]byte(replace.Replace(string(b))), &d); err != nil {
		t.Fatal(err)
	}
	d["version"] = version
	return d
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func collection(t *testing.T, next string, values ...any) []byte {
	t.Helper()
	if values == nil {
		values = []any{}
	}
	return encoded(t, map[string]any{"value": values, "@odata.nextLink": next})
}

func listEntry(id string, version int, start time.Time) map[string]any {
	return map[string]any{"id": id, "version": version, "startDateTime": stamp(start)}
}

func assertList(t *testing.T, address, prefer string) string {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(address, absolutePath+"?") || prefer != "odata.maxpagesize=60" || len(u.Query()) != 1 || u.Query().Get("$filter") == "" {
		t.Fatalf("expected v1.0 callRecords with just a time filter and Prefer page size 60, got %q (%q)", address, prefer)
	}
	return u.Query().Get("$filter")
}

func peoplePage(t *testing.T) []byte {
	t.Helper()
	return []byte(`{"value":[
		{"id":"person-1","identity":{"user":{"id":"person-1","userPrincipalName":"caller@corp.example.com"}}},
		{"id":"guest-1","identity":{"guest":{"id":"guest-1","userPrincipalName":"guest@outside.example.com"}}},
		{"id":"phone-1","identity":{"phone":{"id":"phone-1"}}},
		{"id":"app-1","identity":{"application":{"id":"app-1"}}},
		{"id":"device-1","identity":{"device":{"id":"device-1"}}}
	]}`)
}

func assertAttrs(t *testing.T, log telemetrytest.LogRecord, attrs map[string]string) {
	t.Helper()
	for k, want := range attrs {
		if got := log.Attrs[k]; got != want {
			t.Errorf("%s attribute %s = %q, want %q", log.EventName, k, got, want)
		}
	}
}

func TestCallVersionsAndSites(t *testing.T) {
	start := now.Add(-time.Hour + 125*time.Nanosecond)
	v := 1
	var detailGets, participantGets int
	csv := filepath.Join(t.TempDir(), "sites.csv")
	writeSite := func(name string) {
		t.Helper()
		b := "subnet,location,country,latitude,longitude\n192.0.2.0/24," + name + ",GB,0,0\n198.51.100.0/24,IpOnly,GB,1,2\n2001:db8::/32,Remote,GB,1,0\n2001:db8:1::/48,Annex,AU,3,4\n"
		if err := os.WriteFile(csv, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSite("Original")
	file, err := sites.Open(csv)
	if err != nil {
		t.Fatal(err)
	}
	writeSite("PollSnapshot") // changed since construction
	domains, err := sites.NewDomains([]string{"corp.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/call-a?$expand=sessions($expand=segments)":
			detailGets++
			if v == 1 {
				// Simulate another reload while this poll is still in flight.
				// Its stream must still use the snapshot taken before the GET.
				writeSite("NextPoll")
				if err := file.Reload(); err != nil {
					t.Fatal(err)
				}
			}
			d := syntheticDetail(t, "call-a", v, start)
			segment := d["sessions"].([]any)[0].(map[string]any)["segments"].([]any)[0].(map[string]any)
			// Version 2 reports a distinct callee identity without a UPN. A
			// named site and a populated identity ID cannot make it external.
			if v == 2 {
				segment["callee"] = map[string]any{"associatedIdentity": map[string]any{"id": "opaque-endpoint"}}
			}
			media := segment["media"].([]any)
			audioCallee := media[0].(map[string]any)["calleeNetwork"].(map[string]any)
			audioCallee["subnet"], audioCallee["ipAddress"] = "2001:db8:1:2::/64", "198.51.100.4"
			video := media[1].(map[string]any)
			video["callerNetwork"] = map[string]any{"ipAddress": "198.51.100.5"}
			video["calleeNetwork"].(map[string]any)["subnet"] = "203.0.113.0/24"
			return encoded(t, d), nil
		case absolutePath + "/call-a/participants_v2":
			if prefer != "odata.maxpagesize=130" {
				t.Fatalf("participants Prefer = %q", prefer)
			}
			participantGets++
			return peoplePage(t), nil
		default:
			assertList(t, address, prefer)
			return collection(t, "", listEntry("call-a", v, start)), nil
		}
	})
	dir := t.TempDir()
	newC := func() *Collector {
		return collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant", TeamsSites: file, TeamsInternalDomains: domains})
	}
	c := newC()
	for _, want := range []struct {
		version, logCount int
		restart           bool
	}{{1, 3, false}, {1, 0, false}, {1, 0, true}, {2, 3, false}, {2, 0, true}} {
		v = want.version
		if want.restart {
			c = newC()
		}
		rec := telemetrytest.New()
		outcomes := recordoutcome.NewRecorder()
		if _, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes); err != nil {
			t.Fatal(err)
		}
		if err := outcomes.Snapshot().Validate(); err != nil {
			t.Fatal(err)
		}
		logs := rec.LogRecords()
		if len(logs) != want.logCount {
			t.Fatalf("version %d after restart=%v: got %d logs, want %d", v, want.restart, len(logs), want.logCount)
		}
		if want.logCount == 0 {
			continue
		}
		if logs[0].EventName != callEvent || !logs[0].Timestamp.Equal(start) || logs[1].EventName != streamEvent || !logs[1].Timestamp.Equal(start.Add(2*time.Second)) || !logs[2].Timestamp.Equal(start.Add(3*time.Second)) {
			t.Fatalf("expected call start, audio segment start, and SIP video start (no invalid event), got %+v", logs)
		}
		assertAttrs(t, logs[0], map[string]string{"version": strconv.Itoa(v), "call_id": "call-a", "duration_seconds": "60", "organizer_id": "person-1", "organizer_user_principal_name": "caller@corp.example.com", "participant_count": "5", "participant_users": "1", "participant_guests": "1", "participant_pstn": "1", "participant_apps": "1", "participant_devices": "1", "join_web_url": "https://example.com/join/synthetic", "ingest_transport": "graph"})
		site, calleeScope := "PollSnapshot", "external"
		if v == 2 {
			site, calleeScope = "NextPoll", "unknown"
			if got := logs[1].Attrs["callee_user_principal_name"]; got != "" {
				t.Errorf("different segment endpoint inherited a participant UPN: %q", got)
			}
		} else {
			assertAttrs(t, logs[1], map[string]string{"callee_bot_role": "customBot", "callee_app_id": "synthetic-app"})
		}
		assertAttrs(t, logs[1], map[string]string{"version": strconv.Itoa(v), "stream_id": "audio-nosip", "caller_site": site, "caller_site_country": "GB", "caller_site_latitude": "0", "caller_site_longitude": "0", "caller_is_internal": "true", "caller_identity_scope": "internal", "caller_ip_class": "public", "caller_relay_address_present": "true", "callee_site": "Annex", "callee_site_country": "AU", "callee_site_latitude": "3", "callee_site_longitude": "4", "callee_is_internal": "false", "callee_identity_scope": calleeScope, "callee_ip_class": "public", "callee_relay_address_present": "false", "caller_client_version": "0.0.1", "caller_feedback_rating": "poor", "session_failure_stage": "midcall", "segment_failure_reason": "synthetic-segment-failure", "average_rtt_ms": "75", "max_jitter_ms": "31.5", "average_packet_loss_rate": "0", "packet_utilization": "650", "caller_bandwidth_low_ratio": "0"})
		if _, ok := logs[1].Attrs["post_fec_packet_loss_rate"]; ok {
			t.Error("missing post-FEC loss was fabricated")
		}
		assertAttrs(t, logs[2], map[string]string{"stream_id": "video-sip", "direction": "calleeToCaller", "video_frame_rate": "30", "post_fec_packet_loss_rate": "0.02", "caller_site": "IpOnly", "callee_site": "Remote", "callee_site_country": "GB", "callee_site_latitude": "1", "callee_site_longitude": "0", "callee_ip_class": "public"})
		var hops []Hop
		if err := json.Unmarshal([]byte(logs[1].Attrs["caller_trace_route_hops"]), &hops); err != nil || len(hops) != 1 || hops[0].IP != "192.0.2.11" {
			t.Fatalf("trace route did not preserve structured hop: %+v (%v)", hops, err)
		}
	}
	if detailGets != 2 || participantGets != 2 {
		t.Fatalf("unchanged versions should not fan out again: %d details, %d participants", detailGets, participantGets)
	}
}

func TestRetryLateAndOpaquePages(t *testing.T) {
	start := now.Add(-32 * time.Hour)
	const (
		listNext    = absolutePath + "?$skiptoken=a%2Bb%2F%3D&opaque=4"
		sessionNext = absolutePath + "/late/sessions?$expand=segments&$skiptoken=S%2F1"
		segmentNext = absolutePath + "/late/sessions/session-page-2/segments?$skiptoken=G%2B9"
		peopleNext  = absolutePath + "/late/participants_v2?$skiptoken=P%2Bm%3D"
	)
	phase := "anchor"
	var retryGets, completedGets, suffixGets int
	d := syntheticDetail(t, "late", 2, start) // the list is still advertising v1
	d["sessions"+"@odata.nextLink"] = sessionNext
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case listNext:
			if prefer != "odata.maxpagesize=60" {
				t.Fatal("list continuation lost page-size header")
			}
			return collection(t, "", listEntry("late", 1, start), listEntry("suffix", 1, start.Add(time.Minute))), nil
		case absolutePath + "/late?$expand=sessions($expand=segments)":
			retryGets++
			return encoded(t, d), nil
		case sessionNext:
			return collection(t, "", map[string]any{"id": "session-page-2", "segments": []any{}, "segments" + "@odata.nextLink": segmentNext}), nil
		case segmentNext:
			return collection(t, "", map[string]any{"id": "segment-page-2", "startDateTime": stamp(start.Add(5 * time.Second)), "media": []any{map[string]any{"label": "main-audio", "streams": []any{map[string]any{"streamId": "continued"}}}}}), nil
		case absolutePath + "/late/participants_v2":
			return collection(t, peopleNext, map[string]any{"id": "person-1", "identity": map[string]any{"user": map[string]any{"id": "person-1"}}}), nil
		case peopleNext:
			if phase == "failure" {
				return nil, errors.New("synthetic participants GET failure")
			}
			return collection(t, "", map[string]any{"id": "phone-2", "identity": map[string]any{"phone": map[string]any{"id": "phone-2"}}}), nil
		case absolutePath + "/first?$expand=sessions($expand=segments)":
			completedGets++
			return encoded(t, syntheticDetail(t, "first", 1, start.Add(-time.Minute))), nil
		case absolutePath + "/first/participants_v2", absolutePath + "/suffix/participants_v2":
			return collection(t, ""), nil
		case absolutePath + "/suffix?$expand=sessions($expand=segments)":
			suffixGets++
			return encoded(t, syntheticDetail(t, "suffix", 1, start.Add(time.Minute))), nil
		default:
			filter := assertList(t, address, prefer)
			if phase == "anchor" {
				return collection(t, ""), nil
			}
			lower := now.Add(-time.Minute - maxCallDuration - arrivalAllowance)
			if phase == "retry" {
				lower = lower.Add(5 * time.Minute) // discovery already committed
			}
			if !strings.HasPrefix(filter, "startDateTime ge "+stamp(lower)+" and ") && phase != "seen" {
				t.Fatalf("late call fell out of overlap: %q", filter)
			}
			if phase == "seen" {
				return collection(t, "", listEntry("late", 2, start)), nil
			}
			return collection(t, listNext, listEntry("first", 1, start.Add(-time.Minute))), nil
		}
	})
	dir := t.TempDir()
	newC := func() *Collector {
		return collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
	}
	c := newC()
	rec := telemetrytest.New()
	anchor, err := c.CollectWindow(t.Context(), now.Add(-time.Hour), now, rec.Emitter(), nil)
	if err != nil {
		t.Fatal(err)
	}
	phase = "failure"
	outcomes := recordoutcome.NewRecorder()
	hw, err := c.CollectWindow(t.Context(), anchor, now.Add(5*time.Minute), rec.Emitter(), outcomes)
	if err != nil || !hw.Equal(now.Add(5*time.Minute-lag)) {
		t.Fatalf("recordable auxiliary failure must not pin discovery: %v; %v", hw, err)
	}
	assertDeferred(t, c, checkpoint.DeferredRecord{ID: "late", Version: 2, SourceTime: start})
	anchor = hw
	logs := rec.LogRecords()
	if len(logs) != 6 || logs[0].Attrs["call_id"] != "first" || logs[3].Attrs["call_id"] != "suffix" {
		t.Fatalf("fully hydrated calls on both sides of the failure must emit, got %+v", logs)
	}
	if got := outcomes.Snapshot(); got.Counts != (recordoutcome.Counts{Fetched: 3, Mapped: 2, Emitted: 2, Errored: 1}) || got.Validate() != nil ||
		got.Summarize(nil, false).Cause != recordoutcome.CauseSourceError {
		t.Fatalf("prepare failure miscounted independent rows: %+v", got)
	}
	phase = "retry"
	c = newC()
	rec = telemetrytest.New()
	hw, err = c.CollectWindow(t.Context(), anchor, now.Add(6*time.Minute), rec.Emitter(), nil)
	if err != nil || !hw.After(anchor) {
		t.Fatalf("retry did not finish: %v; %v", hw, err)
	}
	logs = rec.LogRecords()
	if len(logs) != 4 {
		t.Fatalf("retry emitted %d logs; want one late call and three streams", len(logs))
	}
	assertAttrs(t, logs[0], map[string]string{"call_id": "late", "version": "2", "participant_count": "2", "participant_pstn": "1"})
	assertAttrs(t, logs[3], map[string]string{"session_id": "session-page-2", "segment_id": "segment-page-2", "stream_id": "continued"})
	phase = "seen"
	c = newC()
	rec = telemetrytest.New()
	if _, err := c.CollectWindow(t.Context(), hw, now.Add(10*time.Minute), rec.Emitter(), nil); err != nil || len(rec.LogRecords()) != 0 || retryGets != 2 || completedGets != 1 || suffixGets != 1 {
		t.Fatalf("checkpoint did not remember the authoritative version and completed independent calls: late=%d first=%d suffix=%d logs=%d err=%v", retryGets, completedGets, suffixGets, len(rec.LogRecords()), err)
	}
}

func TestSharedCheckpointAndRetentionFloor(t *testing.T) {
	floor := now.Add(-30 * 24 * time.Hour)
	start := floor.Add(time.Hour) // older than the overlap, within source retention
	const id = "within-retention"
	var listStarts int
	var filter string
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/" + id + "?$expand=sessions($expand=segments)":
			return encoded(t, syntheticDetail(t, id, 2, start)), nil
		case absolutePath + "/" + id + "/participants_v2":
			return peoplePage(t), nil
		default:
			listStarts++
			filter = assertList(t, address, prefer)
			return collection(t, "", listEntry(id, 2, start)), nil
		}
	})
	dir := t.TempDir()
	newC := func() *Collector {
		return collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(dir), TenantID: "synthetic-tenant"})
	}
	c := newC()
	rec := telemetrytest.New()
	emitter := telemetry.WithTenant(rec.Emitter(), "synthetic-tenant")
	if err := c.CollectCall(t.Context(), id, emitter, nil); err != nil || len(rec.LogRecords()) != 3 {
		t.Fatalf("direct call did not use the log path: logs=%d err=%v", len(rec.LogRecords()), err)
	}
	if cp := c.CheckpointState(); !cp.Watermark.IsZero() || cp.SeenIDs != 1 {
		t.Fatalf("direct call moved polling checkpoint or did not save its key: %+v", cp)
	}
	c = newC()
	rec = telemetrytest.New()
	if _, err := c.CollectWindow(t.Context(), floor.Add(-24*time.Hour), now, rec.Emitter(), nil); err != nil {
		t.Fatal(err)
	}
	want := "startDateTime ge " + stamp(floor) + " and startDateTime le " + stamp(now)
	if listStarts != 1 || filter != want || len(rec.LogRecords()) != 0 {
		t.Fatalf("retention floor or direct-to-poll dedupe failed: filter=%q, logs=%d", filter, len(rec.LogRecords()))
	}
	if err := c.CollectCall(t.Context(), id, rec.Emitter(), nil); err != nil || len(rec.LogRecords()) != 0 {
		t.Fatalf("seen call must stay deduped outside overlap but inside retention: logs=%d err=%v", len(rec.LogRecords()), err)
	}
}

func TestTraversalLimitAndMissingTime(t *testing.T) {
	t.Run("cap and repeated cursor", func(t *testing.T) {
		for _, tc := range []struct {
			mode string
			gets int
		}{{"repeat", 2}, {"endless", maxContinuationPages}} {
			t.Run(tc.mode, func(t *testing.T) {
				var aux int
				g := fakeGraph(func(address, prefer string) ([]byte, error) {
					switch {
					case address == absolutePath+"/bounded?$expand=sessions($expand=segments)":
						return encoded(t, syntheticDetail(t, "bounded", 1, now.Add(-time.Hour))), nil
					case strings.HasPrefix(address, absolutePath+"/bounded/participants_v2"):
						aux++
						cursor := aux
						if tc.mode == "repeat" {
							cursor = 1
						}
						if aux > maxContinuationPages {
							t.Fatal("unbounded continuation")
						}
						return collection(t, fmt.Sprintf("%s/bounded/participants_v2?$skiptoken=%d", absolutePath, cursor)), nil
					default:
						return collection(t, "", listEntry("bounded", 1, now.Add(-time.Hour))), nil
					}
				})
				c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
				rec := telemetrytest.New()
				outcomes := recordoutcome.NewRecorder()
				hw, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes)
				got := outcomes.Snapshot()
				if err != nil || !hw.Equal(now.Add(-lag)) || aux != tc.gets || len(rec.LogRecords()) != 0 ||
					got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || got.Summarize(err, false).Cause != recordoutcome.CauseSourceError {
					t.Fatalf("auxiliary pagination failure did not stop delivery: gets=%d hw=%v err=%v outcome=%+v", aux, hw, err, got)
				}
				assertDeferred(t, c, checkpoint.DeferredRecord{ID: "bounded", Version: 1, SourceTime: now.Add(-time.Hour)})
			})
		}
	})
	t.Run("no call start", func(t *testing.T) {
		g := fakeGraph(func(address, prefer string) ([]byte, error) {
			if address == absolutePath+"/undated?$expand=sessions($expand=segments)" {
				return []byte(`{"id":"undated","version":1,"startDateTime":"not-a-time"}`), nil
			}
			return collection(t, "", listEntry("undated", 1, now.Add(-time.Hour))), nil
		})
		c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
		rec := telemetrytest.New()
		outcomes := recordoutcome.NewRecorder()
		if _, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes); err != nil || len(rec.LogRecords()) != 0 || outcomes.Snapshot().Counts.Dropped != 1 || c.CheckpointState().SeenIDs != 0 {
			t.Fatalf("undated call was not dropped: %+v; %v", outcomes.Snapshot(), err)
		}
	})
}

func TestStaleOrMissingExpansionDefersDelivery(t *testing.T) {
	for _, tc := range []struct{ name, detail, want string }{
		{"stale detail", `"version":1,"sessions":[]`, "stale ID/version"},
		{"omitted sessions", `"version":2`, "sessions: expected expanded collection was absent"},
		{"omitted segments", `"version":2,"sessions":[{"id":"no-segments"}]`, "segments: expected expanded collection was absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := now.Add(-time.Hour)
			g := fakeGraph(func(address, prefer string) ([]byte, error) {
				switch address {
				case absolutePath + "/incomplete?$expand=sessions($expand=segments)":
					return fmt.Appendf(nil, `{"id":"incomplete","startDateTime":%q,%s}`, stamp(start), tc.detail), nil
				case absolutePath + "/incomplete/participants_v2":
					return collection(t, ""), nil
				default:
					assertList(t, address, prefer)
					return collection(t, "", listEntry("incomplete", 2, start)), nil
				}
			})
			c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
			rec := telemetrytest.New()
			outcomes := recordoutcome.NewRecorder()
			hw, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, rec.Emitter(), outcomes)
			got := outcomes.Snapshot()
			if err != nil || !hw.Equal(now.Add(-lag)) || c.CheckpointState().SeenIDs != 0 || len(rec.LogRecords()) != 0 ||
				got.Counts != (recordoutcome.Counts{Fetched: 1, Errored: 1}) || got.Summarize(err, false).Cause != recordoutcome.CauseSourceError {
				t.Fatalf("incomplete version was not durably deferred: %v; %v; %+v", hw, err, got)
			}
			assertDeferred(t, c, checkpoint.DeferredRecord{ID: "incomplete", Version: 2, SourceTime: start})
			// The direct seam has no list version hint. The stale response is
			// instead covered by the queued hint and the zero emitted/seen keys.
			if tc.name != "stale detail" {
				if err := c.CollectCall(t.Context(), "incomplete", rec.Emitter(), nil); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("direct hydration lost the reason expansion was incomplete: %v", err)
				}
			}
		})
	}
}

func TestTraceRouteFitsOTLPBudget(t *testing.T) {
	start := now.Add(-time.Hour)
	d := syntheticDetail(t, "bounded-trace", 1, start)
	media := d["sessions"].([]any)[0].(map[string]any)["segments"].([]any)[0].(map[string]any)["media"].([]any)[0].(map[string]any)
	network := media["callerNetwork"].(map[string]any)
	hops := make([]any, 60)
	for i := range hops {
		hops[i] = map[string]any{"hopCount": i + 1, "ipAddress": "2001:db8::10", "roundTripTime": "PT0.005S"}
	}
	network["traceRouteHops"] = hops
	network["wifiVendorDriver"] = strings.Repeat("λ", telemetry.MaxAttributeBytes)
	g := fakeGraph(func(address, prefer string) ([]byte, error) {
		switch address {
		case absolutePath + "/bounded-trace?$expand=sessions($expand=segments)":
			return encoded(t, d), nil
		case absolutePath + "/bounded-trace/participants_v2":
			return peoplePage(t), nil
		default:
			return collection(t, "", listEntry("bounded-trace", 1, start)), nil
		}
	})
	c := collectorForTest(t, collectors.WindowDeps{Graph: g, Store: checkpoint.NewStore(t.TempDir()), TenantID: "synthetic-tenant"})
	rec := telemetrytest.New()
	e := telemetry.WithAttributeBudget(rec.Emitter(), telemetry.MaxAttributeBytes, Name, "synthetic-tenant", telemetry.TransportGraph)
	if _, err := c.CollectWindow(t.Context(), now.Add(-2*time.Hour), now, e, nil); err != nil {
		t.Fatal(err)
	}
	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d records, want one call and two valid streams", len(logs))
	}
	a := logs[1].Attrs
	var bounded []Hop
	if err := json.Unmarshal([]byte(a["caller_trace_route_hops"]), &bounded); err != nil || len(bounded) == 0 || len(bounded) >= len(hops) || bounded[0].IP != "2001:db8::10" {
		t.Fatalf("expected a bounded, valid JSON trace route prefix; hops=%d err=%v", len(bounded), err)
	}
	if a["caller_trace_route_hops_omitted"] != strconv.Itoa(len(hops)-len(bounded)) || a["text_fields_truncated"] != "1" || a["attrs.truncated"] != "" {
		t.Fatal("collector did not account for the bounded evidence before the final sink guard")
	}
}

func TestTeamsProfileDefault(t *testing.T) {
	entry := newCollector(collectors.WindowDeps{})
	membership, defaultOn, err := collector.ProfilePolicy(entry.Collector)
	if err != nil || membership != collector.ProfileTeams || defaultOn != collector.ProfileTeams {
		t.Fatalf("census profile membership/default = %v/%v; %v", membership, defaultOn, err)
	}
	if entry.InitialLookback < 30*time.Hour+150*time.Minute {
		t.Fatalf("cold window does not reach the documented horizon: %v", entry.InitialLookback)
	}
}
