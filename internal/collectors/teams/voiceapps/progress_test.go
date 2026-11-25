package voiceapps

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/vaacclient"
)

func TestVoiceAppsResumesDenseOverlap(t *testing.T) {
	for _, tc := range []struct {
		budget       string
		groups, rows int
		spacing      time.Duration
	}{
		{"request", 12, 2001, 30 * time.Minute},
		{"row", 8, 3000, 52*time.Minute + 30*time.Second},
	} {
		t.Run(tc.budget, func(t *testing.T) {
			testDenseOverlap(t, tc.budget, tc.groups, tc.rows, tc.spacing)
		})
	}
}

func testDenseOverlap(t *testing.T, budget string, groupCount, groupSize int, spacing time.Duration) {
	t.Helper()
	anchor := time.Date(2000, 1, 1, 10, 0, 0, 0, time.UTC)
	target := anchor.Add(time.Hour)
	floor := anchor.Add(-6 * time.Hour)
	type group struct {
		at   time.Time
		rows []map[string]any
	}
	var groups []group
	want := make(map[string]bool)
	add := func(at time.Time, size int) {
		_, sample := fixtureRows(at.Format(time.RFC3339Nano))
		g := group{at: at}
		for i := range size {
			id := fmt.Sprintf("synthetic-leg-%d-%d", len(groups), i)
			row := maps.Clone(sample[0])
			row["DialogId"] = id
			g.rows = append(g.rows, row)
			want[id] = true
		}
		groups = append(groups, g)
	}
	// Every cluster fits; the whole scan exceeds the selected budget. The
	// final AA and CQ legs are past the first complete prefix of either case.
	for i := range groupCount {
		add(floor.Add(time.Duration(i)*spacing+500*time.Millisecond), groupSize)
	}
	tailTime := target.Add(-time.Second)
	add(tailTime, 1)
	lastID := fmt.Sprintf("synthetic-leg-%d-0", groupCount)
	aa, _ := fixtureRows(tailTime.Format(time.RFC3339))
	const tailAA = "synthetic-aa-tail"
	want[tailAA] = true

	var aaRequests, cqRequests int
	var firstCQ time.Time
	failCQ := false
	rt := fakeWire(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return reply(http.StatusOK, `{"access_token":"`+fixtureToken+`","expires_in":3600}`), nil
		}
		q := decodeFixtureQuery(t, r)
		lo, errLo := time.Parse(time.RFC3339, q.Filters[0].Value)
		hi, errHi := time.Parse(time.RFC3339, q.Filters[1].Value)
		if errLo != nil || errHi != nil {
			t.Fatal("invalid source interval")
		}
		if q.Filters[2].DataModelName == "HasAA" {
			aaRequests++
			if !tailTime.Before(lo) && !tailTime.After(hi) {
				return fixtureReply(t, q, aa[:1]), nil
			}
			return reply(http.StatusOK, `{"dataResult":[]}`), nil
		}
		cqRequests++
		if cqRequests == 1 {
			firstCQ = lo
		}
		if failCQ {
			return reply(http.StatusForbidden, fixturePassword), nil
		}
		var rows []map[string]any
		for _, g := range groups {
			if !g.at.Before(lo) && !g.at.After(hi) {
				rows = append(rows, g.rows...)
			}
		}
		if len(rows) >= q.LimitResultRowsCount {
			return fixtureReply(t, q, rows[:q.LimitResultRowsCount]), nil
		}
		if len(rows) == 0 {
			return reply(http.StatusOK, `{"dataResult":[]}`), nil
		}
		return fixtureReply(t, q, rows), nil
	})
	dir := t.TempDir()
	store := checkpoint.NewStore(dir)
	cp, err := store.Load(fixtureTenant, name)
	if err != nil {
		t.Fatal(err)
	}
	cp.Watermark = anchor
	if err := store.Save(cp); err != nil {
		t.Fatal(err)
	}
	user, pass := writeFixtureFiles(t)
	client, err := vaacclient.New(fixtureTenant, user, pass, rt)
	if err != nil {
		t.Fatal(err)
	}
	poll := func(to time.Time, expectSavedBatch bool) (time.Time, []string, error) {
		t.Helper()
		aaRequests, cqRequests = 0, 0
		c := &voiceApps{client: client, store: checkpoint.NewStore(dir), tenantID: fixtureTenant}
		out := telemetrytest.New()
		hwm, err := c.CollectWindow(t.Context(), anchor, to, out.Emitter(), recordoutcome.NewRecorder())
		var ids []string
		var cqCount int
		var batchKnown string
		for _, r := range out.LogRecords() {
			switch r.EventName {
			case aaEvent:
				if !r.Timestamp.Equal(tailTime) {
					t.Fatal("unexpected AA leg timestamp")
				}
				ids = append(ids, tailAA)
			case cqEvent:
				cqCount++
				ids = append(ids, r.Attrs["dialog_id"])
			case queueBatch:
				if batchKnown != "" || r.Attrs["queue"] != fixtureCQ {
					t.Fatal("unexpected saved batch queue or duplicate summary")
				}
				batchKnown = r.Attrs["known_result_legs"]
			default:
				t.Fatalf("unexpected event %s", r.EventName)
			}
		}
		wantBatch := ""
		if expectSavedBatch && cqCount > 0 {
			wantBatch = strconv.Itoa(cqCount)
		}
		if batchKnown != wantBatch {
			t.Fatalf("saved-batch count = %q, want %q for %d CQ legs", batchKnown, wantBatch, cqCount)
		}
		if aaRequests > 17 || cqRequests > 17 || len(ids) > 20000 {
			t.Fatalf("poll exceeded a stream budget: AA=%d CQ=%d rows=%d", aaRequests, cqRequests, len(ids))
		}
		return hwm, ids, err
	}
	seen := make(map[string]bool)
	remember := func(ids []string) {
		t.Helper()
		for _, id := range ids {
			if !want[id] || seen[id] {
				t.Fatalf("unexpected or replayed persisted leg %q", id)
			}
			seen[id] = true
		}
	}
	watermark := func() time.Time {
		t.Helper()
		cp, err := store.Load(fixtureTenant, name)
		if err != nil {
			t.Fatal(err)
		}
		return cp.Watermark
	}
	hw, ids, err := poll(target, true)
	if len(ids) == 0 || hw.Equal(target) || !watermark().Equal(anchor) || err == nil || !strings.Contains(err.Error(), "exceeded "+budget+" limit") {
		t.Fatalf("dense overlap pinned the first poll or crossed an incomplete interval: rows=%d, watermark=%v, err=%v", len(ids), hw, err)
	}
	remember(ids)
	if seen[tailAA] || seen[lastID] {
		t.Fatal("emitted tail beyond the jointly complete prefix")
	}
	failCQ = true
	hw, ids, err = poll(target, false)
	if err == nil || strings.Contains(err.Error(), fixturePassword) || len(ids) != 0 || hw.Equal(target) || !watermark().Equal(anchor) || !firstCQ.After(floor) {
		t.Fatalf("failed CQ query crossed or restarted the persisted prefix: rows=%d, start=%v, watermark=%v, err=%v", len(ids), firstCQ, hw, err)
	}
	failCQ = false
	resume := firstCQ
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one atomic checkpoint, found %d: %v", len(files), err)
	}
	if err := os.Mkdir(files[0]+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	hw, _, err = poll(target, false)
	if err == nil || !strings.Contains(err.Error(), "save VAAC checkpoint") || hw.Equal(target) || !watermark().Equal(anchor) || !firstCQ.Equal(resume) {
		t.Fatalf("failed save crossed or restarted the persisted prefix: start=%v, watermark=%v, err=%v", firstCQ, hw, err)
	}
	if err := os.Remove(files[0] + ".tmp"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12 && !hw.Equal(target); i++ {
		hw, ids, err = poll(target, true)
		if i == 0 && !firstCQ.Equal(resume) {
			t.Fatal("restart skipped the prefix whose save failed")
		}
		remember(ids)
	}
	if err != nil || !hw.Equal(target) || !watermark().Equal(target) || len(seen) != len(want) || !seen[lastID] || !seen[tailAA] {
		t.Fatalf("resumed overlap lost legs or never reached forward data: rows=%d/%d, watermark=%v, err=%v", len(seen), len(want), hw, err)
	}
}
