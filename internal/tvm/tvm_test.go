package tvm

import "testing"

func TestStr(t *testing.T) {
	m := map[string]any{"s": "hello", "num": 4.3, "null": map[string]any{}}
	if got := Str(m, "s"); got != "hello" {
		t.Errorf("Str(s) = %q, want hello", got)
	}
	if got := Str(m, "num"); got != "" {
		t.Errorf("Str(num) = %q, want empty (non-string)", got)
	}
	// A null datetime/dynamic arrives as {} — Str must return "", not stringify it.
	if got := Str(m, "null"); got != "" {
		t.Errorf("Str(null-as-empty-map) = %q, want empty", got)
	}
	if got := Str(m, "absent"); got != "" {
		t.Errorf("Str(absent) = %q, want empty", got)
	}
}

func TestSByteBool(t *testing.T) {
	// The hunting API encodes booleans as SByte numbers, so a bool assertion would
	// fail — SByteBool reads the float64.
	m := map[string]any{"yes": float64(1), "no": float64(0), "realbool": true}
	if v, ok := SByteBool(m, "yes"); !ok || !v {
		t.Errorf("SByteBool(1) = (%v,%v), want (true,true)", v, ok)
	}
	if v, ok := SByteBool(m, "no"); !ok || v {
		t.Errorf("SByteBool(0) = (%v,%v), want (false,true)", v, ok)
	}
	// A genuine JSON bool is NOT how this API encodes booleans; treat it as absent
	// rather than silently accepting it, so a wire-shape regression is caught.
	if _, ok := SByteBool(m, "realbool"); ok {
		t.Error("SByteBool should report a JSON bool as not-a-number (this API uses SByte)")
	}
	if _, ok := SByteBool(m, "absent"); ok {
		t.Error("SByteBool(absent) should be ok=false")
	}
}

// TestPlanPartitions_NoTruncation is the #249 guarantee: for any row count and
// cap, the shards tile the rows with no gap (each is 0..Of-1, all share one Of),
// there is always at least one, and Of*cap covers the count — so a fetch can
// never silently drop rows past the 100k ceiling.
func TestPlanPartitions_NoTruncation(t *testing.T) {
	cases := []struct {
		count  int64
		cap    int
		wantOf int
	}{
		{count: 0, cap: 90_000, wantOf: 1},
		{count: 1, cap: 90_000, wantOf: 1},
		{count: 90_000, cap: 90_000, wantOf: 1},  // exactly at cap: still one query
		{count: 90_001, cap: 90_000, wantOf: 2},  // one over: must shard
		{count: 24_912, cap: 90_000, wantOf: 1},  // m7kni today
		{count: 250_000, cap: 90_000, wantOf: 3}, // large tenant
		{count: 1_000_000, cap: 100_000, wantOf: 10},
	}
	for _, tc := range cases {
		parts := PlanPartitions(tc.count, tc.cap)
		if len(parts) != tc.wantOf {
			t.Errorf("PlanPartitions(%d, %d): got %d partitions, want %d", tc.count, tc.cap, len(parts), tc.wantOf)
			continue
		}
		// Coverage: Of shards each capped at `cap` must cover the whole count.
		if int64(len(parts))*int64(tc.cap) < tc.count {
			t.Errorf("PlanPartitions(%d, %d): %d shards * %d cap does not cover the count — rows would be truncated",
				tc.count, tc.cap, len(parts), tc.cap)
		}
		// Every shard shares one Of and the shard indices are exactly 0..Of-1.
		seen := map[int]bool{}
		for _, p := range parts {
			if p.Of != len(parts) {
				t.Errorf("shard %+v has Of=%d, want %d", p, p.Of, len(parts))
			}
			if p.Shard < 0 || p.Shard >= len(parts) {
				t.Errorf("shard index %d out of range [0,%d)", p.Shard, len(parts))
			}
			if seen[p.Shard] {
				t.Errorf("shard %d appears twice — an overlap/gap", p.Shard)
			}
			seen[p.Shard] = true
		}
	}
}

func TestPartitionPredicate(t *testing.T) {
	// A single-partition plan emits no predicate — the base query is unfiltered.
	if got := (Partition{Shard: 0, Of: 1}).Predicate("DeviceId"); got != "" {
		t.Errorf("Of=1 predicate = %q, want empty", got)
	}
	got := (Partition{Shard: 2, Of: 3}).Predicate("DeviceId")
	want := ` | where hash(DeviceId, 3) == 2`
	if got != want {
		t.Errorf("Predicate = %q, want %q", got, want)
	}
}

func TestPlanPartitions_ZeroCapFallsBackToHardCap(t *testing.T) {
	parts := PlanPartitions(HardRowCap+1, 0)
	if len(parts) != 2 {
		t.Errorf("cap<=0 should fall back to HardRowCap: got %d partitions, want 2", len(parts))
	}
}
