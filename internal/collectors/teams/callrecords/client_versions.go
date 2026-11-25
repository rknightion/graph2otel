package callrecords

import (
	"maps"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

type clientBucket struct{ platform, family, version string }

type versionWindow map[time.Time]map[clientBucket]float64

func clientBuckets(e telemetry.Emitter, clients []Agent) map[clientBucket]bool {
	buckets := make(map[clientBucket]bool)
	for _, client := range clients {
		buckets[clientBucket{
			platforms.watch(e, "platform", client.Platform),
			products.watch(e, "productFamily", client.ProductFamily),
			versionBucket(client.Version),
		}] = true
	}
	return buckets
}

func (w *versionWindow) add(end, now time.Time, buckets map[clientBucket]bool) {
	minute := end.Truncate(time.Minute)
	if minute.Before(versionFloor(now)) || len(buckets) == 0 {
		return
	}
	if *w == nil {
		*w = make(versionWindow)
	}
	counts := (*w)[minute]
	if counts == nil {
		counts = make(map[clientBucket]float64)
		(*w)[minute] = counts
	}
	for bucket := range buckets {
		counts[bucket]++
	}
}

func versionFloor(now time.Time) time.Time {
	return now.Truncate(time.Minute).Add(-59 * time.Minute)
}

func (w versionWindow) publish(e telemetry.Emitter, now time.Time) {
	floor := versionFloor(now)
	maps.DeleteFunc(w, func(minute time.Time, _ map[clientBucket]float64) bool {
		return minute.Before(floor) || minute.After(now)
	})
	totals := make(map[clientBucket]float64)
	for _, counts := range w {
		for bucket, count := range counts {
			totals[bucket] += count
		}
	}
	points := make([]telemetry.GaugePoint, 0, len(totals))
	for bucket, value := range totals {
		points = append(points, telemetry.GaugePoint{Value: value, Attrs: telemetry.Attrs{
			semconv.AttrPlatform: bucket.platform, semconv.AttrTeamsProductFamily: bucket.family,
			semconv.AttrTeamsVersionBucket: bucket.version,
		}})
	}
	e.GaugeSnapshot(metricVersions, "{call}", "First accepted Teams calls since process start with a client in the bucket, in the latest 60 call-end minutes.", points)
}
