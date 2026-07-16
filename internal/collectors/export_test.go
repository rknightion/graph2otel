package collectors

import "time"

// SetFleetClock overrides a CachingFleetFetcher's clock for deterministic TTL
// tests. Test-only seam (export_test.go is compiled only under `go test`).
func SetFleetClock(f *CachingFleetFetcher, now func() time.Time) { f.now = now }
