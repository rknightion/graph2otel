package main

// Blank imports register every collector's Factory (via each subpackage's
// init()) into internal/collectors, which the tenant loop then constructs,
// gates, and schedules. Adding a collector = adding one line here; the wiring
// in tenants.go never changes.
import (
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/directorycounts"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/domains"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/groups"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/licensing"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/organization"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/risk"
)
