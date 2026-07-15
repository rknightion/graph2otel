package main

// Blank imports register every collector's Factory (via each subpackage's
// init()) into internal/collectors, which the tenant loop then constructs,
// gates, and schedules. Adding a collector = adding one line here; the wiring
// in tenants.go never changes.
import (
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/agreements"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/authmethodspolicy"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/conditionalaccess"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/consent"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/credentialexpiry"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/devices"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/directoryaudits"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/directorycounts"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/domains"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/groups"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/licensing"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/mfaregistration"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/organization"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/provisioning"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/recommendations"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/risk"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/riskdetections"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/roles"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/securescore"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/securityalerts"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/signinactivity"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/signins"
	_ "github.com/rknightion/graph2otel/internal/collectors/entra/users"
)
