// Package deps exists only during M1 build-out. It blank-imports the
// third-party modules the M1 framework packages will depend on, so those
// modules are pinned in go.mod/go.sum up front and every parallel lane can
// build and test its own package WITHOUT touching go.mod (which would race
// across concurrent lanes).
//
// TEMPORARY: delete this file at the M1 wiring pass, once the real packages
// import these modules directly, then run `go mod tidy`.
package deps

import (
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	_ "go.opentelemetry.io/otel"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	_ "go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	_ "go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	_ "go.opentelemetry.io/otel/sdk/log"
	_ "go.opentelemetry.io/otel/sdk/metric"
	_ "golang.org/x/time/rate"
)
