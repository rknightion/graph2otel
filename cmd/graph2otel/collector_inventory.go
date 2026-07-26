package main

import (
	"context"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exoclient"
)

// collectorFactoryVisitor is the one registration-family contract shared by
// runtime wiring, permission preflight, and the collector-documentation gate.
// Adding an eighth family extends this interface, which makes every independent
// consumer fail to compile until it explicitly handles the new path.
type collectorFactoryVisitor interface {
	Snapshot([]collectors.Factory)
	Window([]collectors.WindowFactory)
	Blob([]collectors.BlobFactory)
	O365([]collectors.O365Factory)
	MDCA([]collectors.MDCAFactory)
	EXO([]collectors.EXOFactory)
	Hunt([]collectors.HuntFactory)
}

func visitRegisteredCollectorFactories(visitor collectorFactoryVisitor) {
	visitor.Snapshot(collectors.All())
	visitor.Window(collectors.WindowAll())
	visitor.Blob(collectors.BlobAll())
	visitor.O365(collectors.O365All())
	visitor.MDCA(collectors.MDCAAll())
	visitor.EXO(collectors.EXOAll())
	visitor.Hunt(collectors.HuntAll())
}

// inertEXO satisfies both collectors.EXOClient and the InvokeFull seam an
// EXO-backed window collector narrows to. Inventory consumers construct
// collectors only to inspect bounded metadata; this client is never invoked.
type inertEXO struct{}

func (inertEXO) Invoke(context.Context, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

func (inertEXO) InvokeFull(context.Context, string, map[string]any) (exoclient.InvokeResult, error) {
	return exoclient.InvokeResult{}, nil
}

// snapshotWindowDeps supplies the inert seams a window factory may condition
// on. Keeping it beside the shared seven-path visitor prevents the availability
// and documentation inventories from independently going blind when a factory
// declines on a zero dependency.
func snapshotWindowDeps() collectors.WindowDeps {
	return collectors.WindowDeps{
		EXO:   inertEXO{},
		Store: checkpoint.NewStore(""),
	}
}
