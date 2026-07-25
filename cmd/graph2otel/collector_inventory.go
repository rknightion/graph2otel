package main

import "github.com/rknightion/graph2otel/internal/collectors"

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
