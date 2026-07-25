package main

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
)

// registrationContractVisitor is deliberately a separate implementation of
// collectorFactoryVisitor. If a registration family is added, the interface
// change makes this test, runtime, preflight, and collector documentation fail
// to compile until every consumer handles it.
type registrationContractVisitor struct {
	snapshot int
	window   int
	blob     int
	o365     int
	mdca     int
	exo      int
	hunt     int
}

func (v *registrationContractVisitor) Snapshot(fs []collectors.Factory)     { v.snapshot = len(fs) }
func (v *registrationContractVisitor) Window(fs []collectors.WindowFactory) { v.window = len(fs) }
func (v *registrationContractVisitor) Blob(fs []collectors.BlobFactory)     { v.blob = len(fs) }
func (v *registrationContractVisitor) O365(fs []collectors.O365Factory)     { v.o365 = len(fs) }
func (v *registrationContractVisitor) MDCA(fs []collectors.MDCAFactory)     { v.mdca = len(fs) }
func (v *registrationContractVisitor) EXO(fs []collectors.EXOFactory)       { v.exo = len(fs) }
func (v *registrationContractVisitor) Hunt(fs []collectors.HuntFactory)     { v.hunt = len(fs) }

var _ collectorFactoryVisitor = (*registrationContractVisitor)(nil)

func TestVisitRegisteredCollectorFactoriesVisitsEveryFamily(t *testing.T) {
	var visitor registrationContractVisitor
	visitRegisteredCollectorFactories(&visitor)
	if visitor.snapshot == 0 || visitor.window == 0 || visitor.blob == 0 || visitor.o365 == 0 || visitor.mdca == 0 || visitor.exo == 0 || visitor.hunt == 0 {
		t.Fatalf("visitor missed a registration family: %+v", visitor)
	}
}
