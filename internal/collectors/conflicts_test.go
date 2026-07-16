package collectors_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
)

// plainFake is a collector that declares no conflicts — the overwhelming
// majority of the registry.
type plainFake struct{ name string }

func (p plainFake) Name() string                   { return p.name }
func (p plainFake) DefaultInterval() time.Duration { return time.Minute }

// declaringFake is a collector that declares it is a second transport for
// records its peers already emit.
type declaringFake struct {
	plainFake
	peers []string
}

func (d declaringFake) ConflictsWith() []string { return d.peers }

func plain(name string) collector.Collector { return plainFake{name: name} }

func declaring(name string, peers ...string) collector.Collector {
	return declaringFake{plainFake: plainFake{name: name}, peers: peers}
}

// TestCheckConflicts_FiresWhenBothTransportsAreRegistered is the core claim:
// a declarer plus its named peer is the double-ship state, and it must not be
// allowed to start.
func TestCheckConflicts_FiresWhenBothTransportsAreRegistered(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		plain("entra.users"),
		declaring("a.blob", "a"),
		plain("a"),
	})
	if err == nil {
		t.Fatal("CheckConflicts returned nil for a registered conflicting pair — a config in this state ships every record twice while reporting healthy")
	}
}

// TestCheckConflicts_ErrorNamesBothCollectorsAndTheFix pins the error's
// content, not just its existence. An error that says "conflict detected" and
// nothing else leaves the operator exactly where they started: the whole point
// of failing fast is that the message resolves the failure.
func TestCheckConflicts_ErrorNamesBothCollectorsAndTheFix(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		declaring("a.blob", "a"),
		plain("a"),
	})
	if err == nil {
		t.Fatal("want an error for a registered conflicting pair, got nil")
	}
	got := err.Error()
	for _, want := range []string{"a.blob", `"a"`, "enabled: false", "collectors."} {
		if !strings.Contains(got, want) {
			t.Errorf("error message does not mention %q — an operator cannot act on it:\n%s", want, got)
		}
	}
}

// TestCheckConflicts_SilentWhenOnlyTheDeclarerIsRegistered is the everyday
// case: blob ingest configured, the polled beta twin left off. That is the
// SUPPORTED way to run this product and must start.
func TestCheckConflicts_SilentWhenOnlyTheDeclarerIsRegistered(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		plain("entra.users"),
		declaring("a.blob", "a"),
	})
	if err != nil {
		t.Fatalf("CheckConflicts fired with only the declarer registered: %v", err)
	}
}

// TestCheckConflicts_SilentWhenOnlyThePeerIsRegistered is the mirror: the
// polled collector on its own, no blob ingest. The declaration lives on the
// blob twin, so nothing is even asserting here — this pins that a peer NAME
// alone (present in some other collector's list) never fires.
func TestCheckConflicts_SilentWhenOnlyThePeerIsRegistered(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		plain("entra.users"),
		plain("a"),
	})
	if err != nil {
		t.Fatalf("CheckConflicts fired with only the peer registered: %v", err)
	}
}

// TestCheckConflicts_SilentWhenNothingDeclares guards the default deployment:
// a registry of collectors that implement no optional interface must start.
func TestCheckConflicts_SilentWhenNothingDeclares(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		plain("entra.users"), plain("entra.groups"), plain("intune.devices"),
	})
	if err != nil {
		t.Fatalf("CheckConflicts fired over a registry with no declarations: %v", err)
	}
}

// TestCheckConflicts_ReportsEveryConflictingPair pins that the check does not
// stop at the first pair. An operator in the conflicting state on three lanes
// should fix all three from one boot, not rediscover them one restart at a
// time.
func TestCheckConflicts_ReportsEveryConflictingPair(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		declaring("a.blob", "a"), plain("a"),
		declaring("b.blob", "b"), plain("b"),
	})
	if err == nil {
		t.Fatal("want an error for two registered conflicting pairs, got nil")
	}
	for _, want := range []string{"a.blob", "b.blob"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits the %q pair — one boot must surface every conflict:\n%s", want, err)
		}
	}
}

// TestCheckConflicts_ReportsAMutualPairOnce guards against the obvious
// double-count: nothing declares mutually today, but the interface does not
// forbid it, and "a and b" plus "b and a" is one problem printed twice.
func TestCheckConflicts_ReportsAMutualPairOnce(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{
		declaring("a", "b"),
		declaring("b", "a"),
	})
	if err == nil {
		t.Fatal("want an error for a mutually-declared conflicting pair, got nil")
	}
	if n := strings.Count(err.Error(), "are both enabled"); n != 1 {
		t.Errorf("mutual pair reported %d times, want 1:\n%s", n, err)
	}
}

// TestCheckConflicts_IgnoresASelfDeclaration guards a copy-paste in a spec
// table: a collector naming itself is registered by definition, so a naive
// membership test would refuse to start on every boot.
func TestCheckConflicts_IgnoresASelfDeclaration(t *testing.T) {
	err := collectors.CheckConflicts([]collector.Collector{declaring("a", "a")})
	if err != nil {
		t.Fatalf("CheckConflicts fired on a self-declaration: %v", err)
	}
}
