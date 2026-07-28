package exofanout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/exofanout"
)

// fakeEXO is a canned EXOClient: no live tenant, no Exchange grants, no HTTP.
type fakeEXO struct {
	rows    []map[string]any
	err     error
	cmdlet  string
	params  map[string]any
	callSeq int
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	f.cmdlet = cmdlet
	f.params = params
	f.callSeq++
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

func mailboxRows(addrs ...string) []map[string]any {
	out := make([]map[string]any, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, map[string]any{
			"PrimarySmtpAddress":   a,
			"DisplayName":          "dn-" + a,
			"Identity":             "id-" + a,
			"RecipientTypeDetails": "UserMailbox",
		})
	}
	return out
}

func TestEnumeratePinsResultSizeUnlimited(t *testing.T) {
	// The default page for Get-Mailbox is undocumented and a truncated page
	// still returns HTTP 200, so a missing ResultSize silently under-reports
	// the TOTAL — which would make the truncation signal itself a lie.
	f := &fakeEXO{rows: mailboxRows("b@x", "a@x")}
	if _, err := exofanout.Enumerate(context.Background(), f, 10); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if f.cmdlet != "Get-Mailbox" {
		t.Errorf("cmdlet = %q, want Get-Mailbox", f.cmdlet)
	}
	if got := f.params["ResultSize"]; got != "Unlimited" {
		t.Errorf("ResultSize = %v, want Unlimited", got)
	}
}

func TestEnumerateSortsDeterministically(t *testing.T) {
	// Which mailboxes fall inside the cap must not depend on the order the
	// service happened to return them, or the covered set silently churns
	// between cycles and the gauges become uninterpretable.
	f := &fakeEXO{rows: mailboxRows("delta@x", "alpha@x", "charlie@x", "bravo@x")}
	got, err := exofanout.Enumerate(context.Background(), f, 2)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got.Mailboxes) != 2 {
		t.Fatalf("covered %d mailboxes, want 2", len(got.Mailboxes))
	}
	if got.Mailboxes[0].PrimarySmtpAddress != "alpha@x" || got.Mailboxes[1].PrimarySmtpAddress != "bravo@x" {
		t.Errorf("got %q,%q; want alpha@x,bravo@x",
			got.Mailboxes[0].PrimarySmtpAddress, got.Mailboxes[1].PrimarySmtpAddress)
	}
}

func TestEnumerateReportsTotalNotCoveredWhenTruncated(t *testing.T) {
	// The whole point of the cap decision: partial data is acceptable, partial
	// data that LOOKS complete is not. Total must survive truncation.
	f := &fakeEXO{rows: mailboxRows("a@x", "b@x", "c@x", "d@x", "e@x")}
	got, err := exofanout.Enumerate(context.Background(), f, 2)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if got.Total != 5 {
		t.Errorf("Total = %d, want 5", got.Total)
	}
	if got.Covered != 2 {
		t.Errorf("Covered = %d, want 2", got.Covered)
	}
	if !got.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestEnumerateNotTruncatedWhenUnderCap(t *testing.T) {
	f := &fakeEXO{rows: mailboxRows("a@x", "b@x")}
	got, err := exofanout.Enumerate(context.Background(), f, 250)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if got.Total != 2 || got.Covered != 2 {
		t.Errorf("Total/Covered = %d/%d, want 2/2", got.Total, got.Covered)
	}
	if got.Truncated {
		t.Error("Truncated = true, want false")
	}
}

func TestEnumerateEmptyTenantIsNotAnError(t *testing.T) {
	// An empty result is a measured fact, not a failure.
	f := &fakeEXO{rows: nil}
	got, err := exofanout.Enumerate(context.Background(), f, 250)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if got.Total != 0 || got.Covered != 0 || got.Truncated {
		t.Errorf("got Total=%d Covered=%d Truncated=%v, want 0/0/false",
			got.Total, got.Covered, got.Truncated)
	}
}

func TestEnumeratePropagatesError(t *testing.T) {
	// A transport failure must NOT read as an empty tenant: zero mailboxes and
	// "could not look" are opposite facts.
	sentinel := errors.New("boom")
	f := &fakeEXO{err: sentinel}
	if _, err := exofanout.Enumerate(context.Background(), f, 250); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped %v", err, sentinel)
	}
}

func TestEnumerateSkipsRowsWithNoPrimarySmtpAddress(t *testing.T) {
	// Every per-mailbox cmdlet is addressed by -Identity <smtp>. A row with no
	// address cannot be queried, so counting it as covered would overstate
	// coverage; it still counts toward Total, which is what was really there.
	rows := mailboxRows("a@x", "b@x")
	rows = append(rows, map[string]any{"DisplayName": "no address"})
	f := &fakeEXO{rows: rows}
	got, err := exofanout.Enumerate(context.Background(), f, 250)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if got.Total != 3 {
		t.Errorf("Total = %d, want 3 (the addressless row existed)", got.Total)
	}
	if got.Covered != 2 {
		t.Errorf("Covered = %d, want 2 (the addressless row is not addressable)", got.Covered)
	}
	if !got.Truncated {
		t.Error("Truncated = false; an unaddressable row means coverage < total")
	}
}

func TestEnumerateZeroCapMeansUnlimited(t *testing.T) {
	// Defensive only: config validation rejects <1, but a zero reaching here
	// must not silently collect NOTHING and report success.
	f := &fakeEXO{rows: mailboxRows("a@x", "b@x", "c@x")}
	got, err := exofanout.Enumerate(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if got.Covered != 3 || got.Truncated {
		t.Errorf("Covered=%d Truncated=%v, want 3/false", got.Covered, got.Truncated)
	}
}
