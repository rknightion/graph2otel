// Package exofanout is the shared per-mailbox fan-out gate for the Exchange
// Online collectors that must call one cmdlet PER MAILBOX (#355 mailbox
// delegation, #363 inbox rules).
//
// # Why a shared gate rather than a per-collector one
//
// Both collectors have the same cost shape and neither has a batch form on
// this transport. Live-measured 2026-07-28 against m7kni, app-only as
// graph2otel-poller:
//
//   - Get-MailboxPermission    846 ms/mailbox
//   - Get-RecipientPermission  602 ms/mailbox  (so #355 is 1+2N, ~1.45 s/mailbox)
//   - Get-InboxRule            995 ms/mailbox  (so #363 is 1+N)
//
// At 5,000 mailboxes that is ~121 min and ~83 min PER CYCLE. The enumeration
// (Get-Mailbox) is identical for both, so sharing one gate also means one
// enumeration rather than two.
//
// # This is NOT HighVolume, and that distinction is load-bearing
//
// The obvious move is to reuse the HighVolume opt-in. It would be wrong.
// HighVolume in this project means a firehose whose rate scales with TRAFFIC
// (m365.message_trace: one record per message per recipient). Per-mailbox
// fan-out scales with TENANT SIZE — a 5,000-mailbox tenant with zero mail flow
// still pays the full two hours. Experimental fits even worse: that flag is
// reserved for genuine Graph BETA surfaces (#183) and this is Exchange Online
// PowerShell, a GA transport. Labeling either way would tell an operator
// something false about why the collector is gated.
//
// So this is a third gate: an explicit per-tenant opt-in plus an explicit cap.
//
// # Truncation is a SIGNAL, never a silent floor
//
// The cap means partial coverage on a large tenant. Partial data is acceptable;
// partial data that looks complete is not. Enumerate therefore always reports
// Total (what the tenant really has) alongside Covered (what fits under the
// cap), so a collector can emit both and an operator can alert on
// covered < total. A cap that quietly collected the first N and reported clean
// success would report healthy over an unknown remainder — the failure mode
// this project treats as worse than not collecting at all.
//
// The covered set is chosen by sorting on PrimarySmtpAddress, NOT by the order
// the service returned rows. Service order is not documented as stable, and an
// unstable covered set would churn which mailboxes are represented between
// cycles, making both the gauges and the twins uninterpretable.
package exofanout

import (
	"context"
	"fmt"
	"sort"
)

// cmdletGetMailbox enumerates the tenant's mailboxes.
const cmdletGetMailbox = "Get-Mailbox"

// paramResultSize / resultSizeUnlimited defeat the default page. Load-bearing:
// the default page size for Get-Mailbox is undocumented and a truncated page
// still returns HTTP 200, so without this the TOTAL itself would be silently
// short — which would make the truncation signal a lie rather than a guard.
const (
	paramResultSize     = "ResultSize"
	resultSizeUnlimited = "Unlimited"
)

// Client is the narrow Exchange Online cmdlet seam this package needs. It is
// satisfied by *exoclient.Client and by collectors.EXOClient implementations,
// so callers pass whichever they already hold.
type Client interface {
	Invoke(ctx context.Context, cmdlet string, params map[string]any) ([]map[string]any, error)
}

// Mailbox is one addressable mailbox in the fan-out set.
type Mailbox struct {
	// PrimarySmtpAddress is the -Identity every per-mailbox cmdlet is addressed
	// by. A row without one is not addressable and never reaches this struct.
	PrimarySmtpAddress string
	// DisplayName and Identity are carried for log twins only, never as metric
	// labels: per-entity identity does not become a series (#112).
	DisplayName string
	Identity    string
	// RecipientTypeDetails distinguishes shared/user/room mailboxes. Absent on
	// some rows, so callers must tolerate "".
	RecipientTypeDetails string
}

// Result is one enumeration: which mailboxes are in scope this cycle, and how
// that compares with what the tenant actually has.
type Result struct {
	// Mailboxes is the covered set, sorted by PrimarySmtpAddress.
	Mailboxes []Mailbox
	// Total is how many mailbox rows the tenant returned, INCLUDING rows that
	// were dropped as unaddressable. It is what really exists.
	Total int
	// Covered is len(Mailboxes) — how many this cycle will actually poll.
	Covered int
	// Truncated reports Covered < Total for any reason: the cap, or an
	// unaddressable row. Either way the cycle does not see everything.
	Truncated bool
}

// Enumerate lists the tenant's mailboxes and applies the fan-out cap.
//
// maxMailboxes <= 0 means unlimited. Config validation rejects values below 1,
// so this is defensive only — but it must mean "no cap" rather than "cap of
// zero", because a zero-valued config that silently collected NOTHING while
// reporting success is exactly the permanent-silence failure this project has
// hit before (PageSize=0 returning HTTP 200 with zero rows).
//
// An empty tenant is (empty Result, nil error): zero mailboxes is a measured
// fact. A transport failure is returned as an error and never flattened into
// an empty result — "no mailboxes" and "could not look" are opposite facts.
func Enumerate(ctx context.Context, c Client, maxMailboxes int) (Result, error) {
	rows, err := c.Invoke(ctx, cmdletGetMailbox, map[string]any{
		paramResultSize: resultSizeUnlimited,
	})
	if err != nil {
		return Result{}, fmt.Errorf("enumerate mailboxes: %w", err)
	}

	out := Result{Total: len(rows)}
	boxes := make([]Mailbox, 0, len(rows))
	for _, r := range rows {
		addr := str(r, "PrimarySmtpAddress")
		if addr == "" {
			// Unaddressable: counted in Total (it exists) but not pollable.
			continue
		}
		boxes = append(boxes, Mailbox{
			PrimarySmtpAddress:   addr,
			DisplayName:          str(r, "DisplayName"),
			Identity:             str(r, "Identity"),
			RecipientTypeDetails: str(r, "RecipientTypeDetails"),
		})
	}

	sort.Slice(boxes, func(i, j int) bool {
		return boxes[i].PrimarySmtpAddress < boxes[j].PrimarySmtpAddress
	})
	if maxMailboxes > 0 && len(boxes) > maxMailboxes {
		boxes = boxes[:maxMailboxes]
	}

	out.Mailboxes = boxes
	out.Covered = len(boxes)
	out.Truncated = out.Covered < out.Total
	return out, nil
}

// str reads a string field, tolerating absence and a non-string type. Exchange
// omits optional fields rather than sending null, so an absent key is ordinary.
func str(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
