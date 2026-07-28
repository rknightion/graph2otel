package config

import "fmt"

// DefaultMaxMailboxes bounds how many mailboxes the per-mailbox Exchange Online
// collectors poll in one cycle when a tenant does not name a cap.
//
// Those collectors call one cmdlet PER MAILBOX with no batch form on the EXO
// transport, so the cycle cost is linear in mailbox count (live-measured
// 2026-07-28: ~1.45 s/mailbox for mailbox delegation, ~1.0 s/mailbox for inbox
// rules). 250 keeps the default cycle near six minutes for the more expensive
// of the two, which sits comfortably inside an hourly interval with headroom,
// and covers a small-to-mid tenant completely.
//
// It is deliberately not thousands: 1,000 mailboxes is already ~24 minutes per
// cycle, which is most of an hourly interval and leaves no room for retries or
// a slow day on Microsoft's side. An operator who wants that reach should ask
// for it explicitly and see the number they are choosing.
const DefaultMaxMailboxes = 250

// ExoPerMailboxConfig is the shared opt-in gate for every Exchange Online
// collector that fans out one cmdlet per mailbox (#355 mailbox delegation,
// #363 inbox rules).
//
// One block gates all of them, rather than one flag each, because they share
// the same cost shape AND the same Get-Mailbox enumeration — splitting the gate
// would mean enumerating twice and giving an operator two numbers to reason
// about when the budget they actually care about is "how long does a cycle
// take".
//
// This is NOT the HighVolume flag and must never be folded into it: HighVolume
// means a firehose whose rate scales with TRAFFIC, whereas this scales with
// TENANT SIZE — an idle 5,000-mailbox tenant still pays full price. It is not
// Experimental either; that flag is reserved for genuine Graph beta surfaces
// (#183) and this is a GA PowerShell transport.
type ExoPerMailboxConfig struct {
	// Enabled is the whole opt-in. False (the default) registers none of the
	// per-mailbox EXO collectors for this tenant, exactly as an unset
	// blob_ingest.account_url registers no blob collectors.
	Enabled bool `yaml:"enabled"`
	// MaxMailboxes caps how many mailboxes one cycle polls. Unset (0) means
	// DefaultMaxMailboxes — never "cap of zero". Mailboxes beyond the cap are
	// not polled, and the shortfall is reported as a covered/total signal
	// rather than passed over silently.
	MaxMailboxes int `yaml:"max_mailboxes"`
}

// Configured reports whether this tenant opted into per-mailbox EXO collection.
func (e ExoPerMailboxConfig) Configured() bool { return e.Enabled }

// Cap returns the effective mailbox cap, substituting the default for an unset
// value. It never returns 0 for a configured block: a zero cap would collect
// nothing and report success, which is the silent-permanent-silence failure
// this project has already hit once (PageSize=0 answering HTTP 200 with zero
// rows).
func (e ExoPerMailboxConfig) Cap() int {
	if e.MaxMailboxes <= 0 {
		return DefaultMaxMailboxes
	}
	return e.MaxMailboxes
}

// validate checks an exo_per_mailbox block in isolation. An unset block is
// valid (opt-out) and an unset cap is valid (it defaults); only a negative cap
// is a configuration error, because it can only be a mistake and silently
// treating it as the default would hide the typo.
func (e ExoPerMailboxConfig) validate() error {
	if e.MaxMailboxes < 0 {
		return fmt.Errorf("max_mailboxes is %d, must be a positive mailbox count (omit it for the default of %d)", e.MaxMailboxes, DefaultMaxMailboxes)
	}
	return nil
}
