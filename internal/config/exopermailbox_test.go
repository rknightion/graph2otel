package config

import "testing"

func TestExoPerMailboxNotConfiguredByDefault(t *testing.T) {
	// The whole gate: unset means these collectors never register, exactly as
	// an unset blob_ingest.account_url registers no blob collectors.
	var e ExoPerMailboxConfig
	if e.Configured() {
		t.Error("Configured() = true on a zero-valued block, want false")
	}
}

func TestExoPerMailboxEnabledIsTheOptIn(t *testing.T) {
	e := ExoPerMailboxConfig{Enabled: true}
	if !e.Configured() {
		t.Error("Configured() = false with Enabled: true, want true")
	}
}

func TestExoPerMailboxCapDefaults(t *testing.T) {
	// An omitted max_mailboxes must not mean "cap of zero" — that would
	// collect nothing while reporting success.
	e := ExoPerMailboxConfig{Enabled: true}
	if got := e.Cap(); got != DefaultMaxMailboxes {
		t.Errorf("Cap() = %d on an unset max_mailboxes, want the default %d", got, DefaultMaxMailboxes)
	}
	if DefaultMaxMailboxes != 250 {
		t.Errorf("DefaultMaxMailboxes = %d, want 250 (~6 min/cycle for delegation at 1.45 s/mailbox)", DefaultMaxMailboxes)
	}
}

func TestExoPerMailboxCapHonoursExplicitValue(t *testing.T) {
	e := ExoPerMailboxConfig{Enabled: true, MaxMailboxes: 42}
	if got := e.Cap(); got != 42 {
		t.Errorf("Cap() = %d, want 42", got)
	}
}

func TestExoPerMailboxValidateRejectsNegativeCap(t *testing.T) {
	e := ExoPerMailboxConfig{Enabled: true, MaxMailboxes: -1}
	if err := e.validate(); err == nil {
		t.Error("validate() = nil for max_mailboxes: -1, want an error")
	}
}

func TestExoPerMailboxValidateAcceptsUnsetAndPositive(t *testing.T) {
	for _, tc := range []ExoPerMailboxConfig{
		{},
		{Enabled: true},
		{Enabled: true, MaxMailboxes: 1},
		{Enabled: true, MaxMailboxes: 5000},
	} {
		if err := e2validate(tc); err != nil {
			t.Errorf("validate(%+v) = %v, want nil", tc, err)
		}
	}
}

func e2validate(e ExoPerMailboxConfig) error { return e.validate() }
