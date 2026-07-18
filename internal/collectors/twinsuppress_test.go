package collectors

import "testing"

func TestSuppressedTwinsRequiresBlobConfiguredAndEnabled(t *testing.T) {
	// Isolate the global registry for this test.
	saved := blobTwinOwners
	blobTwinOwners = []blobTwinOwner{
		{twinEvent: "entra.risky_user", blobCollectorName: "entra.risky_users"},
		{twinEvent: "intune.device", blobCollectorName: "intune.devices_blob"},
	}
	defer func() { blobTwinOwners = saved }()

	allEnabled := func(string) bool { return true }

	// No blob configured -> suppress nothing, even though owners are registered.
	if got := SuppressedTwins(false, allEnabled); len(got) != 0 {
		t.Errorf("blob not configured: got %v, want empty", got)
	}

	// Blob configured + both blob collectors enabled -> both twins suppressed.
	got := SuppressedTwins(true, allEnabled)
	if !got["entra.risky_user"] || !got["intune.device"] {
		t.Errorf("both twins should be suppressed, got %v", got)
	}

	// A disabled blob collector must NOT suppress its twin — else the per-entity
	// data would vanish (blob off, polled twin suppressed = a hole).
	onlyRisky := func(name string) bool { return name == "entra.risky_users" }
	got = SuppressedTwins(true, onlyRisky)
	if !got["entra.risky_user"] {
		t.Errorf("enabled blob collector's twin should be suppressed")
	}
	if got["intune.device"] {
		t.Errorf("disabled blob collector must NOT suppress its twin (would drop the data)")
	}
}

func TestRegisterBlobTwinOwnerAppends(t *testing.T) {
	saved := blobTwinOwners
	blobTwinOwners = nil
	defer func() { blobTwinOwners = saved }()

	RegisterBlobTwinOwner("a.twin", "a.blob")
	RegisterBlobTwinOwner("b.twin", "b.blob")
	if len(blobTwinOwners) != 2 {
		t.Fatalf("got %d owners, want 2", len(blobTwinOwners))
	}
	got := SuppressedTwins(true, func(string) bool { return true })
	if !got["a.twin"] || !got["b.twin"] {
		t.Errorf("both registered twins should suppress, got %v", got)
	}
}
