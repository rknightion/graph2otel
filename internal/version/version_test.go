package version

import "testing"

func TestString(t *testing.T) {
	if String() == "" {
		t.Fatal("version.String() must not be empty")
	}
	if got := String(); got != Version {
		t.Errorf("String() = %q, want Version %q", got, Version)
	}
}
