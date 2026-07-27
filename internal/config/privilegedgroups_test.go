package config

import (
	"strings"
	"testing"
)

const privilegedGroupsTestDirectoryID = "6a7e6e4a-7c2f-4a2a-9f2f-6b1c9f6a2b31"

// basePrivilegedGroupsConfig returns the smallest config that passes Validate,
// so a case can mutate one tenant's privileged_groups block and assert only
// that — mirrors baseValidConfig in mdca_test.go.
func basePrivilegedGroupsConfig(pg PrivilegedGroupsConfig) *Config {
	c := Default()
	c.Tenants = []TenantConfig{{TenantID: privilegedGroupsTestDirectoryID, PrivilegedGroups: pg}}
	return c
}

func TestPrivilegedGroupsConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pg      PrivilegedGroupsConfig
		wantErr string // substring; "" = must pass
	}{
		{
			name: "unset is opt-out and valid",
			pg:   PrivilegedGroupsConfig{},
		},
		{
			name: "a handful of group ids is valid",
			pg:   PrivilegedGroupsConfig{GroupIDs: []string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}},
		},
		{
			name: "exactly the maximum is valid",
			pg:   PrivilegedGroupsConfig{GroupIDs: repeatDistinctIDs(MaxPrivilegedGroupAllowlist)},
		},
		{
			name:    "one over the maximum is an error",
			pg:      PrivilegedGroupsConfig{GroupIDs: repeatDistinctIDs(MaxPrivilegedGroupAllowlist + 1)},
			wantErr: "exceeds the maximum",
		},
		{
			name:    "an empty group id is an error",
			pg:      PrivilegedGroupsConfig{GroupIDs: []string{""}},
			wantErr: "empty",
		},
		{
			name:    "a duplicate group id is an error",
			pg:      PrivilegedGroupsConfig{GroupIDs: []string{"11111111-1111-1111-1111-111111111111", "11111111-1111-1111-1111-111111111111"}},
			wantErr: "duplicate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := basePrivilegedGroupsConfig(tc.pg).Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// repeatDistinctIDs returns n syntactically distinct fake group ids, for
// exercising the allowlist's maximum-size boundary without hand-writing GUIDs.
func repeatDistinctIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = "00000000-0000-0000-0000-" + padID(i)
	}
	return ids
}

func padID(i int) string {
	s := "000000000000"
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if len(digits) == 0 {
		digits = []byte{'0'}
	}
	return s[:len(s)-len(digits)] + string(digits)
}

// TestPrivilegedGroupsConfigConfiguredEnablesCollector pins the opt-in
// predicate the composition root gates on: a non-empty allowlist means the
// collector registers for this tenant.
func TestPrivilegedGroupsConfigConfiguredEnablesCollector(t *testing.T) {
	if (PrivilegedGroupsConfig{}).Configured() {
		t.Error("empty PrivilegedGroupsConfig.Configured() = true, want false (opt-out)")
	}
	if !(PrivilegedGroupsConfig{GroupIDs: []string{"11111111-1111-1111-1111-111111111111"}}).Configured() {
		t.Error("set PrivilegedGroupsConfig.Configured() = false, want true")
	}
}
