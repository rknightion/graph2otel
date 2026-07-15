package preflight

import (
	"reflect"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		granted []string
		reqs    []CollectorReq
		want    Report
	}{
		{
			name:    "all satisfied",
			granted: []string{"AuditLog.Read.All", "User.Read.All"},
			reqs: []CollectorReq{
				{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}},
				{Name: "users", Permissions: []string{"User.Read.All"}},
			},
			want: Report{
				Collectors: []CollectorResult{
					{Name: "sign_ins", Required: []string{"AuditLog.Read.All"}, Missing: nil, OK: true},
					{Name: "users", Required: []string{"User.Read.All"}, Missing: nil, OK: true},
				},
				MissingAggregate:   nil,
				ExpectedExceptions: nil,
				OK:                 true,
			},
		},
		{
			name:    "one collector missing a permission",
			granted: []string{"AuditLog.Read.All"},
			reqs: []CollectorReq{
				{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}},
				{Name: "users", Permissions: []string{"User.Read.All"}},
			},
			want: Report{
				Collectors: []CollectorResult{
					{Name: "sign_ins", Required: []string{"AuditLog.Read.All"}, Missing: nil, OK: true},
					{Name: "users", Required: []string{"User.Read.All"}, Missing: []string{"User.Read.All"}, OK: false},
				},
				MissingAggregate:   []string{"User.Read.All"},
				ExpectedExceptions: nil,
				OK:                 false,
			},
		},
		{
			name:    "missing permission de-duplicated across collectors",
			granted: []string{},
			reqs: []CollectorReq{
				{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}},
				{Name: "audits", Permissions: []string{"AuditLog.Read.All"}},
				{Name: "provisioning", Permissions: []string{"AuditLog.Read.All"}},
			},
			want: Report{
				Collectors: []CollectorResult{
					{Name: "sign_ins", Required: []string{"AuditLog.Read.All"}, Missing: []string{"AuditLog.Read.All"}, OK: false},
					{Name: "audits", Required: []string{"AuditLog.Read.All"}, Missing: []string{"AuditLog.Read.All"}, OK: false},
					{Name: "provisioning", Required: []string{"AuditLog.Read.All"}, Missing: []string{"AuditLog.Read.All"}, OK: false},
				},
				MissingAggregate:   []string{"AuditLog.Read.All"},
				ExpectedExceptions: nil,
				OK:                 false,
			},
		},
		{
			name:    "export ReadWrite scope surfaced as expected exception, granted",
			granted: []string{"DeviceManagementManagedDevices.ReadWrite.All"},
			reqs: []CollectorReq{
				{Name: "intune_reports_export", Permissions: []string{"DeviceManagementManagedDevices.ReadWrite.All"}},
			},
			want: Report{
				Collectors: []CollectorResult{
					{Name: "intune_reports_export", Required: []string{"DeviceManagementManagedDevices.ReadWrite.All"}, Missing: nil, OK: true},
				},
				MissingAggregate:   nil,
				ExpectedExceptions: []string{"DeviceManagementManagedDevices.ReadWrite.All"},
				OK:                 true,
			},
		},
		{
			name:    "export ReadWrite scope surfaced as expected exception even when missing",
			granted: []string{},
			reqs: []CollectorReq{
				{Name: "intune_reports_export", Permissions: []string{"DeviceManagementManagedDevices.ReadWrite.All"}},
			},
			want: Report{
				Collectors: []CollectorResult{
					{Name: "intune_reports_export", Required: []string{"DeviceManagementManagedDevices.ReadWrite.All"}, Missing: []string{"DeviceManagementManagedDevices.ReadWrite.All"}, OK: false},
				},
				MissingAggregate:   []string{"DeviceManagementManagedDevices.ReadWrite.All"},
				ExpectedExceptions: []string{"DeviceManagementManagedDevices.ReadWrite.All"},
				OK:                 false,
			},
		},
		{
			name:    "no requirements at all is trivially OK",
			granted: nil,
			reqs:    nil,
			want: Report{
				Collectors:         []CollectorResult{},
				MissingAggregate:   nil,
				ExpectedExceptions: nil,
				OK:                 true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.granted, tt.reqs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Check(%v, %v) =\n  %+v\nwant\n  %+v", tt.granted, tt.reqs, got, tt.want)
			}
		})
	}
}

func TestBuildRequirements(t *testing.T) {
	collectors := map[string]any{
		"sign_ins": fakePermissionRequirer{perms: []string{"AuditLog.Read.All"}},
		"nothing":  struct{}{}, // doesn't implement PermissionRequirer
	}

	got := BuildRequirements(collectors)

	want := []CollectorReq{
		{Name: "nothing", Permissions: nil},
		{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildRequirements() = %+v, want %+v", got, want)
	}
}

type fakePermissionRequirer struct {
	perms []string
}

func (f fakePermissionRequirer) RequiredPermissions() []string { return f.perms }
