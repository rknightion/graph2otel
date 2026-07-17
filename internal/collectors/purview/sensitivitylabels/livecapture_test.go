package sensitivitylabels

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveSensitivityLabels is a VERBATIM GET
// /security/dataSecurityAndGovernance/sensitivityLabels response from the m7kni
// tenant, read as graph2otel-poller `[live-measured 2026-07-17, #165]`.
//
// This endpoint returns HTTP 200 app-only with the SensitivityLabel.Read
// application role (live-verified 2026-07-16, #126) — the fact TestSensitivityErrorsAlwaysFail
// hangs its no-skip-path posture on. The body is the tenant's full catalog: five
// top-level labels (Personal, Public, General, Confidential, Highly Confidential),
// untrimmed, with their nested sublabels intact. GetAllValues walks only the
// top-level `value` array, so this collector sees exactly those five.
//
// Two WIRE facts this record pins:
//   - The human-readable text lives in `toolTip`, and `description` is "" on
//     every label (#175) — so the mapper reads `toolTip` for the twin's
//     description attribute, falling back to `description` only if a future
//     tenant populates that field instead.
//   - The label name is in `name` ("Personal"); `displayName` is null on every
//     row. The mapper reads `name`, which is correct.
const liveSensitivityLabels = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels",
  "value": [
    {
      "actionSource": "manual",
      "applicableTo": "email,teamwork,file",
      "applicationMode": null,
      "assignedPolicies": [],
      "autoTooltip": "",
      "color": "",
      "customSettings": [
        {
          "name": "isparent",
          "value": "False"
        }
      ],
      "description": "",
      "displayName": null,
      "hasProtection": false,
      "id": "6f7b72fb-5172-4725-b5c4-e0f7a1669b61",
      "isDefault": false,
      "isEnabled": true,
      "isEndpointProtectionEnabled": false,
      "isScopedToUser": null,
      "isSmimeEncryptEnabled": null,
      "isSmimeSignEnabled": null,
      "labelActions": [],
      "locale": null,
      "name": "Personal",
      "priority": 0,
      "rights": null,
      "sublabels": [],
      "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('6f7b72fb-5172-4725-b5c4-e0f7a1669b61')/sublabels",
      "toolTip": "Non-business data, for personal use only."
    },
    {
      "actionSource": "manual",
      "applicableTo": "email,teamwork,file",
      "applicationMode": null,
      "assignedPolicies": [],
      "autoTooltip": "",
      "color": "",
      "customSettings": [
        {
          "name": "isparent",
          "value": "False"
        }
      ],
      "description": "",
      "displayName": null,
      "hasProtection": false,
      "id": "701f788c-2eec-41f8-a2d6-7806ae8fb6f0",
      "isDefault": false,
      "isEnabled": true,
      "isEndpointProtectionEnabled": false,
      "isScopedToUser": null,
      "isSmimeEncryptEnabled": null,
      "isSmimeSignEnabled": null,
      "labelActions": [],
      "locale": null,
      "name": "Public",
      "priority": 1,
      "rights": null,
      "sublabels": [],
      "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('701f788c-2eec-41f8-a2d6-7806ae8fb6f0')/sublabels",
      "toolTip": "Organization data that's specifically prepared and approved for public consumption."
    },
    {
      "actionSource": "manual",
      "applicableTo": "email,teamwork,file",
      "applicationMode": null,
      "assignedPolicies": [],
      "autoTooltip": "",
      "color": "",
      "customSettings": [
        {
          "name": "isparent",
          "value": "True"
        }
      ],
      "description": "",
      "displayName": null,
      "hasProtection": false,
      "id": "e98a2282-e0e1-450c-91a4-e484c8dd23a1",
      "isDefault": false,
      "isEnabled": true,
      "isEndpointProtectionEnabled": false,
      "isScopedToUser": null,
      "isSmimeEncryptEnabled": null,
      "isSmimeSignEnabled": null,
      "labelActions": [],
      "locale": null,
      "name": "General",
      "priority": 2,
      "rights": null,
      "sublabels": [
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "e98a2282-e0e1-450c-91a4-e484c8dd23a1"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": false,
          "id": "f93a4769-72e9-4db8-bcba-6c408ff955aa",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": false,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "Anyone (unrestricted)",
          "priority": 3,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e98a2282-e0e1-450c-91a4-e484c8dd23a1')/sublabels('f93a4769-72e9-4db8-bcba-6c408ff955aa')/sublabels",
          "toolTip": "Organization data that isn't intended for public consumption but can be shared with external partners if appropriate. Examples include customer conversations that don't include sensitive info or released marketing materials."
        },
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "e98a2282-e0e1-450c-91a4-e484c8dd23a1"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": false,
          "id": "4dab3083-43f7-447a-9b2d-c71930277962",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": false,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "All Employees (unrestricted)",
          "priority": 4,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e98a2282-e0e1-450c-91a4-e484c8dd23a1')/sublabels('4dab3083-43f7-447a-9b2d-c71930277962')/sublabels",
          "toolTip": "Organization data that isn't intended for public consumption. If you need to share this content with external partners, make sure it's appropriate with data owners and relabel content as General \\\\ Anyone (unrestricted). Examples include a company internal telephone directory, organizational charts, internal standards, and most internal communication."
        }
      ],
      "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e98a2282-e0e1-450c-91a4-e484c8dd23a1')/sublabels",
      "toolTip": "Organization data that is not intended for public consumption. However, this can be shared with external partners, as required. Examples include a company internal telephone directory, organizational charts, internal standards, and most internal communication."
    },
    {
      "actionSource": "manual",
      "applicableTo": "email,teamwork,file",
      "applicationMode": null,
      "assignedPolicies": [],
      "autoTooltip": "",
      "color": "",
      "customSettings": [
        {
          "name": "isparent",
          "value": "True"
        }
      ],
      "description": "",
      "displayName": null,
      "hasProtection": false,
      "id": "e83c092e-14c6-4e57-a8f7-893149ecce90",
      "isDefault": false,
      "isEnabled": true,
      "isEndpointProtectionEnabled": false,
      "isScopedToUser": null,
      "isSmimeEncryptEnabled": null,
      "isSmimeSignEnabled": null,
      "labelActions": [],
      "locale": null,
      "name": "Confidential",
      "priority": 5,
      "rights": null,
      "sublabels": [
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "e83c092e-14c6-4e57-a8f7-893149ecce90"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": false,
          "id": "99609c11-4cd3-4317-bf5c-8de4d7fd3b84",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": false,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "Anyone (unrestricted)",
          "priority": 6,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e83c092e-14c6-4e57-a8f7-893149ecce90')/sublabels('99609c11-4cd3-4317-bf5c-8de4d7fd3b84')/sublabels",
          "toolTip": "Confidential data that doesn't need to be encrypted. Use this option with care and with appropriate business justification. Make sure to protect the data through other means like DLP."
        },
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "e83c092e-14c6-4e57-a8f7-893149ecce90"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": true,
          "id": "122f2568-cc67-4f07-b1bf-ff9a95dba2aa",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": true,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "All Employees",
          "priority": 7,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e83c092e-14c6-4e57-a8f7-893149ecce90')/sublabels('122f2568-cc67-4f07-b1bf-ff9a95dba2aa')/sublabels",
          "toolTip": "Confidential data that requires protection, which allows all employees full permission. Data owners can track and revoke content."
        },
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "e83c092e-14c6-4e57-a8f7-893149ecce90"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": true,
          "id": "e3468bf3-0c94-4b12-80c2-6133d028089c",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": true,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "Trusted People",
          "priority": 8,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e83c092e-14c6-4e57-a8f7-893149ecce90')/sublabels('e3468bf3-0c94-4b12-80c2-6133d028089c')/sublabels",
          "toolTip": "Confidential data for internal/external sharing that can be reshared by trusted recipients."
        }
      ],
      "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('e83c092e-14c6-4e57-a8f7-893149ecce90')/sublabels",
      "toolTip": "Sensitive business data that could cause damage to the business if shared with unauthorized people. Examples include contracts, security reports, forecast summaries, and sales account data."
    },
    {
      "actionSource": "manual",
      "applicableTo": "email,teamwork,file",
      "applicationMode": null,
      "assignedPolicies": [],
      "autoTooltip": "",
      "color": "",
      "customSettings": [
        {
          "name": "isparent",
          "value": "True"
        }
      ],
      "description": "",
      "displayName": null,
      "hasProtection": true,
      "id": "a78d53f8-e5ad-491b-83a4-b229ed132504",
      "isDefault": false,
      "isEnabled": true,
      "isEndpointProtectionEnabled": true,
      "isScopedToUser": null,
      "isSmimeEncryptEnabled": null,
      "isSmimeSignEnabled": null,
      "labelActions": [],
      "locale": null,
      "name": "Highly Confidential",
      "priority": 9,
      "rights": null,
      "sublabels": [
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "a78d53f8-e5ad-491b-83a4-b229ed132504"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": true,
          "id": "6fa39bd4-16fd-4c0f-934e-4bdf58e80e28",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": true,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "All Employees",
          "priority": 10,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('a78d53f8-e5ad-491b-83a4-b229ed132504')/sublabels('6fa39bd4-16fd-4c0f-934e-4bdf58e80e28')/sublabels",
          "toolTip": "Highly confidential data that allows all employees view, edit, and reply permissions to this content. Data owners can track and revoke content."
        },
        {
          "actionSource": "manual",
          "applicableTo": "email,teamwork,file",
          "applicationMode": null,
          "assignedPolicies": [],
          "autoTooltip": "",
          "color": "",
          "customSettings": [
            {
              "name": "parentid",
              "value": "a78d53f8-e5ad-491b-83a4-b229ed132504"
            },
            {
              "name": "isparent",
              "value": "False"
            }
          ],
          "description": "",
          "displayName": null,
          "hasProtection": true,
          "id": "83e3f770-3af0-4770-ac94-21a513818010",
          "isDefault": false,
          "isEnabled": true,
          "isEndpointProtectionEnabled": true,
          "isScopedToUser": null,
          "isSmimeEncryptEnabled": null,
          "isSmimeSignEnabled": null,
          "labelActions": [],
          "locale": null,
          "name": "Specific People",
          "priority": 11,
          "rights": null,
          "sublabels": [],
          "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('a78d53f8-e5ad-491b-83a4-b229ed132504')/sublabels('83e3f770-3af0-4770-ac94-21a513818010')/sublabels",
          "toolTip": "Highly confidential data that requires protection and can be viewed only by people you specify and with the permission level you choose."
        }
      ],
      "sublabels@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/dataSecurityAndGovernance/sensitivityLabels('a78d53f8-e5ad-491b-83a4-b229ed132504')/sublabels",
      "toolTip": "Very sensitive business data that would cause damage to the business if it was shared with unauthorized people. Examples include employee and customer information, passwords, source code, and pre-announced financial reports."
    }
  ]
}`

// TestSensitivityCollectFromLiveCapture drives the one real sensitivity-label
// catalog this project captured end-to-end through Collect into a Recorder.
//
// Every live label is applicableTo "email,teamwork,file", so the by-target
// metric is email=5, teamwork=5, file=5 (a multi-target label counts in each),
// and there are five purview.sensitivity_label log twins. The `description`
// attribute carries the label's human text from the wire's `toolTip` field
// (#175): `description` itself is "" on every live label, so without the
// toolTip fallback the twin would ship no description from real data.
func TestSensitivityCollectFromLiveCapture(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: liveSensitivityLabels}}
	rec := telemetrytest.New()

	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotTargets := map[string]float64{}
	for _, p := range rec.MetricPoints(sensitivityMetric) {
		gotTargets[p.Attrs["applicable_to"]] = p.Value
	}
	wantTargets := map[string]float64{"email": 5, "teamwork": 5, "file": 5}
	for k, v := range wantTargets {
		if gotTargets[k] != v {
			t.Errorf("applicable_to=%s count = %v, want %v (all: %v)", k, gotTargets[k], v, gotTargets)
		}
	}
	if len(gotTargets) != len(wantTargets) {
		t.Errorf("metric target set = %v, want exactly %v", gotTargets, wantTargets)
	}

	var twins []telemetrytest.LogRecord
	for _, l := range rec.LogRecords() {
		if l.EventName == sensitivityLabelEventName {
			twins = append(twins, l)
		}
	}
	if len(twins) != 5 {
		t.Fatalf("got %d purview.sensitivity_label log twins, want 5 (all: %+v)", len(twins), twins)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range twins {
		byID[l.Attrs["id"]] = l
	}
	personal, ok := byID["6f7b72fb-5172-4725-b5c4-e0f7a1669b61"]
	if !ok {
		t.Fatalf("no log twin for the Personal label id (all: %+v)", twins)
	}
	if personal.Attrs["name"] != "Personal" {
		t.Errorf("name = %q, want Personal (mapper reads `name`, not the null `displayName`)", personal.Attrs["name"])
	}
	if personal.Attrs["priority"] != "0" {
		t.Errorf("priority = %q, want \"0\"", personal.Attrs["priority"])
	}
	if personal.Attrs["applicable_to"] != "email,teamwork,file" {
		t.Errorf("applicable_to = %q, want email,teamwork,file", personal.Attrs["applicable_to"])
	}
	if personal.Attrs["description"] != "Non-business data, for personal use only." {
		t.Errorf("description = %q, want the Personal label's toolTip text", personal.Attrs["description"])
	}
	for _, l := range twins {
		if l.Attrs["description"] == "" {
			t.Errorf("label id=%s carried no description; every live label has a non-empty toolTip", l.Attrs["id"])
		}
	}
}
