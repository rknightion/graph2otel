package livecontract

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/graphclient"
)

func endpoint(t *testing.T, id string) Endpoint {
	t.Helper()
	for _, ep := range Manifest() {
		if ep.ID == id {
			return ep
		}
	}
	t.Fatalf("no manifest endpoint %q", id)
	return Endpoint{}
}

const skuOK = `{"value":[{"id":"x","skuPartNumber":"SKU","consumedUnits":3,"capabilityStatus":"Enabled","prepaidUnits":{"enabled":5}}]}`

func TestCheckShapeAccepts(t *testing.T) {
	oc, err := CheckShape(endpoint(t, "subscribedSkus"), []byte(skuOK))
	if err != nil || oc != OutcomeChecked {
		t.Fatalf("got (%v, %v), want checked", oc, err)
	}
}

// AC3: a broken shape assumption must fail, for the right reason. Each case
// mutates one thing the mapper relies on and wants the error to name that field.
func TestCheckShapeRejectsBrokenAssumption(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"renamed field", strings.Replace(skuOK, "skuPartNumber", "skuPartNum", 1), `"skuPartNumber" missing`},
		{"retyped field", strings.Replace(skuOK, `"consumedUnits":3`, `"consumedUnits":"3"`, 1), `"consumedUnits" is string, want number`},
		{"null non-nullable", strings.Replace(skuOK, `"Enabled"`, "null", 1), `"capabilityStatus" is null`},
		{"object became array", strings.Replace(skuOK, `{"enabled":5}`, "[5]", 1), `"prepaidUnits" is array, want object`},
		{"no value array", `{"error":{}}`, `no "value" array`},
		{"not json", `<html>`, "not a JSON object"},
		{"value not objects", `{"value":[1,2]}`, "not an array of objects"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oc, err := CheckShape(endpoint(t, "subscribedSkus"), []byte(c.body))
			if err == nil {
				t.Fatalf("accepted a broken shape (outcome %q)", oc)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name %q", err, c.want)
			}
			if !strings.Contains(err.Error(), "subscribedSkus") || !strings.Contains(err.Error(), "entra.licensing") {
				t.Fatalf("error %q does not name the endpoint and its collector", err)
			}
		})
	}
}

func TestCheckShapeEmptyIsNotAFailure(t *testing.T) {
	oc, err := CheckShape(endpoint(t, "subscribedSkus"), []byte(`{"value":[]}`))
	if err != nil || oc != OutcomeEmpty {
		t.Fatalf("got (%v, %v), want empty with no error", oc, err)
	}
}

func TestCheckShapeNullableMayBeNull(t *testing.T) {
	body := `{"value":[{"id":"a","deviceName":null,"complianceState":"compliant","operatingSystem":"Windows","isEncrypted":true,"lastSyncDateTime":null}]}`
	if _, err := CheckShape(endpoint(t, "managedDevices"), []byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckShapeNeverEchoesValues(t *testing.T) {
	body := `{"value":[{"id":"secret-tenant-value","skuPartNumber":7}]}`
	_, err := CheckShape(endpoint(t, "subscribedSkus"), []byte(body))
	if err == nil || strings.Contains(err.Error(), "secret-tenant-value") {
		t.Fatalf("error must exist and carry no response value: %v", err)
	}
}

func TestCheckShapeCount(t *testing.T) {
	ep := endpoint(t, "usersCount")
	if oc, err := CheckShape(ep, []byte("42\n")); err != nil || oc != OutcomeChecked {
		t.Fatalf("bare integer: (%v, %v)", oc, err)
	}
	if _, err := CheckShape(ep, []byte(`{"value":[]}`)); err == nil {
		t.Fatal("a JSON object is not a $count body")
	}
}

func TestClassifyDistinguishesMisconfiguration(t *testing.T) {
	for _, code := range []int{401, 403} {
		err := fmt.Errorf("wrapped: %w", &graphclient.HTTPStatusError{Method: "GET", StatusCode: code})
		if oc, ok := Classify(err); !ok || oc != OutcomeMisconfigured {
			t.Errorf("%d: got (%v, %v), want misconfigured", code, oc, ok)
		}
	}
	for _, err := range []error{
		&graphclient.HTTPStatusError{StatusCode: 404},
		&graphclient.HTTPStatusError{StatusCode: 400},
		&graphclient.HTTPStatusError{StatusCode: 500},
		errors.New("dial tcp: i/o timeout"),
	} {
		if oc, ok := Classify(err); ok {
			t.Errorf("%v classified as %v; only 401/403 are misconfiguration", err, oc)
		}
	}
}

func TestManifestIsReadOnlyV1AndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, ep := range Manifest() {
		if seen[ep.ID] {
			t.Errorf("duplicate id %q", ep.ID)
		}
		seen[ep.ID] = true
		if !strings.HasPrefix(ep.Path, "/") || strings.Contains(ep.Path, "beta") {
			t.Errorf("%s: path %q must be a v1.0 relative path", ep.ID, ep.Path)
		}
		if ep.UsedBy == "" {
			t.Errorf("%s: UsedBy is empty", ep.ID)
		}
		if !ep.Count && len(ep.Fields) == 0 {
			t.Errorf("%s: no fields to check", ep.ID)
		}
	}
}
