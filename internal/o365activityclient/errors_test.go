package o365activityclient

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestParseAPIErrorDocumentedCode decodes the documented error envelope
// (verbatim from the API reference's Errors section) into a typed APIError.
func TestParseAPIErrorDocumentedCode(t *testing.T) {
	body := []byte(`{"error":{"code":"AF20051","message":"Content requested with the key abc has already expired. Content older than 7 days cannot be retrieved."}}`)

	err := parseAPIError(http.StatusBadRequest, body, http.MethodGet, "https://manage.office.com/api/v1.0/t/activity/feed/audit/abc")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) = false, want true (err = %v)", err)
	}
	if apiErr.Code != CodeContentExpired {
		t.Errorf("Code = %q, want %q", apiErr.Code, CodeContentExpired)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
	}
	if !IsContentExpired(err) {
		t.Error("IsContentExpired = false, want true")
	}
}

// TestErrorPredicatesMatchTheirOwnCodeOnly is the guard against the failure mode
// CLAUDE.md calls out: a collector must recognize a SPECIFIC documented
// signature and skip on it, never blanket-swallow every error sharing its HTTP
// status. Each predicate must fire on its own code and on nothing else.
func TestErrorPredicatesMatchTheirOwnCodeOnly(t *testing.T) {
	predicates := map[string]struct {
		code string
		fn   func(error) bool
	}{
		"IsMissingPermission":    {CodeMissingPermission, IsMissingPermission},
		"IsNoSubscription":       {CodeNoSubscription, IsNoSubscription},
		"IsSubscriptionDisabled": {CodeSubscriptionDisabled, IsSubscriptionDisabled},
		"IsContentNotFound":      {CodeContentNotFound, IsContentNotFound},
		"IsContentExpired":       {CodeContentExpired, IsContentExpired},
		"IsInvalidTimeRange":     {CodeInvalidTimeRange, IsInvalidTimeRange},
		"IsThrottled":            {CodeTooManyRequests, IsThrottled},
	}

	for name, p := range predicates {
		t.Run(name, func(t *testing.T) {
			own := &APIError{StatusCode: http.StatusBadRequest, Code: p.code}
			if !p.fn(own) {
				t.Errorf("%s(code %s) = false, want true", name, p.code)
			}
			for otherName, other := range predicates {
				if other.code == p.code {
					continue
				}
				foreign := &APIError{StatusCode: http.StatusBadRequest, Code: other.code}
				if p.fn(foreign) {
					t.Errorf("%s(code %s from %s) = true, want false — predicate is over-broad",
						name, other.code, otherName)
				}
			}
		})
	}
}

// TestInvalidTimeRangeMatchesBothDocumentedCodes pins that the time-range
// predicate covers AF20030 AND AF20055 — the reference documents two distinct
// codes for the same "start/end must be <=24h apart, start <=7d back" rule.
func TestInvalidTimeRangeMatchesBothDocumentedCodes(t *testing.T) {
	for _, code := range []string{CodeInvalidTimeRange, CodeInvalidTimeRangeAlt} {
		if !IsInvalidTimeRange(&APIError{StatusCode: http.StatusBadRequest, Code: code}) {
			t.Errorf("IsInvalidTimeRange(%s) = false, want true", code)
		}
	}
}

// TestGenericErrorIsNotClassified is the other half of the "never
// blanket-swallow" property: a 400 that is NOT one of the documented codes —
// a malformed query, an unparsable body, a plain non-API error — must not
// satisfy any skip-gracefully predicate, so it surfaces as a real failure.
func TestGenericErrorIsNotClassified(t *testing.T) {
	cases := map[string]error{
		"unparsable body": parseAPIError(http.StatusBadRequest, []byte("<html>gateway blew up</html>"),
			http.MethodGet, "https://manage.office.com/x"),
		"well-formed envelope, undocumented code": parseAPIError(http.StatusBadRequest,
			[]byte(`{"error":{"code":"AF99999","message":"something new"}}`), http.MethodGet, "https://manage.office.com/x"),
		"empty body":             parseAPIError(http.StatusBadRequest, nil, http.MethodGet, "https://manage.office.com/x"),
		"not an APIError at all": errors.New("dial tcp: connection refused"),
	}

	predicates := map[string]func(error) bool{
		"IsMissingPermission":    IsMissingPermission,
		"IsNoSubscription":       IsNoSubscription,
		"IsSubscriptionDisabled": IsSubscriptionDisabled,
		"IsContentNotFound":      IsContentNotFound,
		"IsContentExpired":       IsContentExpired,
		"IsInvalidTimeRange":     IsInvalidTimeRange,
		"IsThrottled":            IsThrottled,
	}

	for caseName, err := range cases {
		for predName, fn := range predicates {
			if fn(err) {
				t.Errorf("%s(%s) = true, want false — a non-documented error must never be swallowed as a known condition",
					predName, caseName)
			}
		}
	}
}

// TestParseAPIErrorRetainsUnparsableBody keeps the raw body on the error so an
// undecodable failure is still diagnosable rather than becoming an opaque
// "status 400".
func TestParseAPIErrorRetainsUnparsableBody(t *testing.T) {
	err := parseAPIError(http.StatusBadGateway, []byte("upstream exploded"), http.MethodGet, "https://manage.office.com/x")

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) = false, want true")
	}
	if apiErr.Code != "" {
		t.Errorf("Code = %q, want empty for an unparsable body", apiErr.Code)
	}
	if apiErr.Message != "upstream exploded" {
		t.Errorf("Message = %q, want the raw body", apiErr.Message)
	}
	if got := apiErr.Error(); got == "" {
		t.Error("Error() returned an empty string")
	}
}

// TestAPIErrorMessageIncludesCodeAndStatus keeps the human-readable form
// actionable — the code is what a maintainer greps the reference for.
func TestAPIErrorMessageIncludesCodeAndStatus(t *testing.T) {
	err := &APIError{
		StatusCode: http.StatusBadRequest,
		Code:       CodeContentExpired,
		Message:    "Content older than 7 days cannot be retrieved.",
		Method:     http.MethodGet,
		URL:        "https://manage.office.com/api/v1.0/t/activity/feed/audit/abc",
	}
	got := err.Error()
	for _, want := range []string{"AF20051", "400", "Content older than 7 days"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to contain %q", got, want)
		}
	}
}
