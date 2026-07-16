package o365activityclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Documented error codes from the Office 365 Management Activity API reference's
// Errors section. The service reports failures with a standard HTTP status AND a
// JSON body carrying one of these codes; the code is the only reliable
// discriminator, because several unrelated conditions share one status (every
// argument error below is an HTTP 400).
//
// Only the codes graph2otel actually branches on are given predicates. The rest
// are declared so a maintainer reading a logged error can grep the reference
// without decoding the string by hand.
const (
	// CodeMissingPermission (AF10001): the access token's permission set did not
	// include ActivityFeed.Read. A grant/consent problem, not a code problem.
	CodeMissingPermission = "AF10001"
	// CodeMissingParameter (AF20001): a required query parameter was absent.
	CodeMissingParameter = "AF20001"
	// CodeInvalidParameterType (AF20002): a parameter had the wrong type.
	CodeInvalidParameterType = "AF20002"
	// CodeTenantMismatch (AF20010): the tenant ID in the URL does not match the
	// tenant ID in the access token.
	CodeTenantMismatch = "AF20010"
	// CodeTenantNotFound (AF20011): the tenant ID does not exist or was deleted.
	CodeTenantNotFound = "AF20011"
	// CodeInvalidContentType (AF20020): the contentType parameter is not one of
	// the five valid content types.
	CodeInvalidContentType = "AF20020"
	// CodeNoSubscription (AF20022): no subscription exists for the content type.
	// The expected state before /subscriptions/start has ever been called — a
	// skip-gracefully condition, not a failure.
	CodeNoSubscription = "AF20022"
	// CodeSubscriptionDisabled (AF20023): the subscription was disabled by a
	// tenant or service admin. Content cannot be listed or retrieved until it is
	// restarted; also a skip-gracefully condition.
	CodeSubscriptionDisabled = "AF20023"
	// CodeAlreadyEnabled (AF20024): /subscriptions/start was called for a content
	// type whose subscription is already enabled, with nothing to change.
	//
	// This code is UNDOCUMENTED and contradicts the reference, which says a
	// re-start "is used to update the properties of an active webhook" — i.e.
	// that it is a safe idempotent no-op. It is not: the wire returns
	//
	//	HTTP 400  AF20024: The subscription is already enabled. No property change.
	//
	// Verified live 2026-07-16, and it is absent from the reference's own error
	// table (which lists AF20020-23 then jumps to AF20030). It made m365.activity
	// fail on EVERY tick against a tenant whose subscriptions were already on.
	//
	// It is a SUCCESS condition, not a failure: the desired state — an enabled
	// subscription — already holds. IsAlreadyEnabled exists so a caller starting
	// subscriptions idempotently can say so explicitly rather than pattern-matching
	// a 400.
	CodeAlreadyEnabled = "AF20024"
	// CodeInvalidTimeRange (AF20030) and CodeInvalidTimeRangeAlt (AF20055) both
	// report the same rule: startTime and endTime must both be present (or both
	// omitted), be at most 24 hours apart, and start no more than 7 days in the
	// past. ListContent enforces all three client-side, so seeing either code
	// from production means that enforcement has a hole.
	CodeInvalidTimeRange    = "AF20030"
	CodeInvalidTimeRangeAlt = "AF20055"
	// CodeContentNotFound (AF20050): the requested content blob does not exist.
	CodeContentNotFound = "AF20050"
	// CodeContentExpired (AF20051): "Content older than 7 days cannot be
	// retrieved." A blob listed earlier can expire before it is fetched, so this
	// is a normal race on a slow tick rather than a bug — the caller drops that
	// blob and moves on.
	CodeContentExpired = "AF20051"
	// CodeInvalidContentID (AF20052): the content ID in the URL is malformed.
	CodeInvalidContentID = "AF20052"
	// CodeTooManyRequests (AF429): the tenant's request quota (a baseline of
	// 2,000/min) is exhausted. The client-side Limiter exists to keep this from
	// happening.
	CodeTooManyRequests = "AF429"
	// CodeInternalError (AF50000): "An internal error occurred. Retry the
	// request." Documented as retryable, and the retry transport treats it so by
	// virtue of its 5xx status.
	CodeInternalError = "AF50000"
)

// APIError is a non-2xx response from the Management Activity API, carrying the
// documented error code when the service returned one.
//
// Code is empty when the body was not the documented envelope — a proxy's HTML
// error page, an empty body, a shape Microsoft added later. That is deliberate:
// every Is* predicate below matches on Code, so an unrecognized failure
// satisfies none of them and surfaces as a real error instead of being mistaken
// for a known, skippable condition.
type APIError struct {
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Code is the documented error code (e.g. "AF20051"), or "" when the body
	// did not carry the documented envelope.
	Code string
	// Message is the service's message, or the raw body when it was not
	// decodable as the documented envelope.
	Message string
	// Method and URL identify the failed call.
	Method string
	URL    string
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("o365activityclient: ")
	if e.Method != "" {
		b.WriteString(e.Method + " ")
	}
	if e.URL != "" {
		b.WriteString(e.URL + ": ")
	}
	fmt.Fprintf(&b, "status %d", e.StatusCode)
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	return b.String()
}

// errorEnvelope is the documented failure body:
//
//	{"error": {"code": "AF50000", "message": "An internal server error occurred."}}
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// parseAPIError turns a non-2xx response into a typed *APIError, decoding the
// documented envelope when present and otherwise retaining the raw body so the
// failure stays diagnosable.
func parseAPIError(statusCode int, body []byte, method, url string) error {
	apiErr := &APIError{StatusCode: statusCode, Method: method, URL: url}

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Error.Code != "" {
		apiErr.Code = env.Error.Code
		apiErr.Message = env.Error.Message
		return apiErr
	}
	apiErr.Message = strings.TrimSpace(string(body))
	return apiErr
}

// HasCode reports whether err is an *APIError carrying the given documented
// code. It is the general form of the specific predicates below; prefer a named
// predicate where one exists, so the call site says which condition it means.
func HasCode(err error, code string) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == code
}

// IsMissingPermission reports whether err is AF10001 — the token lacked the
// ActivityFeed.Read claim. Actionable only by granting consent, so a caller
// should surface it loudly rather than retry.
func IsMissingPermission(err error) bool { return HasCode(err, CodeMissingPermission) }

// IsNoSubscription reports whether err is AF20022 — no subscription exists for
// the content type yet. The caller's cue to start one (or to skip this tick),
// never to fail.
func IsNoSubscription(err error) bool { return HasCode(err, CodeNoSubscription) }

// IsSubscriptionDisabled reports whether err is AF20023 — an admin disabled the
// subscription. Content is unavailable until it is restarted.
func IsSubscriptionDisabled(err error) bool { return HasCode(err, CodeSubscriptionDisabled) }

// IsAlreadyEnabled reports whether err is AF20024 — /subscriptions/start was
// called for a content type that is already enabled, with nothing to change.
//
// Treat it as SUCCESS. The desired state already holds; the API just declines to
// say so with a 2xx. See CodeAlreadyEnabled for why this exists at all — the
// reference documents a re-start as a safe update and omits this code entirely.
func IsAlreadyEnabled(err error) bool { return HasCode(err, CodeAlreadyEnabled) }

// IsContentNotFound reports whether err is AF20050 — the content blob does not
// exist.
func IsContentNotFound(err error) bool { return HasCode(err, CodeContentNotFound) }

// IsContentExpired reports whether err is AF20051 — the blob aged past the
// 7-day content lifetime. Expected on a blob listed shortly before it expired;
// the caller drops it and continues.
func IsContentExpired(err error) bool { return HasCode(err, CodeContentExpired) }

// IsInvalidTimeRange reports whether err is AF20030 or AF20055 — the two codes
// the reference documents for a startTime/endTime that breaks the both-or-
// neither, <=24h-apart, <=7d-back rule.
func IsInvalidTimeRange(err error) bool {
	return HasCode(err, CodeInvalidTimeRange) || HasCode(err, CodeInvalidTimeRangeAlt)
}

// IsThrottled reports whether err is AF429 — the tenant's request quota is
// exhausted.
func IsThrottled(err error) bool { return HasCode(err, CodeTooManyRequests) }
