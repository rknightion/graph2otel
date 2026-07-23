package exoclient

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Live failure bodies captured from the m7kni tenant as graph2otel-poller on
// 2026-07-23, both HTTP 400. They are pinned verbatim: every field this package
// unwraps is a real observed field, not a shape inferred from documentation.
const (
	// liveInvalidEnumBody is `Get-QuarantineMessage -QuarantineTypes Nonsense`.
	// It carries the unwrapped text ONLY in innererror.internalexception —
	// source 1 — and its details array is absent.
	liveInvalidEnumBody = `{"error":{"code":"BadRequest","message":"Invalid Operation","innererror":{"message":"Invalid Operation","type":"Microsoft.Exchange.Admin.OData.Core.ODataServiceException","stacktrace":"","internalexception":{"message":"Cannot process argument transformation on parameter 'QuarantineTypes'. Cannot convert value \"Nonsense\" to type \"Microsoft.Exchange.Management.FfoQuarantine.QuarantineMessageTypeEnum[]\". Error: \"Unable to match the identifier name Nonsense to a valid enumerator name. Specify one of the following enumerator names and try again: Spam, TransportRule, Bulk, Phish, HighConfPhish, Malware, SPOMalware, DataLossPrevention, FileTypeBlock, AdminTriggered, PPI\"","type":"Microsoft.Exchange.AdminApi.CommandInvocation.ParameterTransformationException","stacktrace":""}},"adminapi.warnings@odata.type":"#Collection(String)","@adminapi.warnings":[]}}`

	// liveUnknownParameterBody is `Get-QuarantineMessage -BogusParameter 1`. It
	// populates BOTH source 1 (innererror) and source 2 (details), so it is the
	// fixture that proves the precedence order rather than merely exercising one
	// branch.
	liveUnknownParameterBody = `{"error":{"code":"BadRequest","message":"Invalid Operation","details":[{"code":"Client","target":"","message":"|Microsoft.Exchange.AdminApi.CommandInvocation.AmbiguousParameterSetException|Parameter set cannot be resolved using the specified named parameters. Invalid cmdlet parameters specified. BogusParameter"}],"innererror":{"message":"Invalid Operation","type":"Microsoft.Exchange.Admin.OData.Core.ODataServiceException","stacktrace":"","internalexception":{"message":"Parameter set cannot be resolved using the specified named parameters. Invalid cmdlet parameters specified. BogusParameter","type":"Microsoft.Exchange.AdminApi.CommandInvocation.AmbiguousParameterSetException","stacktrace":""}}}}`

	// detailsOnlyBody is synthetic: the same shape with innererror removed, so
	// source 2 and the |Type| prefix strip are exercised on their own.
	detailsOnlyBody = `{"error":{"code":"BadRequest","message":"Invalid Operation","details":[{"code":"Client","target":"","message":"|Microsoft.Exchange.AdminApi.CommandInvocation.AmbiguousParameterSetException|Parameter set cannot be resolved using the specified named parameters."}]}}`

	// messageOnlyBody is synthetic: neither innererror nor details, so source 3
	// is the only thing left.
	messageOnlyBody = `{"error":{"code":"BadRequest","message":"Invalid Operation"}}`
)

// TestParseCmdletErrorMessagePrecedence is the heart of this package's error
// handling. error.message is ALWAYS the literal "Invalid Operation" whatever
// went wrong, so a client that surfaces it reports nothing actionable, on every
// error, forever. The unwrapped text is by contrast excellent — the invalid-enum
// case returns the complete list of valid members.
func TestParseCmdletErrorMessagePrecedence(t *testing.T) {
	for name, tc := range map[string]struct {
		body        string
		wantCode    string
		wantType    string
		wantMessage string
		wantSubstr  string
	}{
		"source 1: innererror.internalexception (live invalid enum)": {
			body:       liveInvalidEnumBody,
			wantCode:   "BadRequest",
			wantType:   "Microsoft.Exchange.AdminApi.CommandInvocation.ParameterTransformationException",
			wantSubstr: "Specify one of the following enumerator names and try again: Spam, TransportRule",
		},
		"source 1 wins over source 2 (live unknown parameter)": {
			body:     liveUnknownParameterBody,
			wantCode: "BadRequest",
			wantType: "Microsoft.Exchange.AdminApi.CommandInvocation.AmbiguousParameterSetException",
			// The innererror text, NOT the details text — which is identical here
			// except for the |Type| prefix, so a wrong precedence shows up as the
			// prefix leaking into Message.
			wantMessage: "Parameter set cannot be resolved using the specified named parameters. Invalid cmdlet parameters specified. BogusParameter",
		},
		"source 2: details[0].message with the |Type| prefix stripped": {
			body:        detailsOnlyBody,
			wantCode:    "BadRequest",
			wantMessage: "Parameter set cannot be resolved using the specified named parameters.",
		},
		"source 3: error.message, the last resort": {
			body:        messageOnlyBody,
			wantCode:    "BadRequest",
			wantMessage: "Invalid Operation",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := parseCmdletError(http.StatusBadRequest, []byte(tc.body), "Get-QuarantineMessage")

			var cerr *CmdletError
			if !errors.As(err, &cerr) {
				t.Fatalf("errors.As(*CmdletError) = false for %v", err)
			}
			if cerr.StatusCode != http.StatusBadRequest {
				t.Errorf("StatusCode = %d, want 400", cerr.StatusCode)
			}
			if cerr.Cmdlet != "Get-QuarantineMessage" {
				t.Errorf("Cmdlet = %q, want %q", cerr.Cmdlet, "Get-QuarantineMessage")
			}
			if cerr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", cerr.Code, tc.wantCode)
			}
			if cerr.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", cerr.Type, tc.wantType)
			}
			if tc.wantMessage != "" && cerr.Message != tc.wantMessage {
				t.Errorf("Message = %q, want %q", cerr.Message, tc.wantMessage)
			}
			if tc.wantSubstr != "" && !strings.Contains(cerr.Message, tc.wantSubstr) {
				t.Errorf("Message = %q, want it to contain %q", cerr.Message, tc.wantSubstr)
			}
			if strings.HasPrefix(cerr.Message, "|") {
				t.Errorf("Message = %q, want the leading |TypeName| prefix stripped", cerr.Message)
			}
		})
	}
}

// TestParseCmdletErrorNeverReturnsInvalidOperationWhenBetterTextExists is the
// negative half of the precedence rule, asserted on its own so it cannot be
// weakened by accident. "Invalid Operation" is only ever an acceptable Message
// when the body genuinely carries nothing else.
func TestParseCmdletErrorNeverReturnsInvalidOperationWhenBetterTextExists(t *testing.T) {
	for name, body := range map[string]string{
		"live invalid enum":      liveInvalidEnumBody,
		"live unknown parameter": liveUnknownParameterBody,
		"details only":           detailsOnlyBody,
	} {
		t.Run(name, func(t *testing.T) {
			var cerr *CmdletError
			if !errors.As(parseCmdletError(http.StatusBadRequest, []byte(body), "Get-QuarantineMessage"), &cerr) {
				t.Fatal("errors.As(*CmdletError) = false")
			}
			if cerr.Message == "Invalid Operation" {
				t.Errorf("Message = %q — the useful text was in the body and was thrown away", cerr.Message)
			}
		})
	}
}

// TestParseCmdletErrorNonJSONBody covers the live-captured 403 whose body is a
// run of NUL bytes. This is the shape a missing app role or directory role
// produces, so it is the most likely production failure of the lot — and a
// decoder that only handles the JSON envelope panics or reports nonsense on it.
func TestParseCmdletErrorNonJSONBody(t *testing.T) {
	for name, body := range map[string][]byte{
		"NUL bytes (live capture)": make([]byte, 4096),
		"HTML error page":          []byte("<html><body>gateway blew up</body></html>"),
		"empty body":               nil,
	} {
		t.Run(name, func(t *testing.T) {
			err := parseCmdletError(http.StatusForbidden, body, "Get-QuarantineMessage")

			var cerr *CmdletError
			if !errors.As(err, &cerr) {
				t.Fatalf("errors.As(*CmdletError) = false for %v", err)
			}
			if cerr.StatusCode != http.StatusForbidden {
				t.Errorf("StatusCode = %d, want 403", cerr.StatusCode)
			}
			if cerr.Cmdlet != "Get-QuarantineMessage" {
				t.Errorf("Cmdlet = %q, want the cmdlet name", cerr.Cmdlet)
			}
			if cerr.Code != "" {
				t.Errorf("Code = %q, want empty — there was no envelope to read one from", cerr.Code)
			}
			if !strings.Contains(cerr.Message, "not JSON") {
				t.Errorf("Message = %q, want it to say plainly that the body was not JSON", cerr.Message)
			}
			for _, leak := range []string{"invalid character", "unexpected end of JSON", "cannot unmarshal"} {
				if strings.Contains(cerr.Message, leak) {
					t.Errorf("Message = %q, want no raw JSON-decoder text (%q)", cerr.Message, leak)
				}
			}
			if strings.ContainsRune(cerr.Error(), 0) {
				t.Error("Error() carries raw NUL bytes from the response body")
			}
		})
	}
}

// TestParseCmdletErrorValidJSONButNotTheEnvelope keeps an unrecognized-but-JSON
// body diagnosable rather than collapsing it to a bare "status 500".
func TestParseCmdletErrorValidJSONButNotTheEnvelope(t *testing.T) {
	err := parseCmdletError(http.StatusInternalServerError, []byte(`{"unexpected":"shape"}`), "Get-QuarantineMessage")

	var cerr *CmdletError
	if !errors.As(err, &cerr) {
		t.Fatalf("errors.As(*CmdletError) = false for %v", err)
	}
	if cerr.Message == "" {
		t.Error("Message is empty — an unrecognized body must still be diagnosable")
	}
	if !strings.Contains(cerr.Message, "unexpected") {
		t.Errorf("Message = %q, want it to retain the raw body", cerr.Message)
	}
}

// TestCmdletErrorStringIsActionable pins what an operator reads in a log line:
// the status, the cmdlet that failed, the service's code, the .NET type, and
// the unwrapped message.
func TestCmdletErrorStringIsActionable(t *testing.T) {
	err := &CmdletError{
		StatusCode: http.StatusBadRequest,
		Cmdlet:     "Get-QuarantineMessage",
		Code:       "BadRequest",
		Type:       "Microsoft.Exchange.AdminApi.CommandInvocation.ParameterTransformationException",
		Message:    "Cannot process argument transformation on parameter 'QuarantineTypes'.",
	}
	got := err.Error()
	for _, want := range []string{
		"exoclient",
		"400",
		"Get-QuarantineMessage",
		"BadRequest",
		"ParameterTransformationException",
		"Cannot process argument transformation",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to contain %q", got, want)
		}
	}
}

// TestCmdletErrorZeroValueDoesNotPanic guards the formatting path against an
// empty error, which the non-JSON branch can produce fields-at-a-time.
func TestCmdletErrorZeroValueDoesNotPanic(t *testing.T) {
	if got := (&CmdletError{}).Error(); got == "" {
		t.Error("Error() on a zero CmdletError returned an empty string")
	}
}

// TestErrorsAsRecoversCmdletError checks the typed error survives wrapping, so
// a collector can branch on it rather than string-matching.
func TestErrorsAsRecoversCmdletError(t *testing.T) {
	base := parseCmdletError(http.StatusBadRequest, []byte(liveInvalidEnumBody), "Get-QuarantineMessage")
	wrapped := errors.Join(errors.New("outer context"), base)

	var cerr *CmdletError
	if !errors.As(wrapped, &cerr) {
		t.Fatalf("errors.As through a wrap = false for %v", wrapped)
	}
	if cerr.Code != "BadRequest" {
		t.Errorf("Code = %q, want %q", cerr.Code, "BadRequest")
	}
}
