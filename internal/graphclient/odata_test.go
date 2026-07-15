package graphclient

import (
	"errors"
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// synthODataError builds an *odataerrors.ODataError carrying code+message, as the
// SDK surfaces a Graph API error.
func synthODataError(code, msg string) *odataerrors.ODataError {
	main := odataerrors.NewMainError()
	main.SetCode(&code)
	main.SetMessage(&msg)
	od := odataerrors.NewODataError()
	od.SetErrorEscaped(main)
	return od
}

func TestUnwrapODataError(t *testing.T) {
	err := synthODataError("Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
	code, msg, ok := UnwrapODataError(err)
	if !ok {
		t.Fatal("expected ok=true for an ODataError")
	}
	if code != "Authorization_RequestDenied" {
		t.Errorf("code = %q", code)
	}
	if msg != "Insufficient privileges to complete the operation." {
		t.Errorf("message = %q", msg)
	}
}

func TestUnwrapODataErrorNonOData(t *testing.T) {
	if _, _, ok := UnwrapODataError(errors.New("plain transport error")); ok {
		t.Error("expected ok=false for a non-OData error")
	}
}

func TestFormatODataError(t *testing.T) {
	got := FormatODataError(synthODataError("Request_ResourceNotFound", "not found"))
	if got != "Request_ResourceNotFound: not found" {
		t.Errorf("FormatODataError = %q, want code: message", got)
	}
	// Non-OData falls back to err.Error().
	if got := FormatODataError(errors.New("boom")); got != "boom" {
		t.Errorf("FormatODataError fallback = %q, want boom", got)
	}
	if got := FormatODataError(nil); got != "" {
		t.Errorf("FormatODataError(nil) = %q, want empty", got)
	}
}
