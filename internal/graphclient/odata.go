package graphclient

import (
	"errors"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

// UnwrapODataError extracts the Graph OData error code + message from err, which
// the SDK surfaces as an opaque *odataerrors.ODataError. It returns ok=false for
// a non-OData error (e.g. a transport error), so callers can log the rich Graph
// error ("Authorization_RequestDenied: Insufficient privileges...") instead of
// the SDK's bare "error status code 403".
func UnwrapODataError(err error) (code, message string, ok bool) {
	var odErr *odataerrors.ODataError
	if !errors.As(err, &odErr) {
		return "", "", false
	}
	main := odErr.GetErrorEscaped()
	if main == nil {
		return "", "", false
	}
	if c := main.GetCode(); c != nil {
		code = *c
	}
	if m := main.GetMessage(); m != nil {
		message = *m
	}
	return code, message, true
}

// FormatODataError renders err as a single loggable "code: message" string when
// it is a Graph OData error, or falls back to err.Error() otherwise. Safe to call
// on a nil error (returns "").
func FormatODataError(err error) string {
	if err == nil {
		return ""
	}
	if code, msg, ok := UnwrapODataError(err); ok {
		var b strings.Builder
		b.WriteString(code)
		if msg != "" {
			if code != "" {
				b.WriteString(": ")
			}
			b.WriteString(msg)
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	return err.Error()
}
