package huntclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

// QueryError is a failed advanced-hunting query.
//
// Unlike the Exchange Online admin API (see internal/exoclient), this endpoint
// speaks the standard Graph error vocabulary: an HTTP status that discriminates,
// and a JSON {"error":{"code","message"}} envelope. The two failures that matter
// operationally are 403 (the ThreatHunting.Read.All scope not on the token) and
// 429 (the shared advanced-hunting CPU quota exhausted, #106) — both are legible
// from status and code alone, so this type stays deliberately thinner than the
// exoclient one.
type QueryError struct {
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Label is the code-supplied query label that failed. Every query shares one
	// URL, so without it an error names nothing.
	Label string
	// Code is error.code from the envelope (e.g. "Authorization_RequestDenied",
	// "TooManyRequests"), or "" when the body was not the Graph error envelope.
	Code string
	// Message is error.message, or a truncated raw body when the response was not
	// the documented envelope.
	Message string
}

func (e *QueryError) Error() string {
	var b strings.Builder
	b.WriteString("huntclient: ")
	if e.Label != "" {
		b.WriteString(e.Label + ": ")
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

// graphErrorEnvelope is the standard Graph failure body. Only the fields this
// package surfaces are declared.
type graphErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// maxRawMessageBytes bounds how much of a non-envelope body is copied into the
// error message, so a large HTML gateway page cannot bloat a log line.
const maxRawMessageBytes = 300

// parseQueryError builds a *QueryError from a non-2xx response. A body that is
// not the Graph error envelope still yields a useful error naming the status,
// the label, and a truncated snippet of what came back.
func parseQueryError(status int, body []byte, label string) *QueryError {
	e := &QueryError{StatusCode: status, Label: label}
	var env graphErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Error.Code != "" {
		e.Code = env.Error.Code
		e.Message = env.Error.Message
		return e
	}
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > maxRawMessageBytes {
		snippet = snippet[:maxRawMessageBytes]
	}
	e.Message = snippet
	return e
}
