package teamsadminclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// maxRawBodyInMessage caps how much of an undecodable body is quoted back into
// an error string.
const maxRawBodyInMessage = 200

// errorEnvelope decodes both live-measured failure envelopes. encoding/json
// matches keys case-insensitively, so one struct covers
//
//	{"code":"...","message":"...","action":"...","errorCode":40001}   (text/plain)
//	{"Error":{"Code":"...","Message":"..."}}
//
// Error is raw because a body such as {"error":"text"} must not abort decoding.
type errorEnvelope struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Action    string          `json:"action"`
	ErrorCode any             `json:"errorCode"`
	Error     json.RawMessage `json:"error"`
}

type nestedError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements error. The text never contains the query string and never
// echoes a decoder message.
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "teamsadminclient: GET %s: status %d", e.Path, e.StatusCode)
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if e.ErrorCode != 0 {
		fmt.Fprintf(&b, " (errorCode %d)", e.ErrorCode)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	switch {
	case e.StatusCode == http.StatusForbidden:
		b.WriteString(": the poller's service principal needs an Entra directory role the Teams admin API accepts (Teams Reader is the least-privileged role measured; Global Reader also works)")
	case e.StatusCode == http.StatusUnauthorized:
		b.WriteString(": the Teams admin API rejected the token or its audience")
	case e.StatusCode >= 300 && e.StatusCode < 400:
		b.WriteString(": redirect refused")
	}
	return b.String()
}

// isPermission reports whether err is an *APIError with HTTP status 403. A 401
// is a token or audience problem, not a missing role, so it is not a permission
// error here.
func isPermission(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden
}

// parseError turns a non-2xx response into an *APIError. A body that is not JSON
// (a run of NUL bytes is a live shape on sibling Microsoft admin APIs) is an
// expected branch, never a decoder error.
func parseError(statusCode int, path string, body []byte) *APIError {
	apiErr := &APIError{StatusCode: statusCode, Path: path}

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		apiErr.Message = fmt.Sprintf("response body was not JSON (%d bytes)", len(body))
		if s := printableSnippet(body); s != "" {
			apiErr.Message += ": " + s
		}
		return apiErr
	}

	apiErr.Code = env.Code
	apiErr.Message = strings.TrimSpace(env.Message)
	if f, ok := env.ErrorCode.(float64); ok && f == float64(int(f)) {
		apiErr.ErrorCode = int(f)
	}
	if apiErr.Message != "" && strings.TrimSpace(env.Action) != "" {
		apiErr.Message += " (action: " + strings.TrimSpace(env.Action) + ")"
	}
	if len(env.Error) > 0 {
		var nested nestedError
		if json.Unmarshal(env.Error, &nested) == nil {
			if apiErr.Code == "" {
				apiErr.Code = nested.Code
			}
			if apiErr.Message == "" {
				apiErr.Message = strings.TrimSpace(nested.Message)
			}
		}
	}
	if apiErr.Message == "" && apiErr.Code == "" {
		apiErr.Message = printableSnippet(body)
	}
	return apiErr
}

// printableSnippet renders a bounded, printable-only excerpt of a raw body.
func printableSnippet(body []byte) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, string(body))
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if len(cleaned) > maxRawBodyInMessage {
		cleaned = cleaned[:maxRawBodyInMessage] + "…"
	}
	return cleaned
}
