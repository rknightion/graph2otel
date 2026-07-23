package exoclient

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// CmdletError is a failed cmdlet invocation.
//
// The HTTP status is not a discriminator on this API: every argument error, every
// unknown parameter, every invalid enum value and several authorization failures
// are all HTTP 400 or 403. What separates them is the text buried inside the
// envelope, which is why Message is resolved rather than copied — see
// resolveMessage.
type CmdletError struct {
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Cmdlet is the cmdlet that failed. The URL is identical for every
	// invocation, so without this an error names nothing at all.
	Cmdlet string
	// Code is error.code from the envelope (e.g. "BadRequest"), or "" when the
	// body was not the documented envelope.
	Code string
	// Message is the UNWRAPPED, useful text — never the outer error.message when
	// anything better exists. See resolveMessage for the precedence and why it
	// matters.
	Message string
	// Type is the .NET exception type from innererror.internalexception, when the
	// body carried one. It is the most reliable machine-readable discriminator
	// this API offers, since Code is "BadRequest" for nearly everything.
	Type string
}

func (e *CmdletError) Error() string {
	var b strings.Builder
	b.WriteString("exoclient: ")
	if e.Cmdlet != "" {
		b.WriteString(e.Cmdlet + ": ")
	}
	fmt.Fprintf(&b, "status %d", e.StatusCode)
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if e.Type != "" {
		b.WriteString(": " + e.Type)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	return b.String()
}

// errorEnvelope is the failure body, transcribed from live captures rather than
// from documentation. Only the fields this package reads are declared; the
// stacktrace and adminapi.warnings members are deliberately ignored.
//
//	{"error":{
//	  "code":"BadRequest",
//	  "message":"Invalid Operation",
//	  "details":[{"code":"Client","message":"|Type.Name|real message"}],
//	  "innererror":{"internalexception":{"message":"real message","type":"Type.Name"}}
//	}}
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Code    string `json:"code"`
			Target  string `json:"target"`
			Message string `json:"message"`
		} `json:"details"`
		InnerError struct {
			Message           string `json:"message"`
			Type              string `json:"type"`
			InternalException struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"internalexception"`
		} `json:"innererror"`
	} `json:"error"`
}

// maxRawBodyInMessage caps how much of an undecodable body is quoted back into
// an error string, so a 4 KiB run of junk does not become a 4 KiB log line.
const maxRawBodyInMessage = 200

// parseCmdletError turns a non-2xx response into a typed *CmdletError.
//
// It never returns a JSON-decoder error to the caller. A body that is not JSON
// at all is a REAL, live-observed response shape here — an unauthorized or
// unknown cmdlet answers 403 with a long run of NUL bytes — so the decoder
// failing is an expected branch, not an internal error, and it must still yield
// an error naming the status and the cmdlet.
func parseCmdletError(statusCode int, body []byte, cmdlet string) error {
	cerr := &CmdletError{StatusCode: statusCode, Cmdlet: cmdlet}

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		cerr.Message = notJSONMessage(body)
		return cerr
	}

	cerr.Code = env.Error.Code
	cerr.Type = env.Error.InnerError.InternalException.Type
	cerr.Message = resolveMessage(env)
	if cerr.Message == "" {
		// Valid JSON, but not this envelope. Keep the raw body so the failure
		// stays diagnosable instead of collapsing to a bare status.
		cerr.Message = printableSnippet(body)
	}
	return cerr
}

// resolveMessage picks the most useful text the envelope carries, in a fixed
// precedence order.
//
// This ordering is the whole point of the type. error.message is ALWAYS the
// literal string "Invalid Operation" regardless of what went wrong, so a client
// that surfaces it reports nothing actionable, on every error, forever. The
// unwrapped text is by contrast genuinely excellent: an invalid enum value comes
// back with the complete list of valid members.
//
//  1. error.innererror.internalexception.message — the real .NET exception text.
//  2. error.details[0].message — the same text, prefixed "|<Type.Name>|". Present
//     on some failures where innererror is not.
//  3. error.message — the useless literal, and only ever a last resort.
func resolveMessage(env errorEnvelope) string {
	if m := strings.TrimSpace(env.Error.InnerError.InternalException.Message); m != "" {
		return m
	}
	if len(env.Error.Details) > 0 {
		if m := strings.TrimSpace(stripTypePrefix(env.Error.Details[0].Message)); m != "" {
			return m
		}
	}
	return strings.TrimSpace(env.Error.Message)
}

// stripTypePrefix removes a leading "|<dotted.Type.Name>|" from a details
// message. The prefix is a wire artifact, not part of the sentence, and leaving
// it in makes the message read as corrupt.
func stripTypePrefix(s string) string {
	if !strings.HasPrefix(s, "|") {
		return s
	}
	end := strings.Index(s[1:], "|")
	if end < 0 {
		return s
	}
	return s[end+2:]
}

// notJSONMessage describes an undecodable body without leaking decoder text.
//
// The JSON decoder's own error ("invalid character '\\x00' looking for beginning
// of value") is worse than useless in a log line: it reads as a bug in
// graph2otel rather than as the authorization failure it almost always is.
func notJSONMessage(body []byte) string {
	msg := fmt.Sprintf("response body was not JSON (%d bytes)"+
		" — the usual cause is a missing Exchange.ManageAsApp app role or a missing directory role", len(body))
	if snippet := printableSnippet(body); snippet != "" {
		msg += ": " + snippet
	}
	return msg
}

// printableSnippet renders a bounded, printable-only excerpt of a raw body. The
// live 403 capture is thousands of NUL bytes; pasting those into a log record
// corrupts the line, so anything unprintable is dropped rather than escaped.
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

	cleaned = strings.TrimSpace(strings.Join(strings.Fields(cleaned), " "))
	if len(cleaned) > maxRawBodyInMessage {
		cleaned = cleaned[:maxRawBodyInMessage] + "…"
	}
	return cleaned
}
