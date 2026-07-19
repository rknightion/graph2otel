package mdcaclient

import "fmt"

// APIError is a non-2xx response from the MDCA portal API.
//
// Unlike o365activityclient's AF-coded errors, the MDCA portal API does not
// document a structured error envelope, so this carries the raw status and body
// rather than a parsed code. The body is retained (bounded by maxBodyBytes) so a
// diagnosis is possible, and the status drives the retry decision — a 401/403 is
// a token problem that will not resolve itself, a 429/5xx is transient.
type APIError struct {
	Status int
	Body   string
	Method string
	URL    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mdcaclient: %s %s: status %d: %s", e.Method, e.URL, e.Status, e.Body)
}
