package callnotify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidationEcho(t *testing.T) {
	r := New()
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.invalid/graph/call-records?validationToken=a%2Bb+%3Ctag%3E", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain" || w.Body.String() != "a+b <tag>" {
		t.Fatalf("validation response: status %d, headers %v, body %q", w.Code, w.Header(), w.Body.String())
	}
}
