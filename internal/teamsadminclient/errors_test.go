package teamsadminclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestErrorEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantCode   string
		wantMsg    string
		wantErrNum int
	}{
		{
			name: "flat envelope", status: 400,
			body:     `{"code":"BadRequest","message":"Unknown configuration","action":"Check the name","errorCode":40001}`,
			wantCode: "BadRequest", wantMsg: "Unknown configuration (action: Check the name)", wantErrNum: 40001,
		},
		{
			name: "nested envelope", status: 400,
			body:     `{"Error":{"Code":"InvalidQuery","Message":"bad number management query"}}`,
			wantCode: "InvalidQuery", wantMsg: "bad number management query",
		},
		{
			name: "NUL bytes", status: 403,
			body:    strings.Repeat("\x00", 4096),
			wantMsg: "response body was not JSON (4096 bytes)",
		},
		{
			name: "html", status: 502,
			body:    "<html>Bad gateway</html>",
			wantMsg: "response body was not JSON (24 bytes): <html>Bad gateway</html>",
		},
		{
			name: "json without a message", status: 500,
			body:    `{"unexpected":"shape"}`,
			wantMsg: `{"unexpected":"shape"}`,
		},
		{
			name: "error is a string", status: 500,
			body:    `{"error":"plain text failure"}`,
			wantMsg: `{"error":"plain text failure"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			c, _ := newTestClient(t, srv, nil)
			_, err := c.Configurations(context.Background(), "TenantNetworkSite")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want *APIError", err)
			}
			if apiErr.StatusCode != tc.status || apiErr.Code != tc.wantCode || apiErr.ErrorCode != tc.wantErrNum {
				t.Errorf("APIError = %+v, want status %d code %q errorCode %d", apiErr, tc.status, tc.wantCode, tc.wantErrNum)
			}
			if !strings.HasPrefix(apiErr.Message, tc.wantMsg) {
				t.Errorf("Message = %q, want prefix %q", apiErr.Message, tc.wantMsg)
			}
			if apiErr.Path != "/Skype.Policy/configurations/TenantNetworkSite" {
				t.Errorf("Path = %q", apiErr.Path)
			}
			if strings.ContainsRune(apiErr.Error(), 0) || strings.Contains(apiErr.Error(), "invalid character") {
				t.Errorf("Error() leaks NUL bytes or decoder text: %q", apiErr.Error())
			}
		})
	}
}

func TestStatusMessagesAreDistinct(t *testing.T) {
	msgs := map[int]string{}
	for _, status := range []int{401, 403} {
		srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		c, _ := newTestClient(t, srv, nil)
		_, err := c.Configurations(context.Background(), "X")
		if err == nil {
			t.Fatalf("status %d: nil error", status)
		}
		msgs[status] = err.Error()
	}
	if !strings.Contains(msgs[403], "directory role") {
		t.Errorf("403 message does not name the directory role: %q", msgs[403])
	}
	if !strings.Contains(msgs[401], "token") || !strings.Contains(msgs[401], "audience") {
		t.Errorf("401 message does not say token or audience rejected: %q", msgs[401])
	}
	if strings.Contains(msgs[401], "directory role") || strings.Contains(msgs[403], "audience") {
		t.Errorf("401 and 403 messages overlap: 401=%q 403=%q", msgs[401], msgs[403])
	}
}

func TestIsPermission(t *testing.T) {
	for status, want := range map[int]bool{401: false, 403: true, 404: false, 429: false, 500: false} {
		err := fmt.Errorf("wrapped: %w", &APIError{StatusCode: status})
		if got := IsPermission(err); got != want {
			t.Errorf("IsPermission(status %d) = %v, want %v", status, got, want)
		}
	}
	if IsPermission(nil) || IsPermission(errors.New("403")) {
		t.Error("IsPermission true for a non-APIError")
	}
	if IsPermission(ErrToken) {
		t.Error("IsPermission(ErrToken) = true")
	}
}

func TestErrorTextHasNoQueryString(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	c, _ := newTestClient(t, srv, nil)
	_, err := c.VoiceApps(context.Background(), CallQueues)
	if err == nil {
		t.Fatal("nil error")
	}
	for _, leak := range []string{"First=", "Skip=", "FilterInvalidObos", srv.URL} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text leaks %q: %s", leak, err)
		}
	}
}
