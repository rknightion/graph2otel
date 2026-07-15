package exportjob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDefaultDownloaderFetchesWithoutBearerToken verifies the production
// Downloader sends no Authorization header (a SAS url is self-authenticating
// Azure Blob Storage, not Graph) and returns the response body verbatim.
func TestDefaultDownloaderFetchesWithoutBearerToken(t *testing.T) {
	want := []byte("PK\x03\x04fake-zip-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization header = %q, want none", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	dl := DefaultDownloader()
	got, err := dl.Download(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("Download body = %q, want %q", got, want)
	}
}

// TestDefaultDownloaderNonOKStatus verifies a non-2xx response is surfaced
// as an error rather than silently returning the error page's body as data.
func TestDefaultDownloaderNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("AuthenticationFailed"))
	}))
	defer srv.Close()

	dl := DefaultDownloader()
	if _, err := dl.Download(context.Background(), srv.URL); err == nil {
		t.Fatal("Download with a 403 response: want an error, got nil")
	}
}
