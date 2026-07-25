package exportjob

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestReadDownloadBodyHonoursExactLimitAndDetectsOverflow(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		limit   int64
		wantErr string
	}{
		{name: "exact limit", body: "1234", limit: 4},
		{name: "limit plus one", body: "12345", limit: 4, wantErr: "download exceeds maximum size of 4 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readDownloadBody(bytes.NewBufferString(tt.body), tt.limit)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("readDownloadBody: %v", err)
				}
				if string(got) != tt.body {
					t.Fatalf("body = %q, want %q", got, tt.body)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("readDownloadBody error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultDownloaderUsesPackageLocalTimeout(t *testing.T) {
	dl, ok := DefaultDownloader().(*httpDownloader)
	if !ok {
		t.Fatalf("DefaultDownloader returned %T, want *httpDownloader", DefaultDownloader())
	}
	if dl.client.Timeout == 0 {
		t.Fatal("DefaultDownloader client timeout = 0, want a package-local deadline")
	}
}

func TestDownloaderStalledServerTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	dl := &httpDownloader{client: &http.Client{Timeout: 25 * time.Millisecond}}
	start := time.Now()
	_, err := dl.Download(context.Background(), srv.URL)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Download error = %v, want timeout wrapping context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "download timeout") {
		t.Fatalf("Download error = %v, want timeout context", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Download took %v, want the client deadline to bound it", elapsed)
	}
}

func TestDownloaderProcessCancellationIsImmediate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("canceled request reached server")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := DefaultDownloader().Download(ctx, srv.URL)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Download error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("canceled Download took %v, want immediate return", elapsed)
	}
}
