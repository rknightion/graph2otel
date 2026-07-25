package exportjob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Download bounds are local to this SAS-url client. Export jobs can run for
// longer than an individual download, so this must not become a scheduler-wide
// context deadline.
const (
	// maxDownloadBytes caps a SAS-url download so a pathological response can't
	// exhaust memory; generous for a fleet-wide export ZIP.
	maxDownloadBytes = 256 << 20
	// defaultDownloadTimeout bounds the Azure Blob request, including headers and
	// body reads, independently of an export job's polling lifetime.
	defaultDownloadTimeout = 5 * time.Minute
)

// httpDownloader is the production Downloader: it fetches the pre-signed
// SAS url with NO Authorization header, because that url is already a
// self-authenticating Azure Blob Storage SAS token — attaching a Graph
// bearer token is neither required nor accepted there.
type httpDownloader struct {
	client *http.Client
}

// DefaultDownloader returns the production Downloader, built on a plain
// *http.Client independent of any package-wide default client.
func DefaultDownloader() Downloader {
	return &httpDownloader{client: &http.Client{Timeout: defaultDownloadTimeout}}
}

// Download implements Downloader.
func (d *httpDownloader) Download(ctx context.Context, sasURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sasURL, nil)
	if err != nil {
		return nil, fmt.Errorf("exportjob: build download request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("exportjob: download timeout: %w", err)
		}
		return nil, fmt.Errorf("exportjob: download: %w", err)
	}
	defer resp.Body.Close()

	body, err := readDownloadBody(resp.Body, maxDownloadBytes)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("exportjob: download timeout: %w", err)
		}
		return nil, fmt.Errorf("exportjob: read download body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("exportjob: download: status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// readDownloadBody reads one byte past limit, so an exact-limit response is
// accepted while an oversized one is reported instead of silently truncated.
func readDownloadBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("download exceeds maximum size of %d bytes", limit)
	}
	return body, nil
}
