package exportjob

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// maxDownloadBytes caps a SAS-url download so a pathological response can't
// exhaust memory; generous for a fleet-wide export ZIP.
const maxDownloadBytes = 256 << 20

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
	return &httpDownloader{client: &http.Client{}}
}

// Download implements Downloader.
func (d *httpDownloader) Download(ctx context.Context, sasURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sasURL, nil)
	if err != nil {
		return nil, fmt.Errorf("exportjob: build download request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exportjob: download: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
	if err != nil {
		return nil, fmt.Errorf("exportjob: read download body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("exportjob: download: status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}
