package config

import (
	"fmt"
	"net/url"
)

// validateBlobAccountURL rejects a blob_ingest.account_url that cannot work, at
// startup, naming the bad value. An empty URL is valid — it means blob ingest is
// off for this tenant.
//
// Checking here rather than leaving it to the Azure SDK is deliberate:
// azblob.NewClient accepts a malformed URL and only fails on the first request,
// which would turn a config typo into a per-tick error on every blob collector
// instead of one clear startup failure. https is required because azcore refuses
// to attach a bearer token to a plaintext endpoint, so http:// can never work.
func validateBlobAccountURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q must be an https URL with a host, e.g. https://<account>.blob.core.windows.net", raw)
	}
	return nil
}
