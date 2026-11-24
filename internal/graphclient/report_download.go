package graphclient

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	nethttplibrary "github.com/microsoft/kiota-http-go"
)

// ReportDownloadContext permits one unauthenticated HTTPS hop to the Microsoft
// reporting host for a Graph usage report GET. RawGet still validates the initial
// Graph host. The ticket-bearing URL is not a Graph API endpoint.
func ReportDownloadContext(ctx context.Context) context.Context {
	options := &nethttplibrary.RedirectHandlerOptions{
		MaxRedirects: 1,
		ShouldRedirect: func(_ *http.Request, res *http.Response) bool {
			if res == nil || res.StatusCode != http.StatusFound {
				return false
			}
			target, err := url.Parse(res.Header.Get("Location"))
			if err != nil || target.Scheme != "https" || target.User != nil {
				return false
			}
			// The generic host is documented; all three Teams CSVs in the
			// poller check redirected to Microsoft's West Europe host (#664).
			// Accept only those hosts and the standard HTTPS port.
			switch strings.ToLower(target.Host) {
			case "reports.office.com", "reports.office.com:443", "reportsweu.office.com", "reportsweu.office.com:443":
				return true
			default:
				return false
			}
		},
		ScrubSensitiveHeaders: func(req *http.Request, _ *url.URL) {
			// The download uses the ticket, not Graph request credentials.
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Del("Referer")
		},
	}
	return context.WithValue(ctx, options.GetKey(), options)
}
