package annotations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

// annotationsPath is the ONLY Grafana path this package ever calls. It is a
// constant, not a parameter, because that is what keeps the #310 invariant
// amendment narrow: a caller cannot point this client at another endpoint.
const annotationsPath = "/api/annotations"

// FailureCode is the bounded category of an annotation publish failure. It is
// bounded for the same reason telemetry.DeliveryFailureCode is: it becomes a
// metric label, and a raw error string there is unbounded cardinality (#112).
type FailureCode string

const (
	// FailureUnauthorized is 401/403 — the token is missing, expired, or lacks
	// annotations:create. It is the one an operator most needs named.
	FailureUnauthorized FailureCode = "unauthorized"
	// FailureRateLimited is 429 from Grafana itself (distinct from graph2otel's
	// own max_per_minute ceiling, which never reaches the wire).
	FailureRateLimited FailureCode = "rate_limited"
	// FailureRejected is any other 4xx — a malformed request.
	FailureRejected FailureCode = "rejected"
	// FailureServerError is 5xx.
	FailureServerError FailureCode = "server_error"
	// FailureTransport is a connection, DNS, TLS or timeout failure: the request
	// never got an HTTP status.
	FailureTransport FailureCode = "transport"
)

// FailureCodes returns every failure code in a stable order, so a test can
// enumerate the closed set rather than restate it.
func FailureCodes() []FailureCode {
	return []FailureCode{
		FailureUnauthorized,
		FailureRateLimited,
		FailureRejected,
		FailureServerError,
		FailureTransport,
	}
}

// PublishError carries the bounded code alongside the human detail. The detail
// reaches the log; only Code reaches a metric label.
type PublishError struct {
	Code   FailureCode
	Status int
	Detail string
}

func (e *PublishError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("grafana annotation write failed (%s, HTTP %d): %s", e.Code, e.Status, e.Detail)
	}
	return fmt.Sprintf("grafana annotation write failed (%s): %s", e.Code, e.Detail)
}

// Client posts annotations to one Grafana organization.
//
// It holds the service-account token. The token needs exactly one Grafana
// action — `annotations:create`, scoped `annotations:type:organization` (or
// `annotations:type:dashboard` when DashboardUID is set); the fixed role that
// grants it is `fixed:annotations:writer`. Nothing here asks for or uses any
// other permission, and nothing here calls any other path.
type Client struct {
	endpoint     string
	token        string
	dashboardUID string
	http         *http.Client
}

// NewClient builds the annotation client from the validated config block.
func NewClient(cfg config.GrafanaAnnotationsConfig) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.URL), "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("grafana_annotations.url %q is not a valid absolute URL", cfg.URL)
	}
	token := strings.TrimSpace(cfg.Token.Reveal())
	if token == "" {
		return nil, errors.New("grafana_annotations: no service-account token (set token or token_file)")
	}
	return &Client{
		endpoint:     base.String() + annotationsPath,
		token:        token,
		dashboardUID: strings.TrimSpace(cfg.DashboardUID),
		http:         &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// wireAnnotation is the POST /api/annotations body. Times are epoch
// MILLISECONDS — the API's documented unit, and the one thing about this
// endpoint that is silently wrong rather than rejected if you send seconds: a
// second-resolution value lands in 1970 and the annotation is invisible on every
// dashboard while the API cheerfully returns 200.
type wireAnnotation struct {
	DashboardUID string   `json:"dashboardUID,omitempty"`
	Time         int64    `json:"time"`
	TimeEnd      int64    `json:"timeEnd,omitempty"`
	Tags         []string `json:"tags"`
	Text         string   `json:"text"`
}

// Publish writes one annotation. It returns a *PublishError on failure so the
// caller can record a bounded code without inspecting the error string.
func (c *Client) Publish(ctx context.Context, a Annotation) error {
	body := wireAnnotation{
		DashboardUID: c.dashboardUID,
		Time:         a.Time.UnixMilli(),
		Tags:         a.Tags(),
		Text:         a.Text,
	}
	if !a.TimeEnd.IsZero() {
		body.TimeEnd = a.TimeEnd.UnixMilli()
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return &PublishError{Code: FailureRejected, Detail: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return &PublishError{Code: FailureTransport, Detail: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return &PublishError{Code: FailureTransport, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded prefix: the body carries Grafana's own explanation of a
	// permission failure, which is the single most useful line an operator can
	// be shown, and draining also lets the connection be reused.
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &PublishError{
		Code:   classify(resp.StatusCode),
		Status: resp.StatusCode,
		Detail: strings.TrimSpace(string(detail)),
	}
}

// classify maps an HTTP status onto the bounded failure code.
func classify(status int) FailureCode {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return FailureUnauthorized
	case status == http.StatusTooManyRequests:
		return FailureRateLimited
	case status >= 500:
		return FailureServerError
	default:
		return FailureRejected
	}
}

// rateLimiter is a token bucket sized in annotations per minute. It is a
// CEILING on what reaches Grafana, not a queue: over the ceiling an annotation
// is dropped and counted, because delaying a marker past the moment it explains
// makes it worse than absent.
type rateLimiter struct {
	interval time.Duration
	capacity int
	tokens   int
	last     time.Time
	now      func() time.Time
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		interval: time.Minute / time.Duration(perMinute),
		capacity: perMinute,
		tokens:   perMinute,
		last:     now(),
		now:      now,
	}
}

// allow reports whether one annotation may be written now.
func (l *rateLimiter) allow() bool {
	now := l.now()
	if elapsed := now.Sub(l.last); elapsed >= l.interval {
		refill := int(elapsed / l.interval)
		l.tokens = min(l.capacity, l.tokens+refill)
		l.last = now
	}
	if l.tokens <= 0 {
		return false
	}
	l.tokens--
	return true
}
