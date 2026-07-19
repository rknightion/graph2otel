package graphactivity

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// endpointPathCap bounds the distinct normalized_path label values a single
// collector will emit before collapsing the rest to "other" (#185). A miss in
// normalizeGraphPath (an id shape it does not recognize) would otherwise grow
// active series with tenant traffic; this fails safe well before the SDK's 10k
// otel.metric.overflow backstop (#105), and to a MEANINGFUL bucket rather than
// the opaque overflow series.
const endpointPathCap = 200

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// normalizeGraphPath turns a raw Graph request URI into a bounded template: the
// host and query string are dropped, and every path segment that looks like an
// identifier (GUID, UPN/email, all-numeric, or a long opaque token) becomes
// "{id}". Resource-type and action segments (users, groups, $count,
// batchClassifyAndEvaluate) are kept, so cardinality is bounded by the shape of
// the API surface rather than by tenant data. Written against live MGAL URIs
// (#142), with the distinct-path cap as the hard backstop for any shape missed.
func normalizeGraphPath(rawURI string) string {
	p := rawURI
	if u, err := url.Parse(rawURI); err == nil && u.Path != "" {
		p = u.Path
	} else if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return "/"
	}
	segs := strings.Split(trimmed, "/")
	for i, s := range segs {
		segs[i] = normalizeSegment(s)
	}
	return "/" + strings.Join(segs, "/")
}

// normalizeSegment replaces one identifier-shaped path segment with "{id}".
func normalizeSegment(s string) string {
	// OData bound function call: foo(args) -> foo(). The args vary per call and
	// are not part of the endpoint shape.
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[:i] + "()"
	}
	base := strings.TrimSuffix(s, "()")
	switch {
	case base == "" || strings.HasPrefix(base, "$"): // "", $count, $value, $ref
		return s
	case strings.Contains(base, "@"): // UPN / email
		return "{id}"
	case guidRe.MatchString(base):
		return "{id}"
	case isAllDigits(base):
		return "{id}"
	case len(base) >= 20 && hasDigit(base): // opaque token: mail/drive item ids etc.
		return "{id}"
	default:
		return s
	}
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// statusClass buckets an HTTP status code into its class, so the endpoint
// counter carries a bounded status dimension (5 values) rather than the full
// code (#185).
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "other"
	}
}

// activityDeriver holds the per-collector distinct-path set behind the
// endpoint counter's cap (#185). One instance per collector instance; its
// derive method is the ContainerConfig.Derive hook.
type activityDeriver struct {
	mu   sync.Mutex
	seen map[string]struct{}
	cap  int
}

func newActivityDeriver() *activityDeriver {
	return &activityDeriver{seen: map[string]struct{}{}, cap: endpointPathCap}
}

// derive returns the stateless per-request points (the counter + native
// histograms, deriveActivity) plus the stateful endpoint counter and the
// distinct-path headroom gauge.
func (a *activityDeriver) derive(rec map[string]any, ev telemetry.Event) []blobpipeline.MetricPoint {
	pts := deriveActivity(rec, ev)
	props := nested(rec, "properties")
	if props == nil {
		return pts
	}
	path := a.cappedPath(normalizeGraphPath(str(props, "requestUri")))
	status, _ := intOf(props, "responseStatusCode")
	epAttrs := telemetry.Attrs{}
	telemetry.SetStr(epAttrs, semconv.AttrNormalizedPath, path)
	telemetry.SetStr(epAttrs, semconv.AttrRequestMethod, str(props, "requestMethod"))
	telemetry.SetStr(epAttrs, semconv.AttrResponseStatusClass, statusClass(status))
	pts = append(pts, blobpipeline.MetricPoint{
		Name:  "entra.graph_activity.endpoint_requests",
		Kind:  blobpipeline.MetricCounter,
		Unit:  "{request}",
		Desc:  "Microsoft Graph API calls by normalized endpoint path, method, and status class (#185).",
		Value: 1,
		Attrs: epAttrs,
	})

	a.mu.Lock()
	n := len(a.seen)
	a.mu.Unlock()
	pts = append(pts, blobpipeline.MetricPoint{
		Name:  "graph2otel.blob.endpoint_paths",
		Kind:  blobpipeline.MetricGauge,
		Unit:  "{path}",
		Desc:  "Distinct normalized Graph endpoint paths seen by this collector — headroom against the path cap (#185).",
		Value: float64(n),
		Attrs: telemetry.Attrs{semconv.AttrCollector: collectorName},
	})
	return pts
}

// cappedPath returns p if it is already seen or there is cap headroom (recording
// it), else "other". This is the one guard that keeps a normalization miss from
// growing active series without bound.
func (a *activityDeriver) cappedPath(p string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.seen[p]; ok {
		return p
	}
	if len(a.seen) >= a.cap {
		return "other"
	}
	a.seen[p] = struct{}{}
	return p
}
