package admin

import (
	"encoding/json"
	"io"
	"net/http"
)

// handleHealthz is the unconditional liveness probe: 200 whenever the admin
// server itself is up and able to answer HTTP requests. It makes no Graph API
// calls and has no dependency on collector health — a degraded or failing
// collector is visible on the status page, never on /healthz, so a cluster's
// liveness check never restarts the process over a transient upstream issue.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

// handleStatusJSON serves the current status snapshot as machine-readable JSON.
func (s *Server) handleStatusJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.snapshot())
}

// handleConfigJSON serves the effective NON-secret configuration as JSON (#211).
// Like every admin handler it reads only passive in-memory state (the injected
// config struct) and makes no live tenant call. Secrets are presence-only: the
// ConfigView carries a bool per credential, never the value.
func (s *Server) handleConfigJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.configView())
}

// handleCardinalityJSON serves the output-side active-series snapshot as JSON
// (#215). It reads the existing CardinalityTracker's last completed snapshot (a
// pure in-memory read) plus the configured per_metric_limit — no live tenant call.
func (s *Server) handleCardinalityJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.cardinalityView())
}

// handleIndex renders the HTML status page. Because "/" is the ServeMux
// catch-all, any unknown path that falls through to here 404s rather than
// returning the page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = render(w, s.pageSnapshot())
}
